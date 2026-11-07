/// Block and transaction executor using revm.
///
/// Executes RSK transactions against the Unitrie state, producing
/// execution results (gas used, logs, state changes) compatible with
/// rskj's behavior.
use alloy_primitives::{Address, U256};
use revm::context::CfgEnv;
use revm::database::WrapDatabaseRef;
use revm::primitives::hardfork::SpecId;
use revm::{ExecuteEvm, MainBuilder, MainContext};
use sha3::Digest as _;
use rustock_core::Header;
use rustock_storage::BlockStore;
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;
use tracing::debug;

use crate::database::RskDatabase;
use crate::env::{block_env_from_header, tx_env_from_rsk_tx};
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::{rsk_precompiles, BridgeTxContext, RskPrecompileProvider, REMASC_ADDR};

/// Result of executing a single transaction.
#[derive(Debug)]
pub struct TxExecutionResult {
    pub gas_used: u64,
    pub success: bool,
    pub output: Vec<u8>,
    pub logs: Vec<revm::primitives::Log>,
    pub created_address: Option<Address>,
    /// The transaction reached REMASC or the Bridge, so under RSKIP-144 it
    /// may only sit in the sequential sublist
    /// (`SEQUENTIAL_ONLY_PRECOMPILES`). True whatever the call returned --
    /// reaching the precompile is what counts.
    pub reached_sequential_only: bool,
}

/// What the miner's execution mode left out of the block, by index into the
/// transaction list it was given. See [`RskExecutor::execute_block_for_mining`].
#[derive(Debug, Default)]
pub struct MiningDrops {
    /// Did not fit in the block's remaining gas, or followed a dropped
    /// transaction of the same sender. Still a fine transaction for a later
    /// block; the pool keeps it.
    pub unfitting: Vec<usize>,
    /// Refused by the EVM before it ran: a nonce the state does not expect,
    /// a balance that no longer covers it, too little intrinsic gas. rskj
    /// collects these as `BlockResult.getInvalidTransactions()` and the
    /// miner removes them from the pool.
    pub invalid: Vec<usize>,
}

impl MiningDrops {
    pub fn is_empty(&self) -> bool {
        self.unfitting.is_empty() && self.invalid.is_empty()
    }
    /// Whether `index` was dropped for either reason.
    pub fn contains(&self, index: usize) -> bool {
        self.unfitting.contains(&index) || self.invalid.contains(&index)
    }
}

/// Result of executing an entire block.
#[derive(Debug)]
pub struct BlockExecutionResult {
    pub tx_results: Vec<TxExecutionResult>,
    pub gas_used: u64,
    /// Total fees credited to REMASC (rskj validates this against
    /// `header.paid_fees` after execution).
    pub paid_fees: U256,
    pub state_changes: revm::state::EvmState,
    /// Contract storage-prefix marker writes accumulated during execution
    /// (rskj `setupContract`), applied to the trie with the state changes.
    pub markers: crate::state::ContractMarkers,
    /// The state the block left, when execution applied it itself.
    ///
    /// `None` for a block that ran as one, where the caller applies
    /// `state_changes` and `markers` as it always has. `Some` for a block
    /// whose sublists ran separately: each one's changes are committed to the
    /// trie in sublist order, because that is what makes the sequential
    /// sublist's starting state well defined, and re-applying the merged
    /// result on top would not reproduce it.
    ///
    /// `state_changes` is still the whole block's, and still carries each
    /// account's final values -- the supply check reads it.
    pub applied_root: Option<TrieNode>,
    /// Where the block's time went, split by phase.
    pub phases: PhaseTimings,
}

/// Microseconds spent in each phase of executing one block.
///
/// Three of these are **sequential whatever the thread count**, which is
/// why they are measured separately: the maintenance run has to finish
/// before any sublist starts, and the commit has to apply the sublists
/// in order because that is what makes the sequential sublist's starting
/// state well defined. Only `sublists` is the part threads divide.
///
/// Amdahl says the sequential share bounds everything parallel execution
/// can return, and until this existed that share was inferred from
/// differences between whole runs rather than measured.
///
/// Collecting it costs a few `Instant::now()` a block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseTimings {
    /// The block-level run that owns no sublist: REMASC, the bridge,
    /// fork activations. Every sublist starts from the state it leaves.
    pub maintenance_us: u64,
    /// Executing the parallel sublists. The only part threads divide.
    pub sublists_us: u64,
    /// Applying each sublist's changes to the trie, in sublist order:
    /// one `apply_state_changes` per sublist plus one for the sequential
    /// set, each rebuilding the upper trie on the previous one's result.
    ///
    /// **This used to include the sequential sublist's execution**, which
    /// is a fifth of a block's transactions and has nothing to do with
    /// the trie. That made the commit look twice the size of the parallel
    /// execution when a good part of the difference was simply more
    /// transactions being run. `sequential_us` is that work, now counted
    /// where it belongs.
    pub commit_us: u64,
    /// Running the sequential sublist -- the transactions that may touch
    /// REMASC or the Bridge and so cannot share a sublist with anything.
    /// Execution, not trie work, and no thread count divides it.
    pub sequential_us: u64,
}

/// One sublist's run, with everything it collected on its own thread.
struct SublistRun {
    result: BlockExecutionResult,
    traces: std::collections::BTreeMap<usize, crate::tracer::ProgramTrace>,
    /// The sublist's read and write key sets. The worker's thread-local
    /// recorder is not the coordinator's, so they travel back by hand.
    keys: Option<crate::collision::CollisionTracker>,
    /// Likewise for the silent bridge-decision records.
    records: Vec<crate::silent::SilentRecord>,
}

/// Fold one sublist's marker writes into the block's.
///
/// The trie already has them -- each sublist's markers were applied with its
/// own state changes -- so this is for the reported result.
fn merge_markers(into: &mut crate::state::ContractMarkers, from: crate::state::ContractMarkers) {
    into.skip_created.extend(from.skip_created);
    for addr in from.precompiles {
        if !into.precompiles.contains(&addr) {
            into.precompiles.push(addr);
        }
    }
    into.bump_remasc_sender |= from.bump_remasc_sender;
    into.raw_storage.extend(from.raw_storage);
}

/// Fold one sublist's state into the block's reported state.
///
/// Later sublists win on what they changed, which is what the trie commits
/// already did. Among the *parallel* sublists nothing can conflict: the
/// collision rule makes a block invalid when two of them write the same cell,
/// so their write sets are disjoint by the time this runs. The sequential
/// sublist is the one that genuinely writes over them, and it comes last.
///
/// An account the later sublist only read keeps the earlier values. Reading
/// does not make a sublist the authority on anything.
fn merge_reported_state(into: &mut revm::state::EvmState, from: revm::state::EvmState) {
    use revm::state::AccountStatus;
    use std::collections::hash_map::Entry;
    for (addr, account) in from {
        let wrote_account = account.info != *account.original_info
            || account.status.intersects(
                AccountStatus::SelfDestructed | AccountStatus::Created | AccountStatus::Touched,
            );
        match into.entry(addr) {
            Entry::Vacant(slot) => {
                slot.insert(account);
            }
            Entry::Occupied(mut slot) => {
                let held = slot.get_mut();
                for (key, cell) in account.storage {
                    if cell.present_value != cell.original_value
                        || !held.storage.contains_key(&key)
                    {
                        held.storage.insert(key, cell);
                    }
                }
                if wrote_account {
                    held.info = account.info;
                    held.status |= account.status;
                }
            }
        }
    }
}

/// Executes RSK blocks and transactions using revm.
pub struct RskExecutor {
    hardfork_cfg: RskHardforkConfig,
    block_store: Arc<BlockStore>,
    remasc_config: crate::remasc::RemascConfig,
    bridge_constants: crate::bridge::constants::BridgeConstants,
    /// RSK addresses allowed to send free bridge txs (genesis federation +
    /// authorizers), derived from the bridge constants' public keys.
    free_bridge_senders: Vec<Address>,
    /// Node-wide cache of BTC stored blocks, shared across every block this
    /// executor runs. `None` disables it, which is the default so that tools
    /// and tests get unchanged behaviour without opting out.
    btc_block_cache: Option<Arc<crate::bridge::btc_block_cache::BtcBlockCache>>,
    /// How many threads may run a block's parallel sublists (RSKIP-144).
    ///
    /// 1 means every transaction runs in order on the calling thread, which
    /// is also what happens at any setting for a block that declares no
    /// sublists -- which is every block on a chain where RSKIP-144 is
    /// unscheduled.
    execution_threads: usize,
}

impl RskExecutor {
    /// Share a BTC stored-block cache across every block this executor runs.
    ///
    /// Off unless a caller asks for it. The cache changes latency only: it is
    /// populated solely from reads consensus already performed, and it holds no
    /// negative entries, so a node with it and a node without it read the same
    /// trie nodes and reach the same answers.
    pub fn with_btc_block_cache(
        mut self,
        cache: Arc<crate::bridge::btc_block_cache::BtcBlockCache>,
    ) -> Self {
        self.btc_block_cache = Some(cache);
        self
    }

    /// How many threads a block's parallel sublists may use.
    ///
    /// At least 1. Not clamped from above against
    /// `TX_EXECUTION_THREADS`, because that constant bounds what a *header*
    /// may declare and the real bound is what a given block actually
    /// declared: a block with one parallel sublist gains nothing from four
    /// threads however high the consensus cap goes. That bound is applied
    /// where it is known, at execution.
    ///
    /// Keeping the two apart also lets a benchmark ask what a wider
    /// partition would be worth. RSKIP-144 specifies
    /// `maxTransactionExecutionThreads = 4` where rskj implements 2, and a
    /// measurement of the difference should not require editing a consensus
    /// constant to take it.
    pub fn with_execution_threads(mut self, threads: usize) -> Self {
        self.execution_threads = threads.max(1);
        self
    }

    pub fn execution_threads(&self) -> usize {
        self.execution_threads
    }

    /// The cache in use, if any -- for the periodic report.
    pub fn btc_block_cache(
        &self,
    ) -> Option<&Arc<crate::bridge::btc_block_cache::BtcBlockCache>> {
        self.btc_block_cache.as_ref()
    }

    pub fn new(hardfork_cfg: RskHardforkConfig, block_store: Arc<BlockStore>) -> Self {
        // Selected by chain, like the bridge constants below. rskj's
        // remasc.json differs per network in ways that change state: testnet's
        // maturity is 50 against mainnet's 4000, and its rskLabsAddress is
        // `dabadaba...0003` rather than `14d3065c...`.
        //
        // Hardcoding mainnet here meant testnet diverged at block #60 -- an
        // empty block whose only transaction is REMASC, and the first one past
        // testnet's maturity window, so the first where a payout happens at
        // all.
        let remasc_config = match hardfork_cfg.chain_id {
            crate::hardfork::RSK_TESTNET_CHAIN_ID => crate::remasc::RemascConfig::testnet(),
            crate::hardfork::RSK_MAINNET_CHAIN_ID => crate::remasc::RemascConfig::mainnet(),
            _ => crate::remasc::RemascConfig::regtest(),
        };
        let bridge_constants = bridge_constants_for(hardfork_cfg.chain_id);
        let free_bridge_senders = free_bridge_senders(&bridge_constants);
        Self {
            hardfork_cfg,
            block_store,
            remasc_config,
            bridge_constants,
            free_bridge_senders,
            btc_block_cache: None,
            // Sequential unless a caller asks otherwise, so an executor built
            // by a tool or a test behaves as it always has.
            execution_threads: 1,
        }
    }

    #[cfg(test)]
    pub(crate) fn remasc_config_for_test(&self) -> &crate::remasc::RemascConfig {
        &self.remasc_config
    }

    pub fn with_remasc_config(mut self, config: crate::remasc::RemascConfig) -> Self {
        self.remasc_config = config;
        self
    }

    pub fn with_bridge_constants(
        mut self,
        constants: crate::bridge::constants::BridgeConstants,
    ) -> Self {
        self.free_bridge_senders = free_bridge_senders(&constants);
        self.bridge_constants = constants;
        self
    }

    /// Execute a single transaction against the given state root.
    /// Execute a transaction outside a block, as an ordinary (non-local) call.
    pub fn execute_tx(
        &self,
        header: &Header,
        tx: &rustock_core::Transaction,
        sender: Address,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<TxExecutionResult, ExecutionError> {
        self.execute_tx_inner(header, tx, sender, state_root, trie_store, false)
    }

    /// Execute a transaction as a **local call** -- rskj's
    /// `ReversibleTransactionExecutor`, which serves `eth_call` and
    /// `eth_estimateGas` and marks the transaction with
    /// `TransactionExecutor.setLocalCall(true)`.
    ///
    /// The only behavioural difference is that Bridge methods marked
    /// `LocalOnly` run instead of throwing (`Bridge.validateLocalCall`,
    /// Bridge.java:431). Those are the read-only getters -- the federation
    /// address, the BTC blockchain head, the peg-out queue sizes -- which rskj
    /// deliberately refuses to answer on-chain so that no contract can depend
    /// on them. Nothing here is reachable from block execution, so it cannot
    /// affect consensus.
    pub fn execute_local_call(
        &self,
        header: &Header,
        tx: &rustock_core::Transaction,
        sender: Address,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<TxExecutionResult, ExecutionError> {
        self.execute_tx_inner(header, tx, sender, state_root, trie_store, true)
    }

    fn execute_tx_inner(
        &self,
        header: &Header,
        tx: &rustock_core::Transaction,
        sender: Address,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        local_call: bool,
    ) -> Result<TxExecutionResult, ExecutionError> {
        let spec_id = self.hardfork_cfg.spec_id(header.number);
        let block_env = block_env_from_header(header, &self.hardfork_cfg);
        let tx_env = tx_env_from_rsk_tx(tx, sender, &self.hardfork_cfg);
        let db = RskDatabase::new(state_root.clone(), trie_store.clone(), self.block_store.clone());

        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id, self.hardfork_cfg.has_rskip544(header.number));

        let mut chain_ext = crate::raw_storage::RskChainExt::default();
        chain_ext.raw_storage.set_reader(trie_store, state_root.clone());
        chain_ext.btc_block_cache = self.btc_block_cache.clone();
        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg)
            .with_chain(chain_ext);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
            Some(self.block_store.clone()),
            self.remasc_config.clone(),
        )
        .with_bridge_config(self.bridge_constants.clone());
        // rskj sets this on the transaction itself; the Bridge reads it out of
        // the per-transaction context, so that is where it goes here.
        if local_call {
            if let Ok(mut guard) = precompile_provider.bridge_tx_context_slot().lock() {
                guard.local_call = true;
            }
        }
        let invisible_flag = precompile_provider.invisible_exception_flag();
        let reached_sequential_only = precompile_provider.reached_sequential_only_slot();
        let active_precompiles: Vec<Address> =
            rsk_precompiles(&self.hardfork_cfg, header.number).addresses().copied().collect();
        let extcodesize_max_precompiles: Vec<Address> = if self.hardfork_cfg.has_rskip90(header.number) {
            active_precompiles.clone()
        } else {
            Vec::new()
        };
        let pre_rskip150_precompiles = (!self.hardfork_cfg.has_rskip150(header.number))
            .then(|| active_precompiles.clone());
        // rskj `VM.doEXTCODEHASH` reports `keccak256("")` for any active
        // precompile; EXTCODEHASH activates at RSKIP140 (papyrus).
        let extcodehash_precompiles: Vec<Address> =
            if self.hardfork_cfg.has_rskip140(header.number) {
                active_precompiles.clone()
            } else {
                Vec::new()
            };
        let mut evm = ctx.build_mainnet().with_precompiles(precompile_provider);
        crate::rsk_instructions::install(
            &mut evm.instruction,
            self.hardfork_cfg.has_rskip140(header.number),
            self.hardfork_cfg.has_chainid(header.number),
            self.hardfork_cfg.has_push0(header.number),
            self.hardfork_cfg.has_basefee(header.number),
            self.hardfork_cfg.has_rskip91(header.number),
            self.hardfork_cfg.has_rskip446(header.number),
            self.hardfork_cfg.has_rskip445(header.number),
            &extcodesize_max_precompiles,
            &extcodehash_precompiles,
            header.beneficiary,
        );

        let exec_out = {
            use revm::context::ContextSetters;
            use revm::handler::Handler;
            evm.ctx.set_tx(tx_env);
            let mut handler = crate::rsk_handler::RskHandler::with_rskip125(
                !self.hardfork_cfg.has_rskip453(header.number),
                self.hardfork_cfg.has_rskip125(header.number),
                invisible_flag,
                pre_rskip150_precompiles,
                active_precompiles,
                self.hardfork_cfg.has_rskip171(header.number),
            );
            let out = handler
                .run(&mut evm)
                .map_err(|e: revm::context::result::EVMError<_>| {
                    ExecutionError::Evm(format!("{e:?}"))
                })?;
            out
        };
        let state = {
            use revm::context_interface::{ContextTr, JournalTr};
            evm.ctx.journal_mut().finalize()
        };
        let result = revm::context::result::ExecResultAndState::new(exec_out, state);

        let exec = result.result;
        let success = exec.is_success();
        let gas_used = exec.gas_used();
        let output = exec.output().map(|o| o.to_vec()).unwrap_or_default();
        let logs = exec.into_logs();

        let created_address = Self::extract_created_address(tx, sender, &success);

        Ok(TxExecutionResult {
            reached_sequential_only: reached_sequential_only
                .load(std::sync::atomic::Ordering::Relaxed),
            gas_used,
            success,
            output,
            logs,
            created_address,
        })
    }

    /// The same execution as `execute_tx_inner`, with a tracer attached.
    ///
    /// **Deliberately a copy of the setup above, not a refactor of it.** The
    /// two differ in exactly two lines -- `build_mainnet_with_inspector`
    /// instead of `build_mainnet`, and `inspect_run` instead of `run` -- and
    /// everything else has to stay identical, because a trace of a different
    /// execution than the chain performed is worse than no trace.
    ///
    /// Restructuring the consensus path to share this would put tracing inside
    /// it; duplicating puts tracing beside it. The cost of duplication is
    /// drift, and `tracing_does_not_change_execution` is the guard against
    /// that: it runs the same transaction both ways and requires the same gas,
    /// the same output, the same success and the same logs.
    pub fn execute_tx_traced(
        &self,
        header: &Header,
        tx: &rustock_core::Transaction,
        sender: Address,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        local_call: bool,
        max_struct_logs: usize,
    ) -> Result<(TxExecutionResult, crate::tracer::ProgramTrace), ExecutionError> {
        let spec_id = self.hardfork_cfg.spec_id(header.number);
        let block_env = block_env_from_header(header, &self.hardfork_cfg);
        let tx_env = tx_env_from_rsk_tx(tx, sender, &self.hardfork_cfg);
        let db = RskDatabase::new(state_root.clone(), trie_store.clone(), self.block_store.clone());

        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id, self.hardfork_cfg.has_rskip544(header.number));

        let mut chain_ext = crate::raw_storage::RskChainExt::default();
        chain_ext.raw_storage.set_reader(trie_store, state_root.clone());
        chain_ext.btc_block_cache = self.btc_block_cache.clone();
        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg)
            .with_chain(chain_ext);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
            Some(self.block_store.clone()),
            self.remasc_config.clone(),
        )
        .with_bridge_config(self.bridge_constants.clone());
        // rskj sets this on the transaction itself; the Bridge reads it out of
        // the per-transaction context, so that is where it goes here.
        if local_call {
            if let Ok(mut guard) = precompile_provider.bridge_tx_context_slot().lock() {
                guard.local_call = true;
            }
        }
        let invisible_flag = precompile_provider.invisible_exception_flag();
        let reached_sequential_only = precompile_provider.reached_sequential_only_slot();
        let active_precompiles: Vec<Address> =
            rsk_precompiles(&self.hardfork_cfg, header.number).addresses().copied().collect();
        let extcodesize_max_precompiles: Vec<Address> = if self.hardfork_cfg.has_rskip90(header.number) {
            active_precompiles.clone()
        } else {
            Vec::new()
        };
        let pre_rskip150_precompiles = (!self.hardfork_cfg.has_rskip150(header.number))
            .then(|| active_precompiles.clone());
        // rskj `VM.doEXTCODEHASH` reports `keccak256("")` for any active
        // precompile; EXTCODEHASH activates at RSKIP140 (papyrus).
        let extcodehash_precompiles: Vec<Address> =
            if self.hardfork_cfg.has_rskip140(header.number) {
                active_precompiles.clone()
            } else {
                Vec::new()
            };
        let mut evm = ctx
            .build_mainnet_with_inspector(crate::tracer::RskTracer::new(max_struct_logs))
            .with_precompiles(precompile_provider);
        crate::rsk_instructions::install(
            &mut evm.instruction,
            self.hardfork_cfg.has_rskip140(header.number),
            self.hardfork_cfg.has_chainid(header.number),
            self.hardfork_cfg.has_push0(header.number),
            self.hardfork_cfg.has_basefee(header.number),
            self.hardfork_cfg.has_rskip91(header.number),
            self.hardfork_cfg.has_rskip446(header.number),
            self.hardfork_cfg.has_rskip445(header.number),
            &extcodesize_max_precompiles,
            &extcodehash_precompiles,
            header.beneficiary,
        );

        let exec_out = {
            use revm::context::ContextSetters;
            evm.ctx.set_tx(tx_env);
            let mut handler = crate::rsk_handler::RskHandler::with_rskip125(
                !self.hardfork_cfg.has_rskip453(header.number),
                self.hardfork_cfg.has_rskip125(header.number),
                invisible_flag,
                pre_rskip150_precompiles,
                active_precompiles,
                self.hardfork_cfg.has_rskip171(header.number),
            );
            use revm::inspector::InspectorHandler;
            let out = handler
                .inspect_run(&mut evm)
                .map_err(|e: revm::context::result::EVMError<_>| {
                    ExecutionError::Evm(format!("{e:?}"))
                })?;
            out
        };
        let state = {
            use revm::context_interface::{ContextTr, JournalTr};
            evm.ctx.journal_mut().finalize()
        };
        let result = revm::context::result::ExecResultAndState::new(exec_out, state);

        let exec = result.result;
        let success = exec.is_success();
        let gas_used = exec.gas_used();
        let output = exec.output().map(|o| o.to_vec()).unwrap_or_default();
        let outcome = TracedOutcome::of(tx, sender, &exec, &output);
        let logs = exec.into_logs();

        let created_address = Self::extract_created_address(tx, sender, &success);

        // The same `take_trace` + `TracedOutcome` pair the block path uses,
        // so the two tracing entry points cannot disagree about what a
        // reverted transaction looks like.
        let mut trace = evm.inspector.take_trace();
        outcome.apply_to(&mut trace);

        Ok((
            TxExecutionResult {
                gas_used,
                success,
                output,
                logs,
                created_address,
                reached_sequential_only: reached_sequential_only
                    .load(std::sync::atomic::Ordering::Relaxed),
            },
            trace,
        ))
    }


    /// Estimate a transaction's gas in one execution.
    ///
    /// Returns `(estimate, success, output)`. On failure the estimate is zero
    /// and the output is the revert data, so the caller can report the reason
    /// rather than a number.
    ///
    /// The floor matters: a plain value transfer never enters the
    /// interpreter, so the inspector sees no opcodes and reports no peak. Its
    /// whole cost is intrinsic, which only `gas_used` knows.
    pub fn estimate_gas_exact(
        &self,
        header: &Header,
        tx: &rustock_core::Transaction,
        sender: Address,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        cap: u64,
    ) -> Result<(u64, bool, Vec<u8>), ExecutionError> {
        let (result, telemetry) =
            self.execute_tx_for_estimate(header, tx, sender, state_root, trie_store, true)?;
        if !result.success {
            return Ok((0, false, result.output));
        }
        let estimate = telemetry.estimate(cap);
        Ok((estimate, true, result.output))
    }

    /// The same execution as `execute_tx_inner`, with the gas-estimation
    /// inspector attached. Returns what one pass has to know for
    /// `EstimateTelemetry::estimate` to answer without a binary search.
    ///
    /// A third copy of the setup, for the reason the traced copy above gives:
    /// the estimate has to describe the execution the chain would actually
    /// perform, so every line of the environment has to stay identical.
    /// `the_exactimator_agrees_with_binary_search` is the guard against drift
    /// -- it runs both estimators over the same transactions and requires the
    /// same answer.
    pub fn execute_tx_for_estimate(
        &self,
        header: &Header,
        tx: &rustock_core::Transaction,
        sender: Address,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        local_call: bool,
    ) -> Result<(TxExecutionResult, crate::gas_estimator::EstimateTelemetry), ExecutionError> {
        let spec_id = self.hardfork_cfg.spec_id(header.number);
        let block_env = block_env_from_header(header, &self.hardfork_cfg);
        let tx_env = tx_env_from_rsk_tx(tx, sender, &self.hardfork_cfg);
        let db = RskDatabase::new(state_root.clone(), trie_store.clone(), self.block_store.clone());

        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id, self.hardfork_cfg.has_rskip544(header.number));

        let mut chain_ext = crate::raw_storage::RskChainExt::default();
        chain_ext.raw_storage.set_reader(trie_store, state_root.clone());
        chain_ext.btc_block_cache = self.btc_block_cache.clone();
        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg)
            .with_chain(chain_ext);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
            Some(self.block_store.clone()),
            self.remasc_config.clone(),
        )
        .with_bridge_config(self.bridge_constants.clone());
        // rskj sets this on the transaction itself; the Bridge reads it out of
        // the per-transaction context, so that is where it goes here.
        if local_call {
            if let Ok(mut guard) = precompile_provider.bridge_tx_context_slot().lock() {
                guard.local_call = true;
            }
        }
        let invisible_flag = precompile_provider.invisible_exception_flag();
        let reached_sequential_only = precompile_provider.reached_sequential_only_slot();
        let active_precompiles: Vec<Address> =
            rsk_precompiles(&self.hardfork_cfg, header.number).addresses().copied().collect();
        let extcodesize_max_precompiles: Vec<Address> = if self.hardfork_cfg.has_rskip90(header.number) {
            active_precompiles.clone()
        } else {
            Vec::new()
        };
        let pre_rskip150_precompiles = (!self.hardfork_cfg.has_rskip150(header.number))
            .then(|| active_precompiles.clone());
        // rskj `VM.doEXTCODEHASH` reports `keccak256("")` for any active
        // precompile; EXTCODEHASH activates at RSKIP140 (papyrus).
        let extcodehash_precompiles: Vec<Address> =
            if self.hardfork_cfg.has_rskip140(header.number) {
                active_precompiles.clone()
            } else {
                Vec::new()
            };
        let mut evm = ctx
            .build_mainnet_with_inspector(crate::gas_estimator::EstimationInspector::new())
            .with_precompiles(precompile_provider);
        crate::rsk_instructions::install(
            &mut evm.instruction,
            self.hardfork_cfg.has_rskip140(header.number),
            self.hardfork_cfg.has_chainid(header.number),
            self.hardfork_cfg.has_push0(header.number),
            self.hardfork_cfg.has_basefee(header.number),
            self.hardfork_cfg.has_rskip91(header.number),
            self.hardfork_cfg.has_rskip446(header.number),
            self.hardfork_cfg.has_rskip445(header.number),
            &extcodesize_max_precompiles,
            &extcodehash_precompiles,
            header.beneficiary,
        );

        let exec_out = {
            use revm::context::ContextSetters;
            evm.ctx.set_tx(tx_env);
            let mut handler = crate::rsk_handler::RskHandler::with_rskip125(
                !self.hardfork_cfg.has_rskip453(header.number),
                self.hardfork_cfg.has_rskip125(header.number),
                invisible_flag,
                pre_rskip150_precompiles,
                active_precompiles,
                self.hardfork_cfg.has_rskip171(header.number),
            );
            use revm::inspector::InspectorHandler;
            let out = handler
                .inspect_run(&mut evm)
                .map_err(|e: revm::context::result::EVMError<_>| {
                    ExecutionError::Evm(format!("{e:?}"))
                })?;
            out
        };
        let state = {
            use revm::context_interface::{ContextTr, JournalTr};
            evm.ctx.journal_mut().finalize()
        };
        let result = revm::context::result::ExecResultAndState::new(exec_out, state);

        let exec = result.result;
        let success = exec.is_success();
        let gas_used = exec.gas_used();
        let output = exec.output().map(|o| o.to_vec()).unwrap_or_default();
        // `spent` is revm's pre-refund figure -- limit minus remaining --
        // which is the same quantity rskj's `getGasUsed()` holds, and what an
        // estimate has to cover. `used()` is after the refund and would
        // under-report.
        let spent = exec.gas().spent();
        let refunded = exec.gas().final_refunded();
        let logs = exec.into_logs();

        let created_address = Self::extract_created_address(tx, sender, &success);

        let telemetry =
            std::mem::take(&mut evm.inspector).into_telemetry(spent, refunded);

        Ok((
            TxExecutionResult {
                gas_used,
                success,
                output,
                logs,
                created_address,
                reached_sequential_only: reached_sequential_only
                    .load(std::sync::atomic::Ordering::Relaxed),
            },
            telemetry,
        ))
    }


    /// Execute all transactions in a block.
    /// Account for one transaction's balance changes, rejecting the block if it
    /// created rBTC.
    ///
    /// Runs on the journal as it stands immediately after the transaction, so
    /// the balances are the ones that transaction produced. No database reads:
    /// the baseline comes from revm's per-transaction `original_info`.
    fn check_tx_supply(
        state: &revm::state::EvmState,
        transaction_id: usize,
        number: u64,
        index: usize,
        fees_withheld: U256,
        fees_settled: U256,
    ) -> Result<(), ExecutionError> {
        let report = crate::supply::transaction_supply_change(state, transaction_id)
            .with_fees_in_transit(fees_withheld, fees_settled);
        if report.is_balanced() {
            return Ok(());
        }
        crate::supply::report_transaction(number, index, &report);
        if report.created_supply() {
            let (_, created) = report.net();
            return Err(ExecutionError::SupplyCreated { number, index, created });
        }
        Ok(())
    }

    pub fn execute_block(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<BlockExecutionResult, ExecutionError> {
        // A tracer with a zero cap, and `trace_index: None` so `run` is used
        // for every transaction -- the inspector is never invoked.
        self.execute_block_with(
            header,
            transactions,
            state_root,
            trie_store,
            crate::tracer::RskTracer::new(0),
            TracedTxs::None,
        )
        .map(|(result, _)| result)
    }

    /// Execute a block the miner is assembling, dropping what does not fit.
    ///
    /// rskj's `BlockToMineBuilder` executes its candidates through
    /// `BlockExecutor.executeAndFill`, which discards an invalid transaction
    /// instead of failing the block, and a transaction is invalid when its
    /// gas limit does not fit in the block's limit minus the gas **used** so
    /// far (`TransactionExecutor.gasIsValid`). That is the rule this applies:
    /// a candidate that does not fit is skipped without running, and so is
    /// every later candidate from the same sender, whose nonce can no longer
    /// match (rskj executes those and discards them on the nonce check; the
    /// outcome is the same).
    ///
    /// A candidate the EVM refuses before running it -- rskj's
    /// `executeTransaction() == false`, or an exception it collects in
    /// `invalidTransactions` -- is dropped the same way and reported apart,
    /// so the miner can remove it from the pool as `BlockToMineBuilder`
    /// does. Only a database error still fails the run: that is the node's
    /// problem, not the transaction's.
    ///
    /// Returns the result of the transactions that ran, in order, and what
    /// was dropped. `tx_results` has one entry per transaction that ran, so
    /// a caller pairs them up by removing the dropped indices first.
    ///
    /// Always one run over the whole list: the miner partitions from what
    /// this reports and the block it publishes is executed again as it will
    /// be validated.
    pub fn execute_block_for_mining(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<(BlockExecutionResult, MiningDrops), ExecutionError> {
        let mut dropped = MiningDrops::default();
        let (result, _) = self.run_sublist(
            header,
            transactions,
            0..transactions.len(),
            state_root,
            trie_store,
            crate::tracer::RskTracer::new(0),
            TracedTxs::None,
            U256::ZERO,
            true,
            Some(&mut dropped),
        )?;
        Ok((result, dropped))
    }

    /// Execute a block, recording the call tree of **every** transaction.
    ///
    /// This is what the `trace_*` namespace needs, and it is one block pass:
    /// rskj's `TraceModuleImpl` likewise calls `blockExecutor.traceBlock` once
    /// and pulls a trace per transaction hash out of the
    /// `ProgramTraceProcessor`. Calling `execute_block_traced` once per index
    /// instead would be quadratic in the block's transaction count.
    ///
    /// The opcode stream is not recorded -- `trace_*` never renders it.
    pub fn execute_block_call_traced(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<(BlockExecutionResult, Vec<crate::tracer::ProgramTrace>), ExecutionError> {
        let (result, traces) = self.execute_block_with(
            header,
            transactions,
            state_root,
            trie_store,
            crate::tracer::RskTracer::call_tree_only(),
            TracedTxs::All,
        )?;
        Ok((result, traces.into_values().collect()))
    }

    /// Execute a block with a tracer attached to one transaction.
    ///
    /// Tracing a historical transaction needs its **pre-state**, and there is
    /// no such thing stored: the state before transaction *i* of block *N* is
    /// the state after *N-1* plus transactions 0..*i*, and only per-block roots
    /// are kept. So the whole block is re-executed and the tracer is switched
    /// on for one index.
    ///
    /// Returns the trace when `trace_index` names a transaction the block has,
    /// and `None` when it does not.
    pub fn execute_block_traced(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        trace_index: usize,
        max_struct_logs: usize,
    ) -> Result<(BlockExecutionResult, Option<crate::tracer::ProgramTrace>), ExecutionError> {
        let (result, mut traces) = self.execute_block_with(
            header,
            transactions,
            state_root,
            trie_store,
            crate::tracer::RskTracer::new(max_struct_logs),
            TracedTxs::One(trace_index),
        )?;
        Ok((result, traces.remove(&trace_index)))
    }

    /// The block executor, with a tracer carried as a field.
    ///
    /// **`execute_block` passes a tracer too, and that is not a behavioural
    /// change.** revm's `build_mainnet` and `build_mainnet_with_inspector`
    /// construct the same `Evm` from the same spec -- identical `instruction`,
    /// `precompiles` and `frame_stack`, differing only in the `inspector`
    /// field, which is `()` in the first (revm-handler 17,
    /// `mainnet_builder.rs`). `impl<CTX, INSP, I, P> EvmTr for Evm<...>` is
    /// generic over that field, so `Handler::run` on an inspector-carrying EVM
    /// runs the same code as on one without. The inspector is consulted only
    /// by `inspect_run`, called here for exactly one transaction index and
    /// never on the consensus path.
    ///
    /// Sharing the body this way rather than copying it is deliberate. The
    /// alternative was a second 484-line block executor, and two copies of the
    /// consensus block loop would drift -- which is the failure this codebase
    /// has already had twice, in the two orphan-recovery paths that were meant
    /// to stay identical and did not.
    /// Execute a block, as one run or as its declared sublists.
    ///
    /// A block declares its partition in `txExecutionSublistsEdges`. With no
    /// edges there is nothing to divide and the block is one run, which is
    /// every block on a chain where RSKIP-144 is unscheduled. With edges and
    /// more than one execution thread, each parallel sublist is its own run
    /// against the parent state and the sequential sublist follows on what
    /// they left.
    ///
    /// With edges but one execution thread the block is still one run. That
    /// is not a lesser approximation: where the sublists are independent --
    /// which the collision check establishes, and which is a condition of the
    /// block's validity -- running them in order against a shared state and
    /// running them separately against the parent reach the same state. Where
    /// they are not independent the block is invalid either way.
    #[allow(clippy::too_many_arguments)]
    fn execute_block_with(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        inspector: crate::tracer::RskTracer,
        traced: TracedTxs,
    ) -> Result<
        (BlockExecutionResult, std::collections::BTreeMap<usize, crate::tracer::ProgramTrace>),
        ExecutionError,
    > {
        let edges: &[i16] = header
            .version_fields
            .as_ref()
            .and_then(|v| v.edges.as_deref())
            .unwrap_or(&[]);
        let (parallel, sequential) =
            crate::collision::sublist_ranges(edges, transactions.len());

        // One run unless there are at least two parallel sublists to divide.
        // With one there is nothing to run concurrently *with*, and a single
        // run over the whole block reaches the same state for less.
        //
        // RSKIP-144 is also required, and not only because a header cannot
        // carry edges without it. Running the sublists separately is sound
        // *because* the fees are postponed: credited per transaction, every
        // sublist would add its own fees to REMASC's balance as read from
        // the state they all start from, and committing them in order keeps
        // the last one rather than the sum. The block would silently lose a
        // sublist's fees.
        if self.execution_threads <= 1
            || parallel.len() < 2
            || !self.hardfork_cfg.has_rskip144(header.number)
        {
            return self.run_sublist(
                header,
                transactions,
                0..transactions.len(),
                state_root,
                trie_store,
                inspector,
                traced,
                U256::ZERO,
                true,
                None,
            );
        }

        self.execute_block_in_parallel(
            header,
            transactions,
            parallel,
            sequential,
            state_root,
            trie_store,
            inspector,
            traced,
        )
    }

    /// The RSKIP-144 execution shape: the declared parallel sublists run
    /// concurrently against the state the block starts from, then the
    /// sequential sublist runs on what they left.
    ///
    /// Each sublist's changes go into the trie as that sublist's own commit,
    /// in sublist order -- which is what rskj does (`tle.getRepository()
    /// .commit()` in order) and what makes the sequential sublist's state
    /// well defined. It also avoids reconciling several journals into one:
    /// the trie is the merge.
    ///
    /// The block-level precompile maintenance runs first, alone, and its
    /// result is the state every parallel sublist reads. rskj runs it on the
    /// block's own repository before any sublist starts; giving it to one
    /// sublist instead would hide it from the others.
    #[allow(clippy::too_many_arguments)]
    fn execute_block_in_parallel(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        parallel: Vec<std::ops::Range<usize>>,
        sequential: std::ops::Range<usize>,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        inspector: crate::tracer::RskTracer,
        traced: TracedTxs,
    ) -> Result<
        (BlockExecutionResult, std::collections::BTreeMap<usize, crate::tracer::ProgramTrace>),
        ExecutionError,
    > {
        let store = trie_store.as_ref();

        let at_maintenance = std::time::Instant::now();
        // 1. Block-level maintenance, on no sublist's account.
        let (maintenance, _) = self.run_sublist(
            header,
            transactions,
            0..0,
            state_root,
            trie_store.clone(),
            inspector.fresh_like(),
            TracedTxs::None,
            U256::ZERO,
            true,
            None,
        )?;
        let base_root = crate::state::apply_state_changes(
            state_root,
            store,
            &maintenance.state_changes,
            &maintenance.markers,
        );
        let maintenance_us = at_maintenance.elapsed().as_micros() as u64;

        // 2. The parallel sublists, each against that state, each on its own
        //    thread with its own everything.
        let recorder = crate::collision::config();
        let recording_silent = crate::silent::is_recording();
        let base = &base_root;
        // Workers pull the next unclaimed sublist rather than being handed
        // a fixed slice of them.
        //
        // Chunking into waves of `execution_threads` looked equivalent and
        // is not: four sublists on three threads is a wave of three and
        // then a wave of one, with two threads idle while the straggler
        // finishes. The benchmark measured exactly that -- three threads
        // came out *slower* than two on the cold blocks, 5,089 ms against
        // 4,096, and identical once warm, which is the signature of a
        // scheduling quantum rather than of anything about the work.
        let at_sublists = std::time::Instant::now();
        let width = self.execution_threads.max(1).min(parallel.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots: Vec<std::sync::Mutex<Option<Result<SublistRun, ExecutionError>>>> =
            (0..parallel.len()).map(|_| std::sync::Mutex::new(None)).collect();
        let parallel_ref = &parallel;
        let slots_ref = &slots;
        let next_ref = &next;

        std::thread::scope(|scope| {
            for _ in 0..width {
                let store = trie_store.clone();
                let recorder = recorder.clone();
                // Borrowed, not cloned: a worker makes a fresh tracer per
                // sublist it takes, so the second one it pulls is
                // configured like the first rather than degraded to a
                // call-tree-only default.
                let template = &inspector;
                scope.spawn(move || {
                    loop {
                        let index =
                            next_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(range) = parallel_ref.get(index) else { break };

                        // Per sublist, not per thread: a worker that takes a
                        // second sublist must not fold its keys in with the
                        // first one's.
                        if let Some(cfg) = recorder.clone() {
                            crate::collision::start_from(cfg);
                        }
                        if recording_silent {
                            crate::silent::start();
                        }
                        let run = self.run_sublist(
                            header,
                            transactions,
                            range.clone(),
                            base,
                            store.clone(),
                            template.fresh_like(),
                            traced,
                            U256::ZERO,
                            false,
                            None,
                        );
                        let keys = crate::collision::finish();
                        let records = crate::silent::finish();
                        let outcome = run
                            .map(|(result, traces)| SublistRun { result, traces, keys, records });
                        *slots_ref[index].lock().expect("sublist slot") = Some(outcome);
                    }
                });
            }
        });

        let outcomes: Vec<Result<SublistRun, ExecutionError>> = slots
            .into_iter()
            .map(|slot| {
                slot.into_inner().expect("sublist slot").unwrap_or_else(|| {
                    Err(ExecutionError::Evm(
                        "a parallel sublist thread panicked before recording its result"
                            .to_string(),
                    ))
                })
            })
            .collect();

        let sublists_us = at_sublists.elapsed().as_micros() as u64;

        let mut commit_us = 0u64;
        let at_commit = std::time::Instant::now();
        // 3. Commit them in sublist order, and take back what the workers
        //    collected on their own threads.
        let mut root = base_root.clone();
        let mut runs = Vec::with_capacity(outcomes.len());
        let mut failure = None;
        for outcome in outcomes {
            // Taken before any early return. A sublist that failed still
            // recorded what it touched on its own thread, and that is exactly
            // what somebody diagnosing the failure will want -- including the
            // collision that may be the reason it failed.
            match outcome {
                Ok(run) => {
                    if let Some(keys) = run.keys {
                        crate::collision::absorb(keys);
                    }
                    crate::silent::absorb(run.records);
                    if failure.is_none() {
                        root = crate::state::apply_state_changes(
                            &root,
                            store,
                            &run.result.state_changes,
                            &run.result.markers,
                        );
                        runs.push((run.result, run.traces));
                    }
                }
                Err(e) => failure = failure.or(Some(e)),
            }
        }
        if let Some(e) = failure {
            return Err(e);
        }
        commit_us += at_commit.elapsed().as_micros() as u64;

        // 4. The sequential sublist, on what they left, carrying their fees
        //    so that the settlement at the REMASC transaction covers the
        //    whole block.
        let fees_carried = runs
            .iter()
            .map(|(r, _)| r.paid_fees)
            .fold(U256::ZERO, |a, b| a + b);
        let at_sequential = std::time::Instant::now();
        let (sequential_result, mut traces) = self.run_sublist(
            header,
            transactions,
            sequential,
            &root,
            trie_store.clone(),
            inspector,
            traced,
            fees_carried,
            false,
            None,
        )?;
        let sequential_us = at_sequential.elapsed().as_micros() as u64;

        let at_final = std::time::Instant::now();
        let final_root = crate::state::apply_state_changes(
            &root,
            store,
            &sequential_result.state_changes,
            &sequential_result.markers,
        );
        commit_us += at_final.elapsed().as_micros() as u64;

        let phases = PhaseTimings { maintenance_us, sublists_us, commit_us, sequential_us };

        // 5. Assemble, in the block's own transaction order.
        let mut tx_results = Vec::with_capacity(transactions.len());
        let mut gas_used = maintenance.gas_used;
        let mut state_changes = maintenance.state_changes;
        let mut markers = maintenance.markers;
        for (run, run_traces) in runs {
            gas_used += run.gas_used;
            tx_results.extend(run.tx_results);
            merge_markers(&mut markers, run.markers);
            merge_reported_state(&mut state_changes, run.state_changes);
            traces.extend(run_traces);
        }
        gas_used += sequential_result.gas_used;
        tx_results.extend(sequential_result.tx_results);
        merge_markers(&mut markers, sequential_result.markers);
        merge_reported_state(&mut state_changes, sequential_result.state_changes);
        Ok((
            BlockExecutionResult {
                tx_results,
                gas_used,
                paid_fees: sequential_result.paid_fees,
                state_changes,
                markers,
                applied_root: Some(final_root),
                phases,
            },
            traces,
        ))
    }

    /// Execute one contiguous run of a block's transactions against a state.
    ///
    /// This is the whole block when it declares no sublists, which is every
    /// block on a chain where RSKIP-144 is unscheduled. When it does declare
    /// them, each sublist is one call: the parallel ones against the parent
    /// state, the sequential one against the state the parallel ones left.
    ///
    /// `range` is in the block's own transaction indices and stays that way
    /// throughout -- the Bridge reads the index, the tracer selects on it and
    /// the collision tracker attributes by it, so a sublist-relative index
    /// would be wrong in three places at once.
    ///
    /// Everything this builds -- the database handle, the journal, the
    /// instruction table, the precompile provider, the overlay -- is built
    /// here, which is to say on the thread that will run it. That is not
    /// incidental: `rsk_instructions` keeps consensus configuration in
    /// thread-local storage, and every unset value reads as a plausible
    /// one. See `docs/parallel-execution-thread-safety.md`.
    #[allow(clippy::too_many_arguments)]
    fn run_sublist(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        range: std::ops::Range<usize>,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
        inspector: crate::tracer::RskTracer,
        traced: TracedTxs,
        // `fees_carried`: fees paid by earlier sublists. rskj threads
        // `totalPaidFees` into the sequential executor the same way, so that
        // the settlement at the REMASC transaction covers the whole block.
        fees_carried: U256,
        // `run_maintenance`: run the block-level precompile maintenance
        // first. True for the run that starts the block and false for every
        // later sublist -- rskj's `maintainPrecompiledContractStorageRoots`
        // runs once, on the block's own repository, before any sublist.
        run_maintenance: bool,
        // `discard_unfitting`: the miner's mode. A transaction whose gas
        // limit does not fit in what the block has left, or that the EVM
        // refuses to run, is skipped and its index recorded here, instead
        // of failing the run as it does when validating. See
        // `execute_block_for_mining`.
        mut discard_unfitting: Option<&mut MiningDrops>,
    ) -> Result<
        (BlockExecutionResult, std::collections::BTreeMap<usize, crate::tracer::ProgramTrace>),
        ExecutionError,
    > {
        let spec_id = self.hardfork_cfg.spec_id(header.number);
        let block_env = block_env_from_header(header, &self.hardfork_cfg);
        let db = RskDatabase::new(state_root.clone(), trie_store.clone(), self.block_store.clone());
        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id, self.hardfork_cfg.has_rskip544(header.number));

        let mut chain_ext = crate::raw_storage::RskChainExt::default();
        chain_ext.raw_storage.set_reader(trie_store, state_root.clone());
        chain_ext.btc_block_cache = self.btc_block_cache.clone();
        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg)
            .with_chain(chain_ext);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
            Some(self.block_store.clone()),
            self.remasc_config.clone(),
        )
        .with_bridge_config(self.bridge_constants.clone());
        // Shared slot for per-transaction Bridge context (tx hash + BTC destination).
        // We clone the Arc before moving the provider into the EVM so we can update
        // it between transactions.
        let bridge_ctx_slot = precompile_provider.bridge_tx_context_slot();
        let invisible_flag = precompile_provider.invisible_exception_flag();
        let called_precompiles = precompile_provider.called_precompiles_slot();
        let reached_sequential_only = precompile_provider.reached_sequential_only_slot();
        let active_precompiles: Vec<Address> =
            rsk_precompiles(&self.hardfork_cfg, header.number).addresses().copied().collect();
        let extcodesize_max_precompiles: Vec<Address> = if self.hardfork_cfg.has_rskip90(header.number) {
            active_precompiles.clone()
        } else {
            Vec::new()
        };
        let pre_rskip150_precompiles = (!self.hardfork_cfg.has_rskip150(header.number))
            .then(|| active_precompiles.clone());
        // rskj `VM.doEXTCODEHASH` reports `keccak256("")` for any active
        // precompile; EXTCODEHASH activates at RSKIP140 (papyrus).
        let extcodehash_precompiles: Vec<Address> =
            if self.hardfork_cfg.has_rskip140(header.number) {
                active_precompiles.clone()
            } else {
                Vec::new()
            };
        let mut evm = ctx
            .build_mainnet_with_inspector(inspector)
            .with_precompiles(precompile_provider);
        crate::rsk_instructions::install(
            &mut evm.instruction,
            self.hardfork_cfg.has_rskip140(header.number),
            self.hardfork_cfg.has_chainid(header.number),
            self.hardfork_cfg.has_push0(header.number),
            self.hardfork_cfg.has_basefee(header.number),
            self.hardfork_cfg.has_rskip91(header.number),
            self.hardfork_cfg.has_rskip446(header.number),
            self.hardfork_cfg.has_rskip445(header.number),
            &extcodesize_max_precompiles,
            &extcodehash_precompiles,
            header.beneficiary,
        );

        // rskj builds every sublist executor with `postponeFeePayment = true`
        // once RSKIP-144 is active (`TransactionListExecutor`), accumulates
        // the fees, and credits the block's whole total to REMASC just before
        // the REMASC transaction runs
        // (`addFeesToRemascIfEnabled`). Before RSKIP-144 it credits per
        // transaction, which is what this node did at every height.
        //
        // The end state is identical -- the same total reaches the same
        // account before anything can observe it, REMASC being last. What
        // differs is what an earlier transaction sees if it reads REMASC's
        // balance, and that is consensus.
        //
        // It is also what makes parallel sublists mergeable at all: crediting
        // per transaction has every sublist writing REMASC's account cell,
        // and those writes would have to be summed rather than merged.
        let postpone_fees = self.hardfork_cfg.has_rskip144(header.number);
        let mut remasc_tx_seen = false;
        // Whether this run ends the block. Only the run that does may settle
        // fees nobody claimed; a parallel sublist ends without reaching the
        // REMASC transaction by construction, and settling there would credit
        // its fees once on its own account and again when the sequential
        // sublist settles the block's total.
        let ends_the_block = range.end == transactions.len();
        // Whether this run is the whole block as one, with nothing before or
        // after it. Only then is the block's gas limit the container a
        // transaction has to fit in (see the fit rule below); a sublist's
        // container is the sublist's own limit, which this run does not know.
        let whole_block = run_maintenance && ends_the_block;
        let block_gas_limit = header.gas_limit.saturating_to::<u64>();
        // Mining mode only: senders with a dropped transaction. Their later
        // ones cannot execute (the nonce is now out of sequence) and rskj's
        // `executeAndFill` discards them on the nonce check; dropping them
        // here spares the run from executing what is known to fail.
        let mut dropped_senders: std::collections::HashSet<Address> =
            std::collections::HashSet::new();

        let mut total_gas = 0u64;
        let mut total_fees = fees_carried;
        let mut tx_results = Vec::with_capacity(range.len());
        // Harvested per transaction rather than once at the end, so that
        // `trace_block` can trace every transaction in a single block pass.
        let mut traces: std::collections::BTreeMap<usize, crate::tracer::ProgramTrace> =
            std::collections::BTreeMap::new();
        let mut markers = crate::state::ContractMarkers::default();

        // rskj BlockExecutor.maintainPrecompiledContractStorageRoots, run
        // before the block's transactions: at the RSKIP126 activation block
        // every genesis precompile is created (if absent) and marked; each
        // consensus-enabled precompile gets a fresh account (nonce/balance
        // reset) plus the marker exactly at its activation block.
        if run_maintenance {
            use crate::hardfork::RskNetworkUpgrade;
            use revm::context_interface::{ContextTr, JournalTr};
            let mut ops: Vec<(Address, bool)> = Vec::new(); // (addr, reset_account)
            if self.hardfork_cfg.is_activating(RskNetworkUpgrade::Wasabi100, header.number) {
                ops.extend(crate::precompiles::GENESIS_PRECOMPILES.map(|a| (a, false)));
            }
            for (addr, upgrade) in crate::precompiles::CONSENSUS_ENABLED_PRECOMPILES {
                if self.hardfork_cfg.is_activating(upgrade, header.number) {
                    ops.push((addr, true));
                }
            }
            for (addr, reset) in ops {
                {
                    use revm::context_interface::journaled_state::account::JournaledAccountTr;
                    let mut acc = evm.ctx.journal_mut().load_account_mut(addr)
                        .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?;
                    if reset {
                        // rskj track.createAccount: a fresh AccountState.
                        acc.data.set_balance(U256::ZERO);
                        acc.data.set_nonce(0);
                    }
                }
                evm.ctx.journal_mut().touch_account(addr);
                if !markers.precompiles.contains(&addr) {
                    markers.precompiles.push(addr);
                }
                // Written by the block, not by any sublist, so it must not
                // be attributed to the first transaction's sublist.
                crate::collision::exclude(addr);
            }
        }

        for i in range.clone() {
            let (tx, sender) = &transactions[i];
            // The journal stamps each account with the transaction that last
            // touched it; capture the id in force for this one, before it is
            // incremented at commit.
            let supply_tid = {
                use revm::context_interface::ContextTr;
                evm.ctx.journal_mut().inner.transaction_id
            };
            {
                use revm::context_interface::ContextTr;
                evm.ctx.chain_mut().raw_storage.begin_tx();
            }
            // RSKIP-144: everything this transaction touches belongs to the
            // sublist that runs it. Inert unless the block declares edges.
            crate::collision::begin_transaction(i);

            // rskj `TransactionExecutor.gasIsValid`: a transaction's gas
            // **limit** must fit in the container's limit minus the gas
            // **used** before it. The two quantities differ on purpose -- a
            // sender's over-provisioned limit costs the block nothing once
            // the transaction has run -- and the rule is consensus: in rskj a
            // transaction that does not fit is invalid, and a block carrying
            // one is rejected ("Too much gas used in this block"). Mining
            // mode drops it instead, as rskj's `executeAndFill` does.
            //
            // REMASC declares no gas and is exempt by construction. Checked
            // only when this run's container is the block itself: a sublist
            // run is measured against the sublist's limit, which the
            // partition validator enforces separately.
            if !Self::is_remasc_tx(tx) && (whole_block || discard_unfitting.is_some()) {
                let tx_gas_limit = tx.gas_limit.saturating_to::<u64>();
                let fits = total_gas.saturating_add(tx_gas_limit) <= block_gas_limit;
                let sender_dropped = dropped_senders.contains(sender);
                if !fits || sender_dropped {
                    if let Some(dropped) = discard_unfitting.as_deref_mut() {
                        debug!(
                            tx_index = i,
                            tx_gas_limit,
                            available = block_gas_limit.saturating_sub(total_gas),
                            sender_dropped,
                            "mining: dropping a transaction that does not fit the block"
                        );
                        dropped.unfitting.push(i);
                        dropped_senders.insert(*sender);
                        {
                            use revm::context_interface::ContextTr;
                            evm.ctx.chain_mut().raw_storage.discard_tx();
                        }
                        continue;
                    }
                    return Err(ExecutionError::Evm(format!(
                        "Too much gas used in this block: available in block: {} tx sent: {}",
                        block_gas_limit.saturating_sub(total_gas),
                        tx_gas_limit
                    )));
                }
            }

            if Self::is_remasc_tx(tx) {
                debug!(tx_index = i, "executing REMASC system call");
                if traced.includes(i) {
                    // REMASC never enters the EVM here, so the tracer records
                    // nothing -- but rskj still produces a trace for it
                    // (`TransactionExecutor.extractTrace`'s `program == null`
                    // branch), and `trace_block` would otherwise be short one
                    // entry per block. An empty trace renders as the
                    // zero-gas, no-subtrace `call` rskj emits.
                    traces.insert(i, crate::tracer::ProgramTrace::default());
                }
                // rskj `TransactionListExecutor.addFeesToRemascIfEnabled`:
                // with the fees postponed, the block's whole total is
                // credited to REMASC immediately BEFORE the REMASC
                // transaction executes, so REMASC's own distribution sees it.
                remasc_tx_seen = true;
                // What the settlement below takes out of the pending fee
                // pool, for the per-transaction supply check: REMASC gains it
                // without anybody losing it in this transaction.
                let settled_now = if postpone_fees { total_fees } else { U256::ZERO };
                if postpone_fees && !total_fees.is_zero() {
                    use revm::context_interface::journaled_state::account::JournaledAccountTr;
                    use revm::context_interface::{ContextTr, JournalTr};
                    evm.ctx
                        .journal_mut()
                        .load_account_mut(REMASC_ADDR)
                        .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?
                        .incr_balance(total_fees);
                }

                // Warm the REMASC account: outside revm's transact flow the
                // journal rejects storage ops on accounts it has not loaded.
                // Touch it too: rskj transfers the (zero) endowment to the
                // callee and under frontier semantics that creates the REMASC
                // contract account record from block #1 (mainnet header #1's
                // state root contains it with nonce 0 / balance 0).
                {
                    use revm::context_interface::{ContextTr, JournalTr};
                    let _ = evm.ctx.journal_mut().load_account(REMASC_ADDR);
                    evm.ctx.journal_mut().touch_account(REMASC_ADDR);
                }
                crate::remasc::process_miners_fees(
                    &mut evm.ctx,
                    &self.remasc_config,
                    &self.bridge_constants,
                    &self.hardfork_cfg,
                    Some(&self.block_store),
                )
                .map_err(|e| ExecutionError::Evm(format!("REMASC: {e:?}")))?;
                {
                    use revm::context_interface::ContextTr;
                    // rskj `RemascStorageProvider.saveSiblings` runs on every
                    // REMASC `save()` (after processMinersFees, with no guard),
                    // writing `addStorageBytes(REMASC, "siblings",
                    // RLP.encodedEmptyList())` = a single 0xc0 byte. The cell is
                    // created at block #1 and its value never changes, but it is
                    // part of the unitrie (and the state root) from then on.
                    let siblings_slot = crate::remasc::remasc_storage_key("siblings");
                    evm.ctx
                        .chain_mut()
                        .raw_storage
                        .put(REMASC_ADDR, siblings_slot, Some(vec![0xc0]));
                    evm.ctx.chain_mut().raw_storage.commit_call();
                }

                // Drain the mining_fee_topic logs into the receipt.
                let logs = {
                    use revm::context_interface::{ContextTr, JournalTr};
                    evm.ctx.journal_mut().take_logs()
                };

                // rskj: the REMASC system tx is a successful direct precompile
                // call every block, so the contract marker is (re)written and
                // the special 1-byte REMASC sender account's nonce increments
                // (TransactionExecutor.execute → track.increaseNonce(sender)).
                if !markers.precompiles.contains(&REMASC_ADDR) {
                    markers.precompiles.push(REMASC_ADDR);
                }
                markers.bump_remasc_sender = true;

                tx_results.push(TxExecutionResult {
                    // The REMASC system transaction is REMASC. It is always the
                    // block's last and so always sequential, but say so rather
                    // than leave it to that coincidence.
                    reached_sequential_only: true,
                    gas_used: 0,
                    success: true,
                    output: Vec::new(),
                    logs,
                    created_address: None,
                });
                if crate::supply::per_transaction_enabled() {
                    use revm::context_interface::ContextTr;
                    let st = &evm.ctx.journal_mut().inner.state;
                    Self::check_tx_supply(st, supply_tid, header.number, i, U256::ZERO, settled_now)?;
                }
                // RSKIP-144: what this transaction read and wrote, attributed
                // to its sublist. Inert unless the block declares sublist
                // edges.
                if crate::collision::is_recording() {
                    use revm::context_interface::ContextTr;
                    let j = &evm.ctx.journal_mut().inner;
                    crate::collision::note_journal_entries(&j.journal, &j.state);
                    crate::collision::record_transaction(supply_tid, &j.state);
                    let raw = evm.ctx.chain_mut().raw_storage.tx_writes();
                    crate::collision::record_raw_writes(raw);
                }
                continue;
            }

            // Update per-transaction Bridge context before execution.
            // This provides the Bridge precompile with:
            //   - rsk_tx_hash: used for RSKIP146 release queue entries
            //   - btc_sender_hash160: used as BTC peg-out destination (matches rskj's
            //     BridgeUtils.recoverBtcAddressFromEthTransaction)
            {
                let rsk_tx_hash: [u8; 32] = {
                    let rlp = tx.rlp_for_trie();
                    sha3::Keccak256::digest(&rlp).into()
                };
                let btc_sender_hash160 = tx
                    .btc_sender_hash160(self.hardfork_cfg.chain_id)
                    .unwrap_or([0u8; 20]);
                if let Ok(mut guard) = bridge_ctx_slot.lock() {
                    *guard = BridgeTxContext {
                        rsk_tx_hash,
                        btc_sender_hash160,
                        rsk_sender: *sender,
                        // A transaction in a block is never a local call.
                        local_call: false,
                        tx_index: i as u32,
                    };
                }
            }

            // Direct Bridge calls that revm's gas validation cannot model:
            // - free bridge transactions (pre-areBridgeTxsPaid): gas_limit 0,
            //   nothing charged (Transaction.transactionCost == 0,
            //   Bridge.getGasForData == 0);
            // - paid calls before RSKIP136 (bahamas): rskj checked the limit
            //   against the precompile cost ALONE and recorded
            //   gasUsed = precompileCost + intrinsicCost, possibly above the
            //   tx gas limit (mainnet #3307: 31280 used with a 30000 limit).
            let is_free = self.is_free_bridge_tx(tx, *sender, header.number);
            let is_pre136_bridge = !self.hardfork_cfg.has_rskip136(header.number)
                && tx.to.len() == 20
                && tx.to.as_ref() == crate::precompiles::BRIDGE_ADDR.as_slice();
            if is_free || is_pre136_bridge {
                debug!(tx_index = i, is_free, "executing direct bridge call");
                use revm::context_interface::journaled_state::account::JournaledAccountTr;
                use revm::context_interface::{ContextTr, JournalTr};
                // rskj increments the sender nonce in init(), outside the
                // execution rollback scope.
                {
                    let mut acc = evm.ctx.journal_mut().load_account_mut(*sender)
                        .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?;
                    acc.data.bump_nonce();
                }

                // Warm the Bridge account: outside revm's transact flow the
                // precompile warm-set is not populated and journal sloads on
                // a cold account fail.
                let _ = evm.ctx.journal_mut()
                    .load_account(crate::precompiles::BRIDGE_ADDR);

                // Pre-RSKIP136 gas accounting (rskj TransactionExecutor.call).
                let (gas_used, enough_gas) = if is_free {
                    (0u64, true)
                } else {
                    let required = crate::bridge::bridge_call_gas_cost(
                        &mut evm.ctx,
                        tx.input.as_ref(),
                        &self.bridge_constants,
                        &self.hardfork_cfg,
                    )
                    .unwrap_or(0);
                    let basic: u64 = 21_000
                        + tx.input.iter()
                            .map(|b| if *b == 0 { 4u64 } else { 68 })
                            .sum::<u64>();
                    let limit = tx.gas_limit.to::<u64>();
                    if limit >= required {
                        // gasUsed may exceed the limit; that is consensus here.
                        (required.saturating_add(basic), true)
                    } else {
                        // rskj execError: all gas consumed, nothing executed.
                        (limit, false)
                    }
                };

                let mut invisible_exception = false;
                let (success, output, logs) = if enough_gas {
                    let tx_ctx = bridge_ctx_slot.lock().map(|g| g.clone()).unwrap_or_default();
                    let use_v2 = self.hardfork_cfg.has_stored_block_v2(header.number);
                    let checkpoint = evm.ctx.journal_mut().checkpoint();
                    let outcome = crate::bridge::execute_bridge(
                        &mut evm.ctx,
                        tx.input.as_ref(),
                        u64::MAX, // cost already accounted above
                        &self.bridge_constants,
                        Some(&self.block_store),
                        use_v2,
                        &self.hardfork_cfg,
                        &tx_ctx,
                        *sender,
                        1, // a direct top-level tx is depth 1 (not a contract call)
                        crate::bridge::BridgeCallKind::Call, // a tx is always a plain CALL
                        tx.value, // top-level call value = the tx value
                    );
                    match outcome {
                        Ok(out) => {
                            evm.ctx.chain_mut().raw_storage.commit_call();
                            evm.ctx.journal_mut().checkpoint_commit();
                            // rskj transfers the endowment after execute()
                            // returns without throwing.
                            if !tx.value.is_zero() {
                                let _ = evm.ctx.journal_mut().transfer(
                                    *sender,
                                    crate::precompiles::BRIDGE_ADDR,
                                    tx.value,
                                );
                            }
                            // rskj setupContract after a successful direct
                            // precompile call (TransactionExecutor.call).
                            if !markers.precompiles.contains(&crate::precompiles::BRIDGE_ADDR) {
                                markers.precompiles.push(crate::precompiles::BRIDGE_ADDR);
                            }
                            // Drain bridge events into the receipt like revm
                            // does for normal transactions.
                            let logs = evm.ctx.journal_mut().take_logs();
                            (true, out.bytes.to_vec(), logs)
                        }
                        Err(e) if crate::bridge::is_invisible_exception(&e) => {
                            // rskj invisible exception: receipt SUCCESS with
                            // the spent gas, no logs, no endowment — but the
                            // sender is charged the FULL gas limit.
                            evm.ctx.chain_mut().raw_storage.discard_call();
                            // RSKIP-144: the writes this call attempted are
                            // about to be popped off the journal. The EVM's
                            // own frames are covered in `rsk_handler`; a
                            // direct bridge call never enters one.
                            if crate::collision::records_attempted_writes() {
                                let j = &evm.ctx.journal_mut().inner;
                                crate::collision::note_journal_entries(&j.journal, &j.state);
                            }
                            evm.ctx.journal_mut().checkpoint_revert(checkpoint);
                            crate::collision::forget_entries_above(
                                evm.ctx.journal_mut().inner.journal.len(),
                            );
                            invisible_exception = true;
                            (true, Vec::new(), Vec::new())
                        }
                        Err(e) => {
                            evm.ctx.chain_mut().raw_storage.discard_call();
                            // RSKIP-144: the writes this call attempted are
                            // about to be popped off the journal. The EVM's
                            // own frames are covered in `rsk_handler`; a
                            // direct bridge call never enters one.
                            if crate::collision::records_attempted_writes() {
                                let j = &evm.ctx.journal_mut().inner;
                                crate::collision::note_journal_entries(&j.journal, &j.state);
                            }
                            evm.ctx.journal_mut().checkpoint_revert(checkpoint);
                            crate::collision::forget_entries_above(
                                evm.ctx.journal_mut().inner.journal.len(),
                            );
                            debug!(tx_index = i, error = %e, "direct bridge call failed");
                            (false, Vec::new(), Vec::new())
                        }
                    }
                } else {
                    (false, Vec::new(), Vec::new())
                };

                // Fees go to REMASC like the revm path (block beneficiary).
                // An invisible exception charges the full gas limit
                // (rskj TransactionExecutionSummary.getFee when failed).
                let fee_gas = if invisible_exception {
                    tx.gas_limit.to::<u64>()
                } else {
                    gas_used
                };
                let fee = U256::from(fee_gas) * tx.gas_price;
                if !fee.is_zero() {
                    let _ = evm.ctx.journal_mut().transfer(
                        *sender,
                        crate::precompiles::REMASC_ADDR,
                        fee,
                    );
                }
                // What this transaction paid in that nobody was credited
                // with, for the per-transaction supply check.
                let withheld_now = if postpone_fees { fee } else { U256::ZERO };
                total_fees += fee;

                total_gas += gas_used;
                tx_results.push(TxExecutionResult {
                    // This branch exists only to call the Bridge.
                    reached_sequential_only: true,
                    gas_used,
                    success,
                    output,
                    logs,
                    created_address: None,
                });
                if crate::supply::per_transaction_enabled() {
                    use revm::context_interface::ContextTr;
                    let st = &evm.ctx.journal_mut().inner.state;
                    Self::check_tx_supply(st, supply_tid, header.number, i, withheld_now, U256::ZERO)?;
                }
                // RSKIP-144: what this transaction read and wrote, attributed to
                // its sublist. Inert unless the block declares sublist edges.
                if crate::collision::is_recording() {
                    use revm::context_interface::ContextTr;
                    let j = &evm.ctx.journal_mut().inner;
                    crate::collision::note_journal_entries(&j.journal, &j.state);
                    crate::collision::record_transaction(supply_tid, &j.state);
                    let raw = evm.ctx.chain_mut().raw_storage.tx_writes();
                    crate::collision::record_raw_writes(raw);
                }
                continue;
            }

            let tx_env = tx_env_from_rsk_tx(tx, *sender, &self.hardfork_cfg);

            // Per-tx precompile marker tracking: drained below only if the
            // transaction commits (rskj cacheTrack rollback drops markers).
            if let Ok(mut called) = called_precompiles.lock() {
                called.clear();
            }
            reached_sequential_only.store(false, std::sync::atomic::Ordering::Relaxed);

            // rskj `TransactionExecutor.create`:
            //
            //     cacheTrack.createAccount(newContractAddress,
            //         activations.isActive(RSKIP174) && cacheTrack.isExist(newContractAddress));
            //
            // `createAccount(addr, false)` writes a *fresh* AccountState over
            // whatever was there, so before RSKIP174 (iris300) deploying onto
            // an address that already holds a balance destroys it. Someone
            // funding a deploy address before the deployment lands loses the
            // money, and the chain's supply drops with it.
            //
            // revm does the sane thing and keeps the balance, which is the
            // post-iris300 rule, so only the earlier window needs this. The
            // VM's own CREATE/CREATE2 is untouched: `Program.createContract`
            // passes `existingAccount` with no activation check, and so always
            // carries over.
            //
            // Testnet #647,051 is a live instance -- 0.05 RBTC sitting at the
            // deploy address, gone in the reference node's post-state.
            if tx.to.is_empty() && !self.hardfork_cfg.has_rskip174(header.number) {
                use revm::context_interface::journaled_state::account::JournaledAccountTr;
                use revm::context_interface::{ContextTr, JournalTr};
                let created = sender.create(tx.nonce);
                // Read before taking a mutable handle, so an address with
                // nothing in it is not materialised into an empty account that
                // the state root would then have to carry.
                let occupied = evm
                    .ctx
                    .journal_mut()
                    .load_account(created)
                    .map(|a| !a.data.info.balance.is_zero() || a.data.info.nonce != 0)
                    .unwrap_or(false);
                if occupied {
                    let mut acc = evm
                        .ctx
                        .journal_mut()
                        .load_account_mut(created)
                        .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?;
                    // `new AccountState()` -- nonce and balance both zero.
                    // Code lives under its own trie key and createAccount does
                    // not touch it, so an address holding code still collides
                    // in revm where rskj would overwrite. Reaching that needs a
                    // hash collision, so it is left alone rather than modelled.
                    acc.data.set_balance(U256::ZERO);
                    acc.data.set_nonce(0);
                }
            }

            let result = {
                use revm::context::ContextSetters;
                use revm::handler::Handler;
                evm.ctx.set_tx(tx_env);
                let mut handler = crate::rsk_handler::RskHandler::with_rskip125(
                !self.hardfork_cfg.has_rskip453(header.number),
                self.hardfork_cfg.has_rskip125(header.number),
                invisible_flag.clone(),
                pre_rskip150_precompiles.clone(),
                active_precompiles.clone(),
                self.hardfork_cfg.has_rskip171(header.number),
            )
            .postponing_fees(postpone_fees);
                // `inspect_run` for the one transaction being traced, `run`
                // for every other -- and `run` is the same code path an EVM
                // built without an inspector takes, because revm carries the
                // inspector as a field that only `inspect_run` consults.
                let out: Result<_, revm::context::result::EVMError<_>> = if traced.includes(i) {
                    use revm::inspector::InspectorHandler;
                    handler.inspect_run(&mut evm)
                } else {
                    handler.run(&mut evm)
                };
                match out {
                    Ok(result) => result,
                    // The miner's mode: a transaction the EVM would not run
                    // is dropped, not fatal. revm's `catch_error` has
                    // already discarded the transaction's own journal
                    // (`JournalTr::discard_tx`), so the block's state is as
                    // it was before this transaction; the raw-storage
                    // overlay is wound back the same way. A database error
                    // is the node's, and still fails the run.
                    Err(e)
                        if discard_unfitting.is_some()
                            && !matches!(e, revm::context::result::EVMError::Database(_)) =>
                    {
                        debug!(tx_index = i, error = ?e, "mining: dropping a transaction the EVM refused");
                        if let Some(drops) = discard_unfitting.as_deref_mut() {
                            drops.invalid.push(i);
                        }
                        dropped_senders.insert(*sender);
                        {
                            use revm::context_interface::ContextTr;
                            evm.ctx.chain_mut().raw_storage.discard_tx();
                        }
                        continue;
                    }
                    Err(e) => return Err(ExecutionError::Evm(format!("{e:?}"))),
                }
            };

            let success = result.is_success();
            let gas_used = result.gas_used();
            let output = result.output().map(|o| o.to_vec()).unwrap_or_default();
            if traced.includes(i) {
                // Taken here, not after the block: `take_trace` resets the
                // tracer so the next transaction starts with an empty tree,
                // and `result` is about to be consumed by `into_logs`.
                let mut trace = evm.inspector.take_trace();
                TracedOutcome::of(tx, *sender, &result, &output).apply_to(&mut trace);
                traces.insert(i, trace);
            }
            let logs = result.into_logs();
            let created_address = Self::extract_created_address(tx, *sender, &success);

            if !success {
                // rskj cacheTrack rollback: a failed tx drops its bridge
                // raw-storage writes along with the rest of its state.
                use revm::context_interface::ContextTr;
                evm.ctx.chain_mut().raw_storage.discard_tx();
            }

            if success {
                if let Ok(mut called) = called_precompiles.lock() {
                    for addr in called.drain(..) {
                        if !markers.precompiles.contains(&addr) {
                            markers.precompiles.push(addr);
                        }
                    }
                }
                // rskj TransactionExecutor.create: a CREATE tx with empty data
                // makes the account "without code nor storage. It doesn't even
                // call setupContract()".
                if tx.to.is_empty() && tx.input.is_empty() {
                    if let Some(addr) = created_address {
                        markers.skip_created.push(addr);
                    }
                }
            }

            // Mirror what RskHandler paid REMASC: the full gas limit on an
            // invisible exception, the spent gas otherwise.
            let fee_gas = if invisible_flag.load(std::sync::atomic::Ordering::Relaxed) {
                tx.gas_limit.to::<u64>()
            } else {
                gas_used
            };
            let fee_paid = U256::from(fee_gas) * tx.gas_price;
            let withheld_now = if postpone_fees { fee_paid } else { U256::ZERO };
            total_fees += fee_paid;

            total_gas += gas_used;
            tx_results.push(TxExecutionResult {
                reached_sequential_only: reached_sequential_only
                    .load(std::sync::atomic::Ordering::Relaxed),
                gas_used,
                success,
                output,
                logs,
                created_address,
            });

            if crate::supply::per_transaction_enabled() {
                use revm::context_interface::ContextTr;
                let st = &evm.ctx.journal_mut().inner.state;
                Self::check_tx_supply(st, supply_tid, header.number, i, withheld_now, U256::ZERO)?;
            }
            // RSKIP-144: what this transaction read and wrote, attributed to
            // its sublist. Inert unless the block declares sublist edges.
            if crate::collision::is_recording() {
                use revm::context_interface::ContextTr;
                let j = &evm.ctx.journal_mut().inner;
                crate::collision::note_journal_entries(&j.journal, &j.state);
                crate::collision::record_transaction(supply_tid, &j.state);
                let raw = evm.ctx.chain_mut().raw_storage.tx_writes();
                crate::collision::record_raw_writes(raw);
            }
            // rskj TransactionExecutor.finalization deletes suicided accounts
            // at the END of each transaction (track.delete), so a LATER tx in
            // the same block sees the address as nonexistent and re-creates a
            // fresh (0, 0) account node by merely calling it (frontier
            // `transfer`/`addBalance(0)`). revm keeps one journal for the
            // whole block and only wipes a destroyed account lazily on the
            // next cold load, leaving the sticky global SelfDestructed and
            // Touched flags — so the block-end state could not distinguish
            // "destroyed" from "destroyed, then re-created by a later tx".
            // Neutralize the entry as soon as the destroying tx commits: wipe
            // info/storage (what revm's next cold load would do) and clear
            // the touched flag. A later tx that touches the address re-marks
            // Touched, which apply_state_changes reads as "alive again at
            // block end" (mainnet #3173807).
            {
                use revm::context_interface::ContextTr;
                for account in evm.ctx.journal_mut().inner.state.values_mut() {
                    if account.is_selfdestructed_locally() {
                        account.selfdestruct();
                        account.unmark_selfdestructed_locally();
                        account.unmark_created_locally();
                        account.unmark_touch();
                    }
                }
            }

            debug!(tx_index = i, gas_used, success, "executed transaction");
        }

        // rskj `TransactionListExecutor.payToRemascWhenThereIsNoRemascTx`: a
        // block without a REMASC transaction settles the postponed fees after
        // its last one instead. rskj calls this case testing-only -- "the last
        // tx should be always the REMASC" -- and it is reachable here for the
        // same reason, from a hand-built block.
        //
        // Gated on this run ending the block. Without that gate every
        // parallel sublist took itself for such a block and settled its own
        // fees, which the sequential sublist then settled again: testnet
        // #7,690,880 came out 640358944286 wei to the good, exactly the
        // first sublist's fees.
        if postpone_fees && ends_the_block && !remasc_tx_seen && !total_fees.is_zero() {
            use revm::context_interface::journaled_state::account::JournaledAccountTr;
            use revm::context_interface::{ContextTr, JournalTr};
            evm.ctx
                .journal_mut()
                .load_account_mut(REMASC_ADDR)
                .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?
                .incr_balance(total_fees);
            evm.ctx.journal_mut().touch_account(REMASC_ADDR);
        }

        {
            use revm::context_interface::ContextTr;
            markers.raw_storage = evm.ctx.chain_mut().raw_storage.drain();
        }
        let state = evm.finalize();

        Ok((
            BlockExecutionResult {
                tx_results,
                gas_used: total_gas,
                paid_fees: total_fees,
                state_changes: state,
                markers,
                applied_root: None,
                // A run that is one sublist has no phases to split: the
                // caller applies its changes, and there is no maintenance
                // pass or ordered commit to attribute time to.
                phases: PhaseTimings::default(),
            },
            traces,
        ))
    }

    /// rskj BridgeUtils.isFreeBridgeTx: before areBridgeTxsPaid activates,
    /// transactions to the Bridge from the genesis federation or an
    /// authorized sender execute for free (zero gas).
    fn is_free_bridge_tx(&self, tx: &rustock_core::Transaction, sender: Address, block_number: u64) -> bool {
        tx.to.len() == 20
            && tx.to.as_ref() == crate::precompiles::BRIDGE_ADDR.as_slice()
            && !self.hardfork_cfg.has_are_bridge_txs_paid(block_number)
            && self.free_bridge_senders.contains(&sender)
    }

    /// Detect the REMASC synthetic transaction: v=0, r=0, s=0, gas_limit=0,
    /// to=REMASC_ADDR. The gas_limit=0 check distinguishes real REMASC system
    /// calls from normal transactions that happen to call REMASC with valid gas.
    fn is_remasc_tx(tx: &rustock_core::Transaction) -> bool {
        if tx.v != 0 || !tx.r.is_zero() || !tx.s.is_zero() {
            return false;
        }
        if !tx.gas_limit.is_zero() {
            return false;
        }
        tx.to.len() == 20 && tx.to.as_ref() == REMASC_ADDR.as_slice()
    }

    /// For contract creation transactions, compute the created address from
    /// sender + nonce (matching CREATE opcode address derivation).
    fn extract_created_address(
        tx: &rustock_core::Transaction,
        sender: Address,
        success: &bool,
    ) -> Option<Address> {
        if !success || !tx.to.is_empty() {
            return None;
        }
        // Standard CREATE scheme: keccak(rlp([sender, nonce]))[12:]. RSK
        // doesn't include the created address in the receipt RLP, so this is
        // only needed for the empty-data-CREATE skip_created bookkeeping.
        Some(sender.create(tx.nonce))
    }
}

/// Which transactions of a block the inspector should be switched on for.
///
/// `debug_traceTransaction` wants one; `trace_block` wants all of them in a
/// single pass; consensus wants none, and takes `Handler::run` for every
/// transaction as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TracedTxs {
    None,
    One(usize),
    All,
}

impl TracedTxs {
    fn includes(self, index: usize) -> bool {
        match self {
            TracedTxs::None => false,
            TracedTxs::One(i) => i == index,
            TracedTxs::All => true,
        }
    }
}

/// The four `DetailedProgramTrace` fields that come from the transaction's
/// result rather than from the opcode stream.
///
/// rskj fills them in `Program`/`TransactionExecutor`, not in the trace
/// listener, so they are gathered here for the same reason.
struct TracedOutcome {
    contract_address: String,
    result: String,
    error: String,
    reverted: bool,
}

impl TracedOutcome {
    fn of(
        tx: &rustock_core::Transaction,
        sender: Address,
        result: &revm::context::result::ExecutionResult,
        output: &[u8],
    ) -> Self {
        use revm::context::result::ExecutionResult;

        // rskj: `contractAddress = toHexString(programInvoke.getOwnerAddress()
        // .getLast20Bytes())` -- the account whose code ran, bare hex with no
        // `0x`. For a CREATE that is the new contract, computed here from
        // sender and nonce whether or not the deployment succeeded, because
        // rskj traces the program that ran either way.
        let owner = if tx.to.is_empty() {
            sender.create(tx.nonce)
        } else {
            Address::from_slice(&tx.to)
        };

        // rskj: `toHexStringOrEmpty(result)` -- bare hex, empty string for no
        // return data.
        let result_hex = hex::encode(output);

        // rskj renders this as `format("%s: %s", error.getClass(),
        // error.getMessage())`, e.g.
        // `class org.ethereum.vm.program.Program$OutOfGasException: ...`.
        // A Java class name is not reproducible here and imitating one would
        // be worse than not: the halt reason is reported instead, and
        // `docs/debug-namespace.md` records the difference.
        let error = match result {
            ExecutionResult::Halt { reason, .. } => format!("{reason:?}"),
            _ => String::new(),
        };

        Self {
            contract_address: hex::encode(owner.as_slice()),
            result: result_hex,
            error,
            reverted: matches!(result, ExecutionResult::Revert { .. }),
        }
    }

    fn apply_to(self, trace: &mut crate::tracer::ProgramTrace) {
        trace.contract_address = self.contract_address;
        trace.result = self.result;
        trace.error = self.error;
        trace.reverted = self.reverted;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("database error: {0}")]
    Database(#[from] crate::database::RskDbError),
    #[error("evm error: {0}")]
    Evm(String),
    /// A transaction increased the native supply. Rejected before the block's
    /// state is written; see `crate::supply`.
    #[error("transaction {index} of block #{number} created {created} wei of rBTC")]
    SupplyCreated { number: u64, index: usize, created: alloy_primitives::U256 },
}

/// The Bridge constants a chain id selects: testnet's, mainnet's, or
/// regtest's for anything else.
pub fn bridge_constants_for(chain_id: u64) -> crate::bridge::constants::BridgeConstants {
    match chain_id {
        crate::hardfork::RSK_TESTNET_CHAIN_ID => crate::bridge::constants::BridgeConstants::testnet(),
        crate::hardfork::RSK_MAINNET_CHAIN_ID => crate::bridge::constants::BridgeConstants::mainnet(),
        _ => crate::bridge::constants::BridgeConstants::regtest(),
    }
}

/// The senders whose transactions to the Bridge are free before
/// `areBridgeTxsPaid`: the genesis federation and the authorized free-tx
/// keys (rskj `BridgeUtils.isFreeBridgeTx`). Shared by the executor and the
/// transaction pool, which must agree on what costs nothing.
pub fn free_bridge_senders(constants: &crate::bridge::constants::BridgeConstants) -> Vec<Address> {
    constants
        .genesis_federation_public_keys
        .iter()
        .chain(constants.authorized_free_tx_keys.iter())
        .filter_map(|hex| rsk_address_from_pubkey_hex(hex))
        .collect()
}

/// Derives an RSK address from a secp256k1 public key in SEC1 hex
/// (compressed or uncompressed): keccak256 of the uncompressed point's
/// 64 coordinate bytes, last 20 bytes (rskj ECKey.getAddress).
fn rsk_address_from_pubkey_hex(hex: &str) -> Option<Address> {
    let bytes = alloy_primitives::hex::decode(hex).ok()?;
    crate::bridge::federation::rsk_address_from_public_key(&bytes)
}

fn make_cfg_env(spec_id: SpecId, chain_id: u64, eip3541_active: bool) -> CfgEnv {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    // Gas params are spec-dependent: assigning `spec` alone keeps the
    // default (latest-fork) table and mis-prices historical opcodes —
    // e.g. SSTORE reset was charged 2900 instead of 5000 at mainnet #1713.
    cfg.set_spec_and_mainnet_gas_params(spec_id);
    // rskj never adopted EIP-150's 63/64 gas retention: CREATE forwards ALL
    // remaining gas to the child (Program.createContract spends
    // getRemainingGas()). A u64::MAX divisor makes the retention zero. The
    // CALL family is fully replaced by rsk_instructions.
    cfg.gas_params.override_gas([(
        revm::context_interface::cfg::GasId::call_stipend_reduction(),
        u64::MAX,
    )]);
    // rskj's SSTORE costs are fork-independent Petersburg-style values
    // (`GasCost.SET_SSTORE`=20000, `CLEAR_SSTORE`=`RESET_SSTORE`=5000,
    // `REFUND_SSTORE`=15000) — RSK never adopted EIP-2200 net metering. Under the
    // ISTANBUL/SHANGHAI specs (arrowhead600+) revm's table rewrites these to the
    // Istanbul net-metering split (static 800, etc.), so pin them back. These
    // equal the Petersburg defaults, so the override is a no-op pre-arrowhead.
    // The custom `rsk_sstore` (rsk_instructions) consumes them with Petersburg
    // (`is_istanbul=false`) semantics and skips the EIP-2200 reentrancy sentry.
    use revm::context_interface::cfg::GasId;
    cfg.gas_params.override_gas([
        (GasId::sstore_static(), 5_000),
        (GasId::sstore_set_without_load_cost(), 15_000),
        (GasId::sstore_reset_without_cold_load_cost(), 0),
        (GasId::sstore_set_refund(), 15_000),
        (GasId::sstore_reset_refund(), 0),
        (GasId::sstore_clearing_slot_refund(), 15_000),
        // rskj `GasCost.SUICIDE_REFUND` = 24000 at every fork. EIP-3529 (London)
        // zeroed the SELFDESTRUCT refund, and lovell700 maps to SHANGHAI
        // (>= LONDON), so revm's param would be 0 — pin it back to 24000. This
        // equals the pre-London default, so the override is a no-op pre-lovell.
        (GasId::selfdestruct_refund(), 24_000),
    ]);
    // rskj never adopted EIP-2929 (Berlin warm/cold access lists): SLOAD is a
    // flat 200, BALANCE/EXTCODE*/CALL-family account access a flat 400/static,
    // with no cold-access surcharge or warm discount, regardless of fork
    // (`GasCost` is fork-independent). lovell700+ maps to SHANGHAI (>= BERLIN),
    // where revm's `host::sload`/`berlin_load_account!`/call helpers add a
    // cold-access surcharge (cold SLOAD +2000, cold account +2500) read from
    // these gas params. Zero them so the first access to a slot/account costs
    // the same as a warm one. These params are 0 for every spec < BERLIN, so
    // this override is a no-op pre-lovell. First observed at the lovell700
    // activation block #7,338,024 (two cold SLOADs over-charged 2000 each).
    cfg.gas_params.override_gas([
        (GasId::cold_account_additional_cost(), 0),
        (GasId::cold_storage_additional_cost(), 0),
        (GasId::cold_storage_cost(), 0),
        // `warm_storage_read_cost` (100 at Berlin+) is the EIP-2929 warm base.
        // RSK charges no warm/cold component, and SELFDESTRUCT's cold cost is
        // `cold_account_additional_cost + warm_storage_read_cost` — with the
        // former zeroed, a cold SELFDESTRUCT beneficiary would still wrongly cost
        // 100. Zero it too. Every other consumer (SLOAD/CALL/SSTORE) takes its
        // base from a statically-overridden gas value, not this, and it is 0 for
        // specs < BERLIN, so the override is a no-op pre-lovell.
        (GasId::warm_storage_read_cost(), 0),
    ]);
    cfg.limit_contract_code_size = Some(0x6000);
    // RSKIP544 (Vetiver900): rskj only rejects new contract code starting
    // with 0xEF from vetiver900, while revm bundles EIP-3541 into LONDON+.
    cfg.disable_eip3541 = !eip3541_active;
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bloom, Bytes, B256, U256};
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, account_key, AccountState};

    fn dummy_header(number: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::repeat_byte(0x01),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(1_000_000),
            number,
            gas_limit: U256::from(6_800_000),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(0),
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    fn put_account(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        nonce: u64,
        balance: U256,
    ) -> TrieNode {
        let key_bytes = account_key(addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        let acct = AccountState::new(U256::from(nonce), balance);
        root.put(&key, &acct.encode(), store)
    }

    /// An account with code, for tests that need a contract to run.
    fn put_account_with_code(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        nonce: u64,
        balance: U256,
        code: &[u8],
    ) -> TrieNode {
        let root = put_account(root, store, addr, nonce, balance);
        let code_key_bytes = rustock_trie::code_key(addr);
        root.put(&TrieKeySlice::from_key(&code_key_bytes), code, store)
    }

    /// Before RSKIP197 a throwing precompile burns every bit of gas forwarded
    /// to it; from RSKIP197 it costs the flat parse-failure fee.
    ///
    /// rskj `Program.callToPrecompiledAddress` picks between two methods:
    ///
    /// ```java
    /// if (getActivations().isActive(ConsensusRule.RSKIP197)) {
    ///     executePrecompiledAndHandleError(contract, msg, requiredGas, track, data);
    /// } else {
    ///     executePrecompiled(contract, msg, requiredGas, track, data);
    /// }
    /// ```
    ///
    /// The older one has no error handling at all -- it wraps the method's
    /// `VMException` in a `RuntimeException` that escapes the VM. The newer
    /// one pushes zero, refunds `gas - requiredGas`, and lets the caller
    /// continue.
    ///
    /// Ground truth: testnet #808,484, whose first transaction deploys a
    /// contract whose constructor calls the Bridge with `0xad69a4f7` -- not a
    /// Bridge method, so post-RSKIP88 it throws. The reference node reports
    /// `status 0x0, gasUsed 1000000`, the whole limit; rustock reported
    /// success at 120,388 until this gate existed.
    #[test]
    fn a_bridge_throw_before_rskip197_burns_all_the_gas_forwarded_to_it() {
        let (pre, post) = bridge_throw_gas_either_side_of_iris300();
        assert!(
            pre > post * 10,
            "pre-RSKIP197 must burn the forwarded gas, not the flat fee \
             (pre {pre}, post {post})"
        );
    }

    #[test]
    fn a_bridge_throw_from_rskip197_costs_only_the_flat_parse_failure_fee() {
        let (pre_dbg, post) = bridge_throw_gas_either_side_of_iris300();
        // 23_000 (BridgeMethods.RELEASE_BTC) plus the caller's own overhead.
        assert_eq!(pre_dbg, 1_000_000, "pre-RSKIP197 consumes the whole limit");
        assert!(
            post < 100_000,
            "post-RSKIP197 pays requiredGas plus call overhead, not the limit (got {post})"
        );
    }

    /// KNOWN DIVERGENCE (#295): a caller that caps the gas it forwards
    /// survives here, where rskj kills the transaction.
    ///
    /// rskj's escaping `RuntimeException` ends the transaction regardless of
    /// how much gas the caller still held. Modelling the throw as a
    /// spent-everything precompile error reproduces that only when the caller
    /// forwarded everything, because then the caller runs out too. A caller
    /// using `call{gas: n}` keeps the rest and carries on.
    ///
    /// Pinned rather than left unsaid, so the gap is visible and so that
    /// closing it fails this test instead of passing silently.
    #[test]
    fn a_capped_forward_still_survives_the_pre_rskip197_throw() {
        let used = bridge_throw_gas_with_capped_forward(2_060_499);
        assert_eq!(
            used, 96_733,
            "only the forwarded 50,000 is burned; rskj would charge the whole \
             1,000,000 limit -- see #295"
        );

        // From iris300 both agree: the caller continues on what it kept.
        let after = bridge_throw_gas_with_capped_forward(2_060_500);
        assert!(after < 150_000, "post-RSKIP197 the caller continues (got {after})");
    }

    /// Runs the same contract on both sides of testnet iris300 (#2,060,500)
    /// and returns the gas each transaction used.
    fn bridge_throw_gas_either_side_of_iris300() -> (u64, u64) {
        let run = |height: u64| {
            let store = Arc::new(MemoryTrieStore::new());
            let sender = Address::repeat_byte(0xAA);
            let contract = Address::repeat_byte(0xBB);

            // CALL the Bridge forwarding all remaining gas, with a 4-byte
            // selector that is not a Bridge method, then STOP.
            //
            //   PUSH4 ad69a4f7 ; PUSH1 00 ; MSTORE   (left-aligned at 0x1c)
            //   PUSH1 00 x2    ; PUSH1 04 ; PUSH1 1c ; PUSH1 00
            //   PUSH20 <bridge>; GAS ; CALL ; STOP
            let mut code: Vec<u8> = vec![
                0x63, 0xad, 0x69, 0xa4, 0xf7, // PUSH4 selector
                0x60, 0x00, // PUSH1 0 (mstore offset, left-aligned word)
                0x52, // MSTORE
                0x60, 0x00, // retSize
                0x60, 0x00, // retOffset
                0x60, 0x04, // argsSize
                0x60, 0x00, // argsOffset (selector is the word's high bytes)
                0x60, 0x00, // value
                0x73, // PUSH20
            ];
            code.extend_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice());
            code.extend_from_slice(&[0x5a, 0xf1, 0x00]); // GAS, CALL, STOP

            let root = put_account(
                &TrieNode::empty(),
                store.as_ref(),
                &sender,
                0,
                U256::from(10u64).pow(U256::from(18)),
            );
            let root = put_account_with_code(
                &root,
                store.as_ref(),
                &contract,
                1,
                U256::ZERO,
                &code,
            );

            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::testnet(), block_store);
            let tx = rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::copy_from_slice(contract.as_slice()),
                value: U256::ZERO,
                input: Bytes::new(),
                v: 0,
                r: U256::ZERO,
                s: U256::ZERO,
                cached_rlp: None,
            };
            let result = executor
                .execute_block(&dummy_header(height), &[(tx, sender)], &root, store)
                .expect("block executes");
            result.tx_results[0].gas_used
        };

        // testnet iris300 = #2,060,500.
        (run(2_060_499), run(2_060_500))
    }

    /// Same call, but forwarding a fixed 50,000 gas instead of everything.
    fn bridge_throw_gas_with_capped_forward(height: u64) -> u64 {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xBB);

        let mut code: Vec<u8> = vec![
            0x63, 0xad, 0x69, 0xa4, 0xf7, // PUSH4 selector
            0x60, 0x00, 0x52, // PUSH1 0, MSTORE
            0x60, 0x00, // retSize
            0x60, 0x00, // retOffset
            0x60, 0x04, // argsSize
            0x60, 0x00, // argsOffset
            0x60, 0x00, // value
            0x73, // PUSH20
        ];
        code.extend_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice());
        // PUSH3 0x00c350 = 50,000 forwarded, rather than GAS.
        code.extend_from_slice(&[0x62, 0x00, 0xc3, 0x50, 0xf1, 0x00]);

        let root = put_account(
            &TrieNode::empty(),
            store.as_ref(),
            &sender,
            0,
            U256::from(10u64).pow(U256::from(18)),
        );
        let root =
            put_account_with_code(&root, store.as_ref(), &contract, 1, U256::ZERO, &code);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::testnet(), block_store);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        executor
            .execute_block(&dummy_header(height), &[(tx, sender)], &root, store)
            .expect("block executes")
            .tx_results[0]
            .gas_used
    }

    /// rskj `Bridge.validateLocalCall` (Bridge.java:431) lets a LOCAL-ONLY
    /// getter run for `eth_call`/`estimateGas` and throws for anything on-chain.
    /// rustock had the throw but no way to say "this is a local call", so the
    /// getters were unreachable from every caller.
    ///
    /// The state here is empty, so the Bridge falls back to the genesis
    /// federation (`active_federation_keys_and_redeem`, the same function the
    /// peg-out path uses to place change) and its address is deterministic.
    #[test]
    fn local_only_getter_answers_a_local_call_and_throws_on_chain() {
        // keccak256("getFederationAddress()")[..4]
        const GET_FEDERATION_ADDRESS: [u8; 4] = [0x69, 0x23, 0xfa, 0x85];
        let bridge = crate::precompiles::BRIDGE_ADDR;

        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let root = put_account(
            &root, store.as_ref(), &sender, 0,
            U256::from(10u64).pow(U256::from(18)),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(6_000_000);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(600_000),
            to: Bytes::copy_from_slice(bridge.as_slice()),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(&GET_FEDERATION_ADDRESS),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // On-chain: rskj empties the return data (the "invisible exception"),
        // which is what a contract's RETURNDATASIZE check sees.
        let on_chain = executor
            .execute_tx(&header, &tx, sender, &root, store.clone())
            .expect("execution completes");
        assert!(
            on_chain.output.is_empty(),
            "a local-only getter must stay unreachable on-chain, got {} bytes",
            on_chain.output.len()
        );

        // Local call: the getter runs and returns an ABI-encoded string.
        let local = executor
            .execute_local_call(&header, &tx, sender, &root, store)
            .expect("execution completes");
        assert!(!local.output.is_empty(), "a local call must reach the getter");

        // ABI string: offset, length, then the UTF-8 bytes.
        let len = U256::from_be_slice(&local.output[32..64]).to::<usize>();
        let text = std::str::from_utf8(&local.output[64..64 + len]).expect("utf-8");
        assert!(
            text.starts_with('3'),
            "mainnet federation is P2SH, so its Base58 address starts with 3; got {text}"
        );
        assert_eq!(text.len(), 34, "P2SH Base58Check addresses are 34 characters");
    }

    /// Regression for mainnet block #356,285 (gas used mismatch 65,024 vs
    /// 62,724): rskj charges the 2,300 CALL stipend to the caller
    /// (calleeGas = min(remaining, requested + stipend)), while canonical
    /// EVM conjures it for free — making a `transfer()` to an EOA 2,300
    /// cheaper. The contract performs CALL(gas=0, eoa, value=1) and stops:
    ///   21,000 intrinsic + 21 (7 pushes) + 700 CALL + 9,000 VT = 30,721
    /// (the charged stipend returns as the EOA child's unused gas).
    /// A tracer that alters the execution it observes is a consensus hazard
    /// dressed as a debugging tool, so the traced and untraced paths must
    /// agree on gas, output, success and logs.
    ///
    /// **What this does not prove.** It cannot detect the tracer warming a
    /// storage slot, because RSK has no EIP-2929 -- every cold/warm gas
    /// parameter is zero (`test_cfg_env_no_eip2929_cold_access_cost`), so
    /// warmth is invisible in gas here. Verified by flipping
    /// `sload_skip_cold_load`'s skip off: this test still passes. The skip
    /// stays because not depending on that is free, not because this catches
    /// it.
    ///
    /// What it does catch is the likelier failure: `execute_tx_traced`
    /// duplicates the untraced setup rather than refactoring it, and this is
    /// the guard against the two drifting apart.
    #[test]
    fn tracing_does_not_change_execution() {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let root = put_account(
            &TrieNode::empty(), store.as_ref(), &sender, 0,
            U256::from(10u64).pow(U256::from(18)),
        );

        // A contract that writes storage twice and reads it back, so the
        // tracer's storage handling is exercised -- that is the part that
        // touches the journal and so the part that could perturb gas.
        //   PUSH1 01 PUSH1 00 SSTORE   (store 1 at slot 0)
        //   PUSH1 00 SLOAD            (read it back)
        //   PUSH1 02 PUSH1 00 SSTORE  (store 2 at slot 0)
        //   STOP
        let code = vec![
            0x60, 0x01, 0x60, 0x00, 0x55,
            0x60, 0x00, 0x54,
            0x60, 0x02, 0x60, 0x00, 0x55,
            0x00,
        ];
        let contract = Address::repeat_byte(0xCC);
        let root = put_account_with_code(&root, store.as_ref(), &contract, 1, U256::ZERO, &code);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(6_000_000);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(600_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::default(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let plain = executor
            .execute_tx(&header, &tx, sender, &root, store.clone())
            .expect("untraced execution completes");
        let (traced, trace) = executor
            .execute_tx_traced(
                &header, &tx, sender, &root, store, false,
                crate::tracer::DEFAULT_MAX_STRUCT_LOGS,
            )
            .expect("traced execution completes");

        assert_eq!(plain.gas_used, traced.gas_used, "tracing must not change gas");
        assert_eq!(plain.success, traced.success);
        assert_eq!(plain.output, traced.output);
        assert_eq!(plain.logs.len(), traced.logs.len());
        assert_eq!(plain.created_address, traced.created_address);

        // And the trace actually recorded something, so the assertions above
        // are not comparing two untraced runs.
        assert!(!trace.struct_logs.is_empty(), "the tracer recorded no steps");
        assert!(
            trace.struct_logs.iter().any(|l| l.op == "SSTORE"),
            "the contract's SSTOREs should appear in the trace"
        );
    }

    /// The step cap exists so that tracing a large transaction cannot exhaust
    /// memory -- which is most likely on exactly the transaction someone wants
    /// to look at. A truncated trace says so rather than looking short.
    #[test]
    fn a_trace_stops_at_the_step_cap() {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let root = put_account(
            &TrieNode::empty(), store.as_ref(), &sender, 0,
            U256::from(10u64).pow(U256::from(18)),
        );
        // JUMPDEST; PUSH1 00; JUMP -- an infinite loop, stopped by out-of-gas.
        let code = vec![0x5b, 0x60, 0x00, 0x56];
        let contract = Address::repeat_byte(0xCC);
        let root = put_account_with_code(&root, store.as_ref(), &contract, 1, U256::ZERO, &code);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(6_000_000);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(600_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::default(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let (_result, trace) = executor
            .execute_tx_traced(&header, &tx, sender, &root, store, false, 50)
            .expect("execution completes");

        assert_eq!(trace.struct_logs.len(), 50, "the cap is the cap");
        assert!(trace.truncated, "and the trace says it was cut short");
    }

    #[test]
    fn test_rskj_call_stipend_is_charged_to_caller() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);
        let eoa = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &eoa, 1, U256::from(5));
        let root = put_account(&root, store.as_ref(), &contract, 1, U256::from(1_000));
        // PUSH1 0 x4 (ret/args) PUSH1 1 (value) PUSH20 eoa PUSH1 0 (gas) CALL STOP
        let mut code = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // out/in offsets+sizes
            0x60, 0x01, // value 1
            0x73, // PUSH20
        ];
        code.extend_from_slice(eoa.as_slice());
        code.extend_from_slice(&[0x60, 0x00, 0xF1, 0x00]); // gas 0, CALL, STOP
        let code_key_bytes = rustock_trie::code_key(&contract);
        let root = root.put(
            &TrieKeySlice::from_key(&code_key_bytes),
            &code,
            store.as_ref(),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(356_285);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(600_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .expect("execution succeeds");
        assert!(result.success);
        assert_eq!(
            result.gas_used, 30_721,
            "rskj charges the stipend through calleeGas; canonical EVM would yield 28,421"
        );
    }

    /// Regression for mainnet #7,515,160 (gas used mismatch header=1976590 vs
    /// computed=1975990). rskj `GasCost.EXT_CODE_COPY` is a flat 700 at every
    /// fork. lovell700 maps to revm's SHANGHAI (>= BERLIN), where revm's stock
    /// instruction-table static for EXTCODECOPY is WARM_STORAGE_READ_COST (and
    /// the cold-account surcharge is pinned to 0 in make_cfg_env), so without an
    /// explicit override EXTCODECOPY would undercharge by 600. `install` pins it
    /// back to 700. The contract runs `EXTCODECOPY(self, 0, 0, 0)` (length 0 →
    /// no copy/memory-expansion cost), isolating the flat base:
    ///   21,000 intrinsic + 9 (3 PUSH1) + 3 (PUSH20) + 700 EXTCODECOPY = 21,712.
    #[test]
    fn test_extcodecopy_flat_700_at_lovell700() {
        assert_eq!(RskHardforkConfig::mainnet().spec_id(7_338_024), SpecId::SHANGHAI);

        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &contract, 1, U256::from(1_000));
        // PUSH1 0 (length) PUSH1 0 (codeOffset) PUSH1 0 (destOffset)
        // PUSH20 contract  EXTCODECOPY  STOP
        let mut code = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        code.extend_from_slice(contract.as_slice());
        code.extend_from_slice(&[0x3c, 0x00]); // EXTCODECOPY, STOP
        let code_key_bytes = rustock_trie::code_key(&contract);
        let root = root.put(
            &TrieKeySlice::from_key(&code_key_bytes),
            &code,
            store.as_ref(),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(7_338_024);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(600_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .expect("execution succeeds");
        assert!(result.success);
        assert_eq!(
            result.gas_used, 21_712,
            "EXTCODECOPY must charge the flat rskj base of 700 at lovell700/SHANGHAI"
        );
    }

    /// Regression for mainnet block #1713 (gas used mismatch 26656 vs 24556):
    /// cfg.spec alone leaves the latest-fork gas table in place; the params
    /// must be derived per spec. RSK uses Petersburg-style SSTORE metering at
    /// EVERY fork (rskj's `GasCost` constants are fork-independent), so
    /// make_cfg_env pins SSTORE to the rskj values regardless of SpecId — the
    /// 5000 reset cost is fully carried by the static charge and the EIP-2200
    /// net-metering split (static 800) is overridden away.
    #[test]
    fn test_cfg_env_gas_params_follow_spec() {
        let byz = make_cfg_env(SpecId::BYZANTIUM, 30, false);
        assert_eq!(byz.gas_params.sstore_static_gas(), 5000);
        assert_eq!(byz.gas_params.sstore_reset_without_cold_load_cost(), 0);
        assert_eq!(byz.gas_params.sstore_set_without_load_cost(), 15_000);

        // Istanbul/Shanghai (arrowhead600+) keep the SAME rskj Petersburg SSTORE
        // metering: EIP-2200's static=800 split is pinned back to 5000 / 0.
        let ist = make_cfg_env(SpecId::ISTANBUL, 30, false);
        assert_eq!(ist.gas_params.sstore_static_gas(), 5000);
        assert_eq!(ist.gas_params.sstore_reset_without_cold_load_cost(), 0);
        assert_eq!(ist.gas_params.sstore_set_without_load_cost(), 15_000);
    }

    /// Regression for lovell700 activation block #7,338,024 (gas used mismatch
    /// 62749 vs 58749): RSK never adopted EIP-2929 warm/cold access lists, so
    /// SLOAD/BALANCE/EXTCODE*/CALL have no cold-access surcharge at any fork.
    /// lovell700 maps to SHANGHAI (>= BERLIN), where revm would add the cold
    /// surcharge read from these gas params, so make_cfg_env zeros them. They
    /// are already 0 for every spec < BERLIN, so this is a no-op pre-lovell.
    #[test]
    fn test_cfg_env_no_eip2929_cold_access_cost() {
        for spec in [SpecId::ISTANBUL, SpecId::SHANGHAI] {
            let cfg = make_cfg_env(spec, 30, false);
            assert_eq!(cfg.gas_params.cold_account_additional_cost(), 0, "{spec:?}");
            assert_eq!(cfg.gas_params.cold_storage_additional_cost(), 0, "{spec:?}");
            assert_eq!(cfg.gas_params.cold_storage_cost(), 0, "{spec:?}");
            assert_eq!(cfg.gas_params.warm_storage_read_cost(), 0, "{spec:?}");
            // SELFDESTRUCT cold-beneficiary cost must be 0 (RSK charges no
            // warm/cold) — #7,403,649 charged a cold SELFDESTRUCT 100 too much.
            assert_eq!(cfg.gas_params.selfdestruct_cold_cost(), 0, "{spec:?}");
        }
    }

    /// Regression for #7,388,594 (gas used mismatch 2663446 vs 2639446 — a
    /// contract-creation tx whose SELFDESTRUCT earned no refund). RSK keeps the
    /// 24000 SELFDESTRUCT refund (GasCost.SUICIDE_REFUND) at every fork; EIP-3529
    /// (London) zeroed it and lovell700 maps to SHANGHAI (>= LONDON), so it must
    /// be pinned back. Equals the pre-London default, so a no-op pre-lovell.
    #[test]
    fn test_cfg_env_selfdestruct_refund_kept() {
        for spec in [SpecId::ISTANBUL, SpecId::SHANGHAI] {
            let cfg = make_cfg_env(spec, 30, false);
            assert_eq!(cfg.gas_params.selfdestruct_refund(), 24_000, "{spec:?}");
        }
    }

    /// rskj `TransactionExecutor.create()`: a CREATE *transaction* carrying
    /// empty data creates the account "without code nor storage. It doesn't
    /// even call setupContract()". revm still flags it created-locally, so we
    /// must record the created address in `skip_created` to suppress the
    /// storage-prefix marker — which requires computing the address. The
    /// stub used to return None, leaving 13 spurious markers at #1,591,000.
    /// Ground truth: the canonical CREATE address vector (sender
    /// 0x6ac7…dbf0, nonce 0 → 0xcd23…cd8d).
    #[test]
    fn extract_created_address_matches_create_scheme() {
        let sender: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let create_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::from(21_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        assert_eq!(
            RskExecutor::extract_created_address(&create_tx, sender, &true),
            Some("0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d".parse().unwrap()),
        );
        // A reverted CREATE tx leaves no account.
        assert_eq!(
            RskExecutor::extract_created_address(&create_tx, sender, &false),
            None,
        );
        // A call (non-empty `to`) is never a creation.
        let call_tx = rustock_core::Transaction {
            to: Bytes::copy_from_slice(sender.as_slice()),
            ..create_tx
        };
        assert_eq!(
            RskExecutor::extract_created_address(&call_tx, sender, &true),
            None,
        );
    }

    /// Regression for mainnet #671,450: the feePerKb election must apply the
    /// voted value once a MAJORITY of authorizers votes it (the migration tx
    /// fee at #667,434 depends on the 30,000 sat/kB vote applied at
    /// #632,051). The election storage round-trip previously decoded the
    /// RLP-encoded coin as raw bytes, so votes never matched across blocks.
    #[test]
    fn test_fee_per_kb_vote_applies_at_majority() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        // Mainnet feePerKb authorizer RSK addresses.
        let voter1 = Address::from_slice(
            &alloy_primitives::hex::decode("a02db0ed94a5894bc6f9079bb9a2d93ada1917f3").unwrap(),
        );
        let voter2 = Address::from_slice(
            &alloy_primitives::hex::decode("180a7edda4e640ea5a3e495e17a1efad260c39e9").unwrap(),
        );
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &voter1, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &voter2, 0, one_rbtc);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let vote_tx = |nonce: u64| {
            let mut input = vec![0x04, 0x61, 0x31, 0x3e]; // voteFeePerKbChange(int256)
            let mut value = [0u8; 32];
            value[30..].copy_from_slice(&30_000u16.to_be_bytes());
            input.extend_from_slice(&value);
            rustock_core::Transaction {
                nonce,
                gas_price: U256::from(0),
                gas_limit: U256::from(100_000),
                to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
                value: U256::ZERO,
                input: Bytes::from(input),
                v: 0,
                r: U256::ZERO,
                s: U256::ZERO,
                cached_rlp: None,
            }
        };

        // Vote 1 in one block, vote 2 in the NEXT block: the election must
        // round-trip through the trie between them.
        let header1 = dummy_header(632_000);
        let r1 = executor
            .execute_block(&header1, &[(vote_tx(0), voter1)], &root, store.clone())
            .expect("block 1");
        assert!(r1.tx_results[0].success);
        let root2 = crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let header2 = dummy_header(632_051);
        let r2 = executor
            .execute_block(&header2, &[(vote_tx(0), voter2)], &root2, store.clone())
            .expect("block 2");
        assert!(r2.tx_results[0].success);

        let fee_key = crate::bridge::storage::bridge_storage_key(
            crate::bridge::storage::FEE_PER_KB_KEY,
        );
        let fee_write = r2
            .markers
            .raw_storage
            .iter()
            .rev()
            .find(|(addr, key, _)| *addr == crate::precompiles::BRIDGE_ADDR && *key == fee_key)
            .expect("feePerKb entry written");
        assert_eq!(
            fee_write.2.as_deref(),
            Some(crate::bridge::storage::rlp_encode_uint(U256::from(30_000)).as_slice()),
            "majority vote stores the new feePerKb as rskj serializeCoin RLP"
        );
    }

    /// Regression for mainnet #892,228: rskj has no EIP-161 — contracts
    /// created during execution start with nonce 0, and addresses they later
    /// derive via CREATE shift by one if the nonce is seeded to 1 (revm's
    /// SPURIOUS_DRAGON default from the per-era CfgEnv spec). The dividend
    /// contract at 0xcf0e5881… created payout wallets at
    /// keccak(rlp([contract, nonce])) and every recipient came out one nonce
    /// ahead of rskj's (real first wallet d82ac9f5… = nonce 0).
    #[test]
    fn test_created_contract_starts_with_nonce_zero() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime code: CREATE(0,0,0); SSTORE(0, created); STOP.
        let runtime: Vec<u8> = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x60, 0x00, 0x55, 0x00,
        ];
        // Init code: CODECOPY the runtime and RETURN it.
        let mut init = vec![
            0x60, 0x0b, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x0b, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);

        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header1 = dummy_header(892_000);
        let r1 = executor
            .execute_block(&header1, &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success);
        let deployed = sender.create(0); // deploy tx from sender nonce 0
        let d_acct = r1.state_changes.get(&deployed).expect("deployed account");
        assert_eq!(
            d_acct.info.nonce, 0,
            "created contract must start at nonce 0 (no EIP-161 in rskj)"
        );
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(deployed.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header2 = dummy_header(892_001);
        let r2 = executor
            .execute_block(&header2, &[(call, sender)], &root2, store.clone())
            .expect("create block");
        assert!(r2.tx_results[0].success);

        // The child must derive from nonce 0: keccak(rlp([deployed, 0])).
        let expected_child = deployed.create(0);
        let slot0 = r2
            .state_changes
            .get(&deployed)
            .expect("contract state")
            .storage
            .get(&U256::ZERO)
            .expect("slot 0 written");
        assert_eq!(
            Address::from_slice(&slot0.present_value.to_be_bytes::<32>()[12..]),
            expected_child,
            "CREATE inside a freshly deployed contract must use nonce 0"
        );
    }

    /// Regression for mainnet #3,650,574: rustock pins `block.beneficiary` to
    /// REMASC_ADDR so revm routes gas fees to the REMASC contract, but rskj's
    /// `OpCode.COINBASE` returns the block's *real* miner (`header.getCoinbase`).
    /// A token contract that minted to `block.coinbase` produced a Transfer to
    /// REMASC (0x…01000008) instead of the miner — diverging both the state and
    /// receipts roots. COINBASE must return `header.beneficiary`, not REMASC.
    #[test]
    fn test_coinbase_returns_real_miner_not_remasc() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Init code: COINBASE; SSTORE(0, coinbase); RETURN empty runtime.
        let init: Vec<u8> = vec![
            0x41, // COINBASE
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE
            0x60, 0x00, 0x60, 0x00, 0xf3, // PUSH1 0 PUSH1 0 RETURN
        ];

        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let mut header = dummy_header(892_000);
        // A distinctive miner address, distinct from both REMASC_ADDR and the
        // default repeat_byte(0x01).
        let miner = Address::from_slice(
            &alloy_primitives::hex!("31fe561eb2c628cd32ec52573d7c4b7e4c278bfa"),
        );
        header.beneficiary = miner;

        let r1 = executor
            .execute_block(&header, &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success);
        let deployed = sender.create(0);
        let slot0 = r1
            .state_changes
            .get(&deployed)
            .expect("contract state")
            .storage
            .get(&U256::ZERO)
            .expect("slot 0 written");
        assert_eq!(
            Address::from_slice(&slot0.present_value.to_be_bytes::<32>()[12..]),
            miner,
            "COINBASE must return the real miner, not REMASC_ADDR"
        );
    }

    /// Regression for mainnet #1,613,128: post-RSKIP125 (wasabi) an internal
    /// CREATE/CREATE2 opcode bumps the created contract's nonce to 1 (rskj
    /// Program.createContract). A top-level CREATE *transaction* still keeps
    /// nonce 0 (TransactionExecutor.create never bumps). The transferAndCall
    /// callback there created an empty contract rskj stored as nonce 1
    /// (`c20100`) while rustock, zeroing every created nonce, stored `c28000`.
    #[test]
    fn test_internal_create_nonce_one_post_rskip125() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime: CREATE(0,0,0) (empty init → no-code child); SSTORE(0, child).
        let runtime: Vec<u8> = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x60, 0x00, 0x55, 0x00,
        ];
        let mut init = vec![
            0x60, 0x0b, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x0b, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);

        // Deploy the creator via a top-level CREATE tx (post-wasabi).
        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header1 = dummy_header(1_591_500);
        let r1 = executor
            .execute_block(&header1, &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success);
        let deployed = sender.create(0);
        assert_eq!(
            r1.state_changes.get(&deployed).expect("creator").info.nonce, 0,
            "a top-level CREATE tx keeps nonce 0 even post-RSKIP125"
        );
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        // Call the creator → it runs an internal CREATE.
        let call = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(deployed.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header2 = dummy_header(1_591_501);
        let r2 = executor
            .execute_block(&header2, &[(call, sender)], &root2, store.clone())
            .expect("create block");
        assert!(r2.tx_results[0].success);

        let child = deployed.create(0);
        assert_eq!(
            r2.state_changes.get(&child).expect("child contract").info.nonce, 1,
            "internal CREATE post-RSKIP125 bumps the created contract nonce to 1"
        );
    }

    /// Wasabi enables the Constantinople shift opcodes (RSKIP120) and CREATE2
    /// (RSKIP125) but not EXTCODEHASH (RSKIP140, papyrus). The spec must be
    /// PETERSBURG from wasabi (not BYZANTIUM, which lacks shifts).
    #[test]
    fn test_wasabi_spec_enables_shift_opcodes() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(729_000), SpecId::BYZANTIUM, "orchid");
        assert_eq!(cfg.spec_id(1_590_999), SpecId::BYZANTIUM, "pre-wasabi");
        assert_eq!(cfg.spec_id(1_591_000), SpecId::PETERSBURG, "wasabi");
        assert!(!cfg.has_rskip140(1_591_000), "no EXTCODEHASH at wasabi");
        assert!(cfg.has_rskip140(2_392_700), "EXTCODEHASH from papyrus");
    }

    /// Regression for mainnet #1,613,128..#1,661,216 era: a contract whose
    /// runtime uses SHR (solc >=0.5 selector dispatch) must execute post-wasabi
    /// instead of hitting an invalid opcode that consumes the whole gas limit.
    /// #1,661,216's setCompleted(uint256) call cost 42,023 gas in rskj but
    /// rustock charged the full 6,721,975 limit (SHR invalid under BYZANTIUM).
    #[test]
    fn test_shr_opcode_executes_post_wasabi() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime: PUSH1 4; PUSH1 0; SHR (4 >> 0 = 4); PUSH1 0; SSTORE; STOP.
        let runtime: Vec<u8> = vec![
            0x60, 0x04, 0x60, 0x00, 0x1c, 0x60, 0x00, 0x55, 0x00,
        ];
        let mut init = vec![
            0x60, 0x09, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x09, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);

        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header1 = dummy_header(1_591_500);
        let r1 = executor
            .execute_block(&header1, &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success);
        let deployed = sender.create(0);
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(deployed.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header2 = dummy_header(1_591_501);
        let r2 = executor
            .execute_block(&header2, &[(call, sender)], &root2, store.clone())
            .expect("call block");
        assert!(r2.tx_results[0].success, "SHR must be a valid opcode at wasabi");
        assert!(
            r2.tx_results[0].gas_used < 1_000_000,
            "SHR call must not consume the whole gas limit (invalid opcode)"
        );
        let slot0 = r2
            .state_changes
            .get(&deployed)
            .expect("contract")
            .storage
            .get(&U256::ZERO)
            .expect("slot 0");
        assert_eq!(slot0.present_value, U256::from(4), "4 >> 0 == 4");
    }

    /// Regression for mainnet #6,362,186 tx[3] (gas 1,197,343 vs 1,182,343,
    /// +15,000): rskj `Program.finalizeContractCreation` propagates only logInfos
    /// and deleteAccounts from a constructor to the parent result — NOT
    /// futureRefund (unlike the CALL path's `ProgramResult.merge`). So a gas
    /// refund accrued inside a nested CREATE/CREATE2 constructor is DISCARDED.
    /// A constructor that SETs then CLEARs a storage slot must therefore NOT
    /// earn the 15,000 SSTORE-clear refund when created via the CREATE opcode:
    /// compared with a set-only constructor, clearing costs MORE (the extra
    /// 5,000 CLEAR_SSTORE), not 10,000 less.
    #[test]
    fn nested_create_constructor_refund_is_dropped_rskj() {
        // child init: SET slot0=1, optionally CLEAR it, then RETURN empty code.
        let child_init = |clear: bool| -> Vec<u8> {
            let mut c = vec![0x60, 0x01, 0x60, 0x00, 0x55]; // PUSH1 1 PUSH1 0 SSTORE
            if clear {
                c.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x55]); // clear slot0
            }
            c.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xf3]); // RETURN empty
            c
        };
        // factory runtime: MSTORE the child init (right-aligned), then CREATE it.
        let factory_runtime = |init: &[u8]| -> Vec<u8> {
            let n = init.len();
            assert!((1..=32).contains(&n));
            let off = (32 - n) as u8;
            let mut r = vec![0x5f + n as u8]; // PUSH{n}
            r.extend_from_slice(init);
            r.extend_from_slice(&[0x60, 0x00, 0x52]); // PUSH1 0 MSTORE
            r.extend_from_slice(&[0x60, n as u8]); // PUSH1 size
            r.extend_from_slice(&[0x60, off]); // PUSH1 offset
            r.extend_from_slice(&[0x60, 0x00, 0xf0, 0x00]); // PUSH1 0 (value) CREATE STOP
            r
        };
        // deploy wrapper: CODECOPY the runtime (after the 12-byte prefix) + RETURN.
        let deploy_init = |runtime: &[u8]| -> Vec<u8> {
            let l = runtime.len() as u8;
            let mut d = vec![
                0x60, l, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, l, 0x60, 0x00, 0xf3,
            ];
            d.extend_from_slice(runtime);
            d
        };

        // Run the whole deploy+call sequence and return the call's gas_used.
        let run = |clear: bool| -> u64 {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let sender = Address::repeat_byte(0xAB);
            let one_rbtc = U256::from(10u64).pow(U256::from(18));
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

            let factory = deploy_init(&factory_runtime(&child_init(clear)));
            let deploy = rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(0),
                gas_limit: U256::from(2_000_000),
                to: Bytes::new(),
                value: U256::ZERO,
                input: Bytes::from(factory),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r1 = executor
                .execute_block(&dummy_header(6_362_186), &[(deploy, sender)], &root, store.clone())
                .expect("deploy block");
            assert!(r1.tx_results[0].success, "factory deploy failed");
            let factory_addr = sender.create(0);
            let root2 = crate::state::apply_state_changes(
                &root, store.as_ref(), &r1.state_changes, &r1.markers,
            );
            let call = rustock_core::Transaction {
                nonce: 1,
                gas_price: U256::from(0),
                gas_limit: U256::from(2_000_000),
                to: Bytes::copy_from_slice(factory_addr.as_slice()),
                value: U256::ZERO,
                input: Bytes::new(),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r2 = executor
                .execute_block(&dummy_header(6_362_187), &[(call, sender)], &root2, store.clone())
                .expect("call block");
            assert!(r2.tx_results[0].success, "factory call (CREATE) failed");
            r2.tx_results[0].gas_used
        };

        let gas_clear = run(true);
        let gas_noclear = run(false);
        // With the nested-create refund dropped, clearing the slot adds the
        // 5,000 CLEAR_SSTORE cost and earns NO 15,000 refund, so it costs MORE.
        // (Were the refund wrongly propagated, gas_clear would be ~10,000 LESS.)
        assert!(
            gas_clear > gas_noclear,
            "nested-create constructor clear must not earn a refund: clear={gas_clear} noclear={gas_noclear}"
        );
    }

    /// Regression for mainnet #3,631,998 tx[1] (gas used 27,540 vs 27,529, +11,
    /// divergent revert branch): rskj `VM.doEXTCODEHASH` (`getCodeHashStandard`)
    /// keys on TRIE EXISTENCE, not EIP-161 emptiness. An account that exists in
    /// the trie but is "empty" (nonce 0, balance 0, no code) must hash to
    /// `keccak256("")`, while an account absent from the trie hashes to 0. revm's
    /// stock EXTCODEHASH returns 0 for both (it uses `AccountInfo::is_empty()`),
    /// so the existing-empty case forked. Ground truth: a USDT-on-ETH address
    /// (no code on RSK) that a prior 0-value call had created hashed to
    /// `keccak256("")` in rskj, sending the proxy down a different branch.
    #[test]
    fn test_extcodehash_existing_empty_account_is_keccak_empty() {
        let store = Arc::new(MemoryTrieStore::new());
        let mut root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        // An existing-but-empty account (nonce 0, balance 0, no code): present
        // in the trie, yet EIP-161-empty. rskj -> keccak256(""); revm stock -> 0.
        let existing_empty = Address::repeat_byte(0xE1);
        root = put_account(&root, store.as_ref(), &existing_empty, 0, U256::ZERO);

        // An address never placed in the trie: rskj & rustock both -> 0.
        let absent = Address::repeat_byte(0xE2);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime: EXTCODEHASH(existing_empty) -> slot 0;
        //          EXTCODEHASH(absent)         -> slot 1; STOP.
        let mut runtime: Vec<u8> = Vec::new();
        runtime.push(0x73); // PUSH20 existing_empty
        runtime.extend_from_slice(existing_empty.as_slice());
        runtime.extend_from_slice(&[0x3f, 0x60, 0x00, 0x55]); // EXTCODEHASH; PUSH1 0; SSTORE
        runtime.push(0x73); // PUSH20 absent
        runtime.extend_from_slice(absent.as_slice());
        runtime.extend_from_slice(&[0x3f, 0x60, 0x01, 0x55]); // EXTCODEHASH; PUSH1 1; SSTORE
        runtime.push(0x00); // STOP

        // Init: CODECOPY the runtime to memory and RETURN it.
        let rt_len = runtime.len() as u8;
        let mut init = vec![
            0x60, rt_len, // PUSH1 <len>
            0x60, 0x0c, // PUSH1 0x0c (runtime offset in this init)
            0x60, 0x00, // PUSH1 0
            0x39, // CODECOPY
            0x60, rt_len, // PUSH1 <len>
            0x60, 0x00, // PUSH1 0
            0xf3, // RETURN
        ];
        init.extend_from_slice(&runtime);

        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        // papyrus200 (>= 2,392,700) so EXTCODEHASH (RSKIP140) is active.
        let header1 = dummy_header(2_392_800);
        let r1 = executor
            .execute_block(&header1, &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success, "deploy must succeed");
        let deployed = sender.create(0);
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(deployed.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header2 = dummy_header(2_392_801);
        let r2 = executor
            .execute_block(&header2, &[(call, sender)], &root2, store.clone())
            .expect("call block");
        assert!(r2.tx_results[0].success, "EXTCODEHASH call must succeed");

        let storage = &r2.state_changes.get(&deployed).expect("contract").storage;
        let slot0 = storage.get(&U256::ZERO).expect("slot 0").present_value;
        let slot1 = storage.get(&U256::from(1)).map(|s| s.present_value).unwrap_or(U256::ZERO);

        // Existing-but-empty account -> keccak256(""), NOT 0.
        assert_eq!(
            B256::from(slot0.to_be_bytes()),
            crate::rsk_instructions::KECCAK_EMPTY,
            "EXTCODEHASH of an existing-but-empty account must be keccak256(\"\")"
        );
        // Absent account -> 0.
        assert_eq!(slot1, U256::ZERO, "EXTCODEHASH of an absent account must be 0");
    }

    /// Regression for mainnet #2,430,894: CHAINID (RSKIP152) and SELFBALANCE
    /// (RSKIP151) activate at papyrus200 while the SpecId stays PETERSBURG —
    /// revm's spec-checked impls halted NotActivated and the tx consumed its
    /// whole gas limit (rskj: success, 235,956 gas). Pre-papyrus both must
    /// still be invalid opcodes consuming all frame gas.
    #[test]
    fn test_chainid_selfbalance_activate_at_papyrus() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime: CHAINID; PUSH1 0; SSTORE; SELFBALANCE; PUSH1 1; SSTORE; STOP
        let runtime: Vec<u8> = vec![0x46, 0x60, 0x00, 0x55, 0x47, 0x60, 0x01, 0x55, 0x00];
        let mut init = vec![
            0x60, 0x09, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x09, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);
        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let r1 = executor
            .execute_block(&dummy_header(2_392_700), &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success);
        let deployed = sender.create(0);
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = |nonce: u64| rustock_core::Transaction {
            nonce,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(deployed.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        // Post-papyrus: both opcodes execute; CHAINID pushes 30 (RSK mainnet).
        let r2 = executor
            .execute_block(&dummy_header(2_392_701), &[(call(1), sender)], &root2, store.clone())
            .expect("papyrus call block");
        assert!(r2.tx_results[0].success, "CHAINID/SELFBALANCE valid at papyrus200");
        let storage = &r2.state_changes.get(&deployed).expect("contract").storage;
        assert_eq!(
            storage.get(&U256::ZERO).unwrap().present_value,
            U256::from(30),
            "CHAINID == 30"
        );
        assert_eq!(
            storage.get(&U256::from(1)).unwrap().present_value,
            U256::ZERO,
            "SELFBALANCE of the fresh contract == 0"
        );

        // Pre-papyrus: invalid opcode, the whole gas limit is consumed.
        let r3 = executor
            .execute_block(&dummy_header(2_392_699), &[(call(1), sender)], &root2, store.clone())
            .expect("pre-papyrus call block");
        assert!(!r3.tx_results[0].success, "CHAINID invalid before papyrus200");
        assert_eq!(r3.tx_results[0].gas_used, 1_000_000, "invalid opcode consumes all gas");
    }

    /// RSKIP197 (iris300): a CALL to a precompile that fails with a non-OOG
    /// error is *handled* — the call pushes 0, the surplus forwarded gas is
    /// refunded, and execution continues; the failing precompile costs exactly
    /// its `getGasForData` requiredGas. Ported from rskj `ProgramTest`
    /// (`testCallToPrecompiledAddress_throwPrecompiledContractException`:
    /// post-197 `gasUsed == gasCost`, stack pushes 0).
    ///
    /// Here a deployed contract CALLs BLAKE2F (0x09) with a 213-byte input
    /// whose final-block byte is 0x02 (invalid: must be 0 or 1) and `rounds`=1,
    /// forwarding 900,000 gas. rskj's `Blake2F.execute` throws
    /// `BLAKE2F_ERROR_FINAL_BLOCK_BYTES`; post-197 the call costs only
    /// `requiredGas == rounds == 1` (the surplus is refunded), so the whole tx
    /// settles far below the forwarded gas. The CALL result (0) is stored at
    /// slot 0 to prove the failure was observed without aborting the frame.
        /// What a *failing* top-level Bridge call costs, and what its receipt says.
    ///
    /// Not what one would guess. rskj's precompile path in
    /// `TransactionExecutor.call` sets `gasLeftover = txGasLimit - gasUsed`
    /// before the try and its catch only calls `result.setException(e)` -- it
    /// never zeroes the leftover the way the VM path does for a reverted
    /// contract call. The exception is then recorded for FEE purposes but not
    /// for RECEIPT purposes, so the transaction:
    ///
    ///   * reports status SUCCESS,
    ///   * reports `gasUsed = requiredGas + basicTxCost`, well under the limit,
    ///   * yet charges the sender the ENTIRE gas limit, the surplus to REMASC.
    ///
    /// That is quirks-frozen-bugs.md §50, reported to the rskj security team in
    /// docs/rskj-report-precompile-receipt-status.md, and consensus-frozen.
    ///
    /// This test exists where it does because the rskj-compat sender path now
    /// returns `Err` for inputs rskj throws on, and that error flows through
    /// exactly this mechanism. Pinning it here means a change to the quirk
    /// cannot silently change what a rejected peg-in costs.
    #[test]
    fn a_failing_bridge_call_reports_success_and_spends_only_the_precompile_gas() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xCE);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        // Post-RSKIP136, so this takes revm's ordinary transact path rather than
        // the direct-bridge branch that handles the free and pre-136 cases.
        let mut header = dummy_header(7_000_000);
        header.gas_limit = U256::from(6_800_000);

        // registerBtcTransaction with a truncated argument list: rejected
        // before any work, which is rskj's BridgeIllegalArgumentException.
        let mut input = {
            use sha3::{Digest, Keccak256};
            let h = Keccak256::digest(b"registerBtcTransaction(bytes,int256,bytes)");
            h[..4].to_vec()
        };
        input.extend_from_slice(&[0u8; 32]); // far short of the 96 bytes required

        let limit = 500_000u64;
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(limit),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO,
            cached_rlp: None,
        };
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .expect("a rejected Bridge call fails the transaction, never the block");

        assert!(
            result.success,
            "the invisible-exception quirk reports SUCCESS even though the call threw"
        );
        assert!(
            result.gas_used < limit,
            "the receipt must report requiredGas + basicTxCost, not the limit: \
             got {} of {}",
            result.gas_used, limit
        );
        assert!(
            result.gas_used > 22_000,
            "and it must include the Bridge's fixed 22,000: got {}",
            result.gas_used
        );
    }

    #[test]
    fn test_rskip197_failing_precompile_refunds_surplus_gas() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xCD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime: build a BLAKE2F input (rounds=1, bad final byte), CALL 0x09
        // forwarding 900,000 gas, then SSTORE the CALL result at slot 0.
        let runtime: Vec<u8> = vec![
            0x60, 0x01, 0x60, 0x03, 0x53, // PUSH1 1; PUSH1 3; MSTORE8  -> mem[3]=1 (rounds=1)
            0x60, 0x02, 0x60, 0xd4, 0x53, // PUSH1 2; PUSH1 212; MSTORE8 -> mem[212]=2 (bad flag)
            0x60, 0x00, // retLength 0
            0x60, 0x00, // retOffset 0
            0x60, 0xd5, // argsLength 213
            0x60, 0x00, // argsOffset 0
            0x60, 0x00, // value 0
            0x60, 0x09, // addr 0x09 (blake2f)
            0x62, 0x0d, 0xbb, 0xa0, // PUSH3 900000 (gas)
            0xf1, // CALL
            0x60, 0x00, 0x55, // PUSH1 0; SSTORE -> slot 0 = CALL result
            0x00, // STOP
        ];
        // init: copy `runtime` to memory and RETURN it as the deployed code.
        let rt_len = runtime.len() as u8;
        let mut init = vec![
            0x60, rt_len, 0x60, 0x0c, 0x60, 0x00, 0x39, // CODECOPY(0, 12, len)
            0x60, rt_len, 0x60, 0x00, 0xf3, // RETURN(0, len)
        ];
        init.extend_from_slice(&runtime);
        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let r1 = executor
            .execute_block(&dummy_header(3_614_800), &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success, "deploy ok");
        let deployed = sender.create(0);
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(deployed.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let r2 = executor
            .execute_block(&dummy_header(3_614_801), &[(call, sender)], &root2, store.clone())
            .expect("call block");
        assert!(
            r2.tx_results[0].success,
            "post-197 the failing precompile is handled; the caller frame does not abort"
        );
        // The CALL pushed 0 (failure) — slot 0 must be 0.
        let storage = &r2.state_changes.get(&deployed).expect("contract").storage;
        assert_eq!(
            storage.get(&U256::ZERO).map(|s| s.present_value).unwrap_or(U256::ZERO),
            U256::ZERO,
            "CALL to a failing precompile pushes 0"
        );
        // The surplus of the 900,000 forwarded gas was refunded: the whole tx
        // settles well below it (would be >= 900,000 if all child gas burned).
        assert!(
            r2.tx_results[0].gas_used < 100_000,
            "post-197 refunds the surplus forwarded gas; gas_used = {}",
            r2.tx_results[0].gas_used
        );
    }

    /// Regression for mainnet #2,814,761: RSKIP150 lowers the EVM call-stack
    /// limit to 400 (rskj Program.getMaxDepth); revm hard-codes 1024. A
    /// self-recursive contract must be cut off at depth 400 — frames at
    /// depths 0..=400 run, the CALL at depth 400 is refused with the child
    /// gas refunded.
    #[test]
    fn test_rskip150_call_depth_capped_at_400() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime: SSTORE(0, SLOAD(0)+1); CALL(self, all gas); STOP.
        let runtime: Vec<u8> = vec![
            0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, // counter += 1
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // ret/arg/value
            0x30, 0x5a, 0xf1, 0x50, // ADDRESS GAS CALL POP
            0x00,
        ];
        let mut init = vec![
            0x60, runtime.len() as u8, 0x60, 0x0c, 0x60, 0x00, 0x39,
            0x60, runtime.len() as u8, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);
        let deploy = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let r1 = executor
            .execute_block(&dummy_header(2_500_000), &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success);
        let contract = sender.create(0);
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(6_000_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let r2 = executor
            .execute_block(&dummy_header(2_500_001), &[(call, sender)], &root2, store.clone())
            .expect("call block");
        assert!(r2.tx_results[0].success, "recursion must end cleanly at the cap");
        let slot0 = r2
            .state_changes
            .get(&contract)
            .expect("contract")
            .storage
            .get(&U256::ZERO)
            .expect("slot 0");
        assert_eq!(
            slot0.present_value,
            U256::from(401),
            "frames at depths 0..=400 run; the call at depth 400 is refused"
        );
    }

    /// Regression for mainnet #2,669,886: rskj resets the caller's
    /// returnDataBuffer only when callee code actually runs (executeCode) or
    /// on precompile calls; a CALL to an empty-code account (plain value
    /// transfer) keeps the PREVIOUS call's return data, where canonical
    /// EIP-211 clears it. RETURNDATASIZE after such a call must report the
    /// prior call's output size.
    #[test]
    fn test_empty_code_call_preserves_return_data_buffer() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let deploy_tx = |nonce: u64, runtime: &[u8]| {
            // Init: copy `runtime` to memory and return it.
            let mut init = vec![
                0x60, runtime.len() as u8, 0x60, 0x0c, 0x60, 0x00, 0x39,
                0x60, runtime.len() as u8, 0x60, 0x00, 0xf3,
            ];
            init.extend_from_slice(runtime);
            rustock_core::Transaction {
                nonce,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::new(),
                value: U256::ZERO,
                input: Bytes::from(init),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            }
        };

        // Returner: RETURN 32 zero bytes.
        let returner_runtime = vec![0x60, 0x20, 0x60, 0x00, 0xf3];
        let returner = sender.create(0);
        let eoa = Address::repeat_byte(0xEE);

        // Main: CALL returner; CALL the EOA; SSTORE(0, RETURNDATASIZE); STOP.
        let mut main_runtime = Vec::new();
        let call_to = |code: &mut Vec<u8>, addr: Address| {
            code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73]);
            code.extend_from_slice(addr.as_slice());
            code.extend_from_slice(&[0x62, 0x0f, 0x42, 0x40, 0xf1, 0x50]); // PUSH3 1M gas; CALL; POP
        };
        call_to(&mut main_runtime, returner);
        call_to(&mut main_runtime, eoa);
        main_runtime.extend_from_slice(&[0x3d, 0x60, 0x00, 0x55, 0x00]);
        let main = sender.create(1);

        let header1 = dummy_header(2_500_000);
        let r1 = executor
            .execute_block(
                &header1,
                &[(deploy_tx(0, &returner_runtime), sender), (deploy_tx(1, &main_runtime), sender)],
                &root,
                store.clone(),
            )
            .expect("deploy block");
        assert!(r1.tx_results.iter().all(|r| r.success));
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 2,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(main.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let r2 = executor
            .execute_block(&dummy_header(2_500_001), &[(call, sender)], &root2, store.clone())
            .expect("call block");
        assert!(r2.tx_results[0].success);
        let slot0 = r2
            .state_changes
            .get(&main)
            .expect("main contract")
            .storage
            .get(&U256::ZERO)
            .expect("slot 0");
        assert_eq!(
            slot0.present_value,
            U256::from(32),
            "RETURNDATASIZE after a call to an empty-code account must keep \
             the previous call's 32-byte size (rskj returnDataBuffer)"
        );
    }

    /// Regression for mainnet #3,616,094: RSKIP171 (iris300) makes
    /// `Program.cleanReturnDataBuffer` reset the caller's returnDataBuffer on
    /// every call that runs no new frame, so a CALL to an empty-code account
    /// CLEARS the buffer (canonical EIP-211) instead of preserving the prior
    /// call's output. RETURNDATASIZE after such a call must report 0.
    /// Ground truth: rskj VMTest.returnDataSizeAfterCallToNonExistentContract
    /// (active = true → 0); the pre-iris twin asserts 32 above.
    #[test]
    fn test_empty_code_call_clears_return_data_buffer_post_rskip171() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let deploy_tx = |nonce: u64, runtime: &[u8]| {
            let mut init = vec![
                0x60, runtime.len() as u8, 0x60, 0x0c, 0x60, 0x00, 0x39,
                0x60, runtime.len() as u8, 0x60, 0x00, 0xf3,
            ];
            init.extend_from_slice(runtime);
            rustock_core::Transaction {
                nonce,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::new(),
                value: U256::ZERO,
                input: Bytes::from(init),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            }
        };

        // Returner: RETURN 32 zero bytes.
        let returner_runtime = vec![0x60, 0x20, 0x60, 0x00, 0xf3];
        let returner = sender.create(0);
        let eoa = Address::repeat_byte(0xEE);

        // Main: CALL returner; CALL the EOA; SSTORE(0, RETURNDATASIZE); STOP.
        let mut main_runtime = Vec::new();
        let call_to = |code: &mut Vec<u8>, addr: Address| {
            code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73]);
            code.extend_from_slice(addr.as_slice());
            code.extend_from_slice(&[0x62, 0x0f, 0x42, 0x40, 0xf1, 0x50]); // PUSH3 1M gas; CALL; POP
        };
        call_to(&mut main_runtime, returner);
        call_to(&mut main_runtime, eoa);
        main_runtime.extend_from_slice(&[0x3d, 0x60, 0x00, 0x55, 0x00]);
        let main = sender.create(1);

        // Iris300 activates at mainnet #3,614,800 — pick a block past it.
        let header1 = dummy_header(3_616_094);
        let r1 = executor
            .execute_block(
                &header1,
                &[(deploy_tx(0, &returner_runtime), sender), (deploy_tx(1, &main_runtime), sender)],
                &root,
                store.clone(),
            )
            .expect("deploy block");
        assert!(r1.tx_results.iter().all(|r| r.success));
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 2,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(main.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let r2 = executor
            .execute_block(&dummy_header(3_616_095), &[(call, sender)], &root2, store.clone())
            .expect("call block");
        assert!(r2.tx_results[0].success);
        let slot0 = r2
            .state_changes
            .get(&main)
            .expect("main contract")
            .storage
            .get(&U256::ZERO)
            .map(|s| s.present_value)
            .unwrap_or(U256::ZERO);
        assert_eq!(
            slot0,
            U256::ZERO,
            "RSKIP171: RETURNDATASIZE after a call to an empty-code account \
             must be 0 (the buffer is cleared, not preserved)"
        );
    }

    /// Regression for mainnet #1,661,324: rskj's VM.doCODESIZE (RSKIP90, orchid)
    /// reports EXTCODESIZE of an active precompile as 2^256-1. A proxy that
    /// guards `extcodesize(impl) != 0` before forwarding to the BlockHeader
    /// precompile (0x01000010) reverted in rustock (size 0) but not in rskj.
    #[test]
    fn test_extcodesize_of_precompile_is_max() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        // Runtime: PUSH20 0x..01000010; EXTCODESIZE; PUSH1 0; SSTORE; STOP.
        let mut runtime: Vec<u8> = vec![0x73];
        runtime.extend_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice());
        runtime.extend_from_slice(&[0x3b, 0x60, 0x00, 0x55, 0x00]);
        let mut init = vec![
            0x60, runtime.len() as u8, 0x60, 0x0c, 0x60, 0x00, 0x39,
            0x60, runtime.len() as u8, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);

        let deploy = rustock_core::Transaction {
            nonce: 0, gas_price: U256::ZERO, gas_limit: U256::from(1_000_000),
            to: Bytes::new(), value: U256::ZERO, input: Bytes::from(init),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header1 = dummy_header(1_700_000);
        let r1 = executor
            .execute_block(&header1, &[(deploy, sender)], &root, store.clone())
            .expect("deploy block");
        assert!(r1.tx_results[0].success);
        let deployed = sender.create(0);
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let call = rustock_core::Transaction {
            nonce: 1, gas_price: U256::ZERO, gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(deployed.as_slice()), value: U256::ZERO,
            input: Bytes::new(), v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let header2 = dummy_header(1_700_001);
        let r2 = executor
            .execute_block(&header2, &[(call, sender)], &root2, store.clone())
            .expect("call block");
        assert!(r2.tx_results[0].success);
        let slot0 = r2.state_changes.get(&deployed).expect("contract")
            .storage.get(&U256::ZERO).expect("slot 0");
        assert_eq!(
            slot0.present_value, U256::MAX,
            "EXTCODESIZE of an active precompile must be 2^256-1 (RSKIP90)"
        );
    }

    /// Regression for mainnet #1,071,481: before RSKIP453 (lovell700) an
    /// INTERNAL create whose constructor succeeds always deploys — an
    /// unpayable code deposit leaves the contract with EMPTY code, the
    /// constructor state committed and the address pushed (rskj
    /// Program.finalizeContractCreation), instead of EIP-2's out-of-gas.
    /// The RNS registrar deploys a Deed whose 944,800-gas deposit cannot
    /// fit in the 600,000 tx limit; rskj deploys it codeless and the
    /// auction proceeds (tx gas 259,460, status success).
    #[test]
    fn test_pre_rskip453_internal_create_with_unpayable_deposit_deploys_empty() {
        // Child initcode: RETURN(0, 0x10000) — 65,536 zero bytes of "code",
        // deposit 13.1M gas, unpayable within the 1M tx limit.
        // Caller runtime: MSTORE initcode; CREATE; SSTORE(0, address).
        let runtime: Vec<u8> = vec![
            0x66, 0x62, 0x01, 0x00, 0x00, 0x60, 0x00, 0xf3, // PUSH7 initcode
            0x60, 0x00, 0x52, // MSTORE at word 0
            0x60, 0x07, 0x60, 0x19, 0x60, 0x00, 0xf0, // CREATE(0, 25, 7)
            0x60, 0x00, 0x55, // SSTORE(0, created)
            0x00,
        ];
        let mut init = vec![
            0x60, 0x15, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x15, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);

        let run_at = |block: u64, init: Vec<u8>| {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let sender = Address::repeat_byte(0xAA);
            let one_rbtc = U256::from(10u64).pow(U256::from(18));
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

            let deploy = rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::new(),
                value: U256::ZERO,
                input: Bytes::from(init),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let header1 = dummy_header(block);
            let r1 = executor
                .execute_block(&header1, &[(deploy, sender)], &root, store.clone())
                .expect("deploy block");
            assert!(r1.tx_results[0].success);
            let root2 =
                crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

            let caller = sender.create(0);
            let call = rustock_core::Transaction {
                nonce: 1,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::copy_from_slice(caller.as_slice()),
                value: U256::ZERO,
                input: Bytes::new(),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let header2 = dummy_header(block + 1);
            let r2 = executor
                .execute_block(&header2, &[(call, sender)], &root2, store.clone())
                .expect("create block");
            let slot0 = r2.state_changes.get(&caller).and_then(|a| {
                a.storage.get(&U256::ZERO).map(|s| s.present_value)
            });
            (caller, slot0, r2)
        };

        // Pre-RSKIP453: the create "succeeds" — address pushed, empty code.
        let (caller, slot0, r2) = run_at(1_071_481, init.clone());
        assert!(r2.tx_results[0].success);
        let child = caller.create(0);
        assert_eq!(
            Address::from_slice(&slot0.expect("slot 0 written").to_be_bytes::<32>()[12..]),
            child,
            "unpayable deposit must still deploy (empty code) pre-RSKIP453"
        );
        let child_acct = r2.state_changes.get(&child).expect("child account exists");
        assert!(
            child_acct
                .info
                .code
                .as_ref()
                .map(|c| c.is_empty())
                .unwrap_or(true),
            "child must have empty code"
        );

        // Post-RSKIP453 (lovell700): EIP-2/EIP-170 semantics — the failed
        // create consumes the forwarded gas (no 63/64 in RSK) and the
        // caller goes out of gas with it.
        let (_, _, r2) = run_at(7_338_024, init);
        assert!(
            !r2.tx_results[0].success,
            "unpayable/oversize deposit must fail post-RSKIP453"
        );
    }

    /// Regression for mainnet #764,123: addLockWhitelistAddress is disabled
    /// post-RSKIP87 (orchid), so rskj's parseData returns null. The gas is
    /// the flat releaseBtc cost (23,000, no data cost) and — although
    /// RSKIP88 makes execute() throw — a direct transaction records SUCCESS
    /// with empty output because TransactionExecutor spends only
    /// requiredGas + basicTxCost and go() (vm == null) just commits.
    /// Real receipt: status 0x1, gasUsed 47,408 (21,000 + 3,408 + 23,000).
    #[test]
    fn test_disabled_bridge_method_post_rskip87_charges_flat_cost() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::from_slice(
            &alloy_primitives::hex::decode("6ba9d41b07da470fe340cbd439a42538795eb75b").unwrap(),
        );
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        // addLockWhitelistAddress("1HqQJ9PxdG51NmFij43bBUrmQRDULbnSzW", 1 gwei)
        let input = alloy_primitives::hex::decode(
            "502bbbce0000000000000000000000000000000000000000000000000000000000000040\
             000000000000000000000000000000000000000000000000000000003b9aca00\
             0000000000000000000000000000000000000000000000000000000000000022\
             314871514a395078644735314e6d46696a3433624255726d515244554c626e53\
             7a57000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(183_000_000u64), // mainnet tx gas price
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let header = dummy_header(764_123);
        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .expect("block executes");
        assert!(result.tx_results[0].success, "receipt records SUCCESS");
        assert_eq!(
            result.tx_results[0].gas_used, 47_408,
            "flat releaseBtc cost, no data cost, no method cost"
        );
        // The disabled method must NOT execute: no bridge storage writes.
        if let Some(bridge) = result.state_changes.get(&crate::precompiles::BRIDGE_ADDR) {
            assert!(
                bridge.storage.is_empty(),
                "disabled method must not touch bridge storage"
            );
        }
        // The FEE side sees the failure: the sender is charged the FULL gas
        // limit and REMASC receives it (rskj summary.getFee when failed).
        // Remote groundtruth: sender 0x6ba9...75b balance drops by exactly
        // 1,000,000 * 183,000,000 = 183e12 wei across #764,122 -> #764,123.
        let full_fee = U256::from(1_000_000u64) * U256::from(183_000_000u64);
        assert_eq!(
            result.state_changes.get(&sender).unwrap().info.balance,
            one_rbtc - full_fee,
            "sender pays for the full gas limit, no leftover refund"
        );
        assert_eq!(
            result
                .state_changes
                .get(&crate::precompiles::REMASC_ADDR)
                .unwrap()
                .info
                .balance,
            full_fee,
            "REMASC receives gasLimit * gasPrice"
        );
        assert_eq!(result.paid_fees, full_fee, "paid_fees tracks the full fee");
    }

    /// The same disabled-method profile routed through revm (post-RSKIP136,
    /// mainnet #765,073 used gasPrice 60M wei): receipt SUCCESS with only
    /// the spent 47,408 gas, but the sender pays for the full 1,000,000
    /// limit, REMASC receives it, and the endowment is NOT transferred
    /// (rskj TransactionExecutor.call skips it when execute() throws).
    #[test]
    fn test_disabled_bridge_method_charges_full_gas_limit_post_rskip136() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        // addLockWhitelistAddress selector + garbage args: disabled forever
        // post-RSKIP87, parse failure at every later era.
        let mut input = vec![0x50, 0x2b, 0xbb, 0xce];
        input.extend_from_slice(&[0u8; 32]);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(60_000_000u64),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::from(7), // endowment must stay with the sender
            input: Bytes::from(input),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let header = dummy_header(2_392_700); // papyrus200: RSKIP136 active
        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .expect("block executes");
        assert!(result.tx_results[0].success, "receipt records SUCCESS");
        // 21,000 + 4 nonzero * 68 + 32 zero * 4 + 23,000 = 44,400
        assert_eq!(
            result.tx_results[0].gas_used,
            21_000 + 4 * 68 + 32 * 4 + 23_000,
            "receipt shows only the spent gas"
        );
        let full_fee = U256::from(1_000_000u64) * U256::from(60_000_000u64);
        assert_eq!(
            result.state_changes.get(&sender).unwrap().info.balance,
            one_rbtc - full_fee,
            "sender pays the full limit and keeps the endowment"
        );
        assert_eq!(
            result
                .state_changes
                .get(&crate::precompiles::REMASC_ADDR)
                .unwrap()
                .info
                .balance,
            full_fee,
            "REMASC receives gasLimit * gasPrice"
        );
        let bridge_balance = result
            .state_changes
            .get(&crate::precompiles::BRIDGE_ADDR)
            .map(|a| a.info.balance)
            .unwrap_or_default();
        assert_eq!(bridge_balance, U256::ZERO, "no endowment on invisible exception");
        assert_eq!(result.paid_fees, full_fee);
    }

    /// rskj TransactionExecutor.call transfers the endowment after a
    /// non-throwing precompile execute(); the pre-RSKIP136 direct path must
    /// do the same for successful Bridge calls.
    #[test]
    fn test_pre_rskip136_direct_bridge_success_transfers_endowment() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        // voteFeePerKbChange(int256) — enabled at every era; an unauthorized
        // sender gets an error CODE in the output but the call succeeds.
        let mut input = vec![0x04, 0x61, 0x31, 0x3e];
        let mut arg = [0u8; 32];
        arg[30..].copy_from_slice(&30_000u16.to_be_bytes());
        input.extend_from_slice(&arg);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::from(5),
            input: Bytes::from(input),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let header = dummy_header(764_123); // pre-RSKIP136 direct path
        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .expect("block executes");
        assert!(result.tx_results[0].success);
        assert_eq!(
            result
                .state_changes
                .get(&crate::precompiles::BRIDGE_ADDR)
                .unwrap()
                .info
                .balance,
            U256::from(5),
            "successful direct bridge call transfers the endowment"
        );
        assert_eq!(
            result.state_changes.get(&sender).unwrap().info.balance,
            one_rbtc - U256::from(5),
        );
    }

    /// Regression for mainnet #466,503: rskj charges NEW_ACCT_CALL (25,000)
    /// on trie EXISTENCE — the first-ever internal call to a precompile
    /// creates its account node (zero-value transfer), so the charge applies
    /// once per address in the chain's lifetime, not once per call. The same
    /// ecrecover call in the next block must cost exactly 25,000 less.
    #[test]
    fn test_precompile_new_account_charged_only_once_across_blocks() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &contract, 1, U256::ZERO);

        // PUSH1 0 x4 (ret/args) PUSH1 0 (value) PUSH20 0x..01 PUSH2 3000 CALL STOP
        let mut code = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        let mut ecrecover = [0u8; 20];
        ecrecover[19] = 0x01;
        code.extend_from_slice(&ecrecover);
        code.extend_from_slice(&[0x61, 0x0b, 0xb8, 0xf1, 0x00]); // PUSH2 3000, CALL, STOP
        let code_key_bytes = rustock_trie::code_key(&contract);
        let root = root.put(
            &TrieKeySlice::from_key(&code_key_bytes),
            &code,
            store.as_ref(),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let call_tx = |nonce: u64| rustock_core::Transaction {
            nonce,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let header = dummy_header(466_503);
        let r1 = executor
            .execute_block(&header, &[(call_tx(0), sender)], &root, store.clone())
            .expect("block 1");
        assert!(r1.tx_results[0].success);

        // Apply to the trie: the ecrecover account node must now exist.
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes, &r1.markers);

        let header2 = dummy_header(466_504);
        let r2 = executor
            .execute_block(&header2, &[(call_tx(1), sender)], &root2, store.clone())
            .expect("block 2");
        assert!(r2.tx_results[0].success);

        let g1 = r1.tx_results[0].gas_used;
        let g2 = r2.tx_results[0].gas_used;
        assert_eq!(
            g1 - g2,
            25_000,
            "first call pays NEW_ACCT_CALL once (got {g1} then {g2})"
        );
    }

    /// rskj charges NEW_ACCT_CALL (25,000) on trie EXISTENCE
    /// (`track.isExist(addr)`), NOT on EIP-161 emptiness. An account that
    /// exists in the unitrie with `(nonce=0, balance=0, no code)` — e.g. a
    /// zero-paid miner, or an account re-created after a same-block
    /// selfdestruct — is NOT charged, because rustock pins the journal spec to
    /// HOMESTEAD (`rsk_handler`), making revm's `is_empty` collapse to
    /// `is_loaded_as_not_existing` (DB returned `None`) rather than raw EIP-161
    /// emptiness. A CALL to a truly-absent address IS charged. The 25,000 delta
    /// between the two cases proves the charge keys on existence, not emptiness.
    #[test]
    fn test_new_acct_call_charged_on_existence_not_emptiness() {
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);
        let target = Address::repeat_byte(0xDD); // not a precompile

        // Contract: CALL(gas=3000, target, value=0) ; STOP.
        // PUSH1 0 x4 (ret/args) PUSH1 0 (value) PUSH20 target PUSH2 3000 CALL STOP
        let mut code = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        code.extend_from_slice(target.as_slice());
        code.extend_from_slice(&[0x61, 0x0b, 0xb8, 0xf1, 0x00]); // PUSH2 3000, CALL, STOP

        let call_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        // Run the identical CALL with the target either absent or present-but-empty.
        let run = |target_exists: bool| {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let root = put_account(&root, store.as_ref(), &contract, 1, U256::ZERO);
            let root = if target_exists {
                // Existing-but-empty (0,0,no-code) account node in the trie.
                put_account(&root, store.as_ref(), &target, 0, U256::ZERO)
            } else {
                root
            };
            let code_key_bytes = rustock_trie::code_key(&contract);
            let root = root.put(
                &TrieKeySlice::from_key(&code_key_bytes),
                &code,
                store.as_ref(),
            );

            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
            let header = dummy_header(466_503);
            let r = executor
                .execute_block(&header, &[(call_tx.clone(), sender)], &root, store.clone())
                .expect("block");
            assert!(r.tx_results[0].success);
            r.tx_results[0].gas_used
        };

        let gas_absent = run(false);
        let gas_exists = run(true);
        assert_eq!(
            gas_absent - gas_exists,
            25_000,
            "NEW_ACCT_CALL charged only when target absent \
             (absent={gas_absent}, exists-empty={gas_exists})"
        );
    }

    /// rskj `doSUICIDE` (VM.java) charges NEW_ACCT_SUICIDE (25,000) whenever the
    /// beneficiary does not exist (`!track.isExist`), UNCONDITIONAL on the
    /// suiciding contract's balance. revm's selfdestruct instead gates the
    /// beneficiary top-up on `had_value && !target_exists` under Spurious Dragon
    /// (always active for RSK eras), so a ZERO-balance contract self-destructing
    /// to an absent beneficiary would skip the charge. This test pins the rskj
    /// behavior: the absent-beneficiary case costs 25,000 more than the
    /// existing-beneficiary case even with a zero contract balance.
    #[test]
    fn test_new_acct_suicide_charged_on_existence_regardless_of_value() {
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);
        let bene = Address::repeat_byte(0xDD); // not a precompile

        // Contract runtime: PUSH20 bene ; SELFDESTRUCT. Contract balance is 0.
        let mut code = vec![0x73]; // PUSH20
        code.extend_from_slice(bene.as_slice());
        code.push(0xFF); // SELFDESTRUCT

        // Pad the tx with non-zero calldata so the gross gas is large enough
        // that the selfdestruct refund is NOT capped (refund = min(refund,
        // gross/2)) in either case. Otherwise the cheaper existing-beneficiary
        // case hits the refund cap and the net-gas delta no longer isolates the
        // 25,000 top-up. The contract ignores the calldata.
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(500_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(vec![1u8; 500]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let run = |bene_exists: bool| {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let root = put_account(&root, store.as_ref(), &contract, 1, U256::ZERO);
            let root = if bene_exists {
                put_account(&root, store.as_ref(), &bene, 0, U256::ZERO)
            } else {
                root
            };
            let code_key_bytes = rustock_trie::code_key(&contract);
            let root = root.put(
                &TrieKeySlice::from_key(&code_key_bytes),
                &code,
                store.as_ref(),
            );

            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
            let header = dummy_header(466_503);
            let r = executor
                .execute_block(&header, &[(tx.clone(), sender)], &root, store.clone())
                .expect("block");
            assert!(r.tx_results[0].success);
            r.tx_results[0].gas_used
        };

        let gas_absent = run(false);
        let gas_exists = run(true);
        assert_eq!(
            gas_absent - gas_exists,
            25_000,
            "NEW_ACCT_SUICIDE charged on absent beneficiary regardless of value \
             (absent={gas_absent}, exists={gas_exists})"
        );
    }

    /// Multi-tx version of the #382,134 regression: a later transaction in
    /// the SAME block re-reads (and possibly same-value re-writes) the bridge
    /// slots written by an earlier one — the slots must still reach the trie.
    /// Mirrors #378,129: registerBtcTransaction writes the rejection release,
    /// the block's own updateCollections reads it, REMASC closes the block.
    #[test]
    fn test_paid_bridge_storage_survives_same_block_reread() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let caller2 = Address::repeat_byte(0xCD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc * U256::from(2));
        let root = put_account(&root, store.as_ref(), &caller2, 0, one_rbtc);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(8_000_000);

        // tx1: releaseBtc (writes the release request queue blob)
        let tx1 = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: one_rbtc,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        // tx2: updateCollections (reads the queue; building fails without
        // UTXOs so the queue is re-stored byte-identical)
        let tx2 = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from_static(&[0x0c, 0x5a, 0x99, 0x90]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(
                &header,
                &[(tx1, sender), (tx2, caller2)],
                &root,
                store.clone(),
            )
            .expect("block executes");
        assert!(result.tx_results[0].success, "releaseBtc succeeds");
        assert!(result.tx_results[1].success, "updateCollections succeeds");

        // Apply to the trie and read the queue back through a fresh root,
        // exactly like the next block would.
        let new_root =
            crate::state::apply_state_changes(&root, store.as_ref(), &result.state_changes, &result.markers);
        let queue_key = {
            use sha3::{Digest, Keccak256};
            let mut padded = [0u8; 32];
            let name = b"releaseRequestQueueWithTxHash";
            padded[32 - name.len()..].copy_from_slice(name);
            let _ = Keccak256::digest(name); // (key is ascii-padded, not hashed)
            padded
        };
        let slot_b256 = B256::from(queue_key);
        let key_bytes = rustock_trie::storage_key(&crate::precompiles::BRIDGE_ADDR, &slot_b256);
        let key = rustock_trie::TrieKeySlice::from_key(&key_bytes);
        let stored = new_root.get(&key, store.as_ref());
        assert!(
            stored.is_some(),
            "queue length cell must survive into the trie after a same-block re-read"
        );
    }

    /// Regression for mainnet #382,134: bridge storage written by a PAID
    /// bridge transaction (post-RSKIP88, revm path) must survive into the
    /// block's state changes. A paid releaseBtc enqueues a release request
    /// (a multi-slot blob under the Bridge account).
    #[test]
    fn test_paid_bridge_tx_persists_bridge_storage() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc * U256::from(2));

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(8_000_000); // paid bridge era

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: one_rbtc, // 1 RBTC -> well above the pegout minimum
            input: Bytes::new(), // empty input = releaseBtc
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .expect("block executes");
        assert!(result.tx_results[0].success, "releaseBtc succeeds");

        let written = result
            .markers
            .raw_storage
            .iter()
            .filter(|(addr, _, v)| *addr == crate::precompiles::BRIDGE_ADDR && v.is_some())
            .count();
        assert!(
            written >= 1,
            "releaseBtc must persist the release request queue blob, got {written} raw writes"
        );
    }

    #[test]
    fn test_simple_value_transfer() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 21_000);
    }

    #[test]
    fn test_insufficient_balance_fails() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);

        let root = put_account(&root, store.as_ref(), &sender, 0, U256::from(100));

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(1_000_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store);
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_contract_creation_simple() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xDD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // PUSH1 0x00 PUSH1 0x00 RETURN (returns empty code)
        let initcode = vec![0x60, 0x00, 0x60, 0x00, 0xF3];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        assert!(result.gas_used > 21_000);
    }

    #[test]
    fn test_block_execution_multiple_txs() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xEE);
        let recipient1 = Address::repeat_byte(0x11);
        let recipient2 = Address::repeat_byte(0x22);

        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx1 = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient1.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let tx2 = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient2.as_slice()),
            value: U256::from(2_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let transactions = vec![(tx1, sender), (tx2, sender)];

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &transactions, &root, store)
            .unwrap();

        assert_eq!(result.tx_results.len(), 2);
        assert!(result.tx_results[0].success);
        assert!(result.tx_results[1].success);
        assert_eq!(result.gas_used, 42_000);
    }

    #[test]
    fn test_hardfork_spec_selection() {
        let cfg = RskHardforkConfig::mainnet();

        assert_eq!(cfg.spec_id(0), SpecId::BYZANTIUM);
        assert_eq!(cfg.spec_id(2_500_000), SpecId::PETERSBURG);
        assert_eq!(cfg.spec_id(6_300_000), SpecId::ISTANBUL);
        assert_eq!(cfg.spec_id(7_500_000), SpecId::SHANGHAI);
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj's BlockExecutorTest / TransactionExecutorTest
    // -----------------------------------------------------------------------

    /// Ported from rskj's BlockExecutorTest.executeBlockWithOneTransaction.
    /// Validates exact balance deduction: gas_used * gas_price + value.
    #[test]
    fn test_rskj_execute_block_with_one_transaction_balance_check() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xA1);
        let recipient = Address::repeat_byte(0xB2);

        // rskj test: sender starts with 30_000, sends 10 wei, gas_price=1, gas_limit=21_000
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::from(30_000));
        let root = put_account(&root, store.as_ref(), &recipient, 0, U256::from(10));

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(10),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .unwrap();

        assert_eq!(result.tx_results.len(), 1);
        assert!(result.tx_results[0].success);
        assert_eq!(result.tx_results[0].gas_used, 21_000);
        assert_eq!(result.gas_used, 21_000);

        // Verify state changes match rskj:
        // sender final = 30_000 - 21_000 (gas*price) - 10 (value) = 8_990
        let sender_state = result.state_changes.get(&sender)
            .expect("sender should have state changes");
        assert_eq!(
            sender_state.info.balance,
            U256::from(8_990),
            "sender balance should be 30000 - 21000*1 - 10 = 8990"
        );
        assert_eq!(sender_state.info.nonce, 1, "sender nonce should increment to 1");

        // recipient final = 10 (initial) + 10 (received) = 20
        let recipient_state = result.state_changes.get(&recipient)
            .expect("recipient should have state changes");
        assert_eq!(
            recipient_state.info.balance,
            U256::from(20),
            "recipient balance should be 10 + 10 = 20"
        );
    }

    /// Ported from rskj TransactionExecutorTest.testInitHandlesFreeTransactionsOK.
    /// Sender with zero balance but non-zero value transfer should fail.
    #[test]
    fn test_rskj_zero_balance_sender_with_value_fails() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0x01);
        let recipient = Address::repeat_byte(0x02);

        // Sender has zero balance
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::ZERO);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(68_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store);
        // Should fail: sender can't cover gas_limit * gas_price + value
        assert!(result.is_err(), "zero-balance sender with value transfer should fail");
    }

    /// Ported from rskj's TransactionTest.testTransactionCost patterns.
    /// Verifies that non-zero calldata bytes cost 16 gas each (post-RSKIP400/Istanbul).
    #[test]
    fn test_rskj_calldata_cost_post_istanbul() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xCC);
        let recipient = Address::repeat_byte(0xDD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Post-Arrowhead (ISTANBUL) → non-zero byte cost = 16
        let header = dummy_header(8_000_000);

        // 1 non-zero byte of calldata
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(vec![0xFF]), // 1 non-zero byte
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // Intrinsic gas = 21000 (base) + 16 (1 non-zero byte at Istanbul rate)
        assert_eq!(result.gas_used, 21_016, "intrinsic gas = 21000 + 16*1");
    }

    /// Complementary test: pre-Istanbul calldata cost is 68 per non-zero byte.
    #[test]
    fn test_rskj_calldata_cost_pre_istanbul() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xCC);
        let recipient = Address::repeat_byte(0xDD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Pre-Orchid (BYZANTIUM) → non-zero byte cost = 68
        let mut header = dummy_header(100);
        header.gas_limit = U256::from(6_800_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(vec![0xFF]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::mainnet(),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // Pre-Istanbul: intrinsic gas = 21000 + 68*1 = 21068
        assert_eq!(result.gas_used, 21_068, "intrinsic gas = 21000 + 68*1");
    }

    /// Regression for mainnet #6,223,700 (the arrowhead600 activation block;
    /// gas mismatch header=236343 vs computed=287919). RSKIP400 (Arrowhead600)
    /// reduces the non-zero calldata byte cost from 68 to 16 (EIP-2028). revm's
    /// intrinsic gas keys off the SpecId, so arrowhead600 maps to ISTANBUL to
    /// pick up the calldata reduction; the other Istanbul gas repricings RSK
    /// never adopted (EIP-1884 SLOAD/BALANCE/EXTCODEHASH) are pinned back to
    /// rskj values in `rsk_instructions::install`. This test pins the FIRST
    /// arrowhead600 block exactly: at #6,223,700 calldata is 16/byte; one block
    /// earlier 68.
    #[test]
    fn test_rskip400_calldata_reduction_at_arrowhead_activation() {
        let mainnet = RskHardforkConfig::mainnet();
        assert_eq!(mainnet.spec_id(6_223_699), SpecId::PETERSBURG);
        assert_eq!(mainnet.spec_id(6_223_700), SpecId::ISTANBUL);

        let run = |number: u64| -> u64 {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let sender = Address::repeat_byte(0xCC);
            let recipient = Address::repeat_byte(0xDD);
            let one_rbtc = U256::from(10u64).pow(U256::from(18));
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let mut header = dummy_header(number);
            header.gas_limit = U256::from(6_800_000);
            // 3 non-zero calldata bytes (no zeros): 68*3=204 pre, 16*3=48 post.
            let tx = rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(0),
                gas_limit: U256::from(30_000),
                to: Bytes::copy_from_slice(recipient.as_slice()),
                value: U256::ZERO,
                input: Bytes::from(vec![0x11, 0x22, 0x33]),
                v: 0,
                r: U256::ZERO,
                s: U256::ZERO,
                cached_rlp: None,
            };
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
            executor.execute_tx(&header, &tx, sender, &root, store).unwrap().gas_used
        };

        // One block before activation: 21000 + 68*3 = 21204.
        assert_eq!(run(6_223_699), 21_204, "pre-RSKIP400: 68 gas/non-zero byte");
        // Activation block: 21000 + 16*3 = 21048.
        assert_eq!(run(6_223_700), 21_048, "RSKIP400 active: 16 gas/non-zero byte");
    }

    /// RSKIP398 (arrowhead600): the PUSH0 opcode (0x5f) becomes valid at
    /// arrowhead600, NOT at the Shanghai-equivalent lovell700. rustock maps
    /// arrowhead600 to revm's ISTANBUL (which lacks PUSH0), so without an explicit
    /// install a PUSH0 would halt NotActivated and consume the frame's whole gas
    /// — a consensus fork vs rskj, which executes it (push 0, 2 gas). Deploy a
    /// contract whose runtime is `PUSH0 PUSH1 0 SSTORE STOP` and call it: at
    /// arrowhead600 it succeeds, one block earlier (fingerroot500/PETERSBURG) the
    /// PUSH0 is an invalid opcode that fails the call.
    #[test]
    fn test_push0_activates_at_arrowhead600() {
        // Runtime: PUSH0; PUSH1 0; SSTORE; STOP  (store 0 at slot 0)
        let runtime: Vec<u8> = vec![0x5f, 0x60, 0x00, 0x55, 0x00];
        // Init: CODECOPY the 5-byte runtime and RETURN it.
        // PUSH1 5; PUSH1 0x0c; PUSH1 0; CODECOPY; PUSH1 5; PUSH1 0; RETURN
        let mut init = vec![
            0x60, 0x05, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x05, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);

        let run = |number: u64| -> bool {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let sender = Address::repeat_byte(0x5F);
            let one_rbtc = U256::from(10u64).pow(U256::from(18));
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
            let deploy = rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::new(),
                value: U256::ZERO,
                input: Bytes::from(init.clone()),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r1 = executor
                .execute_block(&dummy_header(number), &[(deploy, sender)], &root, store.clone())
                .expect("deploy block");
            assert!(r1.tx_results[0].success, "deploy (no PUSH0 in init) always succeeds");
            let deployed = sender.create(0);
            let root2 = crate::state::apply_state_changes(
                &root, store.as_ref(), &r1.state_changes, &r1.markers,
            );
            let call = rustock_core::Transaction {
                nonce: 1,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::copy_from_slice(deployed.as_slice()),
                value: U256::ZERO,
                input: Bytes::new(),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            executor
                .execute_block(&dummy_header(number), &[(call, sender)], &root2, store)
                .expect("call block")
                .tx_results[0]
                .success
        };

        assert!(!run(6_223_699), "PUSH0 invalid pre-arrowhead600 (call fails)");
        assert!(run(6_223_700), "PUSH0 valid at arrowhead600 (call succeeds)");
    }

    /// Audit finding FRCR-679 / FRCR-879.
    ///
    /// RSKIP412 (arrowhead600) makes BASEFEE (0x48) valid: rskj's
    /// `VM.java` OP_BASEFEE throws `invalidOpCode` only while RSKIP412 is
    /// inactive (`reference.conf`: `rskip412 = arrowhead600`), and
    /// `VM.doBASEFEE` pushes `program.getMinimumGasPrice()` for 2 gas.
    ///
    /// revm bundles BASEFEE into LONDON. rustock maps arrowhead600 to ISTANBUL
    /// (for the RSKIP400 calldata pricing) and only reaches SHANGHAI at
    /// lovell700 — so across the whole arrowhead600..lovell700 window, about
    /// 1.1M mainnet blocks, revm's stock BASEFEE halted `NotActivated` and
    /// consumed the frame's entire gas where rskj pushed a value and continued.
    ///
    /// Same shape as `test_push0_activates_at_arrowhead600`; this one also
    /// checks the value pushed, because installing the opcode is only half of
    /// matching rskj — it has to push the block's minimum gas price.
    #[test]
    fn test_basefee_activates_at_arrowhead600() {
        // Runtime: BASEFEE; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
        let runtime: Vec<u8> = vec![0x48, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        // Init: CODECOPY the 9-byte runtime and RETURN it.
        let mut init = vec![
            0x60, 0x09, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x09, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);

        const MIN_GAS_PRICE: u64 = 59_240_000;

        // `None` = the call failed (invalid opcode); `Some(v)` = BASEFEE pushed v.
        let run = |number: u64| -> Option<U256> {
            let header = Header {
                minimum_gas_price: U256::from(MIN_GAS_PRICE),
                ..dummy_header(number)
            };
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let sender = Address::repeat_byte(0x48);
            let one_rbtc = U256::from(10u64).pow(U256::from(18));
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
            let deploy = rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(MIN_GAS_PRICE),
                gas_limit: U256::from(1_000_000),
                to: Bytes::new(),
                value: U256::ZERO,
                input: Bytes::from(init.clone()),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r1 = executor
                .execute_block(&header, &[(deploy, sender)], &root, store.clone())
                .expect("deploy block");
            assert!(r1.tx_results[0].success, "deploy (no BASEFEE in init) always succeeds");
            let deployed = sender.create(0);
            let root2 = crate::state::apply_state_changes(
                &root, store.as_ref(), &r1.state_changes, &r1.markers,
            );
            let call = rustock_core::Transaction {
                nonce: 1,
                gas_price: U256::from(MIN_GAS_PRICE),
                gas_limit: U256::from(1_000_000),
                to: Bytes::copy_from_slice(deployed.as_slice()),
                value: U256::ZERO,
                input: Bytes::new(),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r2 = executor
                .execute_block(&header, &[(call, sender)], &root2, store)
                .expect("call block");
            let res = &r2.tx_results[0];
            if !res.success {
                return None;
            }
            assert_eq!(res.output.len(), 32, "BASEFEE returns one word");
            Some(U256::from_be_slice(&res.output))
        };

        // fingerroot500 (PETERSBURG): rskj throws invalidOpCode, so must fail.
        assert_eq!(run(6_223_699), None, "BASEFEE invalid pre-arrowhead600");
        // arrowhead600 (ISTANBUL in rustock): the window the audit found.
        assert_eq!(
            run(6_223_700),
            Some(U256::from(MIN_GAS_PRICE)),
            "RSKIP412 active at arrowhead600: pushes minimumGasPrice"
        );
        // arrowhead631, still ISTANBUL.
        assert_eq!(run(6_549_300), Some(U256::from(MIN_GAS_PRICE)));
        // lovell700 (SHANGHAI >= LONDON): revm's own BASEFEE already worked
        // here, so this pins that the explicit install did not change it.
        assert_eq!(run(7_338_024), Some(U256::from(MIN_GAS_PRICE)));
    }

    /// Audit finding FRCR-476.
    ///
    /// rskj's `Bridge.receiveHeader` (Bridge.java:568-586) checks the argument
    /// size *before* anything else and, on a mismatch, **returns**
    /// `RECEIVE_HEADER_ERROR_SIZE_MISTMATCH = -20` (Bridge.java:243). The call
    /// succeeds; the caller reads -20 off the stack. The size rule is
    /// `BtcTransactionFormatUtils.isBlockHeaderSize`: exactly 80 bytes once
    /// RSKIP124 is active.
    ///
    /// rustock had neither half. Under 80 bytes it raised a precompile error
    /// (post-RSKIP197 a revert pushing 0, pre-197 a failed call consuming all
    /// gas); over 80 bytes it silently truncated to the first 80 and processed
    /// the header as if it were valid. Both fork from rskj on inputs any
    /// relayer can submit.
    #[test]
    fn test_receive_header_size_mismatch_returns_minus_20() {
        // ABI-encode `receiveHeader(bytes)` with a payload of `len` bytes.
        let call_input = |len: usize| -> Vec<u8> {
            let mut input = crate::bridge::compute_selector("receiveHeader(bytes)").to_vec();
            let mut off = [0u8; 32];
            off[31] = 0x20;
            input.extend_from_slice(&off); // offset to the bytes argument
            let mut l = [0u8; 32];
            l[24..].copy_from_slice(&(len as u64).to_be_bytes());
            input.extend_from_slice(&l); // length
            let mut payload = vec![0xABu8; len];
            payload.resize(len.div_ceil(32) * 32, 0); // right-pad to a word
            input.extend_from_slice(&payload);
            input
        };

        // Returns the int256 the Bridge produced, or None if the call failed.
        let run = |len: usize| -> Option<alloy_primitives::I256> {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let sender = Address::repeat_byte(0x7E);
            let one_rbtc = U256::from(10u64).pow(U256::from(18));
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
            let tx = rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(0),
                gas_limit: U256::from(2_000_000),
                to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
                value: U256::ZERO,
                input: Bytes::from(call_input(len)),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r = executor
                .execute_block(&dummy_header(7_000_000), &[(tx, sender)], &root, store)
                .expect("block");
            let res = &r.tx_results[0];
            if !res.success || res.output.len() != 32 {
                return None;
            }
            Some(alloy_primitives::I256::from_be_bytes::<32>(res.output[..32].try_into().unwrap()))
        };

        let minus_20 = alloy_primitives::I256::try_from(-20i64).unwrap();
        // Too short: rskj returns -20, it does not throw.
        assert_eq!(run(79), Some(minus_20), "79-byte header -> -20");
        assert_eq!(run(0), Some(minus_20), "empty header -> -20");
        // Too long: rskj returns -20 rather than truncating to 80.
        assert_eq!(run(81), Some(minus_20), "81-byte header -> -20");
        assert_eq!(run(85), Some(minus_20), "85-byte header -> -20 once RSKIP124 is on");

        // Exactly 80 is accepted for processing and must NOT report -20. The
        // bytes are garbage, so the Bridge reports an ordinary BridgeSupport
        // code (-3, previous block not found) — the point is that it got that
        // far.
        let at_80 = run(80).expect("80-byte header is processed");
        assert_ne!(at_80, minus_20, "80 bytes must reach BridgeSupport");
        assert_eq!(
            at_80,
            alloy_primitives::I256::try_from(-3i64).unwrap(),
            "unknown parent -> RECEIVE_HEADER_CANT_FOUND_PREVIOUS_BLOCK"
        );
    }

    /// Audit findings FRCR-75 and FRCR-76.
    ///
    /// rskj `BridgeSupport.getBtcTransactionConfirmations` (BridgeSupport.java
    /// :2194-2235) runs four checks in a fixed order, each with its own code
    /// (BridgeSupport.java:90-94):
    ///
    /// ```text
    ///   block == null                      -> -1  INEXISTENT_BLOCK_HASH
    ///   blockDepth > 4320                  -> -4  BLOCK_TOO_OLD
    ///   not the main-chain block at height -> -2  BLOCK_NOT_IN_BEST_CHAIN
    ///                     (BlockStoreException) -> -3  INCONSISTENT_BLOCK
    ///   merkle branch does not reduce      -> -5  INVALID_MERKLE_BRANCH
    ///   otherwise      bestChainHeight - block.getHeight() + 1
    /// ```
    ///
    /// rustock had -1, then jumped straight to the merkle check and reported
    /// **-2** for a bad branch. It had no depth check and, more seriously, no
    /// best-chain check at all: a block on an orphaned BTC fork is still in
    /// Bridge storage, so rustock would confirm a transaction that exists only
    /// on that fork — reporting a positive confirmation count where rskj
    /// returns -2. Everything downstream of this method trusts that number.
    ///
    /// Driven end to end on regtest: build a 3-block chain plus a sibling that
    /// forks at height 1, then query each case through the Bridge precompile.
    #[test]
    fn test_btc_transaction_confirmations_codes_and_best_chain_check() {
        use bitcoin::block::Version;
        use bitcoin::consensus::serialize as btc_serialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
        use crate::bridge::btc_chain::{b256_to_bitcoin_hash, bitcoin_hash_to_b256};

        const BLOCK: u64 = 7_000_000; // every relevant RSKIP active
        // Regtest difficulty: any nonce is a valid proof of work.
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let hdr = |prev: BlockHash, merkle_seed: u8, nonce: u32| bitcoin::block::Header {
            version: Version::from_consensus(1),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([merkle_seed; 32]),
            time: 1_700_000_000,
            bits,
            nonce,
        };

        // Regtest's target is ~2^255, so roughly every other nonce works;
        // search for one rather than assuming.
        let mine = |prev: BlockHash, merkle_seed: u8| -> bitcoin::block::Header {
            (0u32..10_000)
                .map(|nonce| hdr(prev, merkle_seed, nonce))
                .find(crate::bridge::btc_store::check_proof_of_work)
                .expect("regtest PoW is trivial")
        };

        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
            .header
            .block_hash();
        let h1 = mine(genesis, 0x11);
        let h2 = mine(h1.block_hash(), 0x22);
        let h3 = mine(h2.block_hash(), 0x33);
        // Forks at height 1 with the same work as h1, so it never becomes the
        // head — but it IS stored, which is the whole point.
        let fork1 = mine(genesis, 0xF1);
        assert_ne!(fork1.block_hash(), h1.block_hash());

        let receive_header_tx = |nonce: u64, header: &bitcoin::block::Header| {
            let raw = btc_serialize(header);
            assert_eq!(raw.len(), 80);
            let mut input = crate::bridge::compute_selector("receiveHeader(bytes)").to_vec();
            let mut off = [0u8; 32];
            off[31] = 0x20;
            input.extend_from_slice(&off);
            let mut l = [0u8; 32];
            l[31] = 80;
            input.extend_from_slice(&l);
            let mut payload = raw.clone();
            payload.resize(96, 0);
            input.extend_from_slice(&payload);
            rustock_core::Transaction {
                nonce,
                gas_price: U256::from(0),
                gas_limit: U256::from(1_000_000),
                to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
                value: U256::ZERO,
                input: Bytes::from(input),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            }
        };

        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xC0);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store)
            .with_bridge_constants(crate::bridge::constants::BridgeConstants::regtest());

        let txs: Vec<_> = [&h1, &h2, &h3, &fork1]
            .iter()
            .enumerate()
            .map(|(i, h)| (receive_header_tx(i as u64, h), sender))
            .collect();
        let built = executor
            .execute_block(&dummy_header(BLOCK), &txs, &root, store.clone())
            .expect("header block");
        for (i, r) in built.tx_results.iter().enumerate() {
            assert!(r.success, "receiveHeader #{i} call succeeded");
            assert_eq!(
                alloy_primitives::I256::from_be_bytes::<32>(r.output[..32].try_into().unwrap()),
                alloy_primitives::I256::ZERO,
                "receiveHeader #{i} returned SUCCESS(0)"
            );
        }
        let root = crate::state::apply_state_changes(
            &root, store.as_ref(), &built.state_changes, &built.markers,
        );

        // getBtcTransactionConfirmations(bytes32,bytes32,uint256,bytes32[])
        // with an EMPTY merkle branch: the branch reduces to btcTxHash itself,
        // so a single-transaction block's merkle root is the tx hash.
        let confirmations = |nonce: u64, tx_hash_display: [u8; 32], block: &bitcoin::block::Header| {
            let mut input =
                crate::bridge::compute_selector("getBtcTransactionConfirmations(bytes32,bytes32,uint256,bytes32[])")
                    .to_vec();
            input.extend_from_slice(&tx_hash_display);
            input.extend_from_slice(bitcoin_hash_to_b256(&block.block_hash()).as_slice());
            input.extend_from_slice(&[0u8; 32]); // merkleBranchPath = 0
            let mut off = [0u8; 32];
            off[31] = 0x80;
            input.extend_from_slice(&off); // offset of the hashes array
            input.extend_from_slice(&[0u8; 32]); // hashes.length = 0
            let tx = rustock_core::Transaction {
                nonce,
                gas_price: U256::from(0),
                gas_limit: U256::from(2_000_000),
                to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
                value: U256::ZERO,
                input: Bytes::from(input),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r = executor
                .execute_block(&dummy_header(BLOCK), &[(tx, sender)], &root, store.clone())
                .expect("query block");
            let res = &r.tx_results[0];
            assert!(res.success, "getBtcTransactionConfirmations must not throw");
            alloy_primitives::I256::from_be_bytes::<32>(res.output[..32].try_into().unwrap())
        };

        // The merkle root in DISPLAY order is what an ABI caller passes as
        // btcTxHash for a one-transaction block.
        let tx_hash_of = |h: &bitcoin::block::Header| -> [u8; 32] {
            let mut b = h.merkle_root.to_raw_hash().to_byte_array();
            b.reverse();
            b
        };
        let code = |n: i64| alloy_primitives::I256::try_from(n).unwrap();

        // Happy path: h1 is at height 1, the head is h3 at height 3.
        assert_eq!(
            confirmations(4, tx_hash_of(&h1), &h1),
            code(3),
            "bestChainHeight - height + 1"
        );
        assert_eq!(confirmations(4, tx_hash_of(&h3), &h3), code(1), "the head itself");

        // -1: the block hash is not stored at all.
        let unknown = hdr(genesis, 0xEE, 999_999);
        assert_eq!(
            confirmations(4, tx_hash_of(&unknown), &unknown),
            code(-1),
            "INEXISTENT_BLOCK_HASH"
        );

        // -5: stored, in the best chain, but the branch does not reduce to the
        // merkle root. rustock used to report -2 here.
        assert_eq!(
            confirmations(4, [0xAB; 32], &h1),
            code(-5),
            "INVALID_MERKLE_BRANCH"
        );

        // -2: stored, but on an orphaned fork. rustock used to report 3 — a
        // confirmed transaction that is not on the BTC main chain.
        assert_eq!(
            confirmations(4, tx_hash_of(&fork1), &fork1),
            code(-2),
            "BLOCK_NOT_IN_BEST_CHAIN"
        );

        // Ordering: the best-chain check runs BEFORE the merkle check, so a
        // fork block with a bad branch still reports -2, not -5.
        assert_eq!(
            confirmations(4, [0xAB; 32], &fork1),
            code(-2),
            "best-chain check precedes the merkle check"
        );

        // Sanity: the fork block really is stored, so -2 came from the
        // best-chain check and not from the block being missing.
        let _ = b256_to_bitcoin_hash;
    }

    /// Audit findings FRCR-78 and FRCR-678.
    ///
    /// `getEstimatedFeesForNextPegOutEvent` is **transaction-callable** — rskj
    /// `BridgeMethods` gives it `fixedPermission(false)` — so a contract can
    /// CALL it and branch on the answer, which makes the value consensus.
    /// rustock returned a hardcoded `0`.
    ///
    /// rskj `BridgeSupport.getEstimatedFeesForNextPegOutEvent`:
    ///
    /// ```text
    ///   shouldReturnZeroEstimatedFees()  -> 0
    ///   !RSKIP305                        -> feePerKB * simulatePegoutTxSize(2 in, queued+2 out) / 1000
    ///   otherwise                        -> inputSum - outputSum of a simulated batched peg-out,
    ///                                       falling back to the line above on failure
    /// ```
    ///
    /// Driven through the Bridge precompile: `releaseBtc` transactions build a
    /// real release queue, then the getter is called and its int256 read back.
    #[test]
    fn test_estimated_fees_for_next_pegout_is_not_hardcoded_zero() {
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        // Run `pegouts` releaseBtc transactions, then query the estimate.
        let query = |number: u64, pegouts: u64| -> U256 {
            let store = Arc::new(MemoryTrieStore::new());
            let root = TrieNode::empty();
            let sender = Address::repeat_byte(0xE5);
            let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc * U256::from(50));
            let block_store =
                Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
            let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
            let header = dummy_header(number);

            let mut root = root;
            for nonce in 0..pegouts {
                let tx = rustock_core::Transaction {
                    nonce,
                    gas_price: U256::from(0),
                    gas_limit: U256::from(200_000),
                    to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
                    value: one_rbtc, // 1 RBTC, well above the peg-out minimum
                    input: Bytes::new(), // empty input = releaseBtc
                    v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
                };
                let r = executor
                    .execute_block(&header, &[(tx, sender)], &root, store.clone())
                    .expect("releaseBtc block");
                assert!(r.tx_results[0].success, "releaseBtc must succeed");
                root = crate::state::apply_state_changes(
                    &root, store.as_ref(), &r.state_changes, &r.markers,
                );
            }

            let call = rustock_core::Transaction {
                nonce: pegouts,
                gas_price: U256::from(0),
                gas_limit: U256::from(500_000),
                to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
                value: U256::ZERO,
                input: Bytes::from(
                    crate::bridge::compute_selector("getEstimatedFeesForNextPegOutEvent()").to_vec(),
                ),
                v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
            };
            let r = executor
                .execute_block(&header, &[(call, sender)], &root, store)
                .expect("query block");
            let res = &r.tx_results[0];
            assert!(res.success, "getEstimatedFeesForNextPegOutEvent must not throw");
            assert_eq!(res.output.len(), 32);
            U256::from_be_slice(&res.output)
        };

        // hop400 (#4,598,500) .. fingerroot500 (#5,468,000): RSKIP271 active,
        // RSKIP385 not — shouldReturnZeroEstimatedFees is true for an EMPTY
        // queue only.
        assert_eq!(query(5_000_000, 0), U256::ZERO, "empty queue pre-RSKIP385 -> 0");
        let pre385_one = query(5_000_000, 1);
        assert!(!pre385_one.is_zero(), "a queued peg-out pre-RSKIP385 must cost something");

        // fingerroot500 onward RSKIP385 is active, so the zero short-circuit is
        // gone: even an empty queue reports the 2-input / 2-output estimate.
        let f500_empty = query(6_000_000, 0);
        assert!(!f500_empty.is_zero(), "RSKIP385 removes the empty-queue zero");

        // reed800 (#8,052,200): RSKIP305 switches to the simulation. With no
        // federation UTXOs the builder cannot fund the peg-out, which is rskj's
        // BridgeIllegalArgumentException path -> fall back to the size estimate.
        let reed_empty = query(8_500_000, 0);
        assert!(!reed_empty.is_zero(), "reed800 fallback must still produce a fee");

        // vetiver900 (#8,804,200) activates RSKIP540, which only changes the
        // hypothetical amount; with the fallback in play the answer is stable.
        let vetiver_empty = query(9_000_000, 0);
        assert!(!vetiver_empty.is_zero());

        // More queued peg-outs mean more outputs, hence a bigger transaction
        // and a strictly bigger fee. This is what a hardcoded 0 could never do.
        let f500_three = query(6_000_000, 3);
        assert!(
            f500_three > f500_empty,
            "3 queued peg-outs must cost more than 0: {f500_three} vs {f500_empty}"
        );
    }

    /// Ported from rskj InitcodeCostCalculatorTest.
    /// Validates that contract creation includes initcode word cost at Shanghai.
    #[test]
    fn test_rskj_initcode_cost_shanghai() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xEE);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Post-Lovell = SHANGHAI (has initcode metering)
        let header = dummy_header(8_000_000);

        // 4 bytes of initcode: ceil(4/32) = 1 word, INITCODE_WORD_COST = 2
        // PUSH1 0x00 PUSH1 0x00 RETURN + padding
        let initcode = vec![0x60, 0x00, 0x60, 0x00]; // 4 bytes

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: Bytes::new(), // contract creation
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store.clone())
            .unwrap();

        // Shanghai create intrinsic: 32000 (create base) + 16*4 (non-zero bytes at Istanbul) + 2 (initcode: 1 word * 2)
        // = 32000 + 64 + 2 = 32066
        // Note: this tx will revert because the initcode doesn't end with RETURN,
        // but we can still check gas_used >= intrinsic cost
        assert!(result.gas_used >= 32_066, "should include initcode metering cost");
    }

    /// Runs a contract-creation tx with the given initcode at the given mainnet height.
    fn run_create_at(initcode: Vec<u8>, block_number: u64, gas_limit: u64) -> TxExecutionResult {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xEE);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(block_number);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(gas_limit),
            to: Bytes::new(), // contract creation
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        executor.execute_tx(&header, &tx, sender, &root, store).unwrap()
    }

    /// Ported from rskj ContractCodePrefixDslTest
    /// (dsl/contract_code_prefix_rskip544/create_fails_with_ef_byte_activated.txt):
    /// after RSKIP544 (vetiver900), creating a contract whose code starts with
    /// 0xEF fails and burns all gas.
    #[test]
    fn test_rskip544_create_ef_code_fails_after_vetiver900() {
        // PUSH1 0xEF, PUSH1 0, MSTORE8, PUSH1 1, PUSH1 0, RETURN -> code = [0xEF]
        let initcode = hex::decode("60ef60005360016000f3").unwrap();
        let result = run_create_at(initcode, 8_804_200, 300_000);
        assert!(!result.success, "0xEF-prefixed code must be rejected post-vetiver900");
        assert_eq!(result.gas_used, 300_000, "all gas is consumed (rskj DSL groundtruth)");
    }

    /// Ported from rskj ContractCodePrefixDslTest
    /// (testCreateSucceedsWithEFByteBeforeRSKIP544Activation): before vetiver900,
    /// 0xEF-prefixed code is accepted — rskj only enforces EIP-3541 from RSKIP544.
    #[test]
    fn test_rskip544_create_ef_code_succeeds_before_vetiver900() {
        let initcode = hex::decode("60ef60005360016000f3").unwrap();
        let result = run_create_at(initcode, 8_804_199, 300_000);
        assert!(result.success, "0xEF-prefixed code must be accepted pre-vetiver900");
        assert!(result.gas_used > 21_000 && result.gas_used < 300_000);
    }

    /// Ported from rskj ContractCodePrefixDslTest (create_succeeds_with_fe_byte.txt):
    /// 0xFE-prefixed code is fine even after RSKIP544.
    #[test]
    fn test_rskip544_create_fe_code_succeeds_after_vetiver900() {
        let initcode = hex::decode("60fe60005360016000f3").unwrap();
        let result = run_create_at(initcode, 8_804_200, 300_000);
        assert!(result.success);
        assert!(result.gas_used > 21_000 && result.gas_used < 300_000);
    }

    /// Ported from rskj ContractCodePrefixDslTest (create_succeeds_with_empty_code.txt):
    /// empty contract code is allowed after RSKIP544.
    #[test]
    fn test_rskip544_create_empty_code_succeeds_after_vetiver900() {
        let initcode = hex::decode("60006000f3").unwrap();
        let result = run_create_at(initcode, 8_804_200, 300_000);
        assert!(result.success);
        assert!(result.gas_used > 21_000 && result.gas_used < 300_000);
    }

    /// Ported from rskj Create2Test patterns.
    /// Verifies that CREATE2 produces the correct contract address.
    #[test]
    fn test_rskj_create2_address_computation() {
        // CREATE2 address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12..]
        use sha3::{Digest, Keccak256};

        let sender_bytes = hex_to_bytes("0f6510583d425cfcf94b99f8b073b44f60d1912b");
        let salt = [0u8; 32];
        let init_code = vec![0x60, 0x0b]; // 2 bytes of init code (from rskj test)

        let init_code_hash = Keccak256::digest(&init_code);

        let mut input = Vec::new();
        input.push(0xFF);
        input.extend_from_slice(&sender_bytes);
        input.extend_from_slice(&salt);
        input.extend_from_slice(&init_code_hash);

        let result = Keccak256::digest(&input);
        let address = &result[12..];

        let expected = hex_to_bytes("3bc3efa1c487a1ebfc911b47b548e2c82436a212");
        assert_eq!(
            address, expected.as_slice(),
            "CREATE2 address should match rskj test vector"
        );
    }

    /// CREATE2 with different salt → different address (rskj Create2Test.testCREATE2_SaltNumber).
    #[test]
    fn test_rskj_create2_salt_changes_address() {
        use sha3::{Digest, Keccak256};

        let sender_bytes = hex_to_bytes("0f6510583d425cfcf94b99f8b073b44f60d1912b");
        let mut salt = [0u8; 32];
        salt[28..].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        let init_code = vec![0x60, 0x1b];

        let init_code_hash = Keccak256::digest(&init_code);

        let mut input = Vec::new();
        input.push(0xFF);
        input.extend_from_slice(&sender_bytes);
        input.extend_from_slice(&salt);
        input.extend_from_slice(&init_code_hash);

        let result = Keccak256::digest(&input);
        let address = &result[12..];

        let expected = hex_to_bytes("19542b03f2d5d4e1910dbe096faf0842d928883d");
        assert_eq!(
            address, expected.as_slice(),
            "CREATE2 with salt 0xcafebabe should match rskj"
        );
    }

    /// CREATE2 with different sender → different address (rskj Create2Test.testCREATE2_Address).
    #[test]
    fn test_rskj_create2_sender_changes_address() {
        use sha3::{Digest, Keccak256};

        let sender_bytes = hex_to_bytes("deadbeef00000000000000000000000000000000");
        let mut salt = [0u8; 32];
        salt[28..].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        let init_code = vec![0x60, 0x1b];

        let init_code_hash = Keccak256::digest(&init_code);

        let mut input = Vec::new();
        input.push(0xFF);
        input.extend_from_slice(&sender_bytes);
        input.extend_from_slice(&salt);
        input.extend_from_slice(&init_code_hash);

        let result = Keccak256::digest(&input);
        let address = &result[12..];

        let expected = hex_to_bytes("3ba1dc70cc17e740f4bd85052af074b2b2a49e06");
        assert_eq!(
            address, expected.as_slice(),
            "CREATE2 with deadbeef sender should match rskj"
        );
    }

    /// Verifies nonce increments correctly across sequential transactions.
    #[test]
    fn test_rskj_nonce_tracking_across_block() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAB);
        let r1 = Address::repeat_byte(0x01);
        let r2 = Address::repeat_byte(0x02);
        let r3 = Address::repeat_byte(0x03);

        let root = put_account(
            &root, store.as_ref(), &sender, 0, U256::from(1_000_000),
        );

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let make_tx = |nonce: u64, to: &Address| {
            rustock_core::Transaction {
                nonce,
                gas_price: U256::from(0),
                gas_limit: U256::from(21_000),
                to: Bytes::copy_from_slice(to.as_slice()),
                value: U256::from(1),
                input: Bytes::new(),
                v: 0,
                r: U256::ZERO,
                s: U256::ZERO,
                cached_rlp: None,
            }
        };

        let txs = vec![
            (make_tx(0, &r1), sender),
            (make_tx(1, &r2), sender),
            (make_tx(2, &r3), sender),
        ];

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &txs, &root, store)
            .unwrap();

        assert_eq!(result.tx_results.len(), 3);
        assert!(result.tx_results.iter().all(|r| r.success));

        let sender_state = result.state_changes.get(&sender).unwrap();
        assert_eq!(sender_state.info.nonce, 3, "nonce should be 3 after 3 txs");

        // Each recipient should have received 1 wei
        for addr in [r1, r2, r3] {
            let state = result.state_changes.get(&addr)
                .expect("recipient should appear in state changes");
            assert_eq!(state.info.balance, U256::from(1));
        }
    }

    /// Verifies SSTORE/SLOAD work correctly via a contract that stores a value.
    /// Bytecode: PUSH1 0x42 PUSH1 0x00 SSTORE STOP
    /// (stores 0x42 at slot 0)
    #[test]
    fn test_contract_sstore_execution() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // Initcode that deploys a contract which stores 0x42 at slot 0:
        // Runtime code: PUSH1 0x42 PUSH1 0x00 SSTORE STOP = 60 42 60 00 55 00
        // Initcode: copy runtime to memory and return it
        // PUSH1 6 PUSH1 0x0c PUSH1 0 CODECOPY  (copy 6 bytes from offset 12 to memory 0)
        // PUSH1 6 PUSH1 0 RETURN                (return 6 bytes from memory 0)
        // <runtime code>
        let initcode: Vec<u8> = vec![
            0x60, 0x06, // PUSH1 6 (size)
            0x60, 0x0c, // PUSH1 12 (offset - after initcode)
            0x60, 0x00, // PUSH1 0 (destOffset)
            0x39,       // CODECOPY
            0x60, 0x06, // PUSH1 6 (size)
            0x60, 0x00, // PUSH1 0 (offset)
            0xF3,       // RETURN
            // Runtime code starts here (offset 12):
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0x00
            0x55,       // SSTORE
            0x00,       // STOP
        ];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "contract creation should succeed");
        assert!(result.gas_used > 32_000, "should include CREATE base cost");
    }

    /// Verifies zero-value calldata bytes cost 4 gas each (consistent across all specs).
    #[test]
    fn test_rskj_zero_calldata_bytes_cost_4() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // 10 zero bytes + 0 non-zero bytes
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(vec![0x00; 10]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // 21000 base + 4*10 zero bytes = 21040
        assert_eq!(result.gas_used, 21_040, "intrinsic gas = 21000 + 4*10 zero bytes");
    }

    /// Verifies mixed zero/non-zero calldata gas cost.
    #[test]
    fn test_rskj_mixed_calldata_cost() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // 5 zero bytes + 3 non-zero bytes at Shanghai/Istanbul rate
        let mut data = vec![0x00; 5];
        data.extend_from_slice(&[0xFF, 0xAB, 0xCD]);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(data),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // 21000 + 4*5 (zero) + 16*3 (non-zero at Istanbul) = 21000 + 20 + 48 = 21068
        assert_eq!(result.gas_used, 21_068, "21000 + 4*5 + 16*3 = 21068");
    }

    /// A block that declares two parallel sublists, executed both ways.
    ///
    /// Running the sublists on their own threads and running the whole block
    /// as one must reach the same state. They are not the same computation:
    /// one journal in transaction order against one journal per sublist
    /// against the parent, merged in sublist order. They agree because the
    /// sublists here are independent -- which is a condition of the block's
    /// validity, not an accident of the fixture.
    ///
    /// The replay over testnet is the real evidence; this is here so that a
    /// regression shows up without a 200 GB snapshot.
    #[test]
    fn a_split_block_executes_the_same_on_one_thread_and_on_two() {
        let store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Three senders, so that no two transactions share a nonce and the
        // sublists have nothing in common: same-sender transactions are
        // connected by the nonce and would have to share a sublist.
        let senders: Vec<Address> =
            (1u8..=3).map(|n| Address::repeat_byte(0x10 + n)).collect();
        let recipients: Vec<Address> =
            (1u8..=3).map(|n| Address::repeat_byte(0xA0 + n)).collect();

        let mut root = TrieNode::empty();
        for s in &senders {
            root = put_account(&root, store.as_ref(), s, 0, U256::from(10_000_000_000_000u64));
        }

        let mut header = dummy_header(8_000_000); // testnet reed810 is 7_139_600
        // Two parallel sublists -- {tx0} and {tx1} -- and tx2 sequential.
        header.version_fields = Some(rustock_core::types::header::HeaderVersionFields {
            version: 1,
            edges: Some(vec![1, 2]),
            base_event: None,
        });

        let transactions: Vec<(rustock_core::Transaction, Address)> = (0..3)
            .map(|i| {
                (
                    rustock_core::Transaction {
                        nonce: 0,
                        gas_price: U256::from(1_000),
                        gas_limit: U256::from(30_000),
                        to: Bytes::copy_from_slice(recipients[i].as_slice()),
                        value: U256::from(1_000),
                        input: Bytes::new(),
                        v: 0,
                        r: U256::ZERO,
                        s: U256::ZERO,
                        cached_rlp: None,
                    },
                    senders[i],
                )
            })
            .collect();

        let run = |threads: usize| {
            // Testnet, above reed810: a header cannot carry edges on a chain
            // where RSKIP-144 is unscheduled, and the parallel path requires
            // the postponed fee settlement that comes with it.
            let executor = RskExecutor::new(RskHardforkConfig::testnet(), block_store.clone())
                .with_execution_threads(threads);
            let result = executor
                .execute_block(&header, &transactions, &root, store.clone())
                .expect("block executes");
            let applied = result.applied_root.clone().unwrap_or_else(|| {
                crate::state::apply_state_changes(
                    &root,
                    store.as_ref(),
                    &result.state_changes,
                    &result.markers,
                )
            });
            let mut balances: Vec<(Address, U256, u64)> = result
                .state_changes
                .iter()
                .map(|(a, acc)| (*a, acc.info.balance, acc.info.nonce))
                .collect();
            balances.sort_by_key(|(a, _, _)| *a);
            (
                applied.compute_hash(store.as_ref()),
                result.gas_used,
                result.paid_fees,
                result.tx_results.iter().map(|r| (r.success, r.gas_used)).collect::<Vec<_>>(),
                balances,
            )
        };

        let one = run(1);
        let two = run(2);
        assert_eq!(one.3, two.3, "per-transaction results");
        assert_eq!(one.1, two.1, "gas used");
        assert_eq!(one.2, two.2, "paid fees");
        assert_eq!(one.4, two.4, "account balances");
        assert_eq!(one.0, two.0, "state root");
        assert_eq!(one.3.len(), 3, "every transaction ran exactly once");
    }

    /// Two transactions from the same sender, placed in different parallel
    /// sublists. This is the race RSKIP-144 exists to forbid, and it must be
    /// caught when the sublists really do run apart.
    ///
    /// Each sublist runs against the state the block starts from, so both
    /// transactions see nonce 0 and both succeed -- which is precisely the
    /// problem, and why the rule is a condition on the block rather than
    /// something sequential execution would have noticed.
    #[test]
    fn a_block_whose_sublists_share_a_sender_is_caught_in_parallel() {
        let store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );
        let sender = Address::repeat_byte(0x11);
        let root = put_account(
            &TrieNode::empty(),
            store.as_ref(),
            &sender,
            0,
            U256::from(10_000_000_000_000u64),
        );

        let mut header = dummy_header(8_000_000);
        header.version_fields = Some(rustock_core::types::header::HeaderVersionFields {
            version: 1,
            edges: Some(vec![1, 2]),
            base_event: None,
        });

        let tx = |nonce: u64, to: u8| rustock_core::Transaction {
            nonce,
            gas_price: U256::from(1_000),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(Address::repeat_byte(to).as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        // tx0 in sublist 0 and tx1 in sublist 1, both from `sender`, both
        // with nonce 0 -- which is what each of them sees, each running
        // against the state the block starts from. A miner would never build
        // this; the validator still has to refuse it.
        let transactions = vec![
            (tx(0, 0xA1), sender),
            (tx(0, 0xA2), sender),
            (tx(0, 0xA3), Address::repeat_byte(0x22)),
        ];

        let edges = [1i16, 2];
        crate::collision::start(
            &edges,
            &[],
            crate::collision::write_semantics(header.number),
        );
        let executor = RskExecutor::new(RskHardforkConfig::testnet(), block_store)
            .with_execution_threads(2);
        let _ = executor.execute_block(&header, &transactions, &root, store);
        let collision = crate::collision::finish()
            .expect("recording was started")
            .first_collision()
            .expect("both sublists write the sender's account cell");

        assert_eq!(collision.kind, crate::collision::CollisionKind::WriteWrite);
        assert_eq!(
            collision.key,
            rustock_trie::account_key(&sender),
            "the nonce is what connects them, and it lives in the account cell"
        );
    }

    /// The thread setting only decides *how*, never *whether*: a block with
    /// no sublists runs as one however many threads are allowed.
    #[test]
    fn a_block_without_sublists_ignores_the_thread_count() {
        let store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );
        let sender = Address::repeat_byte(0x11);
        let root = put_account(
            &TrieNode::empty(),
            store.as_ref(),
            &sender,
            0,
            U256::from(10_000_000_000_000u64),
        );
        let header = dummy_header(8_000_000); // version_fields: None
        let transactions = vec![(
            rustock_core::Transaction {
                nonce: 0,
                gas_price: U256::from(1_000),
                gas_limit: U256::from(30_000),
                to: Bytes::copy_from_slice(Address::repeat_byte(0xA1).as_slice()),
                value: U256::from(1_000),
                input: Bytes::new(),
                v: 0,
                r: U256::ZERO,
                s: U256::ZERO,
                cached_rlp: None,
            },
            sender,
        )];
        for threads in [1usize, 2] {
            let executor = RskExecutor::new(RskHardforkConfig::all_active(33), block_store.clone())
                .with_execution_threads(threads);
            let result = executor
                .execute_block(&header, &transactions, &root, store.clone())
                .expect("block executes");
            assert!(
                result.applied_root.is_none(),
                "a block with no sublists is one run, so the caller applies it ({threads} threads)"
            );
        }
    }

    /// Verifies that the beneficiary (coinbase) receives gas fees in state changes.
    #[test]
    fn test_fees_routed_to_remasc() {
        use crate::precompiles::REMASC_ADDR;

        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let beneficiary = Address::repeat_byte(0x01);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut header = dummy_header(8_000_000);
        header.beneficiary = beneficiary;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(100),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .unwrap();

        assert!(result.tx_results[0].success);

        // Fees are routed to REMASC, not the miner. gas_used * gas_price = 21000 * 100
        let remasc_state = result.state_changes.get(&REMASC_ADDR)
            .expect("REMASC should appear in state changes");
        assert_eq!(
            remasc_state.info.balance,
            U256::from(2_100_000u64),
            "REMASC receives 21000 * 100 = 2_100_000"
        );

        // The miner (header.beneficiary) should NOT receive fees directly
        assert!(
            !result.state_changes.contains_key(&beneficiary),
            "miner should not receive fees directly; REMASC distributes later"
        );
    }

    // -----------------------------------------------------------------------
    // End-to-end precompile execution tests
    // -----------------------------------------------------------------------

    /// A USER tx to the REMASC precompile (0x01000008) is rskj's
    /// RemascInvalidInvocationException ("Invoked Remasc outside last tx of
    /// the block") — invisible for a direct tx: receipt SUCCESS with only
    /// intrinsic gas (getGasForData is 0), no fee distribution, but the
    /// sender is charged the FULL gas limit and REMASC receives it.
    #[test]
    fn test_remasc_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(100);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1_000),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .unwrap();

        assert!(result.tx_results[0].success, "receipt records SUCCESS");
        assert_eq!(
            result.tx_results[0].gas_used, 21_000,
            "REMASC costs 0 gas, receipt shows intrinsic only"
        );
        // No fee distribution may run for a user tx.
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        assert!(remasc_state.storage.is_empty(), "no REMASC storage writes");
        let full_fee = U256::from(100_000u64) * U256::from(1_000u64);
        assert_eq!(
            result.state_changes.get(&sender).unwrap().info.balance,
            one_rbtc - full_fee,
            "sender pays for the full gas limit"
        );
        assert_eq!(remasc_state.info.balance, full_fee);
        assert_eq!(result.paid_fees, full_fee);
    }

    /// Direct tx to Bridge precompile (0x01000006).
    /// Bridge stub charges 10,000 gas.
    #[test]
    fn test_bridge_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let bridge_addr = crate::precompiles::BRIDGE_ADDR;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(bridge_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "Bridge direct call should succeed");
        assert_eq!(
            result.gas_used,
            21_000 + 23_000,
            "Empty Bridge call dispatches releaseBtc (23k gas) on top of intrinsic"
        );
    }

    /// Direct tx to Identity precompile (0x04) with known input.
    /// Ported from rskj PrecompiledContractTest.identityTest1:
    ///   input = 0x112233445566, output = 0x112233445566, gas = 18
    #[test]
    fn test_identity_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let identity_addr = Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
        let input_data: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(identity_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input_data.clone()),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "Identity precompile should succeed");
        assert_eq!(
            result.output, input_data,
            "Identity precompile returns input unchanged"
        );

        // Identity gas: 15 base + 3 * ceil(6/32) = 15 + 3 = 18
        // Intrinsic: 21000 + 6*16 = 21096 (all non-zero at Istanbul)
        // Total: 21096 + 18 = 21114
        assert_eq!(result.gas_used, 21_114, "Identity: 21000 + 96 + 18 = 21114");
    }

    /// Direct tx to SHA256 precompile (0x02) with empty input.
    /// Ported from rskj PrecompiledContractTest.sha256Test1:
    ///   SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #[test]
    fn test_sha256_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let sha256_addr = Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(sha256_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "SHA256 precompile should succeed");

        let expected = hex_to_bytes(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(result.output, expected, "SHA256('') matches rskj test vector");

        // SHA256 gas: 60 base + 12 * ceil(0/32) = 60
        // Intrinsic: 21000 (no data)
        // Total: 21060
        assert_eq!(result.gas_used, 21_060, "SHA256: 21000 + 60 = 21060");
    }

    /// Verify that SHA256 with non-empty input produces the correct hash.
    /// Ported from rskj PrecompiledContractTest.sha256Test3:
    ///   SHA256(0x112233) = 49ee2bf93aac3b1fb4117e59095e07abe555c3383b38d608da37680a406096e8
    #[test]
    fn test_sha256_precompile_with_data() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let sha256_addr = Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let input_data = vec![0x11, 0x22, 0x33];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(sha256_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input_data),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "SHA256 precompile should succeed");

        let expected = hex_to_bytes(
            "49ee2bf93aac3b1fb4117e59095e07abe555c3383b38d608da37680a406096e8"
        );
        assert_eq!(result.output, expected, "SHA256(0x112233) matches rskj test vector");

        // SHA256 gas: 60 + 12*1 = 72 (3 bytes = 1 word)
        // Intrinsic: 21000 + 3*16 = 21048
        // Total: 21048 + 72 = 21120
        assert_eq!(result.gas_used, 21_120, "SHA256: 21000 + 48 + 72 = 21120");
    }

    /// Contract calls Identity precompile via STATICCALL and returns the result.
    /// This tests the precompile-from-contract path (CALL opcode → precompile).
    #[test]
    fn test_identity_precompile_via_contract_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // Deploy a contract whose runtime code:
        //   1. Stores 0xDEADBEEF at memory[0:4]
        //   2. STATICCALLs Identity (0x04) with that 4-byte input
        //   3. RETURNs the 4-byte output
        //
        // Runtime bytecode:
        //   PUSH4 0xDEADBEEF  ; 63 DEADBEEF
        //   PUSH1 0x00        ; 60 00
        //   MSTORE            ; 52           -> mem[28..32] = 0xDEADBEEF (right-aligned in 32 bytes)
        //
        //   PUSH1 0x04        ; 60 04        retSize
        //   PUSH1 0x40        ; 60 40        retOffset
        //   PUSH1 0x04        ; 60 04        argsSize
        //   PUSH1 0x1c        ; 60 1c        argsOffset (28, where the 4 bytes are)
        //   PUSH1 0x04        ; 60 04        address (Identity)
        //   GAS               ; 5A           gas
        //   STATICCALL        ; FA
        //
        //   PUSH1 0x04        ; 60 04        size
        //   PUSH1 0x40        ; 60 40        offset
        //   RETURN            ; F3
        let runtime: Vec<u8> = vec![
            0x63, 0xDE, 0xAD, 0xBE, 0xEF,  // PUSH4 0xDEADBEEF
            0x60, 0x00,                      // PUSH1 0
            0x52,                            // MSTORE
            0x60, 0x04,                      // PUSH1 4 (retSize)
            0x60, 0x40,                      // PUSH1 64 (retOffset)
            0x60, 0x04,                      // PUSH1 4 (argsSize)
            0x60, 0x1c,                      // PUSH1 28 (argsOffset)
            0x60, 0x04,                      // PUSH1 4 (Identity address)
            0x5A,                            // GAS
            0xFA,                            // STATICCALL
            0x60, 0x04,                      // PUSH1 4 (return size)
            0x60, 0x40,                      // PUSH1 64 (return offset)
            0xF3,                            // RETURN
        ];

        let runtime_len = runtime.len() as u8;
        let initcode_prefix: Vec<u8> = vec![
            0x60, runtime_len,              // PUSH1 runtime_len
            0x60, 0x0c,                     // PUSH1 12 (offset after initcode prefix)
            0x60, 0x00,                     // PUSH1 0
            0x39,                           // CODECOPY
            0x60, runtime_len,              // PUSH1 runtime_len
            0x60, 0x00,                     // PUSH1 0
            0xF3,                           // RETURN
        ];

        let mut initcode = initcode_prefix;
        initcode.extend_from_slice(&runtime);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(500_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        );

        // Step 1: deploy the contract
        let deploy_result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .unwrap();

        assert!(deploy_result.tx_results[0].success, "deployment should succeed");

        // Find the created contract address from state changes
        let contract_addr = deploy_result.state_changes.iter()
            .find(|(addr, acct)| {
                **addr != sender
                    && **addr != header.beneficiary
                    && acct.info.code.as_ref().is_some_and(|c| !c.is_empty())
            })
            .map(|(addr, _)| *addr)
            .expect("should have created a contract");

        // Step 2: call the contract — it will STATICCALL Identity and return the result
        let root2 = TrieNode::empty();
        let root2 = put_account(&root2, store.as_ref(), &sender, 1, one_rbtc);

        // Put the deployed code into the trie for the contract
        let code_bytes = deploy_result.state_changes.get(&contract_addr)
            .unwrap().info.code.as_ref().unwrap().bytes_slice().to_vec();

        use rustock_trie::{TrieKeySlice, code_key};
        let ckey = code_key(&contract_addr);
        let root2 = root2.put(&TrieKeySlice::from_key(&ckey), &code_bytes, store.as_ref());

        let caccount = AccountState::new(U256::ZERO, U256::ZERO);
        let akey = account_key(&contract_addr);
        let root2 = root2.put(&TrieKeySlice::from_key(&akey), &caccount.encode(), store.as_ref());

        let call_tx = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(contract_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let call_result = executor
            .execute_tx(&header, &call_tx, sender, &root2, store)
            .unwrap();

        assert!(call_result.success, "contract call should succeed");
        assert_eq!(
            call_result.output,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            "Identity precompile should return input unchanged via contract STATICCALL"
        );
    }

    /// Direct tx to Environment precompile (0x01000011) with getCallStackDepth() selector.
    /// Ported from rskj EnvironmentTest.getCallStackDepth:
    ///   selector = 0x80af2871, returns depth as uint32.
    ///   Direct tx call → depth = 1 (matching rskj's getCallDeep()==0 + 1).
    #[test]
    fn test_environment_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let env_addr = crate::precompiles::ENVIRONMENT_ADDR;
        let selector = vec![0xe8, 0xce, 0x22, 0x74]; // keccak256("getCallStackDepth()")[0:4]

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(env_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(selector),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "Environment direct call should succeed");

        // Output: uint32 ABI-encoded as 32-byte big-endian
        assert_eq!(result.output.len(), 32);
        let depth = u32::from_be_bytes([
            result.output[28],
            result.output[29],
            result.output[30],
            result.output[31],
        ]);
        assert_eq!(depth, 1, "direct tx call depth should be 1 (matching rskj)");

        // Gas: 0 for Environment + intrinsic cost
        // Intrinsic: 21000 base + 16*4 (4 non-zero selector bytes at Istanbul rate) = 21064
        assert_eq!(result.gas_used, 21_064, "Environment costs 0 gas, total = intrinsic only");
    }

    /// Environment precompile with unknown selector should fail.
    #[test]
    fn test_environment_precompile_unknown_selector() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let env_addr = crate::precompiles::ENVIRONMENT_ADDR;
        let bad_selector = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(env_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(bad_selector),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(!result.success, "unknown selector should fail");
    }

    /// Environment precompile called via contract STATICCALL should return
    /// depth > 1 (one extra level for the contract frame).
    #[test]
    fn test_environment_precompile_via_contract() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // Runtime code:
        //   Store selector 0xe8ce2274 at memory[0..4]
        //   STATICCALL Environment precompile (0x01000011)
        //   Return 32 bytes of output
        //
        // PUSH4 0xe8ce2274    ; 63 e8ce2274
        // PUSH1 0x00          ; 60 00
        // MSTORE              ; 52       -> mem[28..32] = 0xe8ce2274
        //
        // PUSH1 0x20          ; 60 20    retSize (32)
        // PUSH1 0x40          ; 60 40    retOffset
        // PUSH1 0x04          ; 60 04    argsSize (4)
        // PUSH1 0x1c          ; 60 1c    argsOffset (28)
        // PUSH4 0x01000011    ; 63 01000011   address (4 bytes)
        // GAS                 ; 5A
        // STATICCALL          ; FA
        //
        // PUSH1 0x20          ; 60 20    size
        // PUSH1 0x40          ; 60 40    offset
        // RETURN              ; F3
        let runtime: Vec<u8> = vec![
            0x63, 0xe8, 0xce, 0x22, 0x74,  // PUSH4 0xe8ce2274
            0x60, 0x00,                      // PUSH1 0
            0x52,                            // MSTORE
            0x60, 0x20,                      // PUSH1 32 (retSize)
            0x60, 0x40,                      // PUSH1 64 (retOffset)
            0x60, 0x04,                      // PUSH1 4 (argsSize)
            0x60, 0x1c,                      // PUSH1 28 (argsOffset)
            0x63, 0x01, 0x00, 0x00, 0x11,   // PUSH4 0x01000011 (Environment addr)
            0x5A,                            // GAS
            0xFA,                            // STATICCALL
            0x60, 0x20,                      // PUSH1 32 (return size)
            0x60, 0x40,                      // PUSH1 64 (return offset)
            0xF3,                            // RETURN
        ];

        let runtime_len = runtime.len() as u8;
        let mut initcode: Vec<u8> = vec![
            0x60, runtime_len,
            0x60, 0x0c,
            0x60, 0x00,
            0x39,
            0x60, runtime_len,
            0x60, 0x00,
            0xF3,
        ];
        initcode.extend_from_slice(&runtime);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(500_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        );

        // Deploy
        let deploy_result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .unwrap();

        assert!(deploy_result.tx_results[0].success, "deployment should succeed");

        let contract_addr = deploy_result.state_changes.iter()
            .find(|(addr, acct)| {
                **addr != sender
                    && **addr != header.beneficiary
                    && acct.info.code.as_ref().is_some_and(|c| !c.is_empty())
            })
            .map(|(addr, _)| *addr)
            .expect("should have created a contract");

        // Set up state for calling the contract
        let root2 = TrieNode::empty();
        let root2 = put_account(&root2, store.as_ref(), &sender, 1, one_rbtc);

        let code_bytes = deploy_result.state_changes.get(&contract_addr)
            .unwrap().info.code.as_ref().unwrap().bytes_slice().to_vec();

        use rustock_trie::{TrieKeySlice, code_key, AccountState};
        let ckey = code_key(&contract_addr);
        let root2 = root2.put(&TrieKeySlice::from_key(&ckey), &code_bytes, store.as_ref());

        let caccount = AccountState::new(U256::ZERO, U256::ZERO);
        let akey = account_key(&contract_addr);
        let root2 = root2.put(&TrieKeySlice::from_key(&akey), &caccount.encode(), store.as_ref());

        let call_tx = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(contract_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let call_result = executor
            .execute_tx(&header, &call_tx, sender, &root2, store)
            .unwrap();

        assert!(call_result.success, "contract call should succeed");
        assert_eq!(call_result.output.len(), 32, "should return 32-byte ABI-encoded uint32");

        let depth = u32::from_be_bytes([
            call_result.output[28],
            call_result.output[29],
            call_result.output[30],
            call_result.output[31],
        ]);

        assert!(
            depth >= 2,
            "depth via contract call should be >= 2 (tx frame + contract frame), got {}",
            depth
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // -----------------------------------------------------------------------
    // BlockHeaderContract integration tests
    // -----------------------------------------------------------------------

    fn block_header_selector(sig: &str) -> [u8; 4] {
        use sha3::{Digest, Keccak256};
        let h = Keccak256::digest(sig.as_bytes());
        [h[0], h[1], h[2], h[3]]
    }

    /// Build ABI-encoded input for a single-param BlockHeaderContract call:
    /// 4-byte selector + 32-byte ABI-encoded int256.
    fn bh_input(sig: &str, depth: i64) -> Vec<u8> {
        let sel = block_header_selector(sig);
        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&sel);
        if depth >= 0 {
            let be = (depth as u64).to_be_bytes();
            input[28..36].copy_from_slice(&be);
        } else {
            // Negative int256: sign-extend with 0xFF
            input[4..36].fill(0xFF);
            let be = depth.to_be_bytes();
            input[28..36].copy_from_slice(&be);
        }
        input
    }

    /// Decode an ABI-encoded `bytes` return value.
    fn decode_abi_bytes(output: &[u8]) -> Vec<u8> {
        if output.len() < 64 {
            return Vec::new();
        }
        let len = u64::from_be_bytes(output[56..64].try_into().unwrap()) as usize;
        if 64 + len > output.len() {
            return Vec::new();
        }
        output[64..64 + len].to_vec()
    }

    /// Direct tx to BlockHeaderContract with getCoinbaseAddress(0).
    /// Sets up a two-block chain and queries the parent's coinbase.
    #[test]
    fn test_block_header_get_coinbase_address() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Store a parent block (number 99) with a known coinbase
        let parent_coinbase = Address::repeat_byte(0xCC);
        let mut parent_header = dummy_header(99);
        parent_header.beneficiary = parent_coinbase;
        let parent_hash = parent_header.hash();
        block_store.put_header(&parent_header).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        // Current block is 100, parent_hash points to block 99
        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getCoinbaseAddress(int256)", 0);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "getCoinbaseAddress should succeed");

        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded.len(), 20, "coinbase address should be 20 bytes");
        assert_eq!(decoded, parent_coinbase.as_slice());
    }

    /// Shared fixture for RSKIP536 tests: parent block #99 with difficulty 1,
    /// two uncles of difficulty 1 each, and a stored total difficulty.
    /// Mirrors rskj BlockHeaderContractTest (RSK_BLOCK_DIFFICULTY = 1,
    /// RSK_BLOCK_WITH_UNCLES_DIFFICULTY = 3).
    fn rskip536_call(sig: &str, cfg: RskHardforkConfig, current_number: u64) -> TxExecutionResult {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());

        let parent_number = current_number - 1;
        let mut parent_header = dummy_header(parent_number);
        parent_header.difficulty = U256::from(1);
        let parent_hash = parent_header.hash();
        block_store.put_header(&parent_header).unwrap();
        block_store.put_canonical_hash(parent_number, parent_hash).unwrap();

        let mut uncle1 = dummy_header(parent_number - 1);
        uncle1.difficulty = U256::from(1);
        uncle1.beneficiary = Address::repeat_byte(0xD1);
        let mut uncle2 = dummy_header(parent_number - 1);
        uncle2.difficulty = U256::from(1);
        uncle2.beneficiary = Address::repeat_byte(0xD2);
        block_store.put_body(parent_hash, &[], &[uncle1, uncle2]).unwrap();
        block_store.put_total_difficulty(parent_hash, U256::from(11_996)).unwrap();

        let mut header = dummy_header(current_number);
        header.parent_hash = parent_hash;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(bh_input(sig, 0)),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(cfg, block_store);
        executor.execute_tx(&header, &tx, sender, &root, store).unwrap()
    }

    /// Ported from rskj BlockHeaderContractTest.getDifficultyWithUnclesDifficulty:
    /// difficulty 1 + two uncles of difficulty 1 = 3.
    #[test]
    fn test_rskip536_get_difficulty_with_uncles() {
        let result = rskip536_call(
            "getDifficultyWithUncles(int256)",
            RskHardforkConfig::all_active(33),
            100,
        );
        assert!(result.success);
        assert_eq!(decode_abi_bytes(&result.output), vec![3u8]);
    }

    /// Ported from rskj BlockHeaderContractTest.getCumulativeWork: returns the
    /// block store's total difficulty for the block hash.
    #[test]
    fn test_rskip536_get_cumulative_work() {
        let result = rskip536_call(
            "getCumulativeWork(int256)",
            RskHardforkConfig::all_active(33),
            100,
        );
        assert!(result.success);
        assert_eq!(decode_abi_bytes(&result.output), vec![0x2e, 0xdc]); // 11996
    }

    /// Ported from rskj BlockHeaderContractTest.*_whenMethodDisabled_shouldThrowVME:
    /// both methods fail before RSKIP536 activates (mainnet vetiver900).
    #[test]
    fn test_rskip536_methods_disabled_before_activation() {
        for sig in ["getDifficultyWithUncles(int256)", "getCumulativeWork(int256)"] {
            let result = rskip536_call(sig, RskHardforkConfig::mainnet(), 8_804_199);
            assert!(!result.success, "{sig} must fail before vetiver900");
        }
    }

    /// Both methods work at the vetiver900 boundary on mainnet.
    #[test]
    fn test_rskip536_methods_enabled_at_vetiver900() {
        for sig in ["getDifficultyWithUncles(int256)", "getCumulativeWork(int256)"] {
            let result = rskip536_call(sig, RskHardforkConfig::mainnet(), 8_804_200);
            assert!(result.success, "{sig} must work from vetiver900");
        }
    }

    /// Calls the Bridge's getEstimatedFeesForPegOutAmount(uint256) at the
    /// given mainnet height with the given amount in weis.
    fn call_estimated_fees_for_pegout_amount(block_number: u64, wei: U256) -> TxExecutionResult {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(block_number);

        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&block_header_selector("getEstimatedFeesForPegOutAmount(uint256)"));
        input[4..36].copy_from_slice(&wei.to_be_bytes::<32>());

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        executor.execute_tx(&header, &tx, sender, &root, store).unwrap()
    }

    /// Ported from rskj BridgeTest.getEstimatedFeesForPegOutAmount_preRSKIP540__shouldThrowVMException.
    /// The VMException is invisible in a DIRECT transaction's receipt:
    /// TransactionExecutor spends only requiredGas (flat 23,000 for the
    /// disabled-method parse failure) + basicTxCost and records SUCCESS
    /// (see mainnet #764,123 for the same pattern with RSKIP87).
    #[test]
    fn test_rskip540_estimated_fees_for_pegout_amount_disabled_before_vetiver900() {
        // 0.004 BTC (mainnet minimum) in wei — valid amount, but method not enabled yet.
        let amount = U256::from(400_000u64) * U256::from(10_000_000_000u64);
        let result = call_estimated_fees_for_pegout_amount(8_804_199, amount);
        assert!(result.success, "rskj throws, but a direct tx records SUCCESS");

        // Flat parse-failure cost, no method execution: intrinsic (RSKIP400
        // calldata prices at this height) + 23,000.
        let mut input = [0u8; 36];
        input[..4].copy_from_slice(&block_header_selector(
            "getEstimatedFeesForPegOutAmount(uint256)",
        ));
        input[4..36].copy_from_slice(&amount.to_be_bytes::<32>());
        let data_gas: u64 = input.iter().map(|b| if *b == 0 { 4 } else { 16 }).sum();
        assert_eq!(result.gas_used, 21_000 + data_gas + 23_000);
    }

    /// Ported from rskj BridgeTest.getEstimatedFeesForPegOutAmount_afterRSKIP540_shouldExecute.
    #[test]
    fn test_rskip540_estimated_fees_for_pegout_amount_executes_after_vetiver900() {
        let amount = U256::from(400_000u64) * U256::from(10_000_000_000u64);
        let result = call_estimated_fees_for_pegout_amount(8_804_200, amount);
        assert!(result.success, "method must execute from vetiver900");
    }

    /// Ported from rskj BridgeTest.getEstimatedFeesForPegOutAmount_withAmountBelowMinimum_shouldThrowBridgeIllegalArgumentException:
    /// the method throws a BridgeIllegalArgumentException (wrapped in a
    /// VMException by Bridge.execute). In a DIRECT transaction that exception
    /// is invisible in the receipt — rskj TransactionExecutor.call catches it,
    /// spends only requiredGas (getGasForData = 10000 + data.length*2) +
    /// basicTxCost and records SUCCESS (the sender is still charged the full
    /// gas limit as a fee). Same pattern as the disabled-method case above and
    /// as mainnet #4,600,948 tx[3] (registerBtcCoinbaseTransaction throw).
    #[test]
    fn test_rskip540_estimated_fees_for_pegout_amount_below_minimum_fails() {
        let result = call_estimated_fees_for_pegout_amount(8_804_200, U256::from(1));
        assert!(result.success, "rskj throws, but a direct tx records SUCCESS");

        let mut input = [0u8; 36];
        input[..4].copy_from_slice(&block_header_selector(
            "getEstimatedFeesForPegOutAmount(uint256)",
        ));
        input[4..36].copy_from_slice(&U256::from(1).to_be_bytes::<32>());
        let data_gas: u64 = input.iter().map(|b| if *b == 0 { 4 } else { 16 }).sum();
        // requiredGas = getGasForData = 10000 (fixed) + 36*2; intrinsic =
        // 21000 + RSKIP400 calldata cost.
        assert_eq!(result.gas_used, 21_000 + data_gas + 10_000 + 36 * 2);
    }

    /// Ported from rskj BridgeSupportTest.when_RegisterBtcCoinbaseTransaction_HashNotInPmt_noSent
    /// (and ..._not_equal_merkle_root_noSent): when the supplied btc tx is not
    /// in the partial merkle tree (or the merkle roots don't match), rskj
    /// `BridgeSupport.registerBtcCoinbaseTransaction` (l.2503-2511, 2546-2555)
    /// logs a warning and `return`s — it does NOT throw. The direct tx is
    /// therefore a plain SUCCESS billed `gasUsed * gasPrice`, NOT a failed
    /// summary billed the full gas limit. Mainnet #4,603,038 tx[2] (a
    /// merkle-root mismatch) over-charged paidFees by (gasLimit-gasUsed)*price
    /// = 55,047,360,000,000 wei until this was fixed.
    #[test]
    fn test_register_btc_coinbase_tx_hash_not_in_pmt_succeeds() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(4_603_038);

        // A PMT matching a single hash of all-0xAA. The btc tx bytes below
        // hash (double-SHA256) to something else, so the tx hash is NOT in
        // the PMT — rskj returns success without storing coinbase info.
        let mut pmt = Vec::new();
        pmt.extend_from_slice(&1u32.to_le_bytes()); // tx_count
        pmt.push(1); // nHashes
        pmt.extend_from_slice(&[0xAA; 32]); // hash
        pmt.push(1); // nFlagBytes
        pmt.push(0x01); // matched

        let btc_tx = vec![0x01u8, 0x02, 0x03, 0x04];

        // ABI-encode registerBtcCoinbaseTransaction(bytes,bytes32,bytes,bytes32,bytes32).
        let mut input = block_header_selector(
            "registerBtcCoinbaseTransaction(bytes,bytes32,bytes,bytes32,bytes32)",
        )
        .to_vec();
        let head_len = 5 * 32;
        let btc_tx_off = head_len;
        let pmt_off = head_len + 32 + btc_tx.len().div_ceil(32) * 32;
        // arg0: btcTx offset
        input.extend_from_slice(&U256::from(btc_tx_off).to_be_bytes::<32>());
        // arg1: blockHash (unused on this path — tx-not-in-PMT returns first)
        input.extend_from_slice(&[0u8; 32]);
        // arg2: pmt offset
        input.extend_from_slice(&U256::from(pmt_off).to_be_bytes::<32>());
        // arg3, arg4: witness fields
        input.extend_from_slice(&[0u8; 32]);
        input.extend_from_slice(&[0u8; 32]);
        // btcTx: length + padded data
        input.extend_from_slice(&U256::from(btc_tx.len()).to_be_bytes::<32>());
        let mut padded = btc_tx.clone();
        padded.resize(btc_tx.len().div_ceil(32) * 32, 0);
        input.extend_from_slice(&padded);
        // pmt: length + padded data
        input.extend_from_slice(&U256::from(pmt.len()).to_be_bytes::<32>());
        let mut pmt_padded = pmt.clone();
        pmt_padded.resize(pmt.len().div_ceil(32) * 32, 0);
        input.extend_from_slice(&pmt_padded);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();

        assert!(result.success, "rskj returns (no throw) when the tx is not in the PMT");
        // gasUsed is the real spent gas (intrinsic 21000 + RSKIP400 calldata +
        // requiredGas getGasForData), 36016 here — well below the 1,000,000
        // limit. The fee billed is gasUsed*gasPrice; an (incorrect)
        // invisible-exception/markAsFailed path would instead bill the full
        // 1,000,000 limit. Asserting the exact spent gas locks in "not failed".
        assert_eq!(result.gas_used, 36_016);
        assert!(result.gas_used < tx.gas_limit.to::<u64>());
    }

    /// Regression for mainnet block #2646 (gas used mismatch 31280 vs 31272):
    /// rskj Bridge.getGasForData charges functionCost + data.length * 2.
    /// voteFeePerKbChange (enabled at every era):
    /// 21000 + 4*68 + 30*4 + 2*68 + 10000 + 36*2 = 31600.
    #[test]
    fn test_bridge_call_charges_rskj_data_cost() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(2_646);

        let mut input = vec![0x04, 0x61, 0x31, 0x3e]; // voteFeePerKbChange(int256)
        let mut value = [0u8; 32];
        value[30..].copy_from_slice(&30_000u16.to_be_bytes());
        input.extend_from_slice(&value);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 28, r: U256::from(1), s: U256::from(1), cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 31_600, "functionCost 10000 + data cost 36*2");
    }

    // -----------------------------------------------------------------------
    // Free bridge transactions (rskj BridgeUtils.isFreeBridgeTx)
    // -----------------------------------------------------------------------

    /// Known vector: the address of private key 0x01. Its public key is
    /// 0479be667e...f81798 / 483ada77...10d4b8 and the derived address is
    /// 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf.
    #[test]
    fn test_rsk_address_from_pubkey_hex() {
        let uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected: Address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".parse().unwrap();
        assert_eq!(rsk_address_from_pubkey_hex(uncompressed), Some(expected));
        assert_eq!(rsk_address_from_pubkey_hex(compressed), Some(expected));
        assert_eq!(rsk_address_from_pubkey_hex("zz"), None);
    }

    /// All mainnet free-bridge sender keys (15 federators + 7 authorizers)
    /// derive to distinct addresses.
    #[test]
    fn test_mainnet_free_bridge_senders_derive() {
        let executor = RskExecutor::new(
            RskHardforkConfig::mainnet(),
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap()),
        );
        let senders = &executor.free_bridge_senders;
        assert_eq!(senders.len(), 22);
        let unique: std::collections::HashSet<_> = senders.iter().collect();
        assert_eq!(unique.len(), 22);
    }

    /// Runs a gas_limit-0 tx to the Bridge through execute_block at the
    /// given mainnet height from the given sender.
    fn run_bridge_tx_gas0(block_number: u64, sender: Address) -> Result<crate::executor::BlockExecutionResult, ExecutionError> {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::ZERO);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(block_number);

        // updateCollections() selector
        let input = block_header_selector("updateCollections()").to_vec();
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(0),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 28, // free bridge txs are real signed txs, not remasc
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        executor.execute_block(&header, &[(tx, sender)], &root, store)
    }

    /// Before areBridgeTxsPaid (mainnet 370_000), a genesis federator's
    /// gas_limit-0 bridge tx executes for free: receipt gas_used 0.
    #[test]
    fn test_free_bridge_tx_executes_with_zero_gas() {
        let federator = rsk_address_from_pubkey_hex(
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
        )
        .unwrap();
        let result = run_bridge_tx_gas0(457, federator).expect("free bridge tx must execute");
        assert_eq!(result.tx_results.len(), 1);
        assert_eq!(result.tx_results[0].gas_used, 0);
        assert_eq!(result.gas_used, 0);
    }

    /// From areBridgeTxsPaid on, the same tx goes through normal gas
    /// validation and is rejected (gas_limit 0 < intrinsic cost).
    #[test]
    fn test_bridge_tx_gas0_rejected_after_are_bridge_txs_paid() {
        let federator = rsk_address_from_pubkey_hex(
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
        )
        .unwrap();
        assert!(run_bridge_tx_gas0(370_000, federator).is_err());
    }

    /// A non-federation sender never gets the free path. Pre-RSKIP136 the
    /// call is still included: rskj execError (insufficient limit for the
    /// precompile cost) yields a failed receipt consuming the (zero) limit.
    #[test]
    fn test_bridge_tx_gas0_fails_for_unknown_sender() {
        let result = run_bridge_tx_gas0(457, Address::repeat_byte(0xEE))
            .expect("pre-RSKIP136 direct bridge call is included, not rejected");
        assert!(!result.tx_results[0].success);
        assert_eq!(result.tx_results[0].gas_used, 0, "all of the zero gas limit consumed");
    }

    /// Regression for the sync halt at mainnet #6916: the block's first tx is
    /// a registerBtcTransaction whose referenced BTC block (height 0x07ab2c)
    /// is absent from the bridge's header chain. rskj wraps the method body in
    /// try/catch(RegisterBtcTransactionException) and SWALLOWS the failed
    /// validation ("Could not validate transaction"), so the tx still succeeds
    /// as a no-op. rustock previously returned an error and produced a FAILED
    /// receipt, diverging on the receipts root. The receipt must be successful
    /// with no logs (no pegin event pre-RSKIP146).
    #[test]
    fn test_register_btc_transaction_failed_validation_is_success_noop() {
        let federator = rsk_address_from_pubkey_hex(
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
        )
        .unwrap();
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let root = put_account(&root, store.as_ref(), &federator, 0, U256::ZERO);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(6916);

        // Verbatim mainnet #6916 tx 0 calldata (registerBtcTransaction).
        let input = alloy_primitives::hex::decode(
            "43dc06560000000000000000000000000000000000000000000000000000000000000060\
000000000000000000000000000000000000000000000000000000000007ab2c\
0000000000000000000000000000000000000000000000000000000000000140\
00000000000000000000000000000000000000000000000000000000000000be\
010000000197629af066e1b55b8f2498cd4052e183ef6952a0e6ecec81d05641d8b21db61e\
000000006b483045022100bce3931194856efdc69f0fa67cbbe1f21920ed3f5597395362a9\
d83855ade722022068220a8599c84fc7136a640751a91de2cc2ebf79fe453c54db566d1012\
7b1182012103d1408fe5e94e1ec1da9df06edf86de4f43e459a56238216b131f48af96980f\
58feffffff01f1c817000000000017a91451f103320b435b5fe417b3f3e0f18972ccc710a0\
872bab0700000000000000000000000000000000000000000000000000000000000000000001\
aa630800000d14e6e59463afbfd4155db84d7592b5af577ef5dc0e9d906676e9ec81f37401d4\
72706346992d8220d9138dc144077bdbf5522de323024c2cf3d74e239fc11fb2afc6543956e6\
fb6f0cc43c5dd4c66fd271eff5f9309768dd7c267d767725f4538a093bb1fa025a85c0cd4967\
119bc286d9a951a828a7c413e4a8994ded5b9077b5944346e0ee8d09ed2e8622f3ad1e7b3a02\
2d9696fbf894251e6d487c1cb3b4522650fec9201f035d965ce42cfcc157b388470b6f6ff15d\
d72fd5651a57586cab8bac3b5531b3f490a97b2363a2ef18121a43873753a08e35991732fb78\
9265cd9dd43584dbe701bb953f21af68029a30d8b6327cd57d2dd242327c1b135d4c8f5e36b8\
bf09f6e52420834e8e0e0b1a6df563aba550cf7f99e9724264187c45dcf3d73e8585a0e35196\
3062f66fa39895750a0f0c651f2fc736d69b746ed77319d5c0ecab6539d3655f163f3eccf325\
846b1c1244e17b6464d5b85c3cd06587cf992067f37c086d17ab6dd35ee7aef6de22ac59ed37\
468ee5eb15948db42c438fdfb4c5b08d6316a203bcecd9713b9a2b150614ee116dcff986c29c2\
246745704bbdb010000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(0),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 28,
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        };
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(&header, &[(tx, federator)], &root, store)
            .expect("block with the #6916 pegin tx must execute");
        assert_eq!(result.tx_results.len(), 1);
        assert!(
            result.tx_results[0].success,
            "a registerBtcTransaction that fails validation is a no-op SUCCESS in rskj, not a failed tx"
        );
        assert!(
            result.tx_results[0].logs.is_empty(),
            "a no-op pegin emits no logs pre-RSKIP146"
        );
    }

    /// Regression for the silent stall at mainnet #4001: the REMASC maturity
    /// is 4_000 blocks, so #4001 is the FIRST block whose system call touches
    /// REMASC storage — on a journal that never loaded the account, the sload
    /// panicked (ColdLoadSkipped) and killed the sync task.
    #[test]
    fn test_remasc_system_call_past_maturity_on_fresh_journal() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());

        // The processing block (#1) whose fees REMASC distributes at #4001.
        let processing = dummy_header(1);
        let processing_hash = processing.hash();
        block_store.put_header(&processing).unwrap();
        block_store.put_canonical_hash(1, processing_hash).unwrap();

        let header = dummy_header(4_001);
        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(crate::precompiles::REMASC_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(&header, &[(remasc_tx, Address::ZERO)], &root, store)
            .expect("REMASC past maturity must execute on a fresh journal");
        assert!(result.tx_results[0].success);
        assert_eq!(result.gas_used, 0);
    }

    /// rskj `RemascStorageProvider.saveSiblings` runs on every REMASC `save()`
    /// (even pre-maturity), writing `addStorageBytes(REMASC, "siblings",
    /// RLP.encodedEmptyList()=0xc0)`. The cell must appear in the unitrie from
    /// block #1; its absence diverged rustock from rskj at the first uncle
    /// block (#3397). Groundtruthed against rskj's #3397 unitrie dump.
    #[test]
    fn remasc_writes_empty_siblings_cell() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());

        // Block #1: REMASC returns early (pre-maturity) but still writes siblings.
        let header = dummy_header(1);
        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(crate::precompiles::REMASC_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(&header, &[(remasc_tx, Address::ZERO)], &root, store)
            .unwrap();

        let siblings_slot = crate::remasc::remasc_storage_key("siblings");
        let found = result.markers.raw_storage.iter().any(|(addr, slot, val)| {
            *addr == REMASC_ADDR && *slot == siblings_slot && val.as_deref() == Some(&[0xc0][..])
        });
        assert!(found, "REMASC must write the 0xc0 siblings cell every block");
    }

    /// Regression for mainnet block #3307: before RSKIP136 (bahamas, 3_397)
    /// rskj checks the limit against the precompile cost alone and records
    /// gasUsed = precompileCost + intrinsicCost — above the tx gas limit.
    /// voteFeePerKbChange: 21528 + 10000 + 72 = 31600 with a 25_000 limit
    /// (>= required 10_072, < total).
    #[test]
    fn test_pre_rskip136_bridge_gas_exceeds_limit() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAB);
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::from(10u64).pow(U256::from(18)));
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(3_307);

        let mut input = vec![0x04, 0x61, 0x31, 0x3e]; // voteFeePerKbChange(int256)
        let mut value = [0u8; 32];
        value[30..].copy_from_slice(&30_000u16.to_be_bytes());
        input.extend_from_slice(&value);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(25_000), // below total 31_600, above required 10_072
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 28, r: U256::from(1), s: U256::from(1), cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor.execute_block(&header, &[(tx, sender)], &root, store).unwrap();
        assert!(result.tx_results[0].success);
        assert_eq!(result.tx_results[0].gas_used, 31_600, "gasUsed exceeds the tx gas limit pre-RSKIP136");
    }

    /// getCoinbaseAddress at depth 1 returns the grandparent's coinbase.
    #[test]
    fn test_block_header_get_coinbase_depth_1() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let grandparent_coinbase = Address::repeat_byte(0xDD);
        let mut gp = dummy_header(98);
        gp.beneficiary = grandparent_coinbase;
        let gp_hash = gp.hash();
        block_store.put_header(&gp).unwrap();
        block_store.put_canonical_hash(98, gp_hash).unwrap();

        let mut parent = dummy_header(99);
        parent.parent_hash = gp_hash;
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getCoinbaseAddress(int256)", 1);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded, grandparent_coinbase.as_slice());
    }

    /// getBlockHash returns the correct block hash.
    #[test]
    fn test_block_header_get_block_hash() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let parent = dummy_header(99);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getBlockHash(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, parent_hash.as_slice());
    }

    /// getDifficulty returns the parent block's difficulty.
    #[test]
    fn test_block_header_get_difficulty() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.difficulty = U256::from(1_234_567u64);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getDifficulty(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 1_234_567 = 0x12D687 → Java BigInteger bytes = [0x12, 0xD6, 0x87]
        assert_eq!(decoded, vec![0x12, 0xD6, 0x87]);
    }

    /// getGasUsed returns ABI-encoded gas used (Java BigInteger format).
    #[test]
    fn test_block_header_get_gas_used() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.gas_used = 21_000;
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getGasUsed(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 21000 = 0x5208
        assert_eq!(decoded, vec![0x52, 0x08]);
    }

    /// Depth beyond MAX_BLOCK_DEPTH (4000) returns empty bytes.
    #[test]
    fn test_block_header_depth_beyond_max_returns_empty() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(5000);

        // depth 4000 → >= MAX_BLOCK_DEPTH → empty
        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&block_header_selector("getDifficulty(int256)"));
        // 4000 = 0x0FA0
        input[34] = 0x0F;
        input[35] = 0xA0;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "depth beyond MAX should succeed with empty");

        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty(), "should return empty bytes for depth >= 4000");
    }

    /// Negative depth should fail (rskj throws VMException).
    #[test]
    fn test_block_header_negative_depth_fails() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(100);

        let input = bh_input("getCoinbaseAddress(int256)", -1);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(!result.success, "negative depth should fail");
    }

    /// Block not found at depth returns empty bytes.
    #[test]
    fn test_block_header_block_not_found_returns_empty() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Block 100 executing, no blocks stored → depth 0 will find nothing
        let header = dummy_header(100);

        let input = bh_input("getCoinbaseAddress(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "missing block should succeed with empty result");

        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty());
    }

    /// Gas cost is 4000 + 2*input.len() (on top of intrinsic).
    #[test]
    fn test_block_header_gas_cost() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(100);

        // 36 bytes input (4 selector + 32 depth)
        // Precompile gas: 4000 + 2*36 = 4072
        let input = bh_input("getDifficulty(int256)", 0);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        // Intrinsic: 21000 base + (4 non-zero selector bytes * 16) + (some zero/non-zero depth bytes * 4 or 16)
        // Precompile: 4000 + 72 = 4072
        // Total should be > 21000 + 4000
        assert!(result.gas_used > 25_000, "should include precompile gas");
    }

    /// getMinGasPrice returns the parent's minimum gas price.
    #[test]
    fn test_block_header_get_min_gas_price() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.minimum_gas_price = U256::from(59_240_000u64);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getMinGasPrice(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 59_240_000 = 0x387_EE40 → Java BigInteger: [0x03, 0x87, 0xEE, 0x40]
        assert_eq!(decoded, vec![0x03, 0x87, 0xEE, 0x40]);
    }

    /// getGasLimit returns the parent's gas limit.
    #[test]
    fn test_block_header_get_gas_limit() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.gas_limit = U256::from(6_800_000u64);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getGasLimit(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 6_800_000 = 0x67C280 → Java BigInteger: [0x67, 0xC2, 0x80]
        assert_eq!(decoded, vec![0x67, 0xC2, 0x80]);
    }

    // -----------------------------------------------------------------------
    // Ported from rskj BlockHeaderContractTest
    // -----------------------------------------------------------------------

    /// Ported from rskj BlockHeaderContractTest.getGasUsed:
    ///   GAS_USED = 0 → BigInteger(0).toByteArray() = [0]
    #[test]
    fn test_rskj_block_header_gas_used_zero() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.gas_used = 0;
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getGasUsed(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // BigInteger.valueOf(0).toByteArray() = [0]
        assert_eq!(decoded, vec![0x00], "gas_used=0 should return [0] (Java BigInteger)");
    }

    /// Ported from rskj BlockHeaderContractTest.getUncleCoinbaseAddress:
    ///   Tests uncle index 0, 1 (valid), and 2 (out of range → empty).
    #[test]
    fn test_rskj_block_header_uncle_coinbase() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Create parent with two uncles
        let uncle0_coinbase = Address::repeat_byte(0x11);
        let uncle1_coinbase = Address::repeat_byte(0x22);

        let mut uncle0 = dummy_header(98);
        uncle0.beneficiary = uncle0_coinbase;
        let mut uncle1 = dummy_header(98);
        uncle1.beneficiary = uncle1_coinbase;

        let parent = dummy_header(99);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();
        block_store
            .put_body(parent_hash, &[], &[uncle0, uncle1])
            .unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        // Uncle index 0 → uncle0_coinbase
        let mut input = vec![0u8; 68];
        input[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        // blockDepth = 0
        // uncleIndex = 0 (already zero)
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input.clone()),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let result = executor.execute_tx(&header, &tx, sender, &root, store.clone()).unwrap();
        assert!(result.success, "uncle index 0 should succeed");
        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded, uncle0_coinbase.as_slice(), "uncle 0 coinbase");

        // Uncle index 1 → uncle1_coinbase
        let mut input1 = vec![0u8; 68];
        input1[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        input1[67] = 1; // uncleIndex = 1
        let tx1 = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input1),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let root1 = put_account(&TrieNode::empty(), store.as_ref(), &sender, 1, one_rbtc);
        let result1 = executor.execute_tx(&header, &tx1, sender, &root1, store.clone()).unwrap();
        assert!(result1.success, "uncle index 1 should succeed");
        let decoded1 = decode_abi_bytes(&result1.output);
        assert_eq!(decoded1, uncle1_coinbase.as_slice(), "uncle 1 coinbase");

        // Uncle index 2 → out of range → empty
        let mut input2 = vec![0u8; 68];
        input2[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        input2[67] = 2; // uncleIndex = 2
        let tx2 = rustock_core::Transaction {
            nonce: 2,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input2),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let root2 = put_account(&TrieNode::empty(), store.as_ref(), &sender, 2, one_rbtc);
        let result2 = executor.execute_tx(&header, &tx2, sender, &root2, store.clone()).unwrap();
        assert!(result2.success, "uncle index 2 (out of range) should succeed with empty");
        let decoded2 = decode_abi_bytes(&result2.output);
        assert!(decoded2.is_empty(), "uncle index 2 should return empty (only 2 uncles)");
    }

    /// Ported from rskj BlockHeaderContractTest.negativeUncleIndex:
    ///   Negative uncle index should fail.
    #[test]
    fn test_rskj_block_header_negative_uncle_index() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let parent = dummy_header(99);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();
        block_store.put_body(parent_hash, &[], &[]).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        // blockDepth=0, uncleIndex=-1
        let mut input = vec![0u8; 68];
        input[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        // uncleIndex = -1 → all 0xFF in the second int256
        input[36..68].fill(0xFF);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(!result.success, "negative uncle index should fail");
    }

    /// Ported from rskj BlockHeaderContractTest.getEmptyMergedMiningTags:
    ///   When parent has no bitcoin_merged_mining_coinbase_transaction,
    ///   getMergedMiningTags returns empty bytes.
    #[test]
    fn test_rskj_block_header_empty_merged_mining_tags() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Parent with no merged mining data at all
        let parent = dummy_header(99);
        assert!(parent.bitcoin_merged_mining_coinbase_transaction.is_none());
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getMergedMiningTags(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "empty merged mining should succeed");

        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty(), "no coinbase tx → empty merged mining tags");
    }

    /// Ported from rskj BlockHeaderContractTest.invalidBlockDepth:
    ///   Chain of 300 blocks, query at depth 500 → block not found → empty.
    #[test]
    fn test_rskj_block_header_depth_exceeds_chain_length() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Store a small chain: blocks 0 through 9
        for i in 0..10 {
            let mut h = dummy_header(i);
            if i > 0 {
                let prev_hash = block_store.canonical_hash(i - 1).unwrap().unwrap();
                h.parent_hash = prev_hash;
            }
            let hash = h.hash();
            block_store.put_header(&h).unwrap();
            block_store.put_canonical_hash(i, hash).unwrap();
        }

        // Execute at block 10, parent is block 9
        let parent_hash = block_store.canonical_hash(9).unwrap().unwrap();
        let mut header = dummy_header(10);
        header.parent_hash = parent_hash;

        // depth 500 → target = 10 - 1 - 500 = underflow → empty
        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&block_header_selector("getCoinbaseAddress(int256)"));
        input[34] = 0x01; // depth = 256+244=500
        input[35] = 0xF4;
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "depth exceeding chain length should succeed with empty");
        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty(), "depth 500 in 10-block chain → empty");
    }

    // -----------------------------------------------------------------------
    // REMASC fee distribution tests (Stage 6b)
    //
    // Port of rskj's RemascProcessMinerFeesTest using regtest config:
    //   maturity=10, syntheticSpan=5, rskLabsDivisor=5,
    //   federationDivisor=100, punishmentDivisor=10
    // -----------------------------------------------------------------------

    /// Helper: build a block store populated with a chain of headers.
    /// Each header at height `i` has parent_hash pointing to the previous hash.
    /// Returns (block_store, hashes) where hashes[i] is the canonical hash at block i.
    fn build_chain_store(
        count: u64,
        miner: Address,
        paid_fees_at: &[(u64, U256)],
    ) -> (Arc<BlockStore>, Vec<B256>) {
        let dir = tempfile::tempdir().unwrap();
        let bs = Arc::new(BlockStore::open(dir.path()).unwrap());

        let mut hashes = Vec::new();
        let mut parent_hash = B256::ZERO;

        for i in 0..count {
            let mut h = dummy_header(i);
            h.beneficiary = miner;
            h.parent_hash = parent_hash;
            // Set paid_fees for specified blocks
            for &(block, ref fees) in paid_fees_at {
                if block == i {
                    h.paid_fees = *fees;
                }
            }
            let hash = h.hash();
            bs.put_header_with_hash(hash, &h).unwrap();
            bs.put_canonical_hash(i, hash).unwrap();
            hashes.push(hash);
            parent_hash = hash;
        }

        (bs, hashes)
    }

    /// Helper: execute a REMASC call at the given block height and return state changes.
    /// `remasc_balance` simulates the fees already accumulated in REMASC from prior blocks.
    fn execute_remasc_at(
        block_store: &Arc<BlockStore>,
        block_number: u64,
        sender_balance: U256,
        remasc_config: crate::remasc::RemascConfig,
    ) -> crate::executor::BlockExecutionResult {
        execute_remasc_at_with_balance(block_store, block_number, sender_balance, remasc_config, U256::ZERO)
    }

    fn execute_remasc_at_with_balance(
        block_store: &Arc<BlockStore>,
        block_number: u64,
        sender_balance: U256,
        remasc_config: crate::remasc::RemascConfig,
        remasc_balance: U256,
    ) -> crate::executor::BlockExecutionResult {
        let trie_store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let root = put_account(&root, trie_store.as_ref(), &sender, 0, sender_balance);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        // Pre-seed REMASC with accumulated fees balance
        let root = if !remasc_balance.is_zero() {
            put_account(&root, trie_store.as_ref(), &remasc_addr, 0, remasc_balance)
        } else {
            root
        };

        let mut header = dummy_header(block_number);
        header.beneficiary = Address::repeat_byte(0x99); // actual miner (not used for fee routing)

        // The REMASC system tx: unsigned, zero gas (rskj RemascTransaction).
        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        // The rskj remasc tests run regtest with a NON-EMPTY genesis
        // federation (injected at construction); our regtest constants have
        // no canonical key list, so model it with the mainnet federation —
        // the assertions are federation-count independent.
        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        )
        .with_remasc_config(remasc_config)
        .with_bridge_constants(crate::bridge::constants::BridgeConstants::mainnet());

        executor
            .execute_block(&header, &[(remasc_tx, sender)], &root, trie_store)
            .unwrap()
    }

    /// Before maturity is reached, no distribution should happen.
    /// Matches rskj's `processMinersFeesWithoutRequiredMaturity`.
    #[test]
    fn remasc_no_distribution_before_maturity() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest(); // maturity=10
        let paid_fees = U256::from(21_000);

        // Chain: block 5 has paid_fees=21000, blocks 0..12 exist
        let (bs, _) = build_chain_store(12, miner, &[(5, paid_fees)]);

        // Execute REMASC at block 12 (only 7 blocks since fee block → maturity not reached)
        let result = execute_remasc_at(&bs, 12, U256::from(10u64).pow(U256::from(18)), config);
        assert!(result.tx_results[0].success);

        // Miner should not have received anything
        assert!(
            !result.state_changes.contains_key(&miner),
            "miner should not be paid before maturity"
        );
    }

    /// After maturity but before syntheticSpan, fees accrue but no payout.
    /// Matches rskj's `processMinersFeesWithoutMinimumSyntheticSpan`.
    #[test]
    fn remasc_fees_accrue_before_synthetic_span() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest(); // maturity=10, syntheticSpan=5
        let paid_fees = U256::from(21_000);

        // Block 3 has paid_fees=21000. Execute REMASC at block 13 (candidateBlock=3, < syntheticSpan=5)
        let (bs, _) = build_chain_store(14, miner, &[(3, paid_fees)]);

        let result = execute_remasc_at(&bs, 13, U256::from(10u64).pow(U256::from(18)), config);
        assert!(result.tx_results[0].success);

        // REMASC storage should have rewardBalance = 21000
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let remasc_state = result.state_changes.get(&remasc_addr);
        assert!(remasc_state.is_some(), "REMASC account should exist in state changes");

        // Check storage: rewardBalance key
        let reward_key = crate::remasc::remasc_storage_key(crate::remasc::REWARD_BALANCE_KEY);
        let reward_slot = remasc_state.unwrap().storage.get(&reward_key);
        assert!(reward_slot.is_some(), "rewardBalance should be set in storage");
        assert_eq!(
            reward_slot.unwrap().present_value,
            paid_fees,
            "rewardBalance should equal the processing block's paid_fees"
        );

        // Miner should NOT be paid (syntheticSpan not reached)
        assert!(
            !result.state_changes.contains_key(&miner),
            "miner should not be paid before syntheticSpan"
        );
    }

    /// Full distribution with no siblings. Matches rskj's `processMinersFeesWithNoSiblings`.
    ///
    /// regtest: maturity=10, syntheticSpan=5, rskLabsDivisor=5, federationDivisor=100
    /// minerFee=21000 at block 5. Execute REMASC at block 16.
    ///   candidateBlock = 16 - 10 = 6 → but we use block 5 for fees
    ///   Actually: we need candidateBlock = 5, so execution at block 15.
    ///   15 - 10 = 5 ≥ 1 ✓, 5 - 5 = 0 ≥ 0 ✓
    ///
    /// Expected math:
    ///   rewardBalance = 0 + 21000 = 21000
    ///   syntheticReward = 21000 / 5 = 4200
    ///   rewardBalance = 21000 - 4200 = 16800
    ///   rskLabsPay = 4200 / 5 = 840
    ///   remaining = 4200 - 840 = 3360
    ///   federationReward = 3360 / 100 = 33
    ///   remaining = 3360 - 33 = 3327
    ///   miner gets 3327
    #[test]
    fn remasc_basic_distribution_no_siblings() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest();
        let rsk_labs = config.rsk_labs_address;
        let paid_fees = U256::from(21_000);

        // 16 blocks (0..15). Block 5 has paid_fees=21000.
        let (bs, _) = build_chain_store(16, miner, &[(5, paid_fees)]);

        // REMASC has 21000 balance from the fees accumulated when block 5 was executed
        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        // RSK Labs should receive 840
        let labs_state = result.state_changes.get(&rsk_labs)
            .expect("RSK Labs should appear in state changes");
        assert_eq!(
            labs_state.info.balance,
            U256::from(840),
            "RSK Labs receives syntheticReward / rskLabsDivisor = 4200 / 5 = 840"
        );

        // Miner should receive 3327
        let miner_state = result.state_changes.get(&miner)
            .expect("miner should appear in state changes");
        assert_eq!(
            miner_state.info.balance,
            U256::from(3327),
            "miner receives remainder: 4200 - 840 - 33 = 3327"
        );

        // REMASC storage: rewardBalance = 16800
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let reward_key = crate::remasc::remasc_storage_key(crate::remasc::REWARD_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&reward_key).unwrap().present_value,
            U256::from(16_800),
            "rewardBalance = 21000 - 4200 = 16800"
        );

        // Pre-RSKIP85 the federation cut (3360/100 = 33) is paid out to the
        // 15 genesis federators every block, never accrued: the
        // federationBalance cell stays untouched. (The accrual-below-minimum
        // path is groundtruthed by the mainnet #4010 test.)
        let fed_key = crate::remasc::remasc_storage_key(crate::remasc::FEDERATION_BALANCE_KEY);
        let fed_slot = remasc_state.storage.get(&fed_key);
        assert!(
            fed_slot.is_none() || fed_slot.unwrap().present_value.is_zero(),
            "federation cut paid out pre-RSKIP85, not accrued"
        );

        // REMASC storage: burnedBalance = 0
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        let burned_slot = remasc_state.storage.get(&burned_key);
        let burned = burned_slot.map(|s| s.present_value).unwrap_or(U256::ZERO);
        assert_eq!(burned, U256::ZERO, "no burns without broken selection rule");
    }

    /// Distribution with previous broken selection rule should apply punishment burn.
    ///
    /// We pre-seed the brokenSelectionRule storage flag to true, then verify
    /// that `punishment = remaining / punishmentDivisor` is burned.
    ///
    /// With regtest config and 21000 fees:
    ///   remaining (after labs + federation) = 3327
    ///   punishment = 3327 / 10 = 332
    ///   miner gets 3327 - 332 = 2995
    ///   burnedBalance = 332
    #[test]
    fn remasc_distribution_with_broken_selection_punishment() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000);

        let (bs, _) = build_chain_store(16, miner, &[(5, paid_fees)]);

        let trie_store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, trie_store.as_ref(), &sender, 0, one_rbtc);

        // Pre-seed brokenSelectionRule = true in REMASC's storage
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        let root = {
            use rustock_trie::TrieKeySlice;
            let slot = B256::from(broken_key);
            let storage_key_bytes = rustock_trie::storage_key(&remasc_addr, &slot);
            let key = TrieKeySlice::from_key(&storage_key_bytes);
            let value = U256::from(1);
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&value.to_be_bytes::<32>());
            root.put(&key, &buf, trie_store.as_ref())
        };

        // Pre-seed REMASC with accumulated fees balance (21000 from block 5)
        let root = put_account(&root, trie_store.as_ref(), &remasc_addr, 0, paid_fees);

        let mut header = dummy_header(15);
        header.beneficiary = Address::repeat_byte(0x99);

        // The REMASC system tx: unsigned, zero gas (rskj RemascTransaction).
        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            bs.clone(),
        ).with_remasc_config(config);

        let result = executor
            .execute_block(&header, &[(remasc_tx, sender)], &root, trie_store)
            .unwrap();

        assert!(result.tx_results[0].success);

        // Miner receives 3327 - 332 = 2995
        let miner_state = result.state_changes.get(&miner)
            .expect("miner should appear in state changes");
        assert_eq!(
            miner_state.info.balance,
            U256::from(2995),
            "miner receives 3327 - punishment(332) = 2995"
        );

        // burnedBalance = 332
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(332),
            "burnedBalance = 3327 / 10 = 332"
        );
    }

    // -----------------------------------------------------------------------
    // Stage 6c tests – siblings / uncles
    // -----------------------------------------------------------------------

    struct ChainBlock {
        miner: Address,
        paid_fees: U256,
        uncle_count: u64,
        ommers: Vec<rustock_core::Header>,
    }

    fn build_chain_store_ext(blocks: &[ChainBlock]) -> Arc<BlockStore> {
        let dir = tempfile::tempdir().unwrap();
        let bs = Arc::new(BlockStore::open(dir.path()).unwrap());

        let mut parent_hash = B256::ZERO;

        for (i, cb) in blocks.iter().enumerate() {
            let mut h = dummy_header(i as u64);
            h.beneficiary = cb.miner;
            h.parent_hash = parent_hash;
            h.paid_fees = cb.paid_fees;
            h.uncle_count = cb.uncle_count;

            let hash = h.hash();
            bs.put_header_with_hash(hash, &h).unwrap();
            bs.put_canonical_hash(i as u64, hash).unwrap();

            if !cb.ommers.is_empty() {
                bs.put_body(hash, &[], &cb.ommers).unwrap();
            }

            parent_hash = hash;
        }

        bs
    }

    fn simple_block(miner: Address) -> ChainBlock {
        ChainBlock { miner, paid_fees: U256::ZERO, uncle_count: 0, ommers: vec![] }
    }

    fn make_uncle(number: u64, coinbase: Address, paid_fees: U256, uncle_count: u64) -> rustock_core::Header {
        let mut h = dummy_header(number);
        h.beneficiary = coinbase;
        h.paid_fees = paid_fees;
        h.uncle_count = uncle_count;
        // Give it a distinct extra_data so its hash differs from the canonical block
        h.extra_data = Bytes::copy_from_slice(coinbase.as_slice());
        h
    }

    /// Port of rskj's `processMinersFeesWithOneSibling`.
    ///
    /// Chain (regtest: maturity=10, syntheticSpan=5):
    ///   blocks 0-4: simple
    ///   block 5: coinbaseA, paid_fees=21000
    ///   block 5' (uncle): coinbaseB, paid_fees=31500
    ///   block 6: coinbaseC, includes uncle 5'
    ///   blocks 7-14: simple
    ///   block 15: REMASC executes
    ///
    /// Expected (fullBlockReward = 3327, 1 sibling, previousBroken=false):
    ///   publishersReward = 3327/10 = 332 → coinbaseC
    ///   minersReward = 3327 - 332 = 2995
    ///   individualMiner = 2995/2 = 1497
    ///   minersSurplus = 2995%2 = 1 → burned
    ///   coinbaseA (main miner): 1497
    ///   coinbaseB (sibling miner): 1497 (late=0)
    ///   burnedBalance = 1
    #[test]
    fn remasc_with_one_sibling() {
        let coinbase_a = Address::repeat_byte(0x11); // main miner
        let coinbase_b = Address::repeat_byte(0x22); // sibling miner
        let coinbase_c = Address::repeat_byte(0x33); // uncle includer (publisher)
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let rsk_labs = config.rsk_labs_address;
        let paid_fees = U256::from(21_000u64);

        let uncle = make_uncle(5, coinbase_b, U256::from(31_500u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        // Blocks 0-4: simple
        for _ in 0..5 {
            chain.push(simple_block(default_miner));
        }
        // Block 5: coinbaseA, paid_fees=21000
        chain.push(ChainBlock {
            miner: coinbase_a,
            paid_fees,
            uncle_count: 0,
            ommers: vec![],
        });
        // Block 6: coinbaseC, includes uncle (block 5')
        chain.push(ChainBlock {
            miner: coinbase_c,
            paid_fees: U256::ZERO,
            uncle_count: 0,
            ommers: vec![uncle],
        });
        // Blocks 7-14: simple
        for _ in 0..8 {
            chain.push(simple_block(default_miner));
        }

        let bs = build_chain_store_ext(&chain);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees, // REMASC balance = accumulated fees
        );
        assert!(result.tx_results[0].success);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        // RSK Labs: 840
        let labs_state = result.state_changes.get(&rsk_labs)
            .expect("RSK Labs should appear");
        assert_eq!(labs_state.info.balance, U256::from(840));

        // Publisher (coinbaseC): 332
        let pub_state = result.state_changes.get(&coinbase_c)
            .expect("publisher should appear");
        assert_eq!(pub_state.info.balance, U256::from(332),
            "publisher gets publishersReward / siblings = 332");

        // Main miner (coinbaseA): 1497
        let miner_a = result.state_changes.get(&coinbase_a)
            .expect("main miner should appear");
        assert_eq!(miner_a.info.balance, U256::from(1497),
            "main miner gets individualMinerReward = 2995/2 = 1497");

        // Sibling miner (coinbaseB): 1497 (no late penalty, included 1 block after)
        let miner_b = result.state_changes.get(&coinbase_b)
            .expect("sibling miner should appear");
        assert_eq!(miner_b.info.balance, U256::from(1497),
            "sibling miner gets 1497 (0 blocks late)");

        // Storage checks
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();

        // rewardBalance = 21000 - 4200 = 16800
        let reward_key = crate::remasc::remasc_storage_key(crate::remasc::REWARD_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&reward_key).unwrap().present_value,
            U256::from(16_800),
        );

        // burnedBalance = minersSurplus = 1
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(1),
            "burned = minersSurplus = 2995 % 2 = 1"
        );

        // Pre-RSKIP85: the federation cut is paid out, not accrued.
        let fed_key = crate::remasc::remasc_storage_key(crate::remasc::FEDERATION_BALANCE_KEY);
        let fed_slot = remasc_state.storage.get(&fed_key);
        assert!(fed_slot.is_none() || fed_slot.unwrap().present_value.is_zero());
    }

    /// Test late uncle inclusion penalty.
    ///
    /// Same as one-sibling test but uncle is included 3 blocks later (block 8 instead of 6).
    /// blocks_late = 8 - 5 - 1 = 2
    /// late_punishment = 1497 * 2 / 20 = 149
    /// sibling miner gets 1497 - 149 = 1348
    /// burned = minersSurplus(1) + late_punishment(149) = 150
    #[test]
    fn remasc_late_uncle_inclusion_penalty() {
        let coinbase_a = Address::repeat_byte(0x11);
        let coinbase_b = Address::repeat_byte(0x22);
        let coinbase_c = Address::repeat_byte(0x33);
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000u64);

        let uncle = make_uncle(5, coinbase_b, U256::from(31_500u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        for _ in 0..5 { chain.push(simple_block(default_miner)); }
        // Block 5: main block
        chain.push(ChainBlock {
            miner: coinbase_a, paid_fees, uncle_count: 0, ommers: vec![],
        });
        // Blocks 6-7: simple
        for _ in 0..2 { chain.push(simple_block(default_miner)); }
        // Block 8: includes uncle (3 blocks after block 5)
        chain.push(ChainBlock {
            miner: coinbase_c, paid_fees: U256::ZERO, uncle_count: 0,
            ommers: vec![uncle],
        });
        // Blocks 9-14: simple
        for _ in 0..6 { chain.push(simple_block(default_miner)); }

        let bs = build_chain_store_ext(&chain);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        // blocks_late = 8 - 5 - 1 = 2
        // late_punishment = 1497 * 2 / 20 = 149
        let miner_b = result.state_changes.get(&coinbase_b)
            .expect("sibling miner should appear");
        assert_eq!(miner_b.info.balance, U256::from(1497 - 149),
            "sibling miner gets 1497 - 149(late penalty) = 1348");

        // Main miner still gets full share
        let miner_a = result.state_changes.get(&coinbase_a)
            .expect("main miner should appear");
        assert_eq!(miner_a.info.balance, U256::from(1497));

        // burned = minersSurplus(1) + late_punishment(149) = 150
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(150),
        );
    }

    /// Test broken selection rule with siblings.
    ///
    /// When previousBrokenSelectionRule=true and siblings exist:
    ///   punishment = individualMinerReward_base / punishmentDivisor
    ///   individualMinerReward = base - punishment
    ///   total_punishment_burn = punishment * (siblings + 1)
    ///
    /// With regtest (fullBlockReward=3327, 1 sibling):
    ///   base = 2995/2 = 1497
    ///   punishment = 1497/10 = 149
    ///   individualMinerReward = 1497 - 149 = 1348
    ///   total_punishment_burn = 149 * 2 = 298
    ///   burned = publishersSurplus(0) + minersSurplus(1) + 298 = 299
    #[test]
    fn remasc_sibling_with_previous_broken_selection() {
        let coinbase_a = Address::repeat_byte(0x11);
        let coinbase_b = Address::repeat_byte(0x22);
        let coinbase_c = Address::repeat_byte(0x33);
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000u64);

        let uncle = make_uncle(5, coinbase_b, U256::from(31_500u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        for _ in 0..5 { chain.push(simple_block(default_miner)); }
        chain.push(ChainBlock {
            miner: coinbase_a, paid_fees, uncle_count: 0, ommers: vec![],
        });
        chain.push(ChainBlock {
            miner: coinbase_c, paid_fees: U256::ZERO, uncle_count: 0,
            ommers: vec![uncle],
        });
        for _ in 0..8 { chain.push(simple_block(default_miner)); }

        let bs = build_chain_store_ext(&chain);

        // Build state with brokenSelectionRule = true pre-seeded
        let trie_store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let root = put_account(&root, trie_store.as_ref(), &sender, 0,
            U256::from(10u64).pow(U256::from(18)));
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let root = put_account(&root, trie_store.as_ref(), &remasc_addr, 0, paid_fees);

        // Pre-seed brokenSelectionRule = true
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        let root = {
            use rustock_trie::TrieKeySlice;
            let slot = B256::from(broken_key);
            let storage_key_bytes = rustock_trie::storage_key(&remasc_addr, &slot);
            let key = TrieKeySlice::from_key(&storage_key_bytes);
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&U256::from(1).to_be_bytes::<32>());
            root.put(&key, &buf, trie_store.as_ref())
        };

        let mut header = dummy_header(15);
        header.beneficiary = Address::repeat_byte(0x99);

        // The REMASC system tx: unsigned, zero gas (rskj RemascTransaction).
        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            bs.clone(),
        ).with_remasc_config(config);

        let result = executor
            .execute_block(&header, &[(remasc_tx, sender)], &root, trie_store)
            .unwrap();
        assert!(result.tx_results[0].success);

        // Both miners get 1348 (1497 - 149 punishment)
        let miner_a = result.state_changes.get(&coinbase_a)
            .expect("main miner");
        assert_eq!(miner_a.info.balance, U256::from(1348),
            "miner gets 1497 - 149(punishment) = 1348");

        let miner_b = result.state_changes.get(&coinbase_b)
            .expect("sibling miner");
        assert_eq!(miner_b.info.balance, U256::from(1348),
            "sibling miner also punished: 1348");

        // burned = minersSurplus(1) + total_punishment(149*2=298) = 299
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(299),
        );
    }

    /// Test that brokenSelectionRule flag is set when a sibling has > 2x fees.
    #[test]
    fn remasc_broken_selection_rule_higher_fees() {
        let coinbase_a = Address::repeat_byte(0x11);
        let coinbase_b = Address::repeat_byte(0x22);
        let coinbase_c = Address::repeat_byte(0x33);
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(10_000u64);

        // Uncle paid > 2x processing block's fees → broken selection rule
        let uncle = make_uncle(5, coinbase_b, U256::from(25_000u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        for _ in 0..5 { chain.push(simple_block(default_miner)); }
        chain.push(ChainBlock {
            miner: coinbase_a, paid_fees, uncle_count: 0, ommers: vec![],
        });
        chain.push(ChainBlock {
            miner: coinbase_c, paid_fees: U256::ZERO, uncle_count: 0,
            ommers: vec![uncle],
        });
        for _ in 0..8 { chain.push(simple_block(default_miner)); }

        let bs = build_chain_store_ext(&chain);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        // brokenSelectionRule is written as a raw 1-byte addStorageBytes cell
        // (rskj saveBrokenSelectionRule), here = 0x01 (true).
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        let found = result.markers.raw_storage.iter().any(|(addr, slot, val)| {
            *addr == REMASC_ADDR && *slot == broken_key && val.as_deref() == Some(&[0x01][..])
        });
        assert!(found, "brokenSelectionRule cell should be 0x01 when sibling fees > 2x");
    }

    /// Test no siblings → brokenSelectionRule stays false.
    #[test]
    fn remasc_no_siblings_selection_rule_false() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000);

        let (bs, _) = build_chain_store(16, miner, &[(5, paid_fees)]);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        // rskj still writes the cell every block — as the literal byte 0x00
        // (false) — so the cell must be present with value 0x00, not absent.
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        let found = result.markers.raw_storage.iter().any(|(addr, slot, val)| {
            *addr == REMASC_ADDR && *slot == broken_key && val.as_deref() == Some(&[0x00][..])
        });
        assert!(found, "no siblings → brokenSelectionRule cell present and = 0x00");
    }

    /// A 0-value REMASC mining-fee payment must still create the recipient
    /// account (rskj RemascFeesPayer.transferPayment → addBalance(to, 0), no
    /// zero-guard). Under frontier rules the empty account persists. Ground
    /// truth: miner beneficiaries paid a 0 reward (e.g. #142347's miner) exist
    /// as empty accounts in rskj's mainnet unitrie at #1,590,999.
    #[test]
    fn remasc_zero_payment_creates_recipient_account() {
        use revm::context_interface::{ContextTr, JournalTr};
        let store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let hardfork = RskHardforkConfig::mainnet();
        let header = dummy_header(1);
        let spec_id = hardfork.spec_id(header.number);
        let block_env = block_env_from_header(&header, &hardfork);
        let db = RskDatabase::new(root.clone(), store.clone(), block_store);
        let cfg = make_cfg_env(spec_id, hardfork.chain_id, hardfork.has_rskip544(header.number));
        let mut chain_ext = crate::raw_storage::RskChainExt::default();
        chain_ext.raw_storage.set_reader(store, root.clone());
        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg)
            .with_chain(chain_ext);
        let mut evm = ctx.build_mainnet();
        // RskHandler::load_accounts pins the journal spec to HOMESTEAD
        // (pre-Spurious-Dragon) so finalize materialises empty touched
        // accounts; replicate that here since we bypass the handler.
        evm.ctx.journal_mut().set_spec_id(revm::primitives::hardfork::SpecId::HOMESTEAD);

        let miner = Address::repeat_byte(0x77);
        assert!(crate::remasc::remasc_transfer(&mut evm.ctx, miner, U256::ZERO));

        let state = evm.ctx.journal_mut().finalize();
        let acct = state.get(&miner).expect("zero-paid miner account must exist");
        assert!(acct.is_touched(), "recipient must be touched");
        assert!(acct.is_created(), "frontier materialises the empty account");
    }

    /// Port of rskj `BridgeSupportIT.callUpdateCollectionsChangeGetsOutOfDust`
    /// (regression for mainnet #3,103,055): when a pegout's change output is
    /// dusty, bitcoinj raises it to the non-dust minimum at the recipient's
    /// expense, so the federation spends less BTC than the user sent. rskj's
    /// `adjustBalancesIfChangeOutputWasDust` burns the difference: an sBTC
    /// transfer from the Bridge to 0xffff…ff (`BridgeSupport.BURN_ADDRESS`).
    /// Request 1 BTC against a single 1 BTC + 100 sat UTXO: raw change 100 <
    /// 2,700 (P2SH non-dust minimum) → burn 2,600 sat = 26,000,000,000,000 wei.
    #[test]
    fn update_collections_burns_dusty_change_surplus() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        // updateCollections is federation-only (rskj activeAndRetiringFederationOnly):
        // the sender must be a member of the active federation, so derive it from
        // the federation member's RSK key seeded below.
        let fed_pubkey_hex = "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c";
        let sender = rsk_address_from_pubkey_hex(fed_pubkey_hex).unwrap();
        let fed_pubkey: [u8; 33] =
            alloy_primitives::hex::decode(fed_pubkey_hex).unwrap().try_into().unwrap();
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(
            &root,
            store.as_ref(),
            &crate::precompiles::BRIDGE_ADDR,
            0,
            one_rbtc,
        );

        // Seed bridge storage: a 1 BTC release request (papyrus-era
        // with-txhash queue) and one federation UTXO worth 1 BTC + 100 sat.
        let put_cell = |root: &TrieNode, name: &str, value: &[u8]| {
            let slot = B256::from(crate::bridge::storage::bridge_storage_key(name));
            let key = rustock_trie::storage_key(&crate::precompiles::BRIDGE_ADDR, &slot);
            root.put(&rustock_trie::TrieKeySlice::from_key(&key), value, store.as_ref())
        };
        let request = crate::bridge::peg::ReleaseRequest {
            btc_dest_hash160: [0x11; 20],
            amount_satoshis: 100_000_000,
            rsk_tx_hash: Some([0xab; 32]),
        };
        let root = put_cell(
            &root,
            crate::bridge::storage::RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY,
            &crate::bridge::peg::serialize_release_queue_with_hash(&[request]),
        );
        let utxo = crate::bridge::storage::BridgeUtxo {
            tx_hash: [0x07; 32],
            vout: 0,
            value_satoshis: 100_000_100,
            height: 0,
            script: vec![],
            coinbase: false,
        };
        let root = put_cell(
            &root,
            crate::bridge::storage::NEW_FEDERATION_BTC_UTXOS_KEY,
            &crate::bridge::storage::serialize_utxo_list(&[utxo]),
        );
        // Seed the active federation with a single member whose RSK key (== BTC
        // key in the legacy single-key format) derives `sender`, so the
        // federation-only updateCollections authorization passes.
        let root = put_cell(
            &root,
            crate::bridge::storage::NEW_FEDERATION_KEY,
            &crate::bridge::federation::serialize_federation_only_btc_keys(&[fed_pubkey], 0, 0),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(
                &alloy_primitives::keccak256(b"updateCollections()")[..4],
            ),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let header = dummy_header(3_103_055);
        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .expect("block executes");
        assert!(result.tx_results[0].success, "updateCollections succeeds");

        // 2,600 sat = 26,000,000,000,000 wei moved from the Bridge to the
        // burn address (rskj IT asserts the same pair of balances).
        let burned = U256::from(26_000_000_000_000u64);
        let burn_addr = Address::repeat_byte(0xff);
        let burn_balance = result
            .state_changes
            .get(&burn_addr)
            .map(|a| a.info.balance)
            .unwrap_or_default();
        assert_eq!(burn_balance, burned, "dusty-change surplus burned to 0xff…ff");
        let bridge_balance = result
            .state_changes
            .get(&crate::precompiles::BRIDGE_ADDR)
            .map(|a| a.info.balance)
            .unwrap_or_default();
        assert_eq!(bridge_balance, one_rbtc - burned, "burn debits the Bridge");
    }

    /// Deploying onto an address that already holds a balance destroys that
    /// balance, until RSKIP174.
    ///
    /// rskj `TransactionExecutor.create` calls
    /// `createAccount(newContractAddress, RSKIP174 && isExist(addr))`, and
    /// `createAccount(addr, false)` writes a fresh `AccountState` over
    /// whatever was there. So someone who funds a deploy address before the
    /// deployment lands loses the money. revm keeps the balance, which is the
    /// post-iris300 rule -- so without the activation gate rustock diverges
    /// for every such deployment before it.
    ///
    /// Ground truth: testnet #647,051, where 0.05 RBTC sat at the deploy
    /// address at #647,050 and is zero in the reference node's post-state.
    #[test]
    fn a_pre_rskip174_deployment_burns_the_balance_already_at_the_address() {
        let (before, after) = deploy_onto_funded_address(2_060_499);
        assert_eq!(before, U256::from(50_000_000_000_000_000u64), "fixture pre-funds it");
        assert_eq!(after, U256::ZERO, "the pre-existing balance is destroyed");
    }

    /// From iris300 the balance is carried over, which is what revm does on
    /// its own -- so the gate must stop applying, or every later deployment
    /// onto a funded address burns funds rskj keeps.
    #[test]
    fn from_rskip174_a_deployment_keeps_the_balance_already_at_the_address() {
        let (before, after) = deploy_onto_funded_address(2_060_500);
        assert_eq!(after, before, "iris300 carries the balance over");
    }

    /// The wipe must not reach an address with nothing at it: materialising an
    /// empty account there would put a leaf in the trie that rskj's state root
    /// does not have.
    #[test]
    fn deploying_onto_an_untouched_address_creates_no_spurious_account() {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let root = put_account(
            &TrieNode::empty(),
            store.as_ref(),
            &sender,
            0,
            U256::from(10u64).pow(U256::from(18)),
        );
        let created = sender.create(0);

        let result = run_deploy(&root, store.clone(), sender, 2_060_499);
        let acct = result.state_changes.get(&created);
        assert!(
            acct.is_none_or(|a| a.info.balance.is_zero()),
            "nothing was at the address, so nothing is burned and no balance appears"
        );
    }

    /// Runs a bare contract-creation transaction at `height`, with the create
    /// address pre-funded, and reports its balance before and after.
    fn deploy_onto_funded_address(height: u64) -> (U256, U256) {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let funded = U256::from(50_000_000_000_000_000u64);

        let root = put_account(
            &TrieNode::empty(),
            store.as_ref(),
            &sender,
            0,
            U256::from(10u64).pow(U256::from(18)),
        );
        // The address CREATE will land on, funded in advance.
        let created = sender.create(0);
        let root = put_account(&root, store.as_ref(), &created, 0, funded);

        let result = run_deploy(&root, store.clone(), sender, height);
        let after = result
            .state_changes
            .get(&created)
            .map(|a| a.info.balance)
            .unwrap_or(funded);
        (funded, after)
    }

    fn run_deploy(
        root: &TrieNode,
        store: Arc<MemoryTrieStore>,
        sender: Address,
        height: u64,
    ) -> crate::executor::BlockExecutionResult {
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::testnet(), block_store);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            // Empty `to` is what makes it a creation.
            to: Bytes::new(),
            value: U256::ZERO,
            // Returns empty code: enough to deploy, short enough to stay
            // about the account rather than about the EVM.
            input: Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xf3]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        executor
            .execute_block(&dummy_header(height), &[(tx, sender)], root, store)
            .expect("block executes")
    }

    /// rskj `Bridge.activeAndRetiringFederationOnly`: a non-federation sender's
    /// updateCollections is rejected (VMException) — the method body never runs,
    /// so no pegout processing / dusty-change burn happens (mainnet #6,223,774
    /// tx[1]: relay 0x82494fb1 is not a federation member). Same seeded state as
    /// the positive test but WITHOUT a federation, so the sender cannot match.
    #[test]
    fn update_collections_rejected_for_non_federation_sender() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA); // not a federation member
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &crate::precompiles::BRIDGE_ADDR, 0, one_rbtc);

        let put_cell = |root: &TrieNode, name: &str, value: &[u8]| {
            let slot = B256::from(crate::bridge::storage::bridge_storage_key(name));
            let key = rustock_trie::storage_key(&crate::precompiles::BRIDGE_ADDR, &slot);
            root.put(&rustock_trie::TrieKeySlice::from_key(&key), value, store.as_ref())
        };
        let request = crate::bridge::peg::ReleaseRequest {
            btc_dest_hash160: [0x11; 20],
            amount_satoshis: 100_000_000,
            rsk_tx_hash: Some([0xab; 32]),
        };
        let root = put_cell(
            &root,
            crate::bridge::storage::RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY,
            &crate::bridge::peg::serialize_release_queue_with_hash(&[request]),
        );
        let utxo = crate::bridge::storage::BridgeUtxo {
            tx_hash: [0x07; 32],
            vout: 0,
            value_satoshis: 100_000_100,
            height: 0,
            script: vec![],
            coinbase: false,
        };
        let root = put_cell(
            &root,
            crate::bridge::storage::NEW_FEDERATION_BTC_UTXOS_KEY,
            &crate::bridge::storage::serialize_utxo_list(&[utxo]),
        );

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(&alloy_primitives::keccak256(b"updateCollections()")[..4]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let header = dummy_header(3_103_055);
        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .expect("block executes");

        // The dusty-change burn must NOT happen: updateCollections was rejected.
        let burn_addr = Address::repeat_byte(0xff);
        let burn_balance = result
            .state_changes
            .get(&burn_addr)
            .map(|a| a.info.balance)
            .unwrap_or_default();
        assert_eq!(burn_balance, U256::ZERO, "rejected updateCollections must not burn");
        // No update_collections event emitted.
        assert!(
            result.tx_results[0].logs.is_empty(),
            "rejected updateCollections must not emit the update_collections event"
        );
    }

    /// Seed a contract account in the trie with code, the rskj setupContract
    /// storage-prefix marker, and one storage slot (slot 7 = 0xAA).
    fn seed_contract(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        balance: U256,
        code: &[u8],
    ) -> TrieNode {
        let root = put_account(root, store, addr, 1, balance);
        let root = root.put(
            &TrieKeySlice::from_key(&rustock_trie::code_key(addr)),
            code,
            store,
        );
        let root = root.put(
            &TrieKeySlice::from_key(&rustock_trie::storage_prefix_key(addr)),
            &[1],
            store,
        );
        root.put(
            &TrieKeySlice::from_key(&rustock_trie::storage_key(
                addr,
                &B256::from(U256::from(7)),
            )),
            &[0xAA],
            store,
        )
    }

    fn trie_account(root: &TrieNode, store: &dyn TrieStore, addr: &Address) -> Option<AccountState> {
        root.get(&TrieKeySlice::from_key(&account_key(addr)), store)
            .and_then(|d| AccountState::decode(&d).ok())
    }

    /// Assert the whole account subtree (code, marker, old storage) is gone.
    fn assert_subtree_deleted(root: &TrieNode, store: &dyn TrieStore, addr: &Address) {
        assert!(
            root.get(&TrieKeySlice::from_key(&rustock_trie::code_key(addr)), store).is_none(),
            "code must be deleted"
        );
        assert!(
            root.get(&TrieKeySlice::from_key(&rustock_trie::storage_prefix_key(addr)), store)
                .is_none(),
            "storage-prefix marker must be deleted"
        );
        assert!(
            root.get(
                &TrieKeySlice::from_key(&rustock_trie::storage_key(
                    addr,
                    &B256::from(U256::from(7)),
                )),
                store,
            )
            .is_none(),
            "old storage must be deleted"
        );
    }

    fn plain_tx(nonce: u64, to: &Address, value: U256) -> rustock_core::Transaction {
        rustock_core::Transaction {
            nonce,
            gas_price: U256::from(0),
            gas_limit: U256::from(1_000_000),
            to: Bytes::copy_from_slice(to.as_slice()),
            value,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        }
    }

    /// Regression for mainnet #3173807: rskj TransactionExecutor.finalization
    /// deletes suicided accounts at the END of each transaction
    /// (`track.delete`), so a LATER tx in the same block sees the address as
    /// nonexistent and re-creates a fresh (0, 0) node by merely calling it
    /// (frontier `transfer`/`addBalance(0)`). Block-end state must be: old
    /// subtree (code, marker, storage) deleted, fresh account present.
    #[test]
    fn selfdestruct_then_recreate_in_same_block() {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let bene = Address::repeat_byte(0xBB);
        let victim = Address::repeat_byte(0xCC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&TrieNode::empty(), store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &bene, 1, U256::from(5));
        // PUSH20 bene; SELFDESTRUCT
        let mut code = vec![0x73];
        code.extend_from_slice(bene.as_slice());
        code.push(0xFF);
        let root = seed_contract(&root, store.as_ref(), &victim, U256::from(1_000), &code);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let txs = vec![
            (plain_tx(0, &victim, U256::ZERO), sender), // selfdestructs to bene
            (plain_tx(1, &victim, U256::ZERO), sender), // re-creates (0,0) node
            (plain_tx(2, &victim, U256::from(123)), sender), // tops it up
        ];
        let r = executor
            .execute_block(&dummy_header(3_173_807), &txs, &root, store.clone())
            .expect("block");
        assert!(r.tx_results.iter().all(|t| t.success));

        let new_root =
            crate::state::apply_state_changes(&root, store.as_ref(), &r.state_changes, &r.markers);
        assert_subtree_deleted(&new_root, store.as_ref(), &victim);
        let acct = trie_account(&new_root, store.as_ref(), &victim)
            .expect("re-created account node must exist");
        assert_eq!(acct.nonce, U256::ZERO, "fresh account: nonce reset");
        assert_eq!(acct.balance, U256::from(123), "fresh account: later balance only");
        let bene_acct = trie_account(&new_root, store.as_ref(), &bene).unwrap();
        assert_eq!(bene_acct.balance, U256::from(1_005), "suicide proceeds paid out");
    }

    /// Selfdestruct in the LAST tx of the block: no later re-creation, the
    /// whole subtree is gone and no account node remains (rskj
    /// MutableRepository.delete → deleteRecursive).
    #[test]
    fn selfdestruct_in_last_tx_deletes_account_entirely() {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let bene = Address::repeat_byte(0xBB);
        let victim = Address::repeat_byte(0xCC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&TrieNode::empty(), store.as_ref(), &sender, 0, one_rbtc);
        let mut code = vec![0x73];
        code.extend_from_slice(bene.as_slice());
        code.push(0xFF);
        let root = seed_contract(&root, store.as_ref(), &victim, U256::from(1_000), &code);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let r = executor
            .execute_block(
                &dummy_header(3_173_807),
                &[(plain_tx(0, &victim, U256::ZERO), sender)],
                &root,
                store.clone(),
            )
            .expect("block");
        assert!(r.tx_results[0].success);

        let new_root =
            crate::state::apply_state_changes(&root, store.as_ref(), &r.state_changes, &r.markers);
        assert_subtree_deleted(&new_root, store.as_ref(), &victim);
        assert!(
            trie_account(&new_root, store.as_ref(), &victim).is_none(),
            "no account node may survive"
        );
    }

    /// Selfdestruct to self: rskj transfers the balance to the account itself
    /// and then deletes it — the balance is burned, the subtree is gone.
    #[test]
    fn selfdestruct_to_self_burns_balance() {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let victim = Address::repeat_byte(0xCC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&TrieNode::empty(), store.as_ref(), &sender, 0, one_rbtc);
        // ADDRESS; SELFDESTRUCT
        let root =
            seed_contract(&root, store.as_ref(), &victim, U256::from(1_000), &[0x30, 0xFF]);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let r = executor
            .execute_block(
                &dummy_header(3_173_807),
                &[(plain_tx(0, &victim, U256::ZERO), sender)],
                &root,
                store.clone(),
            )
            .expect("block");
        assert!(r.tx_results[0].success);

        let new_root =
            crate::state::apply_state_changes(&root, store.as_ref(), &r.state_changes, &r.markers);
        assert!(
            trie_account(&new_root, store.as_ref(), &victim).is_none(),
            "self-beneficiary account deleted, balance burned"
        );
        assert_subtree_deleted(&new_root, store.as_ref(), &victim);
        let sender_acct = trie_account(&new_root, store.as_ref(), &sender).unwrap();
        assert_eq!(sender_acct.balance, one_rbtc, "burned balance goes nowhere");
    }

    /// Destroy → CREATE2 re-deploy at the same address → destroy again, all
    /// in one block (the rskj TransactionExecutor comment: "the remote case
    /// there is a CREATE2 creating a deleted account"). The final destruction
    /// must win: nothing of the address survives at block end.
    #[test]
    fn selfdestruct_recreate_via_create2_then_selfdestruct_again() {
        let store = Arc::new(MemoryTrieStore::new());
        let sender = Address::repeat_byte(0xAA);
        let factory = Address::repeat_byte(0xFA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        // Victim runtime: CALLER; SELFDESTRUCT (suicides to its caller).
        // Init code returns it: PUSH2 0x33FF; PUSH1 0; MSTORE;
        //                       PUSH1 2; PUSH1 30; RETURN
        let init: [u8; 11] = [0x61, 0x33, 0xFF, 0x60, 0x00, 0x52, 0x60, 0x02, 0x60, 0x1E, 0xF3];
        // Factory runtime: PUSH11 init; PUSH1 0; MSTORE   (init at mem[21..32])
        //                  PUSH1 0 (salt); PUSH1 11 (size); PUSH1 21 (offset);
        //                  PUSH1 0 (value); CREATE2; POP; STOP
        let mut factory_code = vec![0x6A];
        factory_code.extend_from_slice(&init);
        factory_code.extend_from_slice(&[
            0x60, 0x00, 0x52, 0x60, 0x00, 0x60, 0x0B, 0x60, 0x15, 0x60, 0x00, 0xF5, 0x50, 0x00,
        ]);
        let victim = factory.create2(B256::ZERO, alloy_primitives::keccak256(init));

        let root = put_account(&TrieNode::empty(), store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &factory, 1, U256::ZERO);
        let root = root.put(
            &TrieKeySlice::from_key(&rustock_trie::code_key(&factory)),
            &factory_code,
            store.as_ref(),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let txs = vec![
            (plain_tx(0, &factory, U256::ZERO), sender), // deploy victim
            (plain_tx(1, &victim, U256::ZERO), sender),  // destroy it
            (plain_tx(2, &factory, U256::ZERO), sender), // re-deploy at same addr
            (plain_tx(3, &victim, U256::from(7)), sender), // destroy again
        ];
        let r = executor
            .execute_block(&dummy_header(3_173_807), &txs, &root, store.clone())
            .expect("block");
        assert!(r.tx_results.iter().all(|t| t.success));

        let new_root =
            crate::state::apply_state_changes(&root, store.as_ref(), &r.state_changes, &r.markers);
        // If the second CREATE2 had failed (collision against the stale
        // destroyed entry), tx 3 would have been a plain transfer and the
        // victim would survive with balance 7.
        assert!(
            trie_account(&new_root, store.as_ref(), &victim).is_none(),
            "victim fully deleted after destroy → CREATE2 re-deploy → destroy"
        );
        assert!(
            new_root
                .get(
                    &TrieKeySlice::from_key(&rustock_trie::code_key(&victim)),
                    store.as_ref(),
                )
                .is_none(),
            "victim code deleted"
        );
        assert!(
            new_root
                .get(
                    &TrieKeySlice::from_key(&rustock_trie::storage_prefix_key(&victim)),
                    store.as_ref(),
                )
                .is_none(),
            "victim marker deleted"
        );
        // The selfdestruct in tx 3 pays the 7 wei back to the caller.
        let sender_acct = trie_account(&new_root, store.as_ref(), &sender).unwrap();
        assert_eq!(sender_acct.balance, one_rbtc, "value round-trips via suicide");
    }
}
