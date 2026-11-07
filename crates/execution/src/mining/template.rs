//! Building the RSK block a miner searches for.
//!
//! The load-bearing hook is that [`BlockProcessor::execute_block`] executes
//! without checking the header's roots while `process_block` checks them: a
//! template can be assembled with placeholder roots, executed, and then have
//! the real roots written back from the result. There is no second execution
//! path for mining, so a block this builds is executed by exactly the code
//! that will later re-execute it on the way in.

use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use rustock_core::config::ChainConfig;
use rustock_core::validation::{DifficultyRule, ValidationError};
use rustock_core::{Block, Header, Transaction, ordered_tx_trie_root};
use rustock_trie::{AccountState, TrieKeySlice, TrieNode, TrieStore, account_key};
use std::collections::HashMap;
use std::sync::Arc;

use crate::hardfork::RskHardforkConfig;
use crate::mining::fork_detection;
use crate::processor::{BlockProcessor, ProcessError, compute_ommers_hash};

/// Knobs an operator sets for the blocks this node builds. None of them are
/// consensus: a block is valid whatever is chosen here, within the bounds the
/// header rules impose.
#[derive(Debug, Clone)]
pub struct MiningConfig {
    /// Where block rewards are paid. REMASC credits this address.
    pub coinbase_address: Address,
    /// `extra_data`, capped at 32 bytes by the header rules.
    pub extra_data: Bytes,
    /// Gas limit to steer towards, one step per block. `None` inherits the
    /// parent's, which is always valid and never drifts.
    pub gas_limit_target: Option<U256>,
    /// Minimum gas price to steer towards, one step per block. `None`
    /// inherits the parent's.
    pub min_gas_price_target: Option<U256>,
    /// How many templates to keep for submissions that arrive late.
    pub work_cache_size: usize,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            coinbase_address: Address::ZERO,
            extra_data: Bytes::new(),
            gas_limit_target: None,
            min_gas_price_target: None,
            // rskj MinerServerImpl.CACHE_SIZE.
            work_cache_size: 20,
        }
    }
}

/// A block ready to be mined, plus everything a submission needs to be matched
/// back to it.
/// A block's transactions in sublist order, with the edges that describe it.
struct Partitioned {
    transactions: Vec<Transaction>,
    edges: Vec<i16>,
}

#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// The block itself, with every field filled except the three
    /// merged-mining ones a solution supplies.
    pub block: Block,
    /// The 32 bytes a coinbase must carry after `RSKBLOCK:`: the first 20 of
    /// the header's merged-mining hash, then RSKIP110 fork-detection data.
    /// This, not the block hash, is what a submission is looked up by.
    pub hash_for_merged_mining: B256,
    /// `U256::MAX / difficulty`: the Bitcoin block hash, read little-endian,
    /// must not exceed this.
    pub target: U256,
    /// Fees this block would pay its miner, for a pool deciding whether the
    /// work is worth switching to.
    pub fees_paid_to_miner: U256,
    /// State root the block was executed against -- so a submission can
    /// re-execute from the same point without hunting for it.
    pub parent_state_root: B256,
}

impl BlockTemplate {
    /// The parent this template builds on.
    pub fn parent_hash(&self) -> B256 {
        self.block.header.parent_hash
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("no parent state root {root} in the trie store: the parent has not been executed")]
    ParentStateMissing { root: B256 },
    #[error("executing the template failed: {0}")]
    Execution(#[from] ProcessError),
    /// The partition probe runs the executor directly rather than the
    /// processor, so its failures arrive unwrapped.
    #[error("partitioning the template failed: {0}")]
    Partition(#[from] crate::executor::ExecutionError),
    #[error("storage error: {0}")]
    Storage(#[from] anyhow::Error),
    /// The assembled block fails a rule every peer applies on import. The
    /// builder is meant to make this unreachable; it is checked because the
    /// alternative is a chain of blocks nobody else accepts.
    #[error("the assembled block fails a block rule: {0}")]
    SelfCheck(ValidationError),
}

/// A transaction waiting to be mined, with its sender already recovered.
///
/// The pool lives in the sync crate and recovers senders on admission; the
/// builder would otherwise recover every sender again on every rebuild, once a
/// minute per pending transaction.
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    pub tx: Transaction,
    pub sender: Address,
    pub hash: B256,
}

/// Where the builder gets transactions. A trait because the pool lives in the
/// sync crate, which depends on this one.
pub trait PendingTransactionSource: Send + Sync {
    fn pending(&self) -> Vec<PendingTransaction>;

    /// Transactions the builder found unusable, which rskj's
    /// `BlockToMineBuilder` removes from the pool
    /// (`transactionPool.removeTransactions`): those `filterTransactions`
    /// set aside as priced under the block's minimum or over the RSKIP252
    /// cap, and those the EVM refused to run (`getInvalidTransactions`): a
    /// nonce the state no longer expects, a balance that no longer covers
    /// them, too little intrinsic gas. A pool that does not would hand them
    /// back on every rebuild. The default does nothing, which is right for
    /// a source that is not a pool.
    fn remove_transactions(&self, _hashes: &[B256]) {}
}

/// Nothing to mine but the REMASC transaction. Useful on regtest and in tests,
/// and it is what an operator mining an idle chain effectively has.
pub struct NoPendingTransactions;

impl PendingTransactionSource for NoPendingTransactions {
    fn pending(&self) -> Vec<PendingTransaction> {
        Vec::new()
    }
}

pub struct BlockTemplateBuilder {
    processor: Arc<BlockProcessor>,
    trie_store: Arc<dyn TrieStore>,
    chain_config: Arc<ChainConfig>,
    hardfork_cfg: RskHardforkConfig,
    mining_config: MiningConfig,
}

impl BlockTemplateBuilder {
    pub fn new(
        processor: Arc<BlockProcessor>,
        trie_store: Arc<dyn TrieStore>,
        chain_config: Arc<ChainConfig>,
        hardfork_cfg: RskHardforkConfig,
        mining_config: MiningConfig,
    ) -> Self {
        Self { processor, trie_store, chain_config, hardfork_cfg, mining_config }
    }

    pub fn mining_config(&self) -> &MiningConfig {
        &self.mining_config
    }

    pub fn processor(&self) -> &BlockProcessor {
        &self.processor
    }

    pub fn trie_store(&self) -> Arc<dyn TrieStore> {
        self.trie_store.clone()
    }

    /// Build a template on top of `mainchain[0]`.
    ///
    /// `mainchain` is the best chain in descending order. Only the first entry
    /// is needed to build the block; the rest feed the fork-detection data,
    /// and passing fewer than [`fork_detection::REQUIRED_MAINCHAIN_BLOCKS`]
    /// simply produces a header without it -- which is correct for a chain
    /// that short and wrong for one that is not, so callers should pass what
    /// they have.
    pub fn build(
        &self,
        mainchain: &[Header],
        ommers: Vec<Header>,
        pending: &dyn PendingTransactionSource,
    ) -> Result<BlockTemplate, TemplateError> {
        let parent = &mainchain[0];
        let parent_state_root = parent.state_root;
        let state_root = self.load_state_root(parent_state_root)?;

        let number = parent.number + 1;
        let timestamp = timestamp_for_child(parent.timestamp);
        let difficulty = DifficultyRule { config: self.chain_config.clone() }
            .difficulty_for_child(parent, number, timestamp, ommers.len() as u64);
        let gas_limit = next_gas_limit(parent, self.mining_config.gas_limit_target);
        let minimum_gas_price =
            next_minimum_gas_price(parent.minimum_gas_price, self.mining_config.min_gas_price_target);

        let (candidates, to_remove) =
            self.select_transactions(pending, &state_root, minimum_gas_price, number);
        // rskj `BlockToMineBuilder.build`: `removePendingTransactions(txsToRemove)`
        // right after the filter, before anything executes.
        if !to_remove.is_empty() {
            tracing::debug!(
                target: "rustock::mining",
                "Removing {} transaction(s) from the pool: priced outside what the block may carry",
                to_remove.len()
            );
            pending.remove_transactions(&to_remove);
        }
        let has_candidates = !candidates.is_empty();
        // Kept by position, so a candidate the probe refuses can be named
        // back to the pool.
        let candidate_hashes: Vec<B256> = candidates.iter().map(|c| c.hash).collect();
        let mut transactions: Vec<Transaction> = candidates.into_iter().map(|c| c.tx).collect();
        // Not appended by the executor: REMASC is an ordinary entry in the
        // block's transaction list, recognised by shape. A template without it
        // executes to a different state root, and the failure reads as an
        // execution bug rather than a missing transaction.
        transactions.push(remasc_transaction(number));

        let rskip126 = self.hardfork_cfg.has_unitrie_state_root(number);
        // rskj sets ummRoot to the empty byte array from papyrus200 on (the
        // UMM contracts were never deployed, so it is never non-empty). Its
        // mere presence changes both the block hash and the merged-mining
        // hash, so a header built without it is rejected by every peer.
        let umm_root = if number >= self.chain_config.activation_heights.papyrus200 {
            Some(Bytes::new())
        } else {
            None
        };

        #[allow(unused_mut)]
        let mut header = Header {
            parent_hash: parent.hash(),
            ommers_hash: compute_ommers_hash(&ommers),
            beneficiary: self.mining_config.coinbase_address,
            // Placeholders: execute_block does not check them, and they are
            // written back from the result below.
            state_root: B256::ZERO,
            transactions_root: ordered_tx_trie_root(&transactions, rskip126),
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            version_fields: None,
            difficulty,
            number,
            gas_limit,
            gas_used: 0,
            timestamp,
            extra_data: self.mining_config.extra_data.clone(),
            paid_fees: U256::ZERO,
            minimum_gas_price,
            uncle_count: ommers.len() as u64,
            umm_root,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };

        // The probe: execute the candidates once, in selection order, to
        // learn two things only execution can tell.
        //
        // Which ones fit. rskj's `BlockToMineBuilder` fills a block by gas
        // **used**: a candidate must fit in the block limit minus the gas the
        // earlier ones consumed (`TransactionExecutor.gasIsValid`), and once
        // it has run only its own consumption counts against the next. A
        // sender that declares more gas than it uses costs the block nothing.
        // Fitting by declared limits instead -- what this did before -- left
        // blocks 40% empty under ordinary wallets, which over-provision as a
        // matter of course.
        //
        // And, under RSKIP-144, what each one touches, which decides the
        // partition and with it the order. rskj does the first pass and
        // reorders its receipts rather than re-executing, relying on a
        // collision-free partition reaching the same state either way --
        // which is true, and is the theorem the validator exists to check
        // rather than assume. Executing the block that will actually be
        // published is the cheaper thing to be sure of, and the receipts
        // have to be rebuilt regardless: `cumulativeGasUsed` restarts at each
        // sublist.
        //
        // Skipped on an idle chain: REMASC alone always fits and has nothing
        // to partition, and the final execution below is the one that counts.
        let partitioned = if has_candidates {
            let (kept, partitioned, invalid) =
                self.probe_and_partition(number, gas_limit, transactions, &header, &state_root)?;
            transactions = kept;
            header.transactions_root = ordered_tx_trie_root(&transactions, rskip126);
            // rskj `BlockToMineBuilder.build`: "Evicting {} invalid
            // transaction(s) from pool after exception during block
            // execution". Done here, on the source, because the probe
            // only knows positions.
            if !invalid.is_empty() {
                let hashes: Vec<B256> =
                    invalid.iter().filter_map(|&i| candidate_hashes.get(i).copied()).collect();
                tracing::warn!(
                    target: "rustock::mining",
                    "Evicting {} invalid transaction(s) from the pool: the EVM refused them while building the template",
                    hashes.len()
                );
                pending.remove_transactions(&hashes);
            }
            partitioned
        } else {
            None
        };
        if let Some(partitioned) = partitioned {
            transactions = partitioned.transactions;
            header.transactions_root = ordered_tx_trie_root(&transactions, rskip126);
            header.version_fields = Some(rustock_core::types::header::HeaderVersionFields {
                // RSKIP-351 travels with RSKIP-144; the extension is what
                // carries the edges.
                version: 1,
                edges: Some(partitioned.edges),
                base_event: None,
            });
        }

        let block = Block { header: header.clone(), transactions, ommers };
        let executed =
            self.processor.execute_block(&block, &state_root, self.trie_store.clone())?;

        header.state_root = executed.state_root_hash;
        header.receipts_root = executed.receipts_root;
        header.logs_bloom = executed.logs_bloom;
        header.gas_used = executed.gas_used;
        header.paid_fees = executed.paid_fees;

        let fork_data = fork_detection::calculate(mainchain);
        let hash_for_merged_mining =
            fork_detection::apply_to_hash(header.hash_for_merged_mining(), &fork_data);

        let block = Block { header, ..block };
        // The rules a peer runs on the body before executing it: the gas
        // price floor and the RSKIP252 cap, REMASC last, extra data, the
        // minimum gas price step. Selection is meant to satisfy them; this is
        // the check that it did, before the block is handed out rather than
        // after every rskj node has refused it. The ancestry rules (uncles,
        // fork detection) are not run here: the first needs the store the
        // import path has, the second the merged-mining fields a solution
        // fills in.
        self.processor
            .validate_block_body_rules(&block, Some(parent))
            .map_err(TemplateError::SelfCheck)?;

        Ok(BlockTemplate {
            block,
            hash_for_merged_mining,
            target: difficulty_to_target(difficulty),
            fees_paid_to_miner: executed.paid_fees,
            parent_state_root,
        })
    }

    /// Execute the candidates once, keep the ones that fit, and under
    /// RSKIP-144 place the kept ones in sublists, as rskj's miner does.
    ///
    /// `transactions` is the selection in price order, REMASC last. The
    /// first element of the result is what survived: every candidate the
    /// executor dropped, for not fitting the block's remaining gas or for
    /// being refused by the EVM (see
    /// [`crate::RskExecutor::execute_block_for_mining`]), is gone, in the
    /// order the rest already had. The second is the partition, `None` when
    /// the block declares none: RSKIP-144 inactive, or the partition came
    /// out all-sequential, which rskj spells as an empty edges array and we
    /// spell as no extension at all. The third is the indices, into
    /// `transactions`, of the candidates the EVM refused: the pool should
    /// hear about those.
    ///
    /// The placement is an approximation on purpose: a transaction is placed
    /// from an execution against the accumulating sequential state, while
    /// its sublist will run against the parent state. Where the two differ
    /// the partition is wrong, and the validator is what catches it -- which
    /// is why the validator re-checks instead of trusting the header.
    fn probe_and_partition(
        &self,
        number: u64,
        gas_limit: U256,
        transactions: Vec<Transaction>,
        header: &Header,
        state_root: &TrieNode,
    ) -> Result<(Vec<Transaction>, Option<Partitioned>, Vec<usize>), TemplateError> {
        let rskip144 = self.hardfork_cfg.has_rskip144(number);
        let chain_id = self.hardfork_cfg.chain_id;
        let with_senders: Vec<(Transaction, Address)> = transactions
            .iter()
            .map(|tx| {
                let sender = tx.recover_sender(chain_id).unwrap_or_default();
                (tx.clone(), sender)
            })
            .collect();

        if rskip144 {
            crate::collision::start_per_transaction(crate::collision::write_semantics(number));
        }
        let executed = self.processor.executor().execute_block_for_mining(
            header,
            &with_senders,
            state_root,
            self.trie_store.clone(),
        );
        // Taken whether or not execution succeeded, so a failure cannot leave
        // this probe's keys behind for the next template.
        let touched = if rskip144 { crate::collision::finish() } else { None };
        let (executed, dropped) = executed?;
        if !dropped.is_empty() {
            tracing::debug!(
                target: "rustock::mining",
                unfitting = dropped.unfitting.len(),
                invalid = dropped.invalid.len(),
                kept = transactions.len() - dropped.unfitting.len() - dropped.invalid.len(),
                "transactions left out of the template"
            );
        }
        let invalid = dropped.invalid.clone();

        // What ran, with each transaction's probe index: `tx_results` is one
        // per executed transaction, `touched` is keyed by the probe index.
        let kept: Vec<(usize, Transaction, Address)> = with_senders
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !dropped.contains(*i))
            .map(|(i, (tx, sender))| (i, tx, sender))
            .collect();
        debug_assert_eq!(kept.len(), executed.tx_results.len(), "one result per executed transaction");
        let kept_transactions: Vec<Transaction> = kept.iter().map(|(_, tx, _)| tx.clone()).collect();

        if !rskip144 {
            return Ok((kept_transactions, None, invalid));
        }
        let touched = touched.unwrap_or_default();

        let mut partitioner = crate::mining::partition::SublistPartitioner::new(
            rustock_core::validation::block_rules::TX_EXECUTION_THREADS,
            gas_limit.saturating_to::<u64>(),
            self.chain_config.min_sequential_set_gas_limit,
        );

        let mut placed: Vec<usize> = Vec::with_capacity(kept.len());
        for (index, (probe_index, tx, sender)) in kept.iter().enumerate() {
            let Some(result) = executed.tx_results.get(index) else {
                continue;
            };

            // REMASC closes the sequential sublist and is not placed by the
            // ordinary rule -- it is the block's last transaction by
            // definition.
            if index + 1 == kept.len() && is_remasc(tx) {
                partitioner.add_remasc(index, result.gas_used);
                placed.push(index);
                continue;
            }

            let keys = touched.keys(*probe_index);
            let footprint = crate::mining::partition::TxFootprint {
                sender: *sender,
                gas_limit: tx.gas_limit.saturating_to::<u64>(),
                gas_used: result.gas_used,
                reads: keys.map(|k| k.read().iter().cloned().collect()).unwrap_or_default(),
                writes: keys.map(|k| k.written().iter().cloned().collect()).unwrap_or_default(),
            };

            // A transaction that reached REMASC or the Bridge may go nowhere
            // but the sequential sublist: a parallel one makes the block
            // invalid (`SEQUENTIAL_ONLY_PRECOMPILES`).
            let seat = if result.reached_sequential_only {
                partitioner.add_to_sequential(index, &footprint)
            } else {
                partitioner.add(index, &footprint)
            };
            // `None` is "it fits nowhere"; the transaction is dropped from
            // the block rather than overflowing a sublist.
            if seat.is_some() {
                placed.push(index);
            }
        }

        let edges = partitioner.edges();
        if edges.is_empty() {
            return Ok((kept_transactions, None, invalid));
        }

        let order = partitioner.transactions_in_order();
        debug_assert_eq!(order.len(), placed.len(), "every placed transaction is ordered");
        let partitioned = Partitioned {
            transactions: order.iter().map(|&i| kept_transactions[i].clone()).collect(),
            edges,
        };
        Ok((kept_transactions, Some(partitioned), invalid))
    }

    /// Reload the parent's state root from the trie store.
    pub fn load_state_root(&self, root: B256) -> Result<TrieNode, TemplateError> {
        if root == rustock_trie::TrieNode::empty().compute_hash(self.trie_store.as_ref()) {
            return Ok(TrieNode::empty());
        }
        self.trie_store
            .get(root.as_slice())
            .map(|data| TrieNode::from_message(&data, self.trie_store.as_ref()))
            .ok_or(TemplateError::ParentStateMissing { root })
    }

    /// Pick the candidates, best price first, each sender's transactions in
    /// nonce order and starting from the nonce the state expects, skipping
    /// anything priced outside what the block may carry.
    ///
    /// rskj `BlockToMineBuilder.getTransactions` with
    /// `MinerUtils.filterTransactions`: every pending transaction that passes
    /// is a candidate; which ones fit the block is decided by executing them
    /// (see `probe_and_partition`), not here. The second element is rskj's
    /// `txsToRemove`: what the pool should drop.
    fn select_transactions(
        &self,
        pending: &dyn PendingTransactionSource,
        state_root: &TrieNode,
        minimum_gas_price: U256,
        number: u64,
    ) -> (Vec<PendingTransaction>, Vec<B256>) {
        let ordered = order_by_price_sender_and_nonce(pending.pending());
        let rskip252 = number >= self.processor.rskip252_height();
        filter_candidates(ordered, minimum_gas_price, rskip252, |sender| {
            account_nonce(state_root, self.trie_store.as_ref(), sender)
        })
    }
}

/// rskj `MinerUtils.filterTransactions`, on transactions already in
/// `order_by_price_sender_and_nonce` order.
///
/// Three things rule a transaction out. Priced under the block's minimum
/// (`isLowGasPriced`): the block would fail `TxsMinGasPriceRule`. Priced over
/// 100 times the block's minimum once RSKIP252 is active (`isHighGasPriced`,
/// `TxGasPriceCap.FOR_BLOCK`): the block would fail `BlockTxsMaxGasPriceRule`
/// on every peer, and the one case the cap short-circuits -- a zero minimum --
/// is the one where there is no cap to exceed. Both of those go to
/// `txsToRemove`, the second element: rskj drops them from the pool, since a
/// later block is no likelier to carry them. And a nonce that is not the
/// next one the sender's account expects, which stays in the pool. Only a
/// gap blocks the sender's later transactions; a nonce below the expected
/// one is a mined leftover and the next may still be wanted.
///
/// `nonce_of` reads the sender's nonce from the state the block builds on,
/// once per sender.
pub(crate) fn filter_candidates(
    ordered: Vec<PendingTransaction>,
    minimum_gas_price: U256,
    rskip252_active: bool,
    mut nonce_of: impl FnMut(&Address) -> u64,
) -> (Vec<PendingTransaction>, Vec<B256>) {
    let cap = (rskip252_active && !minimum_gas_price.is_zero()).then(|| {
        minimum_gas_price.saturating_mul(U256::from(
            rustock_core::validation::block_rules::BlockTxsMaxGasPriceRule::FOR_BLOCK_MULTIPLIER,
        ))
    });

    let mut next_nonce: HashMap<Address, u64> = HashMap::new();
    let mut gapped: std::collections::HashSet<Address> = std::collections::HashSet::new();
    let mut selected = Vec::new();
    let mut to_remove = Vec::new();

    for candidate in ordered {
        if candidate.tx.gas_price < minimum_gas_price {
            to_remove.push(candidate.hash);
            continue;
        }
        if cap.is_some_and(|cap| candidate.tx.gas_price > cap) {
            to_remove.push(candidate.hash);
            continue;
        }
        if gapped.contains(&candidate.sender) {
            continue;
        }

        let expected = *next_nonce
            .entry(candidate.sender)
            .or_insert_with(|| nonce_of(&candidate.sender));
        if candidate.tx.nonce != expected {
            if candidate.tx.nonce > expected {
                gapped.insert(candidate.sender);
            }
            continue;
        }

        next_nonce.insert(candidate.sender, expected + 1);
        selected.push(candidate);
    }

    (selected, to_remove)
}

/// rskj `PendingState.sortByPriceTakingIntoAccountSenderAndNonce`: cluster by
/// sender, order each cluster by nonce, then merge the clusters by price,
/// always comparing only each sender's next transaction. Ordering purely by
/// price would interleave a sender's own transactions out of nonce order and
/// strand all but the first.
#[cfg(test)]
pub(crate) fn order_by_price_sender_and_nonce_for_test(
    pending: Vec<PendingTransaction>,
) -> Vec<PendingTransaction> {
    order_by_price_sender_and_nonce(pending)
}

fn order_by_price_sender_and_nonce(pending: Vec<PendingTransaction>) -> Vec<PendingTransaction> {
    let mut by_sender: HashMap<Address, Vec<PendingTransaction>> = HashMap::new();
    for ptx in pending {
        by_sender.entry(ptx.sender).or_default().push(ptx);
    }

    for txs in by_sender.values_mut() {
        txs.sort_by(|a, b| {
            a.tx.nonce
                .cmp(&b.tx.nonce)
                .then(b.tx.gas_price.cmp(&a.tx.gas_price))
                .then(a.hash.cmp(&b.hash))
        });
        // Cheapest-last, so the next transaction is always `pop`.
        txs.reverse();
    }

    let mut queues: Vec<Vec<PendingTransaction>> = by_sender.into_values().collect();
    let mut out = Vec::new();
    loop {
        let best = queues
            .iter()
            .enumerate()
            .filter_map(|(i, q)| q.last().map(|t| (i, t)))
            .max_by(|(ai, a), (bi, b)| {
                a.tx.gas_price
                    .cmp(&b.tx.gas_price)
                    // Deterministic across runs: a HashMap hands the senders
                    // back in whatever order it likes, and two senders
                    // offering the same price must still be mined in the same
                    // order on every rebuild of the same template.
                    .then(b.hash.cmp(&a.hash))
                    .then(bi.cmp(ai))
            })
            .map(|(i, _)| i);
        match best {
            Some(i) => out.push(queues[i].pop().expect("non-empty queue")),
            None => break,
        }
    }
    out
}

fn account_nonce(state_root: &TrieNode, store: &dyn TrieStore, addr: &Address) -> u64 {
    let key = account_key(addr);
    let expanded = TrieKeySlice::from_key(&key);
    match state_root.get(&expanded, store) {
        Some(data) => AccountState::decode(&data).map(|a| a.nonce.to::<u64>()).unwrap_or(0),
        None => 0,
    }
}

/// The REMASC transaction for a block, byte-for-byte as rskj encodes it.
///
/// `cached_rlp` is not an optimisation here. rskj writes the zero gas price
/// and gas limit as a literal `0x00` byte and the zero value as `0x80`, which
/// canonical RLP would render the other way round; re-encoding this
/// transaction would give it a different hash and put a different
/// transactions root in the header. rskj `RemascTransaction(long blockNumber)`
/// with `Transaction.encode`.
/// Whether `tx` is the REMASC system transaction, by shape.
pub fn is_remasc(tx: &Transaction) -> bool {
    tx.to.as_ref() == crate::precompiles::REMASC_ADDR.as_slice()
        && tx.r.is_zero()
        && tx.s.is_zero()
}

pub fn remasc_transaction(block_number: u64) -> Transaction {
    let nonce = block_number.saturating_sub(1);
    let to = Bytes::copy_from_slice(crate::precompiles::REMASC_ADDR.as_slice());

    let mut payload = Vec::new();
    // nonce: minimal big-endian, and empty when zero
    if nonce == 0 {
        payload.push(0x80);
    } else {
        let bytes = nonce.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).expect("nonce is non-zero");
        let minimal = &bytes[start..];
        if minimal.len() == 1 && minimal[0] < 0x80 {
            payload.push(minimal[0]);
        } else {
            payload.push(0x80 + minimal.len() as u8);
            payload.extend_from_slice(minimal);
        }
    }
    payload.push(0x00); // gasPrice: RLP.encodeCoinNonNullZero(ZERO) -> {0}
    payload.push(0x00); // gasLimit: RLP.encodeElement({0}) -> {0}
    payload.push(0x80 + 20); // to
    payload.extend_from_slice(&to);
    payload.push(0x80); // value: RLP.encodeCoinNullZero(ZERO) -> encodeByte(0) -> 0x80
    payload.push(0x80); // data: null
    payload.push(0x80); // v: unsigned, chainId 0
    payload.push(0x80); // r
    payload.push(0x80); // s

    let mut rlp = Vec::with_capacity(payload.len() + 3);
    if payload.len() < 56 {
        rlp.push(0xc0 + payload.len() as u8);
    } else {
        let len_bytes = (payload.len() as u64).to_be_bytes();
        let start = len_bytes.iter().position(|b| *b != 0).expect("non-empty payload");
        rlp.push(0xf7 + (8 - start) as u8);
        rlp.extend_from_slice(&len_bytes[start..]);
    }
    rlp.extend_from_slice(&payload);

    Transaction {
        nonce,
        gas_price: U256::ZERO,
        gas_limit: U256::ZERO,
        to,
        value: U256::ZERO,
        input: Bytes::new(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: Some(rlp),
    }
}

/// rskj `MinerClock.calculateTimestampForChild`: wall clock, but never at or
/// before the parent -- a header with a timestamp not strictly greater than
/// its parent's is rejected outright.
fn timestamp_for_child(parent_timestamp: u64) -> u64 {
    // `dev::now_with_offset` is wall clock plus whatever `evm_increaseTime`
    // has accumulated -- zero unless a development chain moved it, so this is
    // the same wall clock everywhere else.
    let now = crate::mining::dev::now_with_offset();
    now.max(parent_timestamp + 1)
}

/// One step towards `target`, bounded by what the parent allows.
///
/// The consensus rule is only that a child's gas limit stays within
/// `parent / 1024` of the parent's, so inheriting it unchanged -- which is
/// what `None` does -- is always valid. rskj `GasLimitCalculator`.
fn next_gas_limit(parent: &Header, target: Option<U256>) -> U256 {
    let parent_limit = parent.gas_limit;
    let Some(target) = target else {
        return parent_limit;
    };
    let delta = parent_limit / U256::from(1024);
    if target > parent_limit {
        target.min(parent_limit + delta)
    } else {
        target.max(parent_limit.saturating_sub(delta))
    }
}

/// One step towards `target`, bounded by what the parent allows.
///
/// rskj `MinimumGasPriceCalculator` (RSKIP-09) with `BlockGasPriceRange`: a
/// child may move the minimum gas price by at most 1% of the parent's, or by
/// one wei when 1% rounds to nothing. The parent's own value is always in
/// range, so `None` -- inherit -- is always valid.
pub fn next_minimum_gas_price(parent_price: U256, target: Option<U256>) -> U256 {
    let Some(target) = target else {
        return parent_price;
    };
    let mut delta = parent_price / U256::from(100);
    if delta.is_zero() {
        delta = U256::from(1);
    }
    let upper = parent_price + delta;
    let lower = parent_price.saturating_sub(delta);
    target.clamp(lower, upper)
}

/// rskj `DifficultyUtils.difficultyToTarget`.
pub fn difficulty_to_target(difficulty: U256) -> U256 {
    if difficulty.is_zero() {
        U256::MAX
    } else {
        U256::MAX / difficulty
    }
}
