//! The miner server: hands out work, takes solutions back, and imports the
//! block a solution completes.
//!
//! A solution arrives minutes after the work it answers, by which time the
//! node has usually built several newer templates. So templates are kept in a
//! small cache keyed by the merged-mining hash the coinbase commits to --
//! keeping only the newest would make a miner that was merely a little slow
//! lose a block it had legitimately found. rskj keeps 20; so does this.

use alloy_primitives::{B256, Bytes, U256};
use rustock_core::config::ChainConfig;
use rustock_core::validation::{HeaderValidator, MergedMiningRule};
use rustock_core::validation::merged_mining::{
    BLOCK_HEADER_HASH_SIZE, CoinbaseCompressionError, RSK_TAG, compress_coinbase,
    compute_coinbase_hash, find_last_subsequence,
};
use rustock_core::{Block, Header};
use rustock_storage::BlockStore;
use rustock_trie::TrieStore;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::breakdown::{BreakdownSink, ConnectTimings, Laps};
use crate::mining::coinbase;
use crate::mining::merkle::{self, MerkleProofError};
use crate::mining::template::{
    BlockTemplate, BlockTemplateBuilder, PendingTransactionSource, TemplateError,
};

/// What `mnr_getWork` answers with. rskj `co.rsk.mine.MinerWork`.
#[derive(Debug, Clone)]
pub struct MinerWork {
    /// The 32 bytes to put in the coinbase after `RSKBLOCK:`.
    pub block_hash_for_merged_mining: B256,
    /// The Bitcoin block hash, read little-endian, must not exceed this.
    pub target: U256,
    /// Fees the block pays its miner, as a decimal string -- rskj sends
    /// `String.valueOf(Coin)` here rather than a quantity, and pools parse it.
    pub fees_paid_to_miner: U256,
    /// Set once per genuinely new piece of work, so a pool knows when to push
    /// to its miners rather than wait for the next poll.
    pub notify: bool,
    pub parent_block_hash: B256,
}

/// What the submit methods answer with. rskj `co.rsk.mine.SubmittedBlockInfo`.
#[derive(Debug, Clone)]
pub struct SubmittedBlockInfo {
    pub block_imported_result: ImportResult,
    pub block_hash: B256,
    pub block_included_height: u64,
}

/// The outcomes rskj's `ImportResult` can report for a mined block. A miner
/// reads this to tell "my block won" from "my block was valid but somebody
/// else's arrived first".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportResult {
    ImportedBest,
    ImportedNotBest,
    Exist,
}

impl ImportResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImportResult::ImportedBest => "IMPORTED_BEST",
            ImportResult::ImportedNotBest => "IMPORTED_NOT_BEST",
            ImportResult::Exist => "EXIST",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("could not decode the submitted Bitcoin block: {0}")]
    BitcoinBlockDecode(String),
    #[error("could not decode the submitted Bitcoin header: {0}")]
    BitcoinHeaderDecode(String),
    #[error("could not decode the submitted coinbase transaction: {0}")]
    CoinbaseDecode(String),
    #[error("the submitted coinbase carries no {} tag", String::from_utf8_lossy(RSK_TAG))]
    NoTagInCoinbase,
    #[error("no work outstanding for {hash}: it was never handed out, or it has aged out of the cache")]
    UnknownWork { hash: B256 },
    #[error("the parent of this work ({parent}) is no longer the executed head ({head:?}); the chain moved on")]
    ParentNoLongerHead { parent: B256, head: Option<B256> },
    /// rskj `MinerClientImpl.mineBlock` returns false while
    /// `hasBetterBlockToSync()`: a node still catching up does not mine.
    #[error("not mining: the node has a better block to sync")]
    Syncing,
    /// rskj `SubmissionRateLimitHandler`: "Cannot publish block, block
    /// submission rate limit exceeded".
    #[error("cannot publish block, block submission rate limit exceeded")]
    RateLimited,
    #[error("compressing the coinbase: {0}")]
    Compression(#[from] CoinbaseCompressionError),
    #[error("building the merkle proof: {0}")]
    MerkleProof(#[from] MerkleProofError),
    #[error("the completed block does not satisfy the merged-mining rule: {0}")]
    SelfCheck(rustock_core::validation::ValidationError),
    #[error("re-executing the completed block: {0}")]
    Execution(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("building work: {0}")]
    Template(#[from] TemplateError),
}

/// How the node's chain state is read and advanced. Split out so the server
/// can be driven by a test without a RocksDB store behind it.
pub trait ChainAccess: Send + Sync {
    /// Best chain in descending order, at most `limit` entries: index 0 is the
    /// block a new block would build on.
    fn mainchain(&self, limit: usize) -> Result<Vec<Header>, String>;
    /// Hash of the block whose state the trie store currently holds.
    fn executed_head(&self) -> Result<Option<B256>, String>;
    /// Whether a block with this hash is already stored.
    fn has_block(&self, hash: B256) -> Result<bool, String>;
    /// Uncles to include in a block mined on `parent_hash`.
    fn select_uncles(&self, block_number: u64, parent_hash: B256) -> Result<Vec<Header>, String>;
    /// Store a fully executed block and make it the head if it wins.
    ///
    /// `laps` is the caller's phase clock, disabled when nothing measures:
    /// the implementation laps it around the store writes (`switch_chain`)
    /// and around the hook and the flush (`on_best_block`).
    fn commit_mined_block(
        &self,
        block: &Block,
        state_root: B256,
        laps: &mut Laps,
    ) -> Result<CommitOutcome, String>;
}

/// What [`ChainAccess::commit_mined_block`] reports: the import result and
/// the two phases of the connect that happen inside it.
#[derive(Debug, Clone, Copy)]
pub struct CommitOutcome {
    pub result: ImportResult,
    /// Header, body, total difficulty, canonical index and executed head
    /// written (rskj `switchChainMs`).
    pub switch_chain: std::time::Duration,
    /// The committed hook (the pool told what was mined) and the trie flush
    /// when one is due (rskj `onBestBlockMs`).
    pub on_best_block: std::time::Duration,
}

/// [`ChainAccess`] over the node's real block store.
pub struct StoreChainAccess {
    pub store: Arc<BlockStore>,
    pub trie_store: Arc<dyn TrieStore>,
    /// Called with every block this commits, so a transaction pool can
    /// drop what has just been mined.
    ///
    /// A locally mined block does not travel the sync service's import
    /// path, which is the only place that called `remove_mined`. So
    /// without this the pool keeps every transaction the node itself
    /// mined, forever: `txpool_status` reports them as pending, a miner
    /// rebuilds them into the next block, and the pool grows without
    /// bound. Invisible on a node that only follows the chain, which is
    /// why it survived; immediate on one that mines.
    ///
    /// A closure rather than a pool handle because this crate does not
    /// know what a pool is, and should not have to in order to say "this
    /// block is now committed".
    pub on_committed: Option<Arc<dyn Fn(&Block) + Send + Sync>>,
    /// Best blocks between trie flushes: rskj's
    /// `blockchain.flushNumberOfBlocks`, whose `BlockChainFlusher` flushes
    /// every tenth block a node mines or connects. 1 flushes every block.
    ///
    /// The executed head still moves on every block, so the next template
    /// builds on the block just mined. Between flushes the state of those
    /// blocks lives in the trie store's memory: a crash there leaves the
    /// head naming a root that is not on disk, which the node repairs by
    /// re-executing from the last flushed block, as it does after a crash
    /// while catching up.
    pub flush_every: u64,
    /// Best blocks committed since the last flush.
    pub since_flush: std::sync::atomic::AtomicU64,
}

impl StoreChainAccess {
    /// Flush every block, which is what a node mining for a pool wants:
    /// its blocks are durable before they are announced.
    pub fn new(
        store: Arc<BlockStore>,
        trie_store: Arc<dyn TrieStore>,
        on_committed: Option<Arc<dyn Fn(&Block) + Send + Sync>>,
    ) -> Self {
        Self::with_flush_every(store, trie_store, on_committed, 1)
    }

    pub fn with_flush_every(
        store: Arc<BlockStore>,
        trie_store: Arc<dyn TrieStore>,
        on_committed: Option<Arc<dyn Fn(&Block) + Send + Sync>>,
        flush_every: u64,
    ) -> Self {
        Self {
            store,
            trie_store,
            on_committed,
            flush_every: flush_every.max(1),
            since_flush: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Count a best block and say whether it is time to flush. The counter
    /// starts at 0, so with `flush_every` 10 the flushes fall on the 10th,
    /// 20th, ... block mined, as rskj's flusher counts.
    fn flush_due(&self) -> bool {
        use std::sync::atomic::Ordering;
        let n = self.since_flush.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= self.flush_every {
            self.since_flush.store(0, Ordering::Release);
            true
        } else {
            false
        }
    }
}

impl ChainAccess for StoreChainAccess {
    fn mainchain(&self, limit: usize) -> Result<Vec<Header>, String> {
        let head = match self.store.exec_head().map_err(|e| e.to_string())? {
            Some((hash, _)) => hash,
            None => self
                .store
                .head()
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "the node has no head block".to_string())?,
        };

        let mut chain = Vec::with_capacity(limit);
        let mut cursor = head;
        while chain.len() < limit {
            match self.store.header(cursor).map_err(|e| e.to_string())? {
                Some(mut header) => {
                    // The key a header is stored under is its hash, by
                    // definition; recomputing it from the decoded fields is
                    // not always the same number. A genesis built from an
                    // rskj JSON file hashes over the file's difficulty bytes
                    // as written, which its decoded form no longer has, so
                    // the first template on such a chain would name a
                    // parent no other node knows. (`setup_genesis` stores it
                    // under rskj's hash for the same reason.)
                    header.cached_hash = Some(cursor);
                    let parent = header.parent_hash;
                    let is_genesis = header.number == 0;
                    chain.push(header);
                    if is_genesis {
                        break;
                    }
                    cursor = parent;
                }
                None => break,
            }
        }

        if chain.is_empty() {
            return Err("the head block's header is missing from the store".to_string());
        }
        Ok(chain)
    }

    fn has_block(&self, hash: B256) -> Result<bool, String> {
        self.store.header(hash).map(|h| h.is_some()).map_err(|e| e.to_string())
    }

    fn executed_head(&self) -> Result<Option<B256>, String> {
        match self.store.exec_head().map_err(|e| e.to_string())? {
            Some((hash, _)) => Ok(Some(hash)),
            None => self.store.head().map_err(|e| e.to_string()),
        }
    }

    fn select_uncles(&self, block_number: u64, parent_hash: B256) -> Result<Vec<Header>, String> {
        // An un-upgraded database has no height index, so the family of a
        // block cannot be enumerated and selection would silently return
        // nothing forever. Say so once rather than quietly mine uncleless
        // blocks and leave the operator wondering why.
        if self.store.height_index_is_empty().map_err(|e| e.to_string())? {
            warn!(
                target: "rustock::mining",
                "No block-height index in this database, so no uncle can be found. \
                 Run the node once with --build-height-index to add it."
            );
            return Ok(Vec::new());
        }
        Ok(crate::mining::uncles::select_uncles(&self.store, block_number, parent_hash))
    }

    fn commit_mined_block(
        &self,
        block: &Block,
        state_root: B256,
        laps: &mut Laps,
    ) -> Result<CommitOutcome, String> {
        use std::time::Duration;
        let hash = block.hash();
        let number = block.header.number;
        let mut switch_chain = Duration::ZERO;
        let mut on_best_block = Duration::ZERO;

        if self.store.has_block(hash).map_err(|e| e.to_string())? {
            return Ok(CommitOutcome {
                result: ImportResult::Exist,
                switch_chain: laps.lap(),
                on_best_block,
            });
        }

        let parent_td = self
            .store
            .total_difficulty(block.header.parent_hash)
            .map_err(|e| e.to_string())?
            .unwrap_or(U256::ZERO);
        let td = parent_td + cumulative_difficulty(block);

        // Deliberately not `put_block`: that writes the canonical
        // `number -> hash` pointer unconditionally, which would hand the
        // height to a block that lost the total-difficulty comparison two
        // lines below and leave the canonical chain naming a block that is
        // not on it. Header and body are safe to store either way, being
        // keyed by hash.
        self.store.put_header_with_hash(hash, &block.header).map_err(|e| e.to_string())?;
        self.store
            .put_body(hash, &block.transactions, &block.ommers)
            .map_err(|e| e.to_string())?;
        self.store.put_total_difficulty(hash, td).map_err(|e| e.to_string())?;

        let current_td = match self.store.head().map_err(|e| e.to_string())? {
            Some(head) => self
                .store
                .total_difficulty(head)
                .map_err(|e| e.to_string())?
                .unwrap_or(U256::ZERO),
            None => U256::ZERO,
        };

        switch_chain += laps.lap();

        if let Some(hook) = &self.on_committed {
            hook(block);
        }
        on_best_block += laps.lap();

        let result = if td > current_td {
            self.store.update_canonical_chain(hash).map_err(|e| e.to_string())?;
            self.store.set_exec_head(hash, state_root).map_err(|e| e.to_string())?;
            switch_chain += laps.lap();
            // The trie nodes this block wrote are only durable once flushed;
            // announcing a head whose state cannot be reloaded after a restart
            // would leave the node unable to build on its own block. With
            // `flush_every` above 1 that durability is batched, see the field.
            if self.flush_due() {
                self.trie_store.flush();
            }
            on_best_block += laps.lap();
            ImportResult::ImportedBest
        } else {
            ImportResult::ImportedNotBest
        };

        info!(
            target: "rustock::mining",
            "Mined block #{} {:?} imported: {}", number, hash, result.as_str()
        );
        Ok(CommitOutcome { result, switch_chain, on_best_block })
    }
}

struct ServerState {
    /// Templates still answerable, oldest first.
    cache: VecDeque<BlockTemplate>,
    current: Option<MinerWork>,
    /// Parent of the newest template, to decide whether new work is worth a
    /// notify.
    last_parent: Option<B256>,
    last_fees_with_notify: U256,
}

pub struct MinerServer {
    builder: BlockTemplateBuilder,
    chain: Arc<dyn ChainAccess>,
    pending: Arc<dyn PendingTransactionSource>,
    chain_config: Arc<ChainConfig>,
    state: Mutex<ServerState>,
    /// Whether the node is still catching up. `None` never is.
    sync_gate: Option<Arc<dyn SyncGate>>,
    /// rskj `SubmissionRateLimitHandler`. Disabled unless configured.
    rate_limit: SubmissionRateLimiter,
    /// Decides whether arriving transactions are worth a rebuild.
    rebuild_policy: RebuildPolicy,
    /// Where the `block connect breakdown best:` line of each block this
    /// server connects as best goes. `None`, the default, reads no clock.
    breakdown: Option<BreakdownSink>,
}

/// rskj `SubmissionRateLimitHandler`: at most one submission per
/// `miner.server.workSubmissionRateLimitInMills`. Zero (rskj's default)
/// disables it.
pub struct SubmissionRateLimiter {
    window_ms: u64,
    last_submitted_at: Mutex<u64>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl SubmissionRateLimiter {
    /// rskj `ofMiningConfig`: enabled when the window is positive.
    pub fn new(window_ms: u64) -> Self {
        Self::with_clock(window_ms, Box::new(now_millis))
    }

    pub fn disabled() -> Self {
        Self::new(0)
    }

    /// With a clock of the caller's, for tests (rskj's `TimeProvider`).
    pub fn with_clock(window_ms: u64, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self { window_ms, last_submitted_at: Mutex::new(0), clock }
    }

    pub fn is_enabled(&self) -> bool {
        self.window_ms > 0
    }

    pub fn is_submission_allowed(&self) -> bool {
        if !self.is_enabled() {
            return true;
        }
        let now = (self.clock)();
        now.saturating_sub(*self.last_submitted_at.lock().expect("rate limit lock")) >= self.window_ms
    }

    pub fn on_submit(&self) {
        *self.last_submitted_at.lock().expect("rate limit lock") = (self.clock)();
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// rskj `MinerServerImpl.NewBlockTxListener.isWorthRebuilding`: rebuilding
/// the candidate re-executes every transaction in it, so arriving
/// transactions trigger one only once their fees, accumulated since the
/// last rebuild, reach `fraction` of what the candidate already pays. With
/// no candidate to compare against, any arrival is worth it. Skipping a
/// rebuild only delays a transaction: the next best block rebuilds
/// unconditionally, and so does the refresh timer.
pub struct RebuildPolicy {
    /// rskj `miner.server.rebuildFeeFraction`, 0.1 by default.
    fraction: f64,
    fees_since_last_build: Mutex<U256>,
}

impl RebuildPolicy {
    pub const DEFAULT_FRACTION: f64 = 0.1;

    pub fn new(fraction: f64) -> Self {
        Self { fraction, fees_since_last_build: Mutex::new(U256::ZERO) }
    }

    /// rskj `resetAccumulatedFees`.
    pub fn reset(&self) {
        *self.fees_since_last_build.lock().expect("rebuild policy lock") = U256::ZERO;
    }

    /// rskj `isWorthRebuilding`: `candidate_fees` is what the current
    /// candidate pays its miner, `None` when there is none.
    pub fn worth_rebuilding(&self, candidate_fees: Option<U256>, arrivals: &[rustock_core::Transaction]) -> bool {
        let mut accumulated = self.fees_since_last_build.lock().expect("rebuild policy lock");
        let Some(candidate) = candidate_fees.filter(|f| !f.is_zero()) else {
            *accumulated = U256::ZERO;
            return true;
        };
        for tx in arrivals {
            *accumulated += tx.gas_price.saturating_mul(tx.gas_limit);
        }
        // rskj: `new BigDecimal(candidate).multiply(fraction).toBigInteger()`,
        // the product truncated.
        let threshold = {
            let scaled = (self.fraction * 1_000_000.0).round() as u64;
            candidate.saturating_mul(U256::from(scaled)) / U256::from(1_000_000u64)
        };
        if *accumulated < threshold {
            return false;
        }
        *accumulated = U256::ZERO;
        true
    }
}

/// What the miner asks before building work: rskj
/// `NodeBlockProcessor.hasBetterBlockToSync`, which is
/// `BlockSyncService`'s "the last block number a peer announced is at least
/// `longSyncLimit` past our best". A node that far behind mines on a stale
/// head and every block it seals is orphaned on arrival.
pub trait SyncGate: Send + Sync {
    fn has_better_block_to_sync(&self) -> bool;
}

impl MinerServer {
    pub fn new(
        builder: BlockTemplateBuilder,
        chain: Arc<dyn ChainAccess>,
        pending: Arc<dyn PendingTransactionSource>,
        chain_config: Arc<ChainConfig>,
    ) -> Self {
        Self {
            builder,
            chain,
            pending,
            chain_config,
            state: Mutex::new(ServerState {
                cache: VecDeque::new(),
                current: None,
                last_parent: None,
                last_fees_with_notify: U256::ZERO,
            }),
            sync_gate: None,
            rate_limit: SubmissionRateLimiter::disabled(),
            rebuild_policy: RebuildPolicy::new(RebuildPolicy::DEFAULT_FRACTION),
            breakdown: None,
        }
    }

    /// rskj `miner.server.workSubmissionRateLimitInMills`: refuse a
    /// submission within `window_ms` of the previous one. Zero disables.
    pub fn with_submission_rate_limit(mut self, window_ms: u64) -> Self {
        self.rate_limit = SubmissionRateLimiter::new(window_ms);
        self
    }

    /// The rate limiter with a clock of the caller's, for tests.
    pub fn with_submission_rate_limiter(mut self, limiter: SubmissionRateLimiter) -> Self {
        self.rate_limit = limiter;
        self
    }

    /// rskj `NewBlockTxListener.onBestBlock`: a new parent invalidates the
    /// candidate outright, so rebuild, and start the fee accumulator over.
    pub fn on_best_block(&self) -> Result<MinerWork, SubmitError> {
        self.rebuild_policy.reset();
        self.build_work()
    }

    /// rskj `NewBlockTxListener.onPendingTransactionsReceived`: rebuild
    /// when the arrivals are worth it (see [`RebuildPolicy`]). `None` when
    /// they were not.
    pub fn on_pending_transactions_received(
        &self,
        transactions: &[rustock_core::Transaction],
    ) -> Option<Result<MinerWork, SubmitError>> {
        let candidate_fees = self
            .state
            .lock()
            .expect("miner state lock")
            .current
            .as_ref()
            .map(|w| w.fees_paid_to_miner);
        self.rebuild_policy
            .worth_rebuilding(candidate_fees, transactions)
            .then(|| self.build_work())
    }

    /// Refuse to build work while `gate` says there is a better block to
    /// sync. rskj gates `MinerClientImpl.mineBlock` on it; here the gate sits
    /// on `build_work`, which every miner, in-process or merged, goes
    /// through.
    /// Time every block this server completes and connects, and hand the
    /// `block connect breakdown best:` line of each one connected as best to
    /// `sink`. Same keys and scope as the import path's `--breakdown-log`.
    pub fn with_breakdown_log(mut self, sink: BreakdownSink) -> Self {
        self.breakdown = Some(sink);
        self
    }

    pub fn with_sync_gate(mut self, gate: Arc<dyn SyncGate>) -> Self {
        self.sync_gate = Some(gate);
        self
    }


    /// The address block rewards are paid to.
    pub fn coinbase_address(&self) -> alloy_primitives::Address {
        self.builder.mining_config().coinbase_address
    }

    /// Build a fresh template on the current best block and make it the work
    /// on offer. Called when the chain advances, when the pool changes, and
    /// on a timer -- and by `get_work` when there is nothing to hand out yet.
    pub fn build_work(&self) -> Result<MinerWork, SubmitError> {
        if self.sync_gate.as_ref().is_some_and(|g| g.has_better_block_to_sync()) {
            return Err(SubmitError::Syncing);
        }
        let mainchain = self
            .chain
            .mainchain(crate::mining::fork_detection::REQUIRED_MAINCHAIN_BLOCKS)
            .map_err(SubmitError::Storage)?;

        let parent = &mainchain[0];
        let uncles = self
            .chain
            .select_uncles(parent.number + 1, parent.hash())
            .map_err(SubmitError::Storage)?;
        if !uncles.is_empty() {
            info!(
                target: "rustock::mining",
                "Including {} uncle(s) in the block being mined at #{}",
                uncles.len(),
                parent.number + 1
            );
        }

        let template = self.builder.build(&mainchain, uncles, self.pending.as_ref())?;

        let mut state = self.state.lock().expect("miner state lock");
        let parent_hash = template.parent_hash();
        let notify = Self::should_notify(&state, parent_hash, template.fees_paid_to_miner);
        if notify {
            state.last_fees_with_notify = template.fees_paid_to_miner;
        }
        state.last_parent = Some(parent_hash);

        let work = MinerWork {
            block_hash_for_merged_mining: template.hash_for_merged_mining,
            target: template.target,
            fees_paid_to_miner: template.fees_paid_to_miner,
            notify,
            parent_block_hash: parent_hash,
        };
        state.current = Some(work.clone());

        state.cache.push_back(template);
        while state.cache.len() > self.builder.mining_config().work_cache_size {
            state.cache.pop_front();
        }

        Ok(work)
    }

    /// rskj `MinerServerImpl.getNotify`: a new parent always warrants a push;
    /// otherwise only a meaningfully richer block does, so that a pool is not
    /// woken for every transaction that trickles in.
    fn should_notify(state: &ServerState, parent_hash: B256, fees: U256) -> bool {
        if state.last_parent != Some(parent_hash) {
            return true;
        }
        // rskj NOTIFY_FEES_PERCENTAGE_INCREASE = 10.
        let threshold = state.last_fees_with_notify * U256::from(110) / U256::from(100);
        fees > threshold
    }

    /// The work currently on offer, building it first if there is none.
    ///
    /// `notify` is cleared after it has been read once: it marks the
    /// transition, not the work.
    pub fn get_work(&self) -> Result<MinerWork, SubmitError> {
        // Build first if there is nothing on offer, then fall through to the
        // same clearing path. Returning `build_work`'s result directly would
        // leave the stored copy still flagged, so the *second* caller would be
        // told to notify about work the first one already took.
        if self.state.lock().expect("miner state lock").current.is_none() {
            self.build_work()?;
        }

        let mut state = self.state.lock().expect("miner state lock");
        let work = state
            .current
            .clone()
            .ok_or_else(|| SubmitError::Storage("no work available".into()))?;
        if work.notify {
            state.current = Some(MinerWork { notify: false, ..work.clone() });
        }
        Ok(work)
    }

    /// A full Bitcoin block, from which everything else is derivable.
    /// rskj `mnr_submitBitcoinBlock`.
    pub fn submit_bitcoin_block(&self, raw_block: &[u8]) -> Result<SubmittedBlockInfo, SubmitError> {
        use bitcoin::consensus::Decodable;

        let mut reader = raw_block;
        let btc_block: bitcoin::Block = Decodable::consensus_decode(&mut reader)
            .map_err(|e| SubmitError::BitcoinBlockDecode(e.to_string()))?;

        let coinbase_tx = btc_block
            .txdata
            .first()
            .ok_or_else(|| SubmitError::BitcoinBlockDecode("block has no transactions".into()))?;
        let coinbase_bytes = coinbase::encode_transaction(coinbase_tx);

        let proof = merkle::proof_from_txids(&coinbase::txids_display_order(&btc_block))?;

        self.complete_and_import(
            &coinbase::encode_header(&btc_block.header),
            &coinbase_bytes,
            proof,
        )
    }

    /// Header, coinbase and the block's transaction hashes -- enough to
    /// rebuild the merkle branch without shipping every transaction.
    /// rskj `mnr_submitBitcoinBlockTransactions`.
    pub fn submit_bitcoin_block_transactions(
        &self,
        raw_header: &[u8],
        raw_coinbase: &[u8],
        tx_hashes: &str,
    ) -> Result<SubmittedBlockInfo, SubmitError> {
        let hashes = merkle::parse_wire_hashes(tx_hashes)?;
        let proof = merkle::proof_from_tx_hashes(&hashes)?;
        self.complete_and_import(raw_header, raw_coinbase, proof)
    }

    /// Header, coinbase and the merkle branch itself -- the cheapest form, and
    /// what a pool that already computed the branch sends.
    /// rskj `mnr_submitBitcoinBlockPartialMerkle`.
    pub fn submit_bitcoin_block_partial_merkle(
        &self,
        raw_header: &[u8],
        raw_coinbase: &[u8],
        merkle_hashes: &str,
        _block_tx_count: u32,
    ) -> Result<SubmittedBlockInfo, SubmitError> {
        let hashes = merkle::parse_wire_hashes(merkle_hashes)?;
        let proof = merkle::proof_from_merkle_hashes(&hashes)?;
        self.complete_and_import(raw_header, raw_coinbase, proof)
    }

    /// The common tail of all three submit paths: match the solution to the
    /// work it answers, fill in the three merged-mining fields, check the
    /// result against the same rule a peer would apply, and import it.
    fn complete_and_import(
        &self,
        raw_btc_header: &[u8],
        raw_coinbase: &[u8],
        merkle_proof: Vec<u8>,
    ) -> Result<SubmittedBlockInfo, SubmitError> {
        // The clock of the connect, rskj `internalTryToConnect`'s scope:
        // from matching the solution to its template to the block being best
        // and durable. Reads nothing unless a breakdown sink is set.
        let mut laps = Laps::new(self.breakdown.is_some());
        let mut t = ConnectTimings::default();

        // rskj `processSolution`: the rate limit is checked first, and the
        // submission counts whether or not the work is found.
        if !self.rate_limit.is_submission_allowed() {
            warn!(target: "rustock::mining", "Cannot publish block, block submission rate limit exceeded");
            return Err(SubmitError::RateLimited);
        }
        self.rate_limit.on_submit();

        let work_hash = extract_merged_mining_hash(raw_coinbase)?;
        let template = self.take_template(work_hash)?;


        let compressed = compress_coinbase(raw_coinbase, true)?;

        let mut block = template.block.clone();
        // Filling these must not disturb the merged-mining hash: RSKIP92 keeps
        // them out of the hashed prefix precisely so that a solution can be
        // attached to a block that was already committed to.
        let hash_before = block.header.hash_for_merged_mining();
        block.header.bitcoin_merged_mining_header = Some(Bytes::copy_from_slice(raw_btc_header));
        block.header.bitcoin_merged_mining_coinbase_transaction =
            Some(Bytes::from(compressed));
        block.header.bitcoin_merged_mining_merkle_proof = Some(Bytes::from(merkle_proof));
        debug_assert_eq!(hash_before, block.header.hash_for_merged_mining());

        // The same solution submitted twice: rskj's `addNewMinedBlock`
        // answers `EXIST` and the submission is `OK`. Checked before the
        // parent, which the first submission moved.
        let completed_hash = block.hash();
        if self.chain.has_block(completed_hash).map_err(SubmitError::Storage)? {
            return Ok(SubmittedBlockInfo {
                block_imported_result: ImportResult::Exist,
                block_hash: completed_hash,
                block_included_height: block.header.number,
            });
        }

        let head = self.chain.executed_head().map_err(SubmitError::Storage)?;
        if head != Some(template.parent_hash()) {
            return Err(SubmitError::ParentNoLongerHead {
                parent: template.parent_hash(),
                head,
            });
        }
        t.preamble = laps.lap();

        // The same rule every peer will run. Failing here means the node built
        // something it would itself reject, which is worth catching before it
        // is stored and announced rather than after.
        MergedMiningRule { config: self.chain_config.clone() }
            .validate(&block.header)
            .map_err(SubmitError::SelfCheck)?;
        // RSKIP179: a solution found in a Bitcoin block timestamped five
        // minutes or more from the template is one every peer rejects.
        rustock_core::validation::BitcoinTimestampRule { config: self.chain_config.clone() }
            .validate(&block.header)
            .map_err(SubmitError::SelfCheck)?;
        t.initial_validation = laps.lap();

        let state_root = self
            .builder
            .load_state_root(template.parent_state_root)
            .map_err(SubmitError::Template)?;
        // `process_and_commit`, in its two halves, so the receipts can be
        // timed apart from execution. The timed processor reads the clock
        // only when measuring; the plain one never does.
        let processor = self.builder.processor();
        let trie_store = self.builder.trie_store();
        let mut process = crate::ProcessTimings::default();
        let executed = if laps.enabled() {
            processor.process_block_timed(&block, &state_root, trie_store, &mut process)
        } else {
            processor.process_block(&block, &state_root, trie_store)
        }
        .map_err(|e| SubmitError::Execution(e.to_string()))?;
        laps.lap();
        t.initial_validation += process.pre_validation;
        t.execute = process.execute;
        t.trie_save = process.trie_save;
        t.post_execute_validation = process.post_validation;
        processor
            .commit_receipts(&block, &executed)
            .map_err(|e| SubmitError::Execution(e.to_string()))?;
        t.save_receipts = laps.lap();

        let outcome = self
            .chain
            .commit_mined_block(&block, executed.state_root_hash, &mut laps)
            .map_err(SubmitError::Storage)?;
        t.switch_chain = outcome.switch_chain;
        t.on_best_block = outcome.on_best_block;
        t.total = laps.total();

        if let (Some(sink), ImportResult::ImportedBest) = (&self.breakdown, outcome.result) {
            sink(&t.breakdown_line(
                block.header.number,
                block.hash(),
                block.transactions.len(),
                block.header.gas_used,
            ));
        }

        // The chain moved, so the work on offer is stale whatever happens next.
        if let Err(e) = self.build_work() {
            warn!(target: "rustock::mining", "Could not rebuild work after a submission: {e}");
        }

        Ok(SubmittedBlockInfo {
            block_imported_result: outcome.result,
            block_hash: block.hash(),
            block_included_height: block.header.number,
        })
    }

    /// The cached template a solution answers. Templates are not removed:
    /// two solutions to the same work is not an error, and the second would
    /// otherwise be reported as unknown work rather than as a duplicate block.
    fn take_template(&self, hash: B256) -> Result<BlockTemplate, SubmitError> {
        let state = self.state.lock().expect("miner state lock");
        state
            .cache
            .iter()
            .rev()
            .find(|t| t.hash_for_merged_mining == hash)
            .cloned()
            .ok_or(SubmitError::UnknownWork { hash })
    }

    /// The template builder behind this server, so a test can build a
    /// template on a parent of its choosing without going through the store.
    #[cfg(test)]
    pub(crate) fn builder_for_test(&self) -> &BlockTemplateBuilder {
        &self.builder
    }

    /// The coinbase hash a completed header commits to, for tests and
    /// diagnostics.
    pub fn coinbase_hash(compressed: &[u8]) -> [u8; 32] {
        compute_coinbase_hash(compressed)
    }
}

/// What a block adds to the chain's total difficulty: its own and its
/// uncles', as rskj's `Block.getCumulativeDifficulty` counts it and the
/// sync path's header-and-body accounting does. Counting the header alone
/// leaves the stored total short by every uncle, which an rskj export of
/// the same chain shows at the first block with one.
pub fn cumulative_difficulty(block: &Block) -> U256 {
    block
        .ommers
        .iter()
        .fold(block.header.difficulty, |total, uncle| total.saturating_add(uncle.difficulty))
}

/// The 32 bytes following the last `RSKBLOCK:` in a coinbase: the key a
/// submission is matched to outstanding work by. rskj
/// `MnrModuleImpl.extractBlockHashForMergedMining`.
pub fn extract_merged_mining_hash(coinbase: &[u8]) -> Result<B256, SubmitError> {
    let position = find_last_subsequence(coinbase, RSK_TAG).ok_or(SubmitError::NoTagInCoinbase)?;
    let start = position + RSK_TAG.len();
    let end = start + BLOCK_HEADER_HASH_SIZE;
    if coinbase.len() < end {
        return Err(SubmitError::NoTagInCoinbase);
    }
    Ok(B256::from_slice(&coinbase[start..end]))
}
