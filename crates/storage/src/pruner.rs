//! Deleting block history the node no longer needs.
//!
//! Distinct from the trie collector in `epoch_store`, which reclaims *state*.
//! This reclaims *chain data*: headers, bodies, receipts (and therefore the
//! events in them), the transaction index, and the canonical mapping, for
//! blocks far enough behind the head that nothing can ask for them.
//!
//! # How deep is far enough
//!
//! Two independent requirements stack:
//!
//! - **Reorg tolerance.** The node must be able to rebuild from a
//!   reorganisation up to `D` blocks deep, which needs the blocks themselves.
//! - **Block-info precompiles, and REMASC.** Rootstock exposes precompiles that
//!   read attributes of recent blocks, reaching up to 4,000 blocks back, and
//!   REMASC pays out with a maturity of 4,000. Executing a block at height `h`
//!   may therefore read data from `h - 4000`.
//!
//! They compose rather than overlap: after a 4,000-block reorg the node
//! re-executes from `head - 4000`, and executing *that* block may reach back a
//! further 4,000. So the shallowest safe retention is **8,000 blocks**, and
//! [`MIN_KEEP_DEPTH`] is a floor the configuration cannot go below.
//!
//! # Gaps are a supported state
//!
//! After pruning, the database has no blocks below a floor. Everything that
//! walks the chain must tolerate that: `ensure_canonical_lineage` already stops
//! when a parent header is absent, the sync connection-point search converges to
//! a height at or above the floor because lower ones are not "ours", and the RPC
//! answers `null` for a pruned height exactly as it does for an unknown one.
//!
//! Genesis is always retained. It costs one block and keeps every "start of the
//! chain" lookup working, so the gap is a hole in the middle of the chain rather
//! than a missing beginning.
//!
//! # Measured from the executed head, never the header head
//!
//! Both requirements above are about **execution**: it is the executing block
//! that reaches back 4,000, and a reorg that re-executes. So the retention
//! depth is measured from the block this node has executed to, not from the
//! best header it holds.
//!
//! The two are the same on a node that is keeping up and wildly different on
//! one that is not. A snapshot-synced node has every header of the chain but
//! has executed only from its checkpoint, so its header head can sit thousands
//! of blocks above its executed head -- and a sweep measured from the header
//! head deletes blocks that execution has not reached yet but still needs.
//!
//! Observed: a test node pruned to #9,274,241 while executing #9,275,670,
//! whose REMASC payout needed #9,271,670. That block was gone, execution
//! failed, and no retry could succeed because the data was not coming back.
//!
//! The clamp lives here rather than in the callers. Deleting history is not
//! recoverable, so the rule belongs at the point of deletion where no caller
//! can forget it.
//!
//! The floor is recorded in the database -- number, hash and total difficulty --
//! so a node can say what it holds without a scan, and so the value needed to
//! keep total difficulty accumulating is never the thing that was deleted.

use alloy_primitives::{B256, U256};
use anyhow::{bail, Context, Result};
use rocksdb::WriteBatch;
use std::time::Instant;
use tracing::{debug, info};

use crate::BlockStore;

/// Blocks that must always be retained below the head.
///
/// 4,000 for reorg tolerance plus 4,000 for the block-info precompiles, which a
/// re-executed block may itself reach back through. Configuration is clamped to
/// this; it is not a default.
pub const MIN_KEEP_DEPTH: u64 = 8_000;

/// Key under which the floor record lives.
const KEY_PRUNE_FLOOR: &[u8] = b"prune_floor";

#[derive(Debug, Clone)]
pub struct PruneConfig {
    /// Blocks to keep below the head. Clamped up to [`MIN_KEEP_DEPTH`].
    pub keep_depth: u64,
    /// Most blocks to remove in one sweep, so a single call cannot stall the
    /// node for an unbounded time.
    pub max_batch: u64,
    /// Remove the headers, the canonical index and the total difficulties.
    pub headers: bool,
    /// Remove the block bodies -- **and the uncles inside them**, which is
    /// where uncles live in this database. There is no uncle column family;
    /// `body()` returns `(transactions, ommers)`.
    pub bodies: bool,
    /// Remove the receipts and the transaction index that points into them.
    pub receipts: bool,
}

impl Default for PruneConfig {
    fn default() -> Self {
        Self {
            keep_depth: 100_000,
            max_batch: 50_000,
            headers: true,
            bodies: true,
            receipts: true,
        }
    }
}

impl PruneConfig {
    fn effective_keep_depth(&self) -> u64 {
        self.keep_depth.max(MIN_KEEP_DEPTH)
    }

    /// Whether this configuration would delete anything at all.
    pub fn removes_anything(&self) -> bool {
        self.headers || self.bodies || self.receipts
    }

    /// Why this combination cannot be run, if it cannot.
    ///
    /// Bodies and receipts are keyed by block hash, and the only way to reach
    /// a hash for an old height is the canonical index -- which goes with the
    /// headers. Deleting headers while keeping either leaves data nothing can
    /// name: it occupies the disk it was meant to save and no read will ever
    /// find it again.
    pub fn refusal(&self) -> Option<String> {
        if self.headers && !self.bodies {
            return Some(
                "pruning headers without bodies orphans the bodies: they are keyed by \
                 hash, and the canonical index that finds the hash goes with the headers"
                    .to_string(),
            );
        }
        if self.headers && !self.receipts {
            return Some(
                "pruning headers without receipts orphans the receipts, for the same \
                 reason: nothing can name them once the canonical index is gone"
                    .to_string(),
            );
        }
        None
    }
}

/// The oldest block the database still holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneFloor {
    pub number: u64,
    pub hash: B256,
    /// Cumulative difficulty at the floor. Retained because everything below it
    /// is gone, so this is the only remaining anchor for the chain's weight.
    pub total_difficulty: U256,
}

/// What a sweep would do, computed before it does it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrunePlan {
    /// Lowest block the sweep would delete.
    pub from: u64,
    /// Highest block the sweep would delete, inclusive.
    pub to: u64,
    /// The floor that would follow: the lowest block still held.
    pub new_floor: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PruneStats {
    pub from: u64,
    pub to: u64,
    pub blocks: u64,
    pub bodies: u64,
    pub receipts: u64,
    pub transactions: u64,
    pub seconds: f64,
}

impl BlockStore {
    /// The oldest retained block, if the database has ever been pruned.
    pub fn prune_floor(&self) -> Result<Option<PruneFloor>> {
        let Some(raw) = self.db().get(KEY_PRUNE_FLOOR).context("reading prune floor")? else {
            return Ok(None);
        };
        if raw.len() != 8 + 32 + 32 {
            bail!("prune floor record is {} bytes, expected 72", raw.len());
        }
        let mut num = [0u8; 8];
        num.copy_from_slice(&raw[..8]);
        Ok(Some(PruneFloor {
            number: u64::from_be_bytes(num),
            hash: B256::from_slice(&raw[8..40]),
            total_difficulty: U256::from_be_slice(&raw[40..72]),
        }))
    }

    /// Sets the floor directly, for tests that need a pruned node without
    /// running a sweep to build one.
    pub fn set_prune_floor_for_test(
        &self,
        number: u64,
        hash: B256,
        total_difficulty: U256,
    ) -> Result<()> {
        self.set_prune_floor(&PruneFloor { number, hash, total_difficulty })
    }

    fn set_prune_floor(&self, floor: &PruneFloor) -> Result<()> {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(&floor.number.to_be_bytes());
        buf.extend_from_slice(floor.hash.as_slice());
        buf.extend_from_slice(&floor.total_difficulty.to_be_bytes::<32>());
        self.db().put(KEY_PRUNE_FLOOR, buf).context("writing prune floor")
    }

    /// Removes block data below `head_number - keep_depth`.
    ///
    /// Returns what was removed. Deleting nothing is success, not an error: a
    /// chain shorter than the retention depth simply has nothing to prune.
    /// What the next sweep would delete, without deleting it.
    ///
    /// Returns the inclusive range and the floor that would follow. `None`
    /// when there is nothing to do.
    ///
    /// Exists so that a node can say what it is about to stop serving *before*
    /// it stops serving it. Announcing afterwards leaves a window in which
    /// peers believe this node holds blocks it has already deleted, which is
    /// the direction this module avoids everywhere else: over-reporting what
    /// exists invites a reader to ask for something gone, while
    /// under-reporting only costs a request nobody made.
    ///
    /// The sweep calls this too, so the figure announced and the figure acted
    /// on cannot drift apart.
    pub fn plan_prune(&self, config: &PruneConfig, head_number: u64) -> Result<Option<PrunePlan>> {
        let keep = config.effective_keep_depth();

        let executed = self
            .exec_head()?
            .and_then(|(hash, _)| self.header(hash).ok().flatten())
            .map(|h| h.number);
        let Some(executed) = executed else { return Ok(None) };
        let head_number = head_number.min(executed);

        let Some(mut target) = head_number.checked_sub(keep) else { return Ok(None) };

        // Never delete a body whose uncle headers the freezer has not taken a
        // copy of. The body is the only place they exist, so pruning ahead of
        // the freezer destroys the chain's own record of the work it absorbed,
        // and no later pass can rebuild it.
        //
        // This is a real race rather than a theoretical one: the freezer works
        // below `head - FREEZE_DEPTH` while the pruner works below
        // `head - keep_depth`, and the default keep depth is the shallower of
        // the two. Left alone, the pruner reaches every block first.
        if let Some(f) = self.freezer() {
            let frozen_uncles = f.uncles_end_number();
            if frozen_uncles == 0 {
                debug!(
                    target: "rustock::prune",
                    "holding off: the freezer holds no uncle headers yet, and the bodies \
                     are the only other copy"
                );
                return Ok(None);
            }
            target = target.min(frozen_uncles - 1);
        }

        let floor = self.prune_floor()?;
        let mut from = floor.as_ref().map(|f| f.number).unwrap_or(1).max(1);
        if let Some(lowest) = self.lowest_indexed_height()? {
            from = from.max(lowest);
        }
        if from > target {
            return Ok(None);
        }
        let to = target.min(from + config.max_batch.max(1) - 1);
        Ok(Some(PrunePlan { from, to, new_floor: to + 1 }))
    }

    pub fn prune_blocks(&self, config: &PruneConfig, head_number: u64) -> Result<PruneStats> {
        let keep = config.effective_keep_depth();
        let started = Instant::now();
        let mut stats = PruneStats::default();

        // One source of truth for what this sweep covers, shared with
        // `plan_prune` so that the range a node announces and the range it
        // deletes cannot disagree.
        let Some(plan) = self.plan_prune(config, head_number)? else {
            debug!(
                target: "rustock::prune",
                "nothing to prune below #{head_number} at a depth of {keep}"
            );
            return Ok(stats);
        };
        let (from, to) = (plan.from, plan.to);

        // Establish the new floor *before* deleting, so an interrupted sweep
        // leaves a floor that understates what is held rather than one that
        // claims blocks already gone. Over-reporting what exists is the
        // dangerous direction: it invites a reader to ask for something deleted.
        let new_floor_number = plan.new_floor;
        let new_floor = self.floor_record(new_floor_number)?;
        if let Some(f) = &new_floor {
            self.set_prune_floor(f)?;
        }

        let cf_headers = self.cf_headers()?;
        let cf_bodies = self.cf_bodies()?;
        let cf_numbers = self.cf_numbers()?;
        let cf_td = self.cf_td()?;
        let cf_receipts = self.cf_receipts()?;
        let cf_tx_index = self.cf_tx_index()?;

        // A prune can span thousands of blocks and said nothing until it
        // finished. Same rule as everywhere else: nothing that runs for
        // minutes goes without a sign of life.
        const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(10);
        // Reuse the timer started at the top of the function. A second one
        // here shadows it, and `stats.seconds` below then measures from the
        // wrong point.
        let mut last_report = started;

        let mut batch = WriteBatch::default();
        for number in from..=to {
            if last_report.elapsed() >= REPORT_EVERY {
                last_report = std::time::Instant::now();
                let span = (to - from + 1) as f64;
                info!(
                    target: "rustock::prune",
                    "pruning: {:.1}% (at #{number} of #{from}..#{to}), {} block(s) removed, \
                     {:.0}s elapsed",
                    (number - from) as f64 / span * 100.0,
                    stats.blocks,
                    started.elapsed().as_secs_f64()
                );
            }
            let Some(hash) = self.canonical_hash(number)? else {
                continue;
            };

            // The transaction index is keyed by transaction hash, so the body
            // has to be read to know which entries belong to this block. Read
            // it when either the body or the index is going.
            if config.bodies || config.receipts {
                if let Ok(Some((txs, _))) = self.body(hash) {
                    if config.receipts {
                        for tx in &txs {
                            let mut buf = Vec::new();
                            alloy_rlp::Encodable::encode(tx, &mut buf);
                            let tx_hash = B256::from_slice(
                                &<sha3::Keccak256 as sha3::Digest>::digest(&buf),
                            );
                            batch.delete_cf(cf_tx_index, tx_hash.as_slice());
                            stats.transactions += 1;
                        }
                    }
                    if config.bodies {
                        // The uncles go with the body: they live inside it.
                        batch.delete_cf(cf_bodies, hash.as_slice());
                        stats.bodies += 1;
                    }
                }
            }
            if config.receipts && matches!(self.receipts(hash), Ok(Some(_))) {
                batch.delete_cf(cf_receipts, hash.as_slice());
                stats.receipts += 1;
            }
            if config.headers {
                batch.delete_cf(cf_headers, hash.as_slice());
                batch.delete_cf(cf_td, hash.as_slice());
                batch.delete_cf(cf_numbers, number.to_be_bytes());
            }
            stats.blocks += 1;
        }

        self.db().write(batch).context("committing prune batch")?;

        stats.from = from;
        stats.to = to;
        stats.seconds = started.elapsed().as_secs_f64();
        info!(
            target: "rustock::prune",
            "Pruned #{}..#{}: {} blocks, {} bodies, {} receipts, {} tx index entries in {:.1}s \
             (floor now #{})",
            stats.from, stats.to, stats.blocks, stats.bodies, stats.receipts,
            stats.transactions, stats.seconds,
            new_floor.as_ref().map(|f| f.number).unwrap_or(new_floor_number)
        );
        Ok(stats)
    }

    /// The lowest height with a `number -> hash` entry in the block database.
    ///
    /// Deliberately asks the column family rather than `canonical_hash`, which
    /// falls back to the freezer: this is "where does the block database
    /// begin", and the freezer is not the block database. Genesis is skipped
    /// because it is always retained and would otherwise answer 0 on every
    /// node.
    fn lowest_indexed_height(&self) -> Result<Option<u64>> {
        let cf = self.cf_numbers()?;
        let iter = self.db().iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&1u64.to_be_bytes(), rocksdb::Direction::Forward),
        );
        for item in iter {
            let (k, _) = item.context("scanning for the lowest indexed height")?;
            if k.len() == 8 {
                return Ok(Some(u64::from_be_bytes(k[..8].try_into().unwrap_or([0; 8]))));
            }
        }
        Ok(None)
    }

    /// The lowest block above genesis that the database holds contiguously: the
    /// prune floor if it has been pruned, genesis otherwise.
    ///
    /// Genesis itself is always present, so this is not "the oldest block" so
    /// much as "where uninterrupted history begins". Callers that need a chain
    /// anchor can keep using block 0.
    pub fn oldest_block(&self) -> Result<Option<(u64, B256)>> {
        if let Some(f) = self.prune_floor()? {
            if self.canonical_hash(f.number)? == Some(f.hash) {
                return Ok(Some((f.number, f.hash)));
            }
        }
        Ok(self.canonical_hash(0)?.map(|h| (0, h)))
    }

    /// Builds the floor record for a block that is being retained.
    fn floor_record(&self, number: u64) -> Result<Option<PruneFloor>> {
        let Some(hash) = self.canonical_hash(number)? else {
            return Ok(None);
        };
        let td = self.total_difficulty(hash)?.unwrap_or_default();
        Ok(Some(PruneFloor { number, hash, total_difficulty: td }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockStore;
    use rustock_core::types::header::Header;
    use tempfile::tempdir;

    pub(super) fn header(number: u64, parent: B256) -> Header {
        Header {
            number,
            parent_hash: parent,
            ommers_hash: B256::ZERO,
            beneficiary: alloy_primitives::Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(1_000u64),
            gas_limit: U256::ZERO,
            gas_used: 0,
            timestamp: 1_700_000_000 + number,
            extra_data: alloy_primitives::Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
            kept: None,
        }
    }

    /// Builds a canonical chain of `n` blocks (0..n-1) with total difficulty,
    /// executed to the top.
    ///
    /// The executed head matters: retention is measured from it, so a fixture
    /// without one describes a node that has run nothing and must not prune.
    pub(super) fn chain(store: &BlockStore, n: u64) -> Vec<B256> {
        let mut hashes = Vec::with_capacity(n as usize);
        let mut parent = B256::ZERO;
        let mut td = U256::ZERO;
        for i in 0..n {
            let h = header(i, parent);
            let hash = h.hash();
            td += h.difficulty;
            store.put_header(&h).unwrap();
            store.put_canonical_hash(i, hash).unwrap();
            store.put_total_difficulty(hash, td).unwrap();
            store.put_body(hash, &[], &[]).unwrap();
            parent = hash;
            hashes.push(hash);
        }
        if let Some(top) = hashes.last() {
            store.set_exec_head(*top, B256::ZERO).unwrap();
        }
        hashes
    }

    #[test]
    fn keeps_at_least_the_minimum_depth_whatever_the_configuration_says() {
        // The floor exists because Rootstock's block-info precompiles reach
        // 4,000 blocks back and a reorg may re-execute from 4,000 back, so a
        // re-executed block can read 8,000 back. A configuration asking for less
        // must be clamped, not honoured.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 12_000);

        let cfg = PruneConfig { keep_depth: 10, max_batch: 100_000, ..PruneConfig::default() };
        assert_eq!(cfg.effective_keep_depth(), MIN_KEEP_DEPTH);

        let stats = store.prune_blocks(&cfg, 11_999).unwrap();
        assert_eq!(stats.to, 11_999 - MIN_KEEP_DEPTH, "pruned no closer than the floor");

        // Everything inside the retention window is still readable.
        for n in (11_999 - MIN_KEEP_DEPTH + 1)..=11_999 {
            let hash = store.canonical_hash(n).unwrap().expect("retained block");
            assert!(store.header(hash).unwrap().is_some(), "#{n} must survive");
        }
    }

    #[test]
    fn prunes_nothing_on_a_chain_shorter_than_the_retention_depth() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 500);
        let stats = store.prune_blocks(&PruneConfig::default(), 499).unwrap();
        assert_eq!(stats.blocks, 0);
        assert!(store.prune_floor().unwrap().is_none(), "no floor recorded");
        assert!(store.header(store.canonical_hash(0).unwrap().unwrap()).unwrap().is_some());
    }

    #[test]
    fn removes_headers_bodies_receipts_and_the_transaction_index() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 9_000);

        let doomed = store.canonical_hash(5).unwrap().unwrap();
        let survivor = store.canonical_hash(8_999).unwrap().unwrap();
        store.put_receipts(doomed, &[]).unwrap();

        let stats = store
            .prune_blocks(&PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() }, 8_999)
            .unwrap();
        assert!(stats.blocks > 0, "something must have been pruned");

        assert!(store.header(doomed).unwrap().is_none(), "header gone");
        assert!(store.body(doomed).unwrap().is_none(), "body gone");
        assert!(store.receipts(doomed).unwrap().is_none(), "receipts and their events gone");
        assert!(store.canonical_hash(5).unwrap().is_none(), "canonical mapping gone");
        assert!(store.total_difficulty(doomed).unwrap().is_none(), "td gone");

        assert!(store.header(survivor).unwrap().is_some(), "the head is untouched");
    }

    /// Bodies may go while the headers stay: a node that keeps a walkable,
    /// servable chain without the transactions.
    #[test]
    fn pruning_bodies_alone_leaves_the_chain_intact() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 9_000);
        let doomed = store.canonical_hash(5).unwrap().unwrap();

        store
            .prune_blocks(
                &PruneConfig {
                    keep_depth: MIN_KEEP_DEPTH,
                    max_batch: 100_000,
                    headers: false,
                    bodies: true,
                    receipts: false,
                },
                8_999,
            )
            .unwrap();

        assert!(store.body(doomed).unwrap().is_none(), "the body is gone");
        assert!(
            store.header(doomed).unwrap().is_some(),
            "the header stays, so the chain is still walkable"
        );
        assert_eq!(
            store.canonical_hash(5).unwrap(),
            Some(doomed),
            "and still reachable by height"
        );
    }

    /// Headers without bodies is refused rather than run.
    ///
    /// Bodies are keyed by block hash, and the only way to reach a hash for an
    /// old height is the canonical index, which goes with the headers.
    /// Deleting headers while keeping bodies leaves data nothing can name: it
    /// occupies the disk it was meant to save and no read will ever find it.
    #[test]
    fn pruning_headers_without_bodies_is_refused() {
        let cfg = PruneConfig {
            keep_depth: MIN_KEEP_DEPTH,
            max_batch: 100,
            headers: true,
            bodies: false,
            receipts: true,
        };
        let why = cfg.refusal().expect("this combination must be refused");
        assert!(why.contains("orphans the bodies"), "the reason must say why: {why}");

        // And the coherent ones are not refused.
        assert!(PruneConfig::default().refusal().is_none(), "prune everything is fine");
        assert!(
            PruneConfig { headers: false, ..PruneConfig::default() }.refusal().is_none(),
            "keeping headers while dropping the rest is fine"
        );
    }

    #[test]
    fn genesis_is_never_pruned() {
        // Keeping block 0 costs one block and keeps every "start of the chain"
        // lookup working, so a pruned database has a hole in the middle rather
        // than a missing beginning.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hashes = chain(&store, 12_000);

        store
            .prune_blocks(&PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() }, 11_999)
            .unwrap();

        assert_eq!(store.canonical_hash(0).unwrap(), Some(hashes[0]), "genesis kept");
        assert!(store.header(hashes[0]).unwrap().is_some(), "genesis header kept");
        assert!(store.canonical_hash(1).unwrap().is_none(), "block 1 pruned");
        assert!(store.header(hashes[1]).unwrap().is_none());
    }

    #[test]
    fn records_a_floor_that_can_be_read_back() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 9_000);

        store
            .prune_blocks(&PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() }, 8_999)
            .unwrap();

        let floor = store.prune_floor().unwrap().expect("floor recorded");
        assert_eq!(floor.number, 8_999 - MIN_KEEP_DEPTH + 1, "floor is the lowest retained block");
        // The floor's own data is retained, including the total difficulty that
        // everything below it used to carry.
        assert_eq!(store.canonical_hash(floor.number).unwrap(), Some(floor.hash));
        assert!(store.header(floor.hash).unwrap().is_some());
        assert!(!floor.total_difficulty.is_zero(), "difficulty anchor kept");
        assert_eq!(store.total_difficulty(floor.hash).unwrap(), Some(floor.total_difficulty));
    }

    #[test]
    fn pruning_is_resumable_and_idempotent() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 12_000);

        // Small batches, as a continuous pruner would use.
        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 500, ..PruneConfig::default() };
        let mut total = 0;
        for _ in 0..20 {
            total += store.prune_blocks(&cfg, 11_999).unwrap().blocks;
        }
        // Blocks 1..=target are prunable; genesis is retained, so the count is
        // `target`, not `target + 1`.
        assert_eq!(total, 11_999 - MIN_KEEP_DEPTH, "all prunable blocks removed across sweeps");

        // Running again removes nothing and does not move the floor.
        let before = store.prune_floor().unwrap().unwrap();
        assert_eq!(store.prune_blocks(&cfg, 11_999).unwrap().blocks, 0);
        assert_eq!(store.prune_floor().unwrap().unwrap(), before);
    }

    #[test]
    fn the_chain_above_the_floor_stays_walkable_by_parent_hash() {
        // A pruned database has a gap below the floor. Walking back from the
        // head must still work down to the floor, and must stop there rather
        // than failing.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 9_500);
        store
            .prune_blocks(&PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() }, 9_499)
            .unwrap();

        let floor = store.prune_floor().unwrap().unwrap();
        let mut hash = store.canonical_hash(9_499).unwrap().unwrap();
        let mut walked = 0u64;
        loop {
            let Some(h) = store.header(hash).unwrap() else { break };
            walked += 1;
            if h.number == 0 {
                break;
            }
            hash = h.parent_hash;
        }
        assert_eq!(
            walked,
            9_499 - floor.number + 1,
            "the walk reaches the floor and stops, rather than running off the end"
        );
    }
}

#[cfg(test)]
mod bridge_event_tests {
    use super::tests::chain;
    use super::*;
    use crate::BlockStore;
    use tempfile::tempdir;

    /// Peg history outlives the blocks it came from.
    ///
    /// Receipts are pruned — that is the point, they are most of the weight —
    /// so `eth_getTransactionReceipt` stops answering for a pruned height. The
    /// Bridge events inside them must not go with them: they live in their own
    /// index, keyed by event signature, and the value carries the transaction
    /// hash, topics and data rather than pointing back into the receipt. That
    /// is what the peg is debugged from, long after the blocks are gone.
    #[test]
    fn bridge_events_survive_the_blocks_they_came_from() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 12_000);

        // A peg-in recorded at a height that is about to be pruned, and one
        // safely inside the retention window.
        let peg_in = B256::repeat_byte(0xa1);
        let doomed_height = 100u64;
        let kept_height = 11_500u64;
        for (h, tx) in [(doomed_height, 0xd1u8), (kept_height, 0xd2)] {
            store
                .put_bridge_event(
                    peg_in,
                    h,
                    0,
                    0,
                    B256::repeat_byte(tx),
                    &[peg_in, B256::repeat_byte(0xbb)],
                    b"amount and address",
                )
                .unwrap();
        }

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() };
        let stats = store.prune_blocks(&cfg, 11_999).unwrap();
        assert!(stats.blocks > 0, "the sweep must actually have removed something");
        assert!(doomed_height <= stats.to, "the peg-in's block was in the swept range");

        // The block really is gone, receipts included.
        assert!(
            store.canonical_hash(doomed_height).unwrap().is_none(),
            "the block should have been pruned"
        );

        // The event is not.
        let found = store.scan_bridge_events(peg_in, 0, u64::MAX).unwrap();
        let heights: Vec<u64> = found.iter().map(|e| e.0).collect();
        assert!(
            heights.contains(&doomed_height),
            "the peg-in at #{doomed_height} was lost with its block; found {heights:?}"
        );
        assert!(heights.contains(&kept_height));

        // And it is still self-contained: the data came from the event index,
        // not from a receipt that no longer exists.
        let (_, _, _, tx_hash, topics, data) =
            found.iter().find(|e| e.0 == doomed_height).unwrap();
        assert_eq!(*tx_hash, B256::repeat_byte(0xd1));
        assert_eq!(data.as_slice(), b"amount and address");
        assert_eq!(topics.len(), 2, "topics come from the event index, not a receipt");
    }

    /// Receipts, by contrast, are meant to go.
    #[test]
    fn receipts_are_pruned_with_their_blocks() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hashes = chain(&store, 12_000);

        let doomed = hashes[100];
        store.put_receipts(doomed, &[]).unwrap();
        assert!(store.receipts(doomed).unwrap().is_some());

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() };
        store.prune_blocks(&cfg, 11_999).unwrap();

        assert!(
            store.receipts(doomed).unwrap().is_none(),
            "receipts are most of the weight; pruning that keeps them saves little"
        );
    }
}

#[cfg(test)]
mod snap_synced_tests {
    use super::tests::{chain, header};
    use super::*;
    use crate::BlockStore;
    use tempfile::tempdir;

    /// A snapshot-synced node holds the canonical index only for a window
    /// around its checkpoint. A sweep must begin there, not at block 1.
    ///
    /// Walking up from 1 is not merely slow: `canonical_hash` falls back to
    /// the freezer, so those heights answer even though nothing was ever
    /// written to the block database for them, and each sweep burns its whole
    /// batch deleting entries that do not exist. Nine million blocks at fifty
    /// thousand a sweep is a hundred and eighty sweeps before the first real
    /// deletion.
    #[test]
    fn a_sweep_starts_where_the_block_database_begins() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Headers for the whole chain, as the snapshot walk leaves them:
        // written by hash, with the canonical index only near the top.
        let height = 60_000u64;
        let window_from = 50_000u64;
        let mut parent = B256::ZERO;
        let mut td = U256::ZERO;
        for i in 0..=height {
            let h = header(i, parent);
            let hash = h.hash();
            td += h.difficulty;
            store.put_header(&h).unwrap();
            store.put_total_difficulty(hash, td).unwrap();
            if i >= window_from || i == 0 {
                store.put_canonical_hash(i, hash).unwrap();
            }
            if i == height {
                store.set_exec_head(hash, B256::ZERO).unwrap();
            }
            parent = hash;
        }

        // One sweep, with a batch far smaller than the distance from block 1.
        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 1_000, ..PruneConfig::default() };
        let stats = store.prune_blocks(&cfg, height).unwrap();

        assert!(
            stats.from >= window_from,
            "the sweep began at #{} — below where the block database starts (#{window_from}), \
             so it spent its batch on heights that were never written",
            stats.from
        );
        assert!(stats.blocks > 0, "and it should have removed something real");
        assert!(
            stats.to <= height - MIN_KEEP_DEPTH,
            "never closer to the head than the retention floor"
        );
    }

    /// On an ordinarily synced node, whose index starts at the bottom, nothing
    /// changes: the sweep still begins at block 1.
    #[test]
    fn an_ordinary_node_still_sweeps_from_the_bottom() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 12_000);

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100, ..PruneConfig::default() };
        let stats = store.prune_blocks(&cfg, 11_999).unwrap();
        assert_eq!(stats.from, 1, "genesis is retained, so the first prunable block is 1");
    }
}

#[cfg(test)]
mod executed_head_tests {
    use super::tests::header;
    use super::*;
    use crate::BlockStore;
    use tempfile::tempdir;

    /// Builds a chain and marks `executed` as the block this node has run to.
    fn chain_executed_to(store: &BlockStore, n: u64, executed: u64) -> Vec<B256> {
        let mut hashes = Vec::with_capacity(n as usize);
        let mut parent = B256::ZERO;
        let mut td = U256::ZERO;
        for i in 0..n {
            let h = header(i, parent);
            let hash = h.hash();
            td += h.difficulty;
            store.put_header(&h).unwrap();
            store.put_canonical_hash(i, hash).unwrap();
            store.put_total_difficulty(hash, td).unwrap();
            store.put_body(hash, &[], &[]).unwrap();
            parent = hash;
            hashes.push(hash);
        }
        store.set_exec_head(hashes[executed as usize], B256::ZERO).unwrap();
        hashes
    }

    /// The bug this exists to prevent, seen on a real node.
    ///
    /// A snapshot-synced node holds every header but has executed only from
    /// its checkpoint, so the header head sits thousands of blocks above the
    /// executed head. Measuring retention from the header head deletes blocks
    /// execution has not reached yet and still needs: the node pruned to
    /// #9,274,241 while executing #9,275,670, whose REMASC payout needed
    /// #9,271,670. That block was gone and no retry could bring it back.
    #[test]
    fn retention_is_measured_from_the_executed_head_not_the_header_head() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Headers to #30,000; executed only to #20,000, as after a snapshot
        // sync whose forward header download has run ahead.
        let executed = 20_000u64;
        chain_executed_to(&store, 30_001, executed);

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() };
        let stats = store.prune_blocks(&cfg, 30_000).unwrap();

        let highest_removed = stats.to;
        assert!(
            highest_removed <= executed - MIN_KEEP_DEPTH,
            "pruned up to #{highest_removed}, but execution is at #{executed} and reaches \
             {MIN_KEEP_DEPTH} blocks back — everything above #{} is still needed",
            executed - MIN_KEEP_DEPTH
        );

        // The block REMASC would ask for while executing the next one.
        let needed = executed + 1 - 4_000;
        assert!(
            store.canonical_hash(needed).unwrap().is_some(),
            "#{needed} is what REMASC reads when executing #{}; it must survive",
            executed + 1
        );
        assert!(store.body(store.canonical_hash(needed).unwrap().unwrap()).unwrap().is_some());
    }

    /// A node that has executed nothing has no safe reference, so it prunes
    /// nothing rather than guessing.
    #[test]
    fn a_node_that_has_executed_nothing_prunes_nothing() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let mut parent = B256::ZERO;
        let mut td = U256::ZERO;
        for i in 0..30_000u64 {
            let h = header(i, parent);
            let hash = h.hash();
            td += h.difficulty;
            store.put_header(&h).unwrap();
            store.put_canonical_hash(i, hash).unwrap();
            store.put_total_difficulty(hash, td).unwrap();
            parent = hash;
        }
        // No exec head set.

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() };
        let stats = store.prune_blocks(&cfg, 29_999).unwrap();
        assert_eq!(stats.blocks, 0, "nothing executed means no safe reference");
        assert!(store.prune_floor().unwrap().is_none(), "and no floor was claimed");
    }

    /// When the node is keeping up, the two heads agree and nothing changes.
    #[test]
    fn a_node_that_is_keeping_up_prunes_as_before() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain_executed_to(&store, 20_000, 19_999);

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..PruneConfig::default() };
        let stats = store.prune_blocks(&cfg, 19_999).unwrap();
        assert_eq!(stats.to, 19_999 - MIN_KEEP_DEPTH);
    }
}

#[cfg(test)]
mod plan_tests {
    use super::tests::chain;
    use super::*;
    use crate::BlockStore;
    use tempfile::tempdir;

    /// The plan is what the sweep then does. If these drift, a node announces
    /// one range and deletes another, and the announcement becomes a lie in
    /// whichever direction the drift went.
    #[test]
    fn the_plan_matches_what_the_sweep_does() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 20_000);

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 3_000, ..PruneConfig::default() };
        let plan = store.plan_prune(&cfg, 19_999).unwrap().expect("something to do");
        let stats = store.prune_blocks(&cfg, 19_999).unwrap();

        assert_eq!((plan.from, plan.to), (stats.from, stats.to));
        assert_eq!(
            store.prune_floor().unwrap().unwrap().number,
            plan.new_floor,
            "the floor the sweep left is the one the plan promised"
        );
    }

    /// Planning does not delete. The whole point is to be able to say what is
    /// about to go while it is still there.
    #[test]
    fn planning_changes_nothing() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hashes = chain(&store, 20_000);

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 3_000, ..PruneConfig::default() };
        let plan = store.plan_prune(&cfg, 19_999).unwrap().expect("something to do");

        assert!(store.prune_floor().unwrap().is_none(), "no floor was written");
        for n in [plan.from, plan.to] {
            assert!(
                store.header(hashes[n as usize]).unwrap().is_some(),
                "#{n} is in the plan but must still be here until the sweep runs"
            );
        }
    }

    /// The announced floor is never below the one the sweep achieves.
    ///
    /// This is the property that makes announcing first safe. A sweep may stop
    /// short of its plan -- `max_batch` truncates it -- so the figure
    /// announced beforehand is an upper bound. Over-estimating means briefly
    /// claiming to serve less than this node holds, which costs a request
    /// nobody made; under-estimating would invite peers to ask for blocks
    /// already gone.
    #[test]
    fn the_announced_floor_is_never_below_the_achieved_one() {
        for max_batch in [1u64, 7, 500, 3_000, 100_000] {
            let dir = tempdir().unwrap();
            let store = BlockStore::open(dir.path()).unwrap();
            chain(&store, 20_000);

            let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch, ..PruneConfig::default() };
            let plan = store.plan_prune(&cfg, 19_999).unwrap().expect("something to do");
            store.prune_blocks(&cfg, 19_999).unwrap();
            let achieved = store.prune_floor().unwrap().unwrap().number;

            assert!(
                plan.new_floor >= achieved,
                "max_batch {max_batch}: announced #{} but kept blocks down to #{achieved}, \
                 so peers were told this node holds less than it does -- the safe \
                 direction -- but the inequality must hold the other way never",
                plan.new_floor
            );
        }
    }

    /// Nothing to do is said plainly, so a caller does not announce a range
    /// that is not changing.
    #[test]
    fn a_node_with_nothing_to_prune_has_no_plan() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 1_000); // shorter than the retention depth

        let cfg = PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 1_000, ..PruneConfig::default() };
        assert_eq!(store.plan_prune(&cfg, 999).unwrap(), None);
    }
}

#[cfg(test)]
mod freezer_guard_tests {
    use super::tests::chain;
    use super::*;
    use crate::freezer::Freezer;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn config() -> PruneConfig {
        PruneConfig { keep_depth: MIN_KEEP_DEPTH, max_batch: 100_000, ..Default::default() }
    }

    /// The pruner must not delete a body whose uncle headers the freezer has
    /// not copied. The body is the only other place they exist, so pruning
    /// first destroys the chain's record of the work it absorbed.
    ///
    /// This is the default arrangement, not a corner case: the freezer works
    /// below `head - FREEZE_DEPTH` (20,000) while the pruner works below
    /// `head - keep_depth` (8,000), so the pruner reaches every block first.
    #[test]
    fn pruning_waits_for_the_freezer_to_copy_the_uncles() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 30_000);

        let fdir = tempdir().unwrap();
        let f = Arc::new(Freezer::open(fdir.path()).unwrap());
        store.set_freezer(f.clone());

        // The freezer has copied uncles up to #5,000.
        for n in 0..5_000u64 {
            f.put_uncles(n, &[]).unwrap();
        }
        f.sync().unwrap();

        let plan = store.plan_prune(&config(), 30_000).unwrap().expect("something to prune");
        assert!(
            plan.to < 5_000,
            "must not pass the freezer's uncle progress; planned to #{}",
            plan.to
        );
    }

    /// With nothing copied at all, there is nothing safe to delete.
    #[test]
    fn nothing_is_pruned_before_the_freezer_has_started() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 30_000);

        let fdir = tempdir().unwrap();
        store.set_freezer(Arc::new(Freezer::open(fdir.path()).unwrap()));

        assert!(store.plan_prune(&config(), 30_000).unwrap().is_none());
    }

    /// Once the freezer is well ahead, the keep depth is what binds again --
    /// the guard holds the pruner back, it does not replace the depth rule.
    #[test]
    fn the_keep_depth_still_binds_once_the_freezer_is_ahead() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        chain(&store, 30_000);

        let fdir = tempdir().unwrap();
        let f = Arc::new(Freezer::open(fdir.path()).unwrap());
        store.set_freezer(f.clone());
        for n in 0..29_999u64 {
            f.put_uncles(n, &[]).unwrap();
        }
        f.sync().unwrap();

        let plan = store.plan_prune(&config(), 30_000).unwrap().expect("something to prune");
        assert!(
            plan.to <= 30_000 - MIN_KEEP_DEPTH,
            "the minimum keep depth is still honoured; planned to #{}",
            plan.to
        );
    }
}
