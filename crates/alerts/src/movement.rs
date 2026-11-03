//! What the node's own execution saw move, so the watcher can decide which
//! blocks are worth re-executing.
//!
//! # Why this exists
//!
//! [`crate::value`] finds large transfers by re-executing the block, because a
//! value transfer leaves nothing behind to read. Measured on mainnet that
//! costs about 24 ms a block at the median -- and it was being paid on every
//! block, because every one of 300 consecutive mainnet blocks sampled in
//! November 2026 had transactions in it.
//!
//! Almost all of that work finds nothing. Over the same 300 blocks the largest
//! single transfer in a block was 2.0 RBTC, and the median was zero. A watch
//! for transfers above 50 RBTC re-executed three hundred blocks to report
//! nothing at all.
//!
//! The node already knows better. The supply check walks every account a block
//! wrote and records `before`/`after` for each, on every block, as part of
//! ordinary execution -- see `rustock_execution::supply`. The largest of those
//! deltas is a free, already-computed answer to "could anything here be worth
//! looking at". So execution reports it, this type remembers it, and the
//! watcher re-executes only the blocks where something actually moved.
//!
//! # What this gives up
//!
//! A balance delta is a **net** figure. A transfer is missed when every
//! account in the block nets out below the filter, which means the value came
//! back to where it started inside the same block.
//!
//! Pass-through is **not** that case and is not missed: a router that receives
//! 100 and forwards 100 nets to zero, but the originator is still -100 and the
//! final recipient +100, so the block is re-executed and every hop reported.
//!
//! The case genuinely given up is a **closed cycle** -- most realistically a
//! flash loan, where a pool lends and is repaid within one transaction and
//! only the borrower's profit nets out. This is why the filter threshold is
//! its own setting and defaults far below the alert threshold: at 0.1 RBTC a
//! cycle has to leave every account within 0.1 RBTC of where it started,
//! which is to say nobody profited. Raising the filter to meet the alert
//! threshold reopens the hole, and the configuration says so.
//!
//! # Keyed by hash
//!
//! A block that was executed and then orphaned shares its number with the
//! canonical block at that height. Keyed by number, the orphan's deltas could
//! answer for the canonical block -- so the key is the hash.

use alloy_primitives::{B256, U256};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// Blocks remembered. The watcher trails execution by one poll interval, so a
/// handful would do; this is generous enough to cover a watcher that fell
/// behind for a few minutes and still costs about 3 KB.
pub const DEFAULT_CAPACITY: usize = 64;

/// The largest balance movement of each recently executed block.
#[derive(Debug)]
pub struct MovementLog {
    inner: Mutex<LruCache<B256, U256>>,
}

impl Default for MovementLog {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl MovementLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity.max(1)).expect("max(1) is non-zero"),
            )),
        }
    }

    /// Called from the thread executing blocks, so it must stay trivial: one
    /// lock, one insert, no allocation beyond the cache's own.
    pub fn record(&self, block_hash: B256, max_movement: U256) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.put(block_hash, max_movement);
    }

    /// What execution saw this block move, if it is still remembered.
    ///
    /// `peek` rather than `get`: reading must not reorder the cache, because
    /// the watcher reads every block in turn and would otherwise keep the
    /// oldest entry alive forever.
    pub fn largest_movement(&self, block_hash: &B256) -> Option<U256> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.peek(block_hash).copied()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

/// Whether a block has to be re-executed, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// Something moved. Re-execute and look at the transfers.
    Moved,
    /// This node did not execute the block, or did not record what it moved,
    /// so there is nothing to filter on. **Re-executing is the safe answer**:
    /// treating "no record" as "nothing moved" would turn a missing hook into
    /// a silently blind watch, which is the one failure that must not happen
    /// quietly.
    NotRecorded,
    /// Nothing in this block moved more than the filter allows. Skip it.
    Skip,
}

/// The decision, as a pure function of what was recorded.
///
/// A filter of zero means every block is re-executed, which is the behaviour
/// before this filter existed and is kept reachable on purpose: it is the
/// control an operator uses to find out what the filter is costing them.
pub fn decide(recorded: Option<U256>, filter_wei: U256) -> Replay {
    match recorded {
        None => Replay::NotRecorded,
        // Strictly greater, like every other threshold in this crate.
        Some(moved) if moved > filter_wei => Replay::Moved,
        Some(_) => Replay::Skip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    #[test]
    fn a_block_that_moved_nothing_is_skipped() {
        assert_eq!(decide(Some(U256::ZERO), U256::from(100)), Replay::Skip);
        assert_eq!(decide(Some(U256::from(100)), U256::from(100)), Replay::Skip);
    }

    #[test]
    fn a_block_that_moved_more_than_the_filter_is_replayed() {
        assert_eq!(decide(Some(U256::from(101)), U256::from(100)), Replay::Moved);
    }

    /// The failure that must not be quiet. A node that imported blocks rather
    /// than executing them, or one whose supply check is off, records nothing
    /// -- and "nothing recorded" must not read as "nothing happened".
    #[test]
    fn an_unrecorded_block_is_replayed_rather_than_assumed_quiet() {
        assert_eq!(decide(None, U256::from(100)), Replay::NotRecorded);
        assert_ne!(decide(None, U256::from(100)), Replay::Skip);
    }

    #[test]
    fn a_zero_filter_replays_everything_that_moved_at_all() {
        assert_eq!(decide(Some(U256::from(1)), U256::ZERO), Replay::Moved);
        // Still not a block in which literally nothing changed.
        assert_eq!(decide(Some(U256::ZERO), U256::ZERO), Replay::Skip);
    }

    #[test]
    fn what_was_recorded_comes_back() {
        let log = MovementLog::new(4);
        log.record(hash(1), U256::from(500));
        assert_eq!(log.largest_movement(&hash(1)), Some(U256::from(500)));
        assert_eq!(log.largest_movement(&hash(2)), None);
    }

    /// Two blocks at the same height, one of them orphaned. Keyed by number
    /// the orphan would answer for the canonical block; keyed by hash it
    /// cannot.
    #[test]
    fn an_orphan_cannot_answer_for_the_canonical_block_at_its_height() {
        let log = MovementLog::new(4);
        let orphan = hash(0xAA);
        let canonical = hash(0xBB);
        log.record(orphan, U256::ZERO);
        log.record(canonical, U256::from(9_000));
        assert_eq!(log.largest_movement(&canonical), Some(U256::from(9_000)));
        assert_eq!(log.largest_movement(&orphan), Some(U256::ZERO));
    }

    #[test]
    fn the_log_is_bounded_and_forgets_the_oldest() {
        let log = MovementLog::new(2);
        for i in 1..=5u8 {
            log.record(hash(i), U256::from(i));
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.largest_movement(&hash(1)), None, "forgotten");
        assert_eq!(log.largest_movement(&hash(5)), Some(U256::from(5)));
    }

    /// Reading must not reorder the cache: the watcher reads every block in
    /// turn, and a read that refreshed would keep the oldest entry alive and
    /// evict the newest instead.
    #[test]
    fn reading_does_not_keep_an_entry_alive() {
        let log = MovementLog::new(2);
        log.record(hash(1), U256::from(1));
        log.record(hash(2), U256::from(2));
        let _ = log.largest_movement(&hash(1));
        log.record(hash(3), U256::from(3));
        assert_eq!(log.largest_movement(&hash(1)), None, "reading refreshed it");
        assert_eq!(log.largest_movement(&hash(3)), Some(U256::from(3)));
    }
}
