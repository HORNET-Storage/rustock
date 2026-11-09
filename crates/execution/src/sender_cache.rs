//! Remembering which key signed which transaction.
//!
//! A transaction's sender is recovered from its signature, and the same
//! transaction has its sender recovered several times over its life: once when
//! the pool admits it, again when the block carrying it executes, again on
//! every RPC render, and again on each re-execution after a reorg. The
//! recovery is identical every time and it is the most expensive arithmetic
//! the node does per transaction.
//!
//! ## Keyed by the transaction hash, and why that is safe here
//!
//! The key is `Transaction::tx_hash()`. A cache keyed by a hash is only sound
//! if the hash separates every pair of transactions that could recover to
//! different senders. Two transactions that hashed alike but recovered
//! differently would let the first one seen decide the sender of the second.
//!
//! The hash determines everything recovery reads, for three reasons, and
//! `the_hash_follows_what_v_names` in `rustock_core::types::transaction`
//! pins the second:
//!
//! - `tx_hash()` is the keccak of the encoding rskj hashes a transaction by
//!   (`getEncoded`), kept when the transaction is read. Its first six items
//!   are the fields rskj signs (`getEncodedRaw`), and its v is the one rskj
//!   rebuilds from the chain id and the recovery id, with r and s after it.
//! - Reading that v back gives the same chain id and recovery id, so one
//!   encoding has one signing hash and one recovery id. The only v whose
//!   rebuilt form would read differently are those naming a negative chain,
//!   which the reader refuses: no network accepts them.
//! - Only signed transactions are cached. An unsigned one has no sender to
//!   remember, and REMASC's is set by its place in the block, not a key.
//!
//! Anything that changes how the hash is formed, or what reading a
//! transaction keeps, invalidates this cache, which is why both are stated
//! here rather than left to be rediscovered.
//!
//! ## Two tiers, because the two origins are not alike
//!
//! Senders arrive from two places, and they want opposite retention
//! policies. rskj keeps two caches for this and the reason is worth stating,
//! because it is not obvious from the sizes alone:
//!
//! | origin | lifetime | pressure |
//! |---|---|---|
//! | our pool, at admission | long -- a transaction can wait many blocks to be mined | steady, bounded by the pool |
//! | a block from a peer | short -- the block is validated once | bursty, unbounded, attacker-chosen |
//!
//! A single map serving both lets the second evict the first. A peer that
//! streams blocks full of transactions we have never seen would walk the
//! whole cache every few blocks, and the pool-to-execution hop -- the one the
//! cache exists for -- would miss every time. The cache would still *work*,
//! and would simply stop paying, silently.
//!
//! So block-origin entries go in their own small tier and cannot evict
//! pool-origin ones. Lookups read both, so a transaction the pool recovered
//! is still found when its block executes; only writes are segregated. That
//! is exactly what rskj's `BlockTxSignatureCache` does by wrapping
//! `ReceivedTxSignatureCache` and never writing through to it.
//!
//! ## The locking shape
//!
//! The obvious implementation — consult a `Mutex<HashMap>` once per
//! transaction — would serialise the one region `recover_senders` exists to
//! parallelise, and would do it invisibly: the work still happens, just one
//! thread at a time, with no error and nothing in the logs.
//!
//! So the lock is never taken from a worker. A block is looked up **once**,
//! before the threads start; the misses are recovered in parallel with no
//! cache access at all; and the results are written back **once**, after the
//! threads have joined. Two lock acquisitions per block, not one per
//! transaction.

use alloy_primitives::{Address, B256};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// Pool-origin entries: transactions this node admitted and expects to see
/// again when a block carries them. rskj keeps 6,000, described there as
/// "txs in three blocks"; the bound that matters is how long a transaction
/// may wait in the pool, so this covers a full pool several times over and
/// costs about 400 KB.
pub const DEFAULT_POOL_CAPACITY: usize = 8_192;

/// Block-origin entries: transactions seen for the first time inside a block.
/// Worth keeping only briefly -- for a re-execution after a reorg, chiefly --
/// and deliberately small, because this is the tier an untrusted peer can
/// drive. rskj uses 900, about one block's worth; 2,048 here, still far too
/// small to matter next to the pool tier it protects.
pub const DEFAULT_BLOCK_CAPACITY: usize = 2_048;

/// Senders already recovered, keyed by transaction hash.
///
/// Cloneable handles share one cache: the node has a single pool feeding a
/// single executor, and a per-component cache would miss exactly the hop the
/// cache exists for.
#[derive(Debug)]
pub struct SenderCache {
    /// Both tiers under one lock, so looking a block up costs one
    /// acquisition rather than one per tier.
    inner: Mutex<Tiers>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

#[derive(Debug)]
struct Tiers {
    pool: LruCache<B256, Address>,
    block: LruCache<B256, Address>,
}

/// Which tier a newly recovered sender belongs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Recovered while admitting a transaction to this node's pool.
    Pool,
    /// Recovered while validating or executing a block.
    Block,
}

impl Default for SenderCache {
    fn default() -> Self {
        Self::new(DEFAULT_POOL_CAPACITY, DEFAULT_BLOCK_CAPACITY)
    }
}

impl SenderCache {
    pub fn new(pool_capacity: usize, block_capacity: usize) -> Self {
        let nz = |n: usize| NonZeroUsize::new(n.max(1)).expect("max(1) is non-zero");
        Self {
            inner: Mutex::new(Tiers {
                pool: LruCache::new(nz(pool_capacity)),
                block: LruCache::new(nz(block_capacity)),
            }),
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Look up a whole block in one acquisition.
    ///
    /// Returns a slot per transaction, `Some` where the sender was already
    /// known. The caller recovers the `None`s itself; this type deliberately
    /// does not offer a one-transaction lookup, because offering one would
    /// invite calling it from inside the parallel region.
    pub fn get_many(&self, hashes: &[B256]) -> Vec<Option<Address>> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(hashes.len());
        let (mut hit, mut miss) = (0u64, 0u64);
        for h in hashes {
            // Both tiers, pool first: that is where the entry worth having
            // lives. `get` rather than `peek`, because a hit is a use and
            // should keep the entry alive -- a transaction seen by the pool
            // and then by execution is exactly what to keep.
            let found = match guard.pool.get(h) {
                Some(a) => Some(*a),
                None => guard.block.get(h).copied(),
            };
            match found {
                Some(a) => {
                    hit += 1;
                    out.push(Some(a));
                }
                None => {
                    miss += 1;
                    out.push(None);
                }
            }
        }
        drop(guard);
        use std::sync::atomic::Ordering::Relaxed;
        self.hits.fetch_add(hit, Relaxed);
        self.misses.fetch_add(miss, Relaxed);
        out
    }

    /// Record what was recovered, in one acquisition.
    ///
    /// `origin` decides the tier, and therefore whose entries this can
    /// evict. A block from a peer can only ever push out other block-origin
    /// entries.
    pub fn put_many(&self, origin: Origin, entries: impl IntoIterator<Item = (B256, Address)>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let tier = match origin {
            Origin::Pool => &mut guard.pool,
            Origin::Block => &mut guard.block,
        };
        for (hash, address) in entries {
            tier.put(hash, address);
        }
    }

    /// Hits and misses since start, for the metrics endpoint.
    pub fn stats(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (self.hits.load(Relaxed), self.misses.load(Relaxed))
    }

    #[cfg(test)]
    fn lens(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap();
        (g.pool.len(), g.block.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::repeat_byte(b)
    }
    fn hash(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    #[test]
    fn a_miss_is_reported_per_slot_and_in_order() {
        let c = SenderCache::new(8, 8);
        c.put_many(Origin::Pool, [(hash(2), addr(0x22))]);
        assert_eq!(c.get_many(&[hash(1), hash(2), hash(3)]), vec![None, Some(addr(0x22)), None]);
    }

    #[test]
    fn either_tier_satisfies_a_lookup() {
        let c = SenderCache::new(8, 8);
        c.put_many(Origin::Pool, [(hash(1), addr(1))]);
        c.put_many(Origin::Block, [(hash(2), addr(2))]);
        assert_eq!(c.get_many(&[hash(1), hash(2)]), vec![Some(addr(1)), Some(addr(2))]);
    }

    /// The reason there are two tiers. A peer streaming blocks of unseen
    /// transactions must not be able to flush what the pool recovered --
    /// otherwise the pool-to-execution hop misses every time and the cache
    /// quietly stops paying.
    #[test]
    fn block_traffic_cannot_evict_pool_entries() {
        let c = SenderCache::new(4, 2);
        c.put_many(Origin::Pool, (1..=4u8).map(|i| (hash(i), addr(i))));

        // A flood of block-origin transactions, far more than either tier.
        c.put_many(Origin::Block, (100..=160u8).map(|i| (hash(i), addr(i))));

        for i in 1..=4u8 {
            assert_eq!(
                c.get_many(&[hash(i)]),
                vec![Some(addr(i))],
                "pool entry {i} was evicted by block traffic"
            );
        }
        let (pool_len, block_len) = c.lens();
        assert_eq!(pool_len, 4, "the pool tier must be untouched");
        assert_eq!(block_len, 2, "the block tier must stay at its own bound");
    }

    #[test]
    fn the_oldest_entry_is_evicted_at_capacity() {
        let c = SenderCache::new(2, 2);
        c.put_many(Origin::Pool, [(hash(1), addr(1)), (hash(2), addr(2)), (hash(3), addr(3))]);
        assert_eq!(c.lens().0, 2);
        assert_eq!(c.get_many(&[hash(1)]), vec![None], "the oldest should have gone");
        assert_eq!(c.get_many(&[hash(3)]), vec![Some(addr(3))]);
    }

    /// A hit refreshes the entry, so the pool-to-execution hop survives a
    /// burst of unrelated traffic.
    #[test]
    fn a_hit_keeps_the_entry_alive() {
        let c = SenderCache::new(2, 2);
        c.put_many(Origin::Pool, [(hash(1), addr(1)), (hash(2), addr(2))]);
        assert_eq!(c.get_many(&[hash(1)]), vec![Some(addr(1))]); // refresh 1
        c.put_many(Origin::Pool, [(hash(3), addr(3))]);
        assert_eq!(c.get_many(&[hash(1)]), vec![Some(addr(1))], "1 was just used");
        assert_eq!(c.get_many(&[hash(2)]), vec![None], "2 was the stale one");
    }

    #[test]
    fn hits_and_misses_are_counted() {
        let c = SenderCache::new(8, 8);
        c.put_many(Origin::Pool, [(hash(1), addr(1))]);
        c.get_many(&[hash(1), hash(2), hash(3)]);
        assert_eq!(c.stats(), (1, 2));
    }

    /// A panic while a caller held the lock must not take the node down with
    /// it; a sender cache is an optimisation and has no business being fatal.
    #[test]
    fn a_poisoned_lock_is_recovered_from() {
        let c = std::sync::Arc::new(SenderCache::new(8, 8));
        let c2 = c.clone();
        let _ = std::thread::spawn(move || {
            let _g = c2.inner.lock().unwrap();
            panic!("holder panics");
        })
        .join();
        c.put_many(Origin::Pool, [(hash(9), addr(9))]);
        assert_eq!(c.get_many(&[hash(9)]), vec![Some(addr(9))]);
    }
}
