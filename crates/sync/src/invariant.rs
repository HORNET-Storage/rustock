//! The coherence invariant: the relations that must hold over the node's
//! picture of the chain, stated once and checked after every commit.
//!
//! Stage 2 of `docs/sync-redesign.md`. The node keeps several independent
//! notions of "where am I" -- `KEY_HEAD`, `KEY_EXEC_HEAD` and the canonical
//! index -- and every sync stall to date has been two of them disagreeing
//! while some code path read the one that was wrong. Nothing in the code
//! asserted they agreed, so each disagreement was silent until it had cost
//! hours.
//!
//! This module does not fix that; it makes it loud. A violation names the
//! relation and the height, which turns a multi-hour wedge into a log line.
//!
//! | Stall | Violates |
//! |---|---|
//! | 1 -- cursor skipped an unexecuted range | I4, I5 |
//! | 2 -- canonical hole | I1, I3 |
//! | 3 -- follow-mode gap | I4, I5 |
//! | 4 -- orphaned head | I5 |
//! | 5 -- canonical pointer to a block we never downloaded | I2, I3 |
//! | 6 -- canonical entry stranded above the head | **I6** |
//! | 7 -- head naming a block that is not canonical | **I8** |
//! | 8 -- execution on the losing side of a tip sibling fork | **I5** |
//!
//! # Four of these are now repaired, not only reported
//!
//! `SyncService::verify_coherence` acts on I5, I6, I7 and I8. That was not
//! the original intent -- "it makes it loud" was -- and stall 8 is why it
//! changed. On 2026-09-24 a one-block sibling fork at the tip left execution
//! on the losing side; I5 named it correctly every thirty-five seconds for
//! twelve minutes and nothing consumed the report, because every other guard
//! in the sync service compares block *numbers* and all those differences are
//! zero in that state.
//!
//! An invariant that is only ever printed is a diagnostic. Once a violation
//! has a repair that is safe and well defined, leaving it to a human -- or to
//! the watchdog, which is a liveness net for the failures nothing else
//! understands -- is choosing to stall.
//!
//! Stall 6 is the one this was written after: `ensure_canonical_lineage`
//! wrote a canonical entry at #9,262,402 while `KEY_HEAD` stayed at
//! #9,262,401, and because every path that could have executed the block
//! reads `KEY_HEAD`, the block was invisible for three hours. I6 catches it
//! on the first commit.

use alloy_primitives::B256;
use rustock_storage::{BlockRef, BlockStore};
use rustock_trie::TrieStore;

// `BlockRef` -- a block by height and hash -- is re-exported from the storage
// crate rather than defined again here: two structurally identical `BlockRef`
// types in one crate is exactly the kind of near-duplicate that lets a caller
// pass the wrong one, and this module predates `rustock_storage::position`.

/// The three notions of position, read together.
///
/// Stage 3 replaces this with a cursor that cannot be inconsistent by
/// construction. Until then it is read straight from the store, which is the
/// point: the invariant checks the representation the node actually has.
#[derive(Debug, Clone, Copy)]
pub struct Cursor {
    /// `KEY_HEAD` -- the highest block we consider downloaded and linked.
    pub validated_head: BlockRef,
    /// `KEY_EXEC_HEAD` -- the highest block we have actually executed.
    pub executed: BlockRef,
    /// The state root recorded alongside the executed head.
    pub state_root: B256,
}

/// Which heights to check.
#[derive(Debug, Clone, Copy)]
pub enum Scope {
    /// Only the heights a commit touched, inclusive. O(1) per commit; this is
    /// what production uses.
    Delta { from: u64, to: u64 },
    /// Everything from the pruning floor to the head. Startup, tests and the
    /// simulator.
    Full,
}

impl Scope {
    /// The heights to walk, clamped to the chain we actually have.
    fn heights(&self, floor: u64, head: u64) -> std::ops::RangeInclusive<u64> {
        match *self {
            Scope::Full => floor..=head,
            Scope::Delta { from, to } => from.max(floor)..=to.min(head),
        }
    }
}

/// A broken relation, named and located.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    #[error("I1: no canonical entry at #{at}")]
    NoCanonicalEntry { at: u64 },

    #[error("I2: canonical #{at} names {hash} but we do not hold that header")]
    CanonicalHeaderMissing { at: u64, hash: B256 },

    #[error(
        "I3: canonical #{at} has parent {parent} but canonical #{} is {canonical_below}",
        at.saturating_sub(1)
    )]
    ParentMismatch { at: u64, parent: B256, canonical_below: B256 },

    #[error("I4: executed head #{executed} is above the validated head #{head}")]
    ExecutedAboveHead { executed: u64, head: u64 },

    #[error("I5: executed head #{at} ({hash}) is not the canonical block at that height ({canonical:?})")]
    ExecutedOffChain { at: u64, hash: B256, canonical: Option<B256> },

    #[error("I6: canonical entry {hash} at #{at} sits above the validated head #{head}")]
    CanonicalAboveHead { at: u64, hash: B256, head: u64 },

    #[error("I7: the state root {root} recorded at executed head #{at} is not in the trie store")]
    StateRootMissing { at: u64, root: B256 },

    #[error("I8: the head is {hash} at #{at} but the canonical block at that height is {canonical:?}")]
    HeadNotCanonical { at: u64, hash: B256, canonical: Option<B256> },

    #[error("the store could not be read while checking coherence: {0}")]
    StoreUnreadable(String),
}

impl Violation {
    /// The relation this violates, for metrics and log filtering.
    pub fn relation(&self) -> &'static str {
        match self {
            Violation::NoCanonicalEntry { .. } => "I1",
            Violation::CanonicalHeaderMissing { .. } => "I2",
            Violation::ParentMismatch { .. } => "I3",
            Violation::ExecutedAboveHead { .. } => "I4",
            Violation::ExecutedOffChain { .. } => "I5",
            Violation::CanonicalAboveHead { .. } => "I6",
            Violation::StateRootMissing { .. } => "I7",
            Violation::HeadNotCanonical { .. } => "I8",
            Violation::StoreUnreadable(_) => "??",
        }
    }

    /// The height the violation is anchored at, where it has one.
    pub fn at(&self) -> Option<u64> {
        match *self {
            Violation::NoCanonicalEntry { at }
            | Violation::CanonicalHeaderMissing { at, .. }
            | Violation::ParentMismatch { at, .. }
            | Violation::ExecutedOffChain { at, .. }
            | Violation::CanonicalAboveHead { at, .. }
            | Violation::StateRootMissing { at, .. }
            | Violation::HeadNotCanonical { at, .. } => Some(at),
            Violation::ExecutedAboveHead { executed, .. } => Some(executed),
            Violation::StoreUnreadable(_) => None,
        }
    }
}

/// Read the three position keys.
///
/// `None` when the node has no head at all -- an empty database, before
/// genesis is written. There is nothing to be incoherent about yet.
pub fn derive_cursor(store: &BlockStore) -> Result<Option<Cursor>, Violation> {
    let read = |e: anyhow::Error| Violation::StoreUnreadable(e.to_string());

    let Some(head_hash) = store.head().map_err(read)? else {
        return Ok(None);
    };
    let Some(head) = store.header(head_hash).map_err(read)? else {
        // KEY_HEAD names a header we do not hold. This is stall 5's shape and
        // it is not expressible as any of I1..I7, which are all stated
        // relative to a cursor -- so it is reported where it is found.
        return Err(Violation::CanonicalHeaderMissing { at: u64::MAX, hash: head_hash });
    };

    // No executed head yet (a database that has downloaded but never executed)
    // means execution is trivially not ahead and trivially on-chain.
    let (exec_hash, state_root) = match store.exec_head().map_err(read)? {
        Some(pair) => pair,
        None => (head_hash, B256::ZERO),
    };
    let exec_number = store
        .header(exec_hash)
        .map_err(read)?
        .map(|h| h.number)
        .ok_or(Violation::CanonicalHeaderMissing { at: u64::MAX, hash: exec_hash })?;

    Ok(Some(Cursor {
        validated_head: BlockRef { number: head.number, hash: head_hash },
        executed: BlockRef { number: exec_number, hash: exec_hash },
        state_root,
    }))
}

/// Check the coherence condition.
///
/// `trie` is optional: I7 is skipped when the caller has no trie store (a
/// header-only node, or a test that does not model state).
pub fn check(
    store: &BlockStore,
    trie: Option<&dyn TrieStore>,
    scope: Scope,
) -> Result<(), Violation> {
    let Some(cursor) = derive_cursor(store)? else {
        return Ok(());
    };
    check_with_cursor(store, trie, scope, &cursor)
}

/// The relations themselves, against a cursor the caller already has.
pub fn check_with_cursor(
    store: &BlockStore,
    trie: Option<&dyn TrieStore>,
    scope: Scope,
    cursor: &Cursor,
) -> Result<(), Violation> {
    let read = |e: anyhow::Error| Violation::StoreUnreadable(e.to_string());

    let floor = store
        .prune_floor()
        .map_err(read)?
        .map_or(0, |f| f.number);

    let head = cursor.validated_head.number;

    for h in scope.heights(floor, head) {
        // I1 -- a canonical entry exists
        let c = store
            .canonical_hash(h)
            .map_err(read)?
            .ok_or(Violation::NoCanonicalEntry { at: h })?;

        // I2 -- and we hold the header it names
        let hdr = store
            .header(c)
            .map_err(read)?
            .ok_or(Violation::CanonicalHeaderMissing { at: h, hash: c })?;

        // I3 -- and it links to the canonical entry below.
        //
        // Not checked at the floor itself: below a pruning floor there is
        // deliberately nothing, and genesis has no parent to link to.
        if h > floor && h > 0 {
            let below = store
                .canonical_hash(h - 1)
                .map_err(read)?
                .ok_or(Violation::NoCanonicalEntry { at: h - 1 })?;
            if hdr.parent_hash != below {
                return Err(Violation::ParentMismatch {
                    at: h,
                    parent: hdr.parent_hash,
                    canonical_below: below,
                });
            }
        }
    }

    // I4 -- execution never runs ahead of validated headers
    if cursor.executed.number > head {
        return Err(Violation::ExecutedAboveHead { executed: cursor.executed.number, head });
    }

    // I5 -- and is on the same chain.
    //
    // Skipped below the floor: a pruned height has no canonical entry by
    // design, so the question cannot be asked there.
    if cursor.executed.number >= floor {
        let canonical = store.canonical_hash(cursor.executed.number).map_err(read)?;
        if canonical != Some(cursor.executed.hash) {
            return Err(Violation::ExecutedOffChain {
                at: cursor.executed.number,
                hash: cursor.executed.hash,
                canonical,
            });
        }
    }

    // I6 -- nothing canonical above the head.
    //
    // This is the relation stall 6 broke, and the reason it is worth checking
    // even though it looks like it could never happen: a canonical entry above
    // the head is not merely untidy, it is a block the node holds and can
    // never reach, because every path that looks for work reads the head.
    if let Some(hash) = store.canonical_hash(head + 1).map_err(read)? {
        return Err(Violation::CanonicalAboveHead { at: head + 1, hash, head });
    }

    // I8 -- the head is itself on the canonical chain.
    //
    // Added after the first deployment of this module: `KEY_HEAD` named a block
    // at #9,262,401 that was not the canonical block at that height, while the
    // canonical index below and above it was perfectly consistent. I5 asks this
    // of the *executed* head and nothing asked it of the head, so the
    // disagreement had no relation to break -- which is exactly the failure this
    // module exists to stop. Seven notions of position, six relations.
    if head >= floor {
        let canonical = store.canonical_hash(head).map_err(read)?;
        if canonical != Some(cursor.validated_head.hash) {
            return Err(Violation::HeadNotCanonical {
                at: head,
                hash: cursor.validated_head.hash,
                canonical,
            });
        }
    }

    // I7 -- the state we would continue from actually exists
    if let Some(trie) = trie {
        if !cursor.state_root.is_zero() && trie.get(cursor.state_root.as_slice()).is_none() {
            return Err(Violation::StateRootMissing {
                at: cursor.executed.number,
                root: cursor.state_root,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) use super::tests::{chain as coherent_chain, header as test_header};
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, U256};
    use rustock_core::Header;
    use tempfile::tempdir;

    pub(crate) fn header(number: u64, parent: B256) -> Header {
        Header {
            number,
            parent_hash: parent,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(1),
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: number * 15,
            extra_data: Bytes::default(),
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

    /// A coherent chain of `len` blocks (0..=len-1), head and executed head
    /// both at the top. Returns the store, the temp dir (which must outlive
    /// it) and the hashes by height.
    pub(crate) fn chain(len: u64) -> (BlockStore, tempfile::TempDir, Vec<B256>) {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let mut hashes = Vec::new();
        let mut parent = B256::ZERO;
        for n in 0..len {
            let h = header(n, parent);
            let hash = h.hash();
            store.update_head(&h, U256::from(n + 1)).unwrap();
            parent = hash;
            hashes.push(hash);
        }
        store.set_exec_head(*hashes.last().unwrap(), B256::ZERO).unwrap();
        (store, dir, hashes)
    }

    #[test]
    fn a_coherent_chain_satisfies_every_relation() {
        let (store, _dir, _) = chain(10);
        assert_eq!(check(&store, None, Scope::Full), Ok(()));
    }

    /// Stall 6, 2026-09-22: `ensure_canonical_lineage` wrote a canonical entry
    /// at #9,262,402 while `KEY_HEAD` stayed at #9,262,401. Every path that
    /// could have executed the block reads `KEY_HEAD`, so it was held, linked,
    /// valid and unreachable for three hours with no error logged.
    #[test]
    fn i6_catches_a_canonical_entry_stranded_above_the_head() {
        let (store, _dir, hashes) = chain(10);

        // A block above the head: stored, canonical, linked to the head.
        let orphan = header(10, *hashes.last().unwrap());
        let orphan_hash = orphan.hash();
        store.put_header_with_hash(orphan_hash, &orphan).unwrap();
        store.put_canonical_hash(10, orphan_hash).unwrap();
        // KEY_HEAD deliberately left at #9.

        let err = check(&store, None, Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I6");
        assert_eq!(err.at(), Some(10));
        assert!(matches!(err, Violation::CanonicalAboveHead { head: 9, .. }));
    }

    /// The delta scope is what production uses, so the relation that matters
    /// most has to fire there too -- I6 is checked outside the height loop
    /// precisely so that a narrow scope cannot hide it.
    #[test]
    fn i6_fires_under_the_delta_scope_as_well() {
        let (store, _dir, hashes) = chain(10);
        let orphan = header(10, *hashes.last().unwrap());
        store.put_header_with_hash(orphan.hash(), &orphan).unwrap();
        store.put_canonical_hash(10, orphan.hash()).unwrap();

        let err = check(&store, None, Scope::Delta { from: 9, to: 9 }).unwrap_err();
        assert_eq!(err.relation(), "I6");
    }

    /// Stall 2: a hole in the canonical index.
    #[test]
    fn i1_catches_a_canonical_hole() {
        let (store, _dir, _) = chain(10);
        store.delete_canonical_hash(5).unwrap();

        let err = check(&store, None, Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I1");
        assert_eq!(err.at(), Some(5));
    }

    /// Stall 5: the canonical pointer names a block we never downloaded.
    #[test]
    fn i2_catches_a_pointer_to_a_block_we_do_not_hold() {
        let (store, _dir, _) = chain(10);
        store.put_canonical_hash(5, B256::repeat_byte(0xab)).unwrap();

        let err = check(&store, None, Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I2");
        assert_eq!(err.at(), Some(5));
    }

    /// Stall 2's other face: the canonical entry exists and we hold it, but it
    /// does not link to the height below.
    #[test]
    fn i3_catches_a_broken_link() {
        let (store, _dir, _) = chain(10);
        // A block at #5 whose parent is not canonical #4.
        let wrong = header(5, B256::repeat_byte(0xcd));
        store.put_header_with_hash(wrong.hash(), &wrong).unwrap();
        store.put_canonical_hash(5, wrong.hash()).unwrap();

        let err = check(&store, None, Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I3");
        assert_eq!(err.at(), Some(5));
    }

    /// Stalls 1 and 3: execution ahead of the validated head.
    #[test]
    fn i4_catches_execution_running_ahead_of_the_head() {
        let (store, _dir, hashes) = chain(10);
        store.set_head(hashes[4]).unwrap();

        let err = check(&store, None, Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I4");
    }

    /// Stall 4: the executed head was orphaned by a reorg and is no longer the
    /// canonical block at its height.
    #[test]
    fn i5_catches_an_executed_head_off_the_canonical_chain() {
        let (store, _dir, hashes) = chain(10);
        // A sibling at #9 that is not canonical, adopted as the executed head.
        let sibling = header(9, hashes[8]);
        let mut sibling = sibling;
        sibling.timestamp += 1; // make it a distinct block
        store.put_header_with_hash(sibling.hash(), &sibling).unwrap();
        store.set_exec_head(sibling.hash(), B256::ZERO).unwrap();

        let err = check(&store, None, Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I5");
        assert_eq!(err.at(), Some(9));
    }

    #[test]
    fn i7_catches_a_state_root_the_trie_store_does_not_hold() {
        use rustock_trie::MemoryTrieStore;
        let (store, _dir, hashes) = chain(10);
        store.set_exec_head(*hashes.last().unwrap(), B256::repeat_byte(0x11)).unwrap();

        let trie = MemoryTrieStore::default();
        let err = check(&store, Some(&trie), Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I7");
    }

    /// A zero state root means "nothing executed yet", not "a root that is
    /// missing" -- checking it would make every fresh database incoherent.
    #[test]
    fn i7_ignores_the_zero_state_root() {
        use rustock_trie::MemoryTrieStore;
        let (store, _dir, _) = chain(10);
        let trie = MemoryTrieStore::default();
        assert_eq!(check(&store, Some(&trie), Scope::Full), Ok(()));
    }

    /// An empty database has no position to be incoherent about.
    #[test]
    fn an_empty_store_is_vacuously_coherent() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(check(&store, None, Scope::Full), Ok(()));
    }

    /// The delta scope must not walk the whole chain: that is what makes the
    /// check affordable after every commit.
    #[test]
    fn the_delta_scope_only_visits_the_heights_it_is_given() {
        let (store, _dir, _) = chain(10);
        // Break a height outside the delta window.
        store.delete_canonical_hash(2).unwrap();

        // Full scope sees it …
        assert_eq!(check(&store, None, Scope::Full).unwrap_err().relation(), "I1");
        // … the delta window above it does not.
        assert_eq!(check(&store, None, Scope::Delta { from: 8, to: 9 }), Ok(()));
    }

    /// The seventh disagreement, found by deploying this module: `KEY_HEAD`
    /// named a block at #9,262,401 that was not the canonical block at that
    /// height, while the canonical index below *and* above it was perfectly
    /// consistent. I5 asks this of the executed head; nothing asked it of the
    /// head itself, so the disagreement had no relation to break.
    #[test]
    fn i8_catches_a_head_that_is_not_the_canonical_block_at_its_height() {
        let (store, _dir, hashes) = chain(10);

        // A sibling at #9: held, but not canonical. Point KEY_HEAD at it.
        let mut sibling = header(9, hashes[8]);
        sibling.timestamp += 1;
        store.put_header_with_hash(sibling.hash(), &sibling).unwrap();
        store.set_head(sibling.hash()).unwrap();
        store.set_exec_head(sibling.hash(), B256::ZERO).unwrap();

        let err = check(&store, None, Scope::Full).unwrap_err();
        // I5 fires first here (the executed head is off-chain too), so check
        // the head relation on its own with execution left canonical.
        assert!(matches!(err.relation(), "I5" | "I8"));

        store.set_exec_head(hashes[9], B256::ZERO).unwrap();
        store.set_head(sibling.hash()).unwrap();
        let err = check(&store, None, Scope::Full).unwrap_err();
        assert_eq!(err.relation(), "I8");
        assert_eq!(err.at(), Some(9));
    }
}

#[cfg(test)]
mod lookback_tests {
    use super::tests_support::*;
    use super::*;

    /// A stale canonical pointer *below* the executed head is reported.
    ///
    /// This is the relation that went unchecked on mainnet 2026-10-04. I3 was
    /// always correct; the window it ran over started at the executed head, so
    /// a reorg that rewrote a pointer underneath left nothing to notice. Seven
    /// of them accumulated, and the first to mature through REMASC's
    /// 4,000-block delay stopped the node for good.
    #[test]
    fn a_stale_pointer_below_the_executed_head_is_caught() {
        let (store, _dir, hashes) = coherent_chain(40);

        // A sibling at #20: same parent, different block. Exactly what a reorg
        // leaves behind when the lineage walk stops above it.
        let mut sibling = test_header(20, hashes[19]);
        sibling.timestamp += 1;
        sibling.cached_hash = None;
        let sibling_hash = sibling.hash();
        store.put_header_with_hash(sibling_hash, &sibling).unwrap();
        store.put_canonical_hash(20, sibling_hash).unwrap();

        // Checked from well below the executed head, as the service now does.
        let v = check(&store, None, Scope::Delta { from: 10, to: 39 })
            .expect_err("a chain that does not link must be reported");
        assert!(
            matches!(v, Violation::ParentMismatch { at: 21, .. }),
            "expected the break named at the height above it, got {v:?}"
        );

        // And the window that shipped before would have missed it entirely.
        assert!(
            check(&store, None, Scope::Delta { from: 30, to: 39 }).is_ok(),
            "a window starting above the damage cannot see it -- which is the bug"
        );
    }
}
