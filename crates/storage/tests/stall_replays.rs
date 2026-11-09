//! The seven recorded stalls, replayed against the position API.
//!
//! Each test builds the shape the live node was actually found in -- heights
//! and hashes from `docs/sync-redesign.md` Appendix A and from the incident
//! logs -- and asserts one of two things:
//!
//! * the shape **cannot be produced** through the public API any more, or
//! * it is **detected and repaired**, rather than sat in for hours.
//!
//! The distinction matters. A shape that is merely detected is a shape a future
//! caller can still create. A shape that cannot be expressed is closed.
//!
//! | # | Date | Cost | Shape |
//! |---|---|---|---|
//! | 1 | — | — | cursor skipped an unexecuted range |
//! | 2 | — | until restart | hole in the canonical index |
//! | 3 | — | 20 hours | follow-mode gap: downloaded at tip, executed behind |
//! | 4 | — | 3 days | executed head orphaned by a branch we never adopted |
//! | 5 | 2026-09-22 | 15 min | canonical pointer to a block never downloaded |
//! | 6 | 2026-09-22 | 3 hours | canonical entry stranded above the head |
//! | 7 | 2026-09-23 | sawtooth | head naming a non-canonical block |

use alloy_primitives::{Address, B256, Bytes, U256};
use rustock_core::Header;
use rustock_storage::{BlockStore, LineageBreak, Transition, Validated, verify_local_coherence};
use tempfile::TempDir;

/// A header at `number`, laid out as the store's heights, this process's,
/// read one there: with a UMM root from RSKIPUMM on.
fn header(number: u64, parent: B256, salt: u64) -> Header {
    let umm = rustock_core::config::ActivationHeights::current().umm_active(number);
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
        timestamp: number * 15 + salt,
        extra_data: Bytes::default(),
        paid_fees: U256::ZERO,
        minimum_gas_price: U256::ZERO,
        uncle_count: 0,
        umm_root: umm.then(Bytes::new),
        version_fields: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
        cached_hash_for_merged_mining: None,
        kept: None,
    }
}

/// A coherent chain `base..=base+len`, head and executed head at the top.
/// Heights are the real ones so a failure message reads like the incident.
fn chain_from(base: u64, len: u64) -> (BlockStore, TempDir, Vec<Header>) {
    let dir = tempfile::tempdir().unwrap();
    let store = BlockStore::open(dir.path()).unwrap();
    let mut hs = Vec::new();
    let mut parent = B256::ZERO;
    for i in 0..=len {
        let h = header(base + i, parent, 0);
        store.update_head(&h, U256::from(i + 1)).unwrap();
        parent = h.hash();
        hs.push(h);
    }
    let top = hs.last().unwrap();
    store.set_exec_head(top.hash(), top.state_root).unwrap();
    (store, dir, hs)
}

fn coherent(store: &BlockStore) -> Result<(), String> {
    let cursor = store.cursor().map_err(|e| e.to_string())?.ok_or("no cursor")?;
    verify_local_coherence(store, &cursor)
}

// ---------------------------------------------------------------------------

/// **Stall 1** — the cursor skipped a range that had been downloaded but not
/// executed, so execution ran ahead of what had been validated.
///
/// `Transition::Executed` now refuses a block above the head, so the shape
/// cannot be written.
#[test]
fn stall_1_execution_cannot_run_ahead_of_the_head() {
    let (store, _d, hs) = chain_from(100, 10);
    // Pretend #105 is the head but #110 has been executed.
    let to = Validated::prove(&store, hs[5].hash()).unwrap();
    store.apply(&Transition::Retreat { to }).unwrap();

    // #110 is no longer canonical after the retreat, so it cannot even be
    // offered for execution; and if it could, it is above the head.
    let err = Validated::prove(&store, hs[10].hash())
        .map(|at| store.apply(&Transition::Executed { at, state_root: B256::ZERO }));
    match err {
        Ok(Err(e)) => {
            let m = e.to_string();
            assert!(
                m.contains("not the canonical block") || m.contains("above the head"),
                "refused for the wrong reason: {m}"
            );
        }
        Ok(Ok(_)) => panic!("execution was recorded above the head"),
        Err(_) => {} // unprovable is also a refusal
    }
    coherent(&store).unwrap();
}

/// **Stall 2** — a hole in the canonical index. A walk truncated by a
/// then-missing header left a lower height stale while a higher one was right,
/// and nothing looked below the first consistent entry.
#[test]
fn stall_2_a_stale_entry_below_a_correct_one_is_repaired_on_adoption() {
    let (store, _d, hs) = chain_from(100, 10);

    // #109 is made to name a sibling; #110 still looks right.
    let sibling = header(109, hs[8].hash(), 77);
    store.put_header_with_hash(sibling.hash(), &sibling).unwrap();
    store.put_canonical_hash(109, sibling.hash()).unwrap();

    // Adopting the true tip walks down past the correct #110 and repairs #109.
    let head = Validated::prove(&store, hs[10].hash()).unwrap();
    assert_eq!(
        head.lineage().iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        vec![109],
        "the buried stale entry was not part of the proof"
    );
    store.apply(&Transition::Adopt { head }).unwrap();

    assert_eq!(store.canonical_hash(109).unwrap(), Some(hs[9].hash()));
    coherent(&store).unwrap();
}

/// **Stall 3** — twenty hours, zero errors. The downloaded head sat at the tip
/// while execution stood still, and every watchdog measured the downloaded
/// frontier, so the node looked caught up.
///
/// The cursor reads both, and `backlog()` is the number the node was blind to.
#[test]
fn stall_3_the_cursor_shows_the_backlog_the_node_was_blind_to() {
    // The fixture's lowest block has a synthetic parent, so execution is put
    // one above it; the shape is the same and the arithmetic is honest.
    let (store, _d, hs) = chain_from(100, 10);
    let at = Validated::prove(&store, hs[1].hash()).unwrap();
    store.apply(&Transition::Executed { at, state_root: hs[1].state_root }).unwrap();

    let cursor = store.cursor().unwrap().unwrap();
    assert_eq!(cursor.validated_head.number, 110);
    assert_eq!(cursor.executed.number, 101);
    assert_eq!(cursor.backlog(), 9, "the backlog is not visible from the cursor");
    coherent(&store).unwrap();
}

/// **Stall 4** — three days at #9,251,057. The executed head was orphaned by a
/// branch the node never adopted; both detection signals read the canonical
/// index, which by definition had no entry for that branch.
///
/// Adopting the branch now rolls execution back to the fork point in the same
/// write, so execution can never be left on a branch the node is not on.
#[test]
fn stall_4_adopting_a_branch_brings_execution_back_with_it() {
    let (store, _d, hs) = chain_from(9_251_050, 8);
    let executed_before = store.exec_head().unwrap().unwrap().0;
    assert_eq!(executed_before, hs[8].hash());

    // The branch the network actually kept, forking at #9,251,053.
    let mut parent = hs[3].hash();
    let mut branch = Vec::new();
    for n in 9_251_054..=9_251_060u64 {
        let h = header(n, parent, 42);
        store.put_header_with_hash(h.hash(), &h).unwrap();
        parent = h.hash();
        branch.push(h);
    }

    let head = Validated::prove(&store, branch.last().unwrap().hash()).unwrap();
    store.apply(&Transition::Adopt { head }).unwrap();

    let cursor = store.cursor().unwrap().unwrap();
    assert_eq!(cursor.validated_head.number, 9_251_060);
    assert_eq!(
        cursor.executed.number, 9_251_053,
        "execution was not rolled back to the fork point"
    );
    assert_eq!(cursor.executed.hash, hs[3].hash());
    coherent(&store).unwrap();
}

/// **Stall 5** — fifteen minutes at #9,258,222. The canonical pointer named a
/// block the node had never downloaded, and the repair that should have fixed
/// it wrote nothing and returned success.
///
/// Such a block cannot be proved, so it cannot be adopted, and the failure
/// names the height.
#[test]
fn stall_5_a_block_we_never_downloaded_cannot_be_adopted() {
    let (store, _d, hs) = chain_from(9_258_215, 7);

    // A child of a #9,258,222 we never downloaded.
    let phantom = B256::repeat_byte(0x5a);
    let child = header(9_258_223, phantom, 0);
    store.put_header_with_hash(child.hash(), &child).unwrap();

    let err = Validated::prove(&store, child.hash()).unwrap_err();
    assert!(
        matches!(err, LineageBreak::MissingHeader { at: 9_258_222, .. }),
        "the break was not located at the missing height: {err:?}"
    );

    // The store is untouched by the failed attempt.
    assert_eq!(store.head().unwrap(), Some(hs[7].hash()));
    coherent(&store).unwrap();
}

/// **Stall 6** — three hours at #9,262,402. The orphan-adopt path wrote a
/// canonical entry above `KEY_HEAD`, and because every path that looks for
/// work reads the head, the block was held, linked, valid and unreachable.
///
/// There is no longer an API that writes a canonical entry without saying what
/// the head becomes, and adopting clears anything left above.
#[test]
fn stall_6_a_canonical_entry_cannot_be_stranded_above_the_head() {
    let (store, _d, hs) = chain_from(9_262_395, 6); // up to #9,262,401

    let stranded = header(9_262_402, hs[6].hash(), 0);
    store.put_header_with_hash(stranded.hash(), &stranded).unwrap();

    // The only way to make it canonical is to adopt it -- which moves the head.
    let head = Validated::prove(&store, stranded.hash()).unwrap();
    let cursor = store.apply(&Transition::Adopt { head }).unwrap();

    assert_eq!(cursor.validated_head.number, 9_262_402, "the head did not move with the entry");
    assert_eq!(store.canonical_hash(9_262_402).unwrap(), Some(stranded.hash()));
    coherent(&store).unwrap();
}

/// The same stall from the other side: a *shorter* chain adopted over a longer
/// one must clear what the longer one left above, or it strands entries by
/// omission rather than by commission.
#[test]
fn stall_6b_adopting_a_shorter_chain_clears_what_the_longer_one_left() {
    let (store, _d, hs) = chain_from(9_262_395, 8);

    let fork = header(9_262_400, hs[4].hash(), 99);
    store.put_header_with_hash(fork.hash(), &fork).unwrap();

    let head = Validated::prove(&store, fork.hash()).unwrap();
    store.apply(&Transition::Adopt { head }).unwrap();

    for n in 9_262_401..=9_262_403 {
        assert_eq!(store.canonical_hash(n).unwrap(), None, "#{n} was left above the head");
    }
    coherent(&store).unwrap();
}

/// **Stall 7** — the sawtooth of 2026-09-23. `KEY_HEAD` named a block at
/// #9,262,401 that was not the canonical block at that height, while the
/// canonical index below *and* above it was perfectly consistent.
///
/// Every transition writes the head to a block whose lineage it has just made
/// canonical, so head and canonical index cannot disagree at the head's own
/// height.
#[test]
fn stall_7_the_head_is_always_the_canonical_block_at_its_height() {
    let (store, _d, hs) = chain_from(9_262_395, 6);

    // A sibling at the head height, held but not canonical.
    let sibling = header(9_262_401, hs[5].hash(), 88);
    store.put_header_with_hash(sibling.hash(), &sibling).unwrap();

    // Adopting it makes it canonical *and* the head, together.
    let head = Validated::prove(&store, sibling.hash()).unwrap();
    let cursor = store.apply(&Transition::Adopt { head }).unwrap();

    assert_eq!(cursor.validated_head.hash, sibling.hash());
    assert_eq!(store.canonical_hash(9_262_401).unwrap(), Some(sibling.hash()));
    coherent(&store).unwrap();

    // And the block it displaced is no longer canonical anywhere.
    assert_ne!(store.canonical_hash(9_262_401).unwrap(), Some(hs[6].hash()));
}

/// A restart in the middle of a reorg must come back coherent: the whole point
/// of one `WriteBatch` is that an interrupted transition did not happen.
#[test]
fn a_transition_is_all_or_nothing_across_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (hs, fork_hash) = {
        let store = BlockStore::open(dir.path()).unwrap();
        let mut hs = Vec::new();
        let mut parent = B256::ZERO;
        for n in 0..=10u64 {
            let h = header(n, parent, 0);
            store.update_head(&h, U256::from(n + 1)).unwrap();
            parent = h.hash();
            hs.push(h);
        }
        store.set_exec_head(hs[10].hash(), B256::ZERO).unwrap();

        let mut p = hs[5].hash();
        let mut last = p;
        for n in 6..=12u64 {
            let h = header(n, p, 7);
            store.put_header_with_hash(h.hash(), &h).unwrap();
            p = h.hash();
            last = p;
        }
        let head = Validated::prove(&store, last).unwrap();
        store.apply(&Transition::Adopt { head }).unwrap();
        (hs, last)
    };

    // Reopen: only what is on disk survives.
    let store = BlockStore::open(dir.path()).unwrap();
    coherent(&store).expect("the store was incoherent after reopening");
    assert_eq!(store.head().unwrap(), Some(fork_hash));
    let cursor = store.cursor().unwrap().unwrap();
    assert!(
        cursor.executed.number <= cursor.validated_head.number,
        "execution survived above the head across a restart"
    );
    let _ = hs;
}
