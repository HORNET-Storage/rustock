//! Filling the canonical index, in batches, resumably.

use alloy_primitives::{Address, B256, U256};
use rustock_core::Header;
use rustock_storage::BlockStore;
use std::sync::Arc;

fn header(number: u64, parent: B256) -> Header {
    Header {
        parent_hash: parent,
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: B256::repeat_byte(4),
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::from(100u64),
        number,
        gas_limit: U256::from(6_800_000u64),
        gas_used: 0,
        timestamp: 1_700_000_000 + number,
        extra_data: Default::default(),
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

/// A node as a snapshot sync leaves it: every header on disk by hash, but the
/// canonical index covering only a window near the top.
fn snap_synced(height: u64, window: u64) -> (Arc<BlockStore>, Vec<Header>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));

    let mut chain = vec![header(0, B256::ZERO)];
    for i in 1..=height {
        let parent = chain[(i - 1) as usize].hash();
        chain.push(header(i, parent));
    }

    for h in &chain {
        store.put_header_with_hash(h.hash(), h).expect("header");
    }
    // Only the window is indexed, as the sync leaves it.
    for h in chain.iter().filter(|h| h.number + window > height) {
        store.put_canonical_hash(h.number, h.hash()).expect("index");
    }

    (store, chain, dir)
}

/// The gap below the window is filled, and every height maps to the right
/// block.
#[tokio::test]
async fn the_index_is_filled_below_the_window() {
    let (store, chain, _dir) = snap_synced(5_000, 400);
    let head = chain.last().unwrap().hash();

    // Before: the deep heights are missing.
    assert!(store.canonical_hash(100).unwrap().is_none());

    crate::snap::indexer::fill_canonical_index(store.clone(), head).await;

    for h in &chain {
        assert_eq!(
            store.canonical_hash(h.number).unwrap(),
            Some(h.hash()),
            "height {} is wrong or missing",
            h.number
        );
    }
}

/// **The property that makes it worth running at all.** A pass resumes from
/// the cursor rather than from the head: an hour of disk must not be lost to a
/// restart.
///
/// Asserted by what it does *not* do. Starting from a cursor part way down,
/// the heights above it stay unindexed -- which could only happen if the walk
/// began there rather than at the top.
#[tokio::test]
async fn a_fill_resumes_from_its_cursor_rather_than_the_head() {
    let (store, chain, _dir) = snap_synced(3_000, 100);
    let head = chain.last().unwrap().hash();

    // As an interrupted pass would have left it.
    let resume_at = 1_000u64;
    store
        .set_index_cursor(resume_at, chain[resume_at as usize].hash())
        .expect("cursor");

    crate::snap::indexer::fill_canonical_index(store.clone(), head).await;

    // Everything from the cursor down is indexed.
    for h in chain.iter().filter(|h| h.number <= resume_at) {
        assert_eq!(
            store.canonical_hash(h.number).unwrap(),
            Some(h.hash()),
            "height {} below the cursor was not filled",
            h.number
        );
    }

    // And the gap above it was left alone, so the walk really did start at the
    // cursor instead of the head.
    let untouched = chain
        .iter()
        .filter(|h| h.number > resume_at && h.number + 100 <= 3_000)
        .filter(|h| store.canonical_hash(h.number).unwrap().is_none())
        .count();
    assert!(
        untouched > 0,
        "every height was filled, so the cursor was ignored and the walk started at the head"
    );

    assert!(
        store.index_cursor().unwrap().is_none(),
        "a finished pass left a cursor behind"
    );
}

/// A pass records where it has got to *before* pausing, so a kill during the
/// pause costs nothing.
#[test]
fn a_cursor_survives_a_restart() {
    let (store, chain, _dir) = snap_synced(1_000, 100);

    let hash = chain[500].hash();
    store.set_index_cursor(500, hash).expect("write");

    // As a fresh process would read it.
    assert_eq!(store.index_cursor().unwrap(), Some((500, hash)));

    store.clear_index_cursor().expect("clear");
    assert_eq!(store.index_cursor().unwrap(), None);
}

/// Running it on a node that is already indexed costs one batch and stops,
/// Running it on a node that is already indexed costs one batch and stops,
/// rather than rewriting nine million entries.
#[tokio::test]
async fn a_complete_index_is_left_alone() {
    let (store, chain, _dir) = snap_synced(2_000, 5_000);
    let head = chain.last().unwrap().hash();

    let before = std::time::Instant::now();
    crate::snap::indexer::fill_canonical_index(store.clone(), head).await;
    let elapsed = before.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "a complete index took {elapsed:?}, so it was rewritten"
    );
    for h in &chain {
        assert_eq!(store.canonical_hash(h.number).unwrap(), Some(h.hash()));
    }
}

/// A batch stops at a height already indexed to the same block, because
/// everything below it was indexed by whoever wrote it.
#[test]
fn a_batch_skips_agreeing_heights_without_stopping() {
    let (store, chain, _dir) = snap_synced(1_000, 100);
    let head = chain.last().unwrap().hash();

    let (written, next) = store.index_canonical_batch(head, 10_000).expect("indexes");
    assert!(next.is_none(), "the walk did not finish");
    // Everything below the window was filled; the window itself was walked
    // through without being rewritten.
    assert_eq!(written, 1_001 - 100, "wrote {written} heights");
}

/// The batch bound is honoured, so the caller can yield between batches.
#[test]
fn a_batch_stops_at_its_bound() {
    let (store, chain, _dir) = snap_synced(5_000, 10);
    let head = chain.last().unwrap().hash();

    let (written, next) = store.index_canonical_batch(head, 50).expect("indexes");
    assert!(written <= 50, "wrote {written} heights for a bound of 50");
    let (number, _) = next.expect("more to do");
    assert!(number < 5_000 && number > 4_000, "resumed at an implausible height {number}");
}

/// On a pruning node the fill stops at the floor.
///
/// The fill writes `number -> hash` downward; the pruner deletes exactly those
/// entries below its floor. Without this they undo each other in a loop — the
/// fill rebuilds the index for heights the pruner has just discarded, the next
/// sweep discards them again, and the node spends its background disk writing
/// what it is about to delete. There is nothing below the floor to point at
/// anyway: those blocks are gone.
#[tokio::test]
async fn the_fill_stops_at_the_prune_floor() {
    let (store, chain, _dir) = snap_synced(5_000, 400);
    let head = chain.last().unwrap().hash();

    // A floor as a sweep would leave it: everything below #3,000 discarded.
    let floor_at = 3_000u64;
    for h in chain.iter().filter(|h| h.number < floor_at && h.number > 0) {
        store.delete_canonical_hash(h.number).expect("prune");
    }
    let floor_hash = chain[floor_at as usize].hash();
    store
        .set_prune_floor_for_test(floor_at, floor_hash, U256::from(1u64))
        .expect("floor");

    crate::snap::indexer::fill_canonical_index(store.clone(), head).await;

    // Down to the floor, filled.
    assert_eq!(
        store.canonical_hash(4_000).unwrap(),
        Some(chain[4_000].hash()),
        "heights above the floor should still be indexed"
    );

    // Below it, left alone: the pruner threw those blocks away.
    for n in [1_000u64, 2_000, 2_999] {
        assert!(
            store.canonical_hash(n).unwrap().is_none(),
            "#{n} is below the prune floor and was re-indexed anyway"
        );
    }

    // And the pass is finished, not merely paused, so it does not resume into
    // the pruned range on the next restart.
    assert!(
        store.index_cursor().unwrap().is_none(),
        "the fill should have completed at the floor"
    );
}
