//! Does a node actually record a Flyover peg-in as it follows the chain?
//!
//! The offline reconstruction is well covered: `verify_range
//! --record-legacy-events` drives `events_for` directly and has unit tests
//! around every branch. The **live** path does not go through any of that.
//! It runs inside `BlockProcessor::process_block_timed`, where the records
//! are drained from a thread-local sink that `execute_block` opens and
//! `commit_receipts` empties.
//!
//! Three things can go wrong there and in no unit test:
//!
//! - the sink is opened on one thread and drained on another, so nothing is
//!   ever recorded and the store looks like a chain with no Flyover peg-ins;
//! - the drain happens before the events are synthesised, or after something
//!   else has already emptied it;
//! - the gate suppresses what it should keep.
//!
//! Each failure is silent — an empty store is indistinguishable from a quiet
//! chain — which is why this replays a block known to contain one and
//! asserts the event lands.
//!
//! Needs the node's own data and an archival trie, so it is `#[ignore]`d:
//!
//! ```text
//! RUSTOCK_BLOCKS_DB=/var/lib/rustock RUSTOCK_ARCHIVE_TRIE=/mnt/import/rustock-trie \
//!   cargo test --release -p rustock-execution --test live_peg_event_recording \
//!   -- --ignored --nocapture
//! ```

use rustock_execution::{BlockProcessor, RskHardforkConfig};
use rustock_storage::legacy_event_store::LegacyEventStore;
use rustock_storage::{BlockStore, RocksDbTrieStore};
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;

/// A mainnet block holding exactly one Flyover peg-in, located by
/// `flyover_find` and confirmed by an offline replay: the Bridge credits
/// `0x0Fc7386A…` with 501,000 sat for btcTx `0xe45ac516…`.
const FLYOVER_BLOCK: u64 = 4_603_129;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[test]
#[ignore = "needs a synced block store (RUSTOCK_BLOCKS_DB) and an archival trie (RUSTOCK_ARCHIVE_TRIE)"]
fn a_flyover_pegin_is_recorded_through_the_live_commit_path() {
    let (Some(blocks_dir), Some(trie_dir)) =
        (env("RUSTOCK_BLOCKS_DB"), env("RUSTOCK_ARCHIVE_TRIE"))
    else {
        eprintln!("skipping: set RUSTOCK_BLOCKS_DB and RUSTOCK_ARCHIVE_TRIE");
        return;
    };

    let store = Arc::new(BlockStore::open_read_only(&blocks_dir).expect("block store"));
    let trie: Arc<dyn TrieStore> =
        Arc::new(RocksDbTrieStore::open_read_only(&trie_dir).expect("archival trie"));

    let hash = store
        .canonical_hash(FLYOVER_BLOCK)
        .expect("canonical lookup")
        .expect("block is canonical");
    let header = store.header(hash).expect("header read").expect("header present");
    let (txs, ommers) = store.body(hash).expect("body read").expect("body present");
    let block = rustock_core::Block { header: header.clone(), transactions: txs, ommers };

    let parent = store
        .header(header.parent_hash)
        .expect("parent read")
        .expect("parent present");
    let pre_bytes = trie
        .get(parent.state_root.as_slice())
        .expect("parent state is in the archival trie");
    let pre = TrieNode::from_message(&pre_bytes, trie.as_ref());

    let events_dir = tempfile::tempdir().expect("tempdir");
    let events = Arc::new(
        LegacyEventStore::open(events_dir.path().to_str().unwrap()).expect("event store"),
    );

    let processor = BlockProcessor::new(RskHardforkConfig::for_network(30), store.clone())
        .with_legacy_event_store(Arc::clone(&events));

    // The import loop does these two in sequence (`sync/src/import.rs`):
    // `process_block_timed` executes and fills the thread-local sink, and
    // `commit_receipts` empties it. The recording half is called directly
    // here because the other half of `commit_receipts` writes receipts, and
    // this test runs against the node's real store, opened read-only.
    let mut timings = rustock_execution::ProcessTimings::default();
    processor
        .process_block_timed(&block, &pre, trie.clone(), &mut timings)
        .expect("block executes");
    processor
        .record_unlogged_peg_events(&block)
        .expect("records the events the Bridge did not emit");

    let topic = rustock_execution::bridge::legacy_events::pegin_btc(
        alloy_primitives::Address::ZERO,
        &[0u8; 32],
        0,
        0,
    )
    .topic0;
    let found = events.scan(topic, FLYOVER_BLOCK, FLYOVER_BLOCK).expect("scan");

    assert_eq!(
        found.len(),
        1,
        "expected exactly one reconstructed pegin_btc at #{FLYOVER_BLOCK}; \
         an empty result means the live path recorded nothing, which on a \
         real chain is indistinguishable from there being no Flyover peg-ins"
    );

    // The receiver is an indexed topic, so a wrong one would still count as
    // "an event" above. Check the value, not just the shape.
    let (_, _, _, _, topics, data) = &found[0];
    assert_eq!(topics.len(), 3, "pegin_btc indexes receiver and btcTxHash");
    let receiver = alloy_primitives::Address::from_slice(&topics[1].as_slice()[12..]);
    assert_eq!(
        format!("{receiver:?}").to_lowercase(),
        "0x0fc7386a22e00629fe611516b2c97004d5ff4082",
        "credited LiquidityBridgeContract"
    );
    let amount = alloy_primitives::U256::from_be_slice(&data[..32]);
    assert_eq!(amount, alloy_primitives::U256::from(501_000u64), "amount in satoshis");
}
