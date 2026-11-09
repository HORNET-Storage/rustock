use super::*;
use alloy_primitives::{Address, B256, U256, Bytes, B512};
use tempfile::tempdir;
use crate::service::EXECUTION_OFF_CHAIN_GRACE;

/// A stand-in node id. Header handling is per peer now, so every call needs
/// one; which peer it is only matters where a test says so.
fn test_peer() -> B512 {
    B512::repeat_byte(0xAB)
}

pub(crate) fn dummy_header(number: u64, parent: B256, difficulty: U256) -> Header {
    Header {
        number,
        parent_hash: parent,
        // The real empty-body commitments, not zeroes. Bodies are now checked
        // against the header at receipt (#114), so a header claiming
        // `B256::ZERO` describes a body no peer could ever supply -- and a
        // fixture that cannot be satisfied tests the rejection path by
        // accident rather than whatever the test meant.
        ommers_hash: rustock_execution::processor::compute_ommers_hash(&[]),
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: rustock_core::ordered_tx_trie_root(&[], true),
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty,
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
    }
}

// -- SyncManager tests (validation logic) --------------------------------

#[tokio::test]
async fn test_sync_manager_processing() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new()
        .with_parent_rule(rustock_core::validation::BlockNumberRule)
        .with_parent_rule(rustock_core::validation::ParentHashRule));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    // 1. Valid sequential block
    let b1 = dummy_header(1, genesis_hash, U256::from(10));
    manager.handle_headers_response(vec![b1.clone()], test_peer()).unwrap();
    assert_eq!(store.head().unwrap(), Some(b1.hash()));
    assert_eq!(store.total_difficulty(b1.hash()).unwrap(), Some(U256::from(11)));

    // 2. Duplicate block (should be ignored)
    manager.handle_headers_response(vec![b1.clone()], test_peer()).unwrap();
    assert_eq!(store.head().unwrap(), Some(b1.hash()));

    // 3. Extension block
    let b2 = dummy_header(2, b1.hash(), U256::from(5));
    manager.handle_headers_response(vec![b2.clone()], test_peer()).unwrap();
    assert_eq!(store.head().unwrap(), Some(b2.hash()));

    // 4. Gap block: the named parent is not held, so there is nothing to
    //    verify it against and it is not stored. It is kept as evidence that
    //    this peer has a chain we cannot connect to, which is what provokes a
    //    search for where the two diverge.
    let b4 = dummy_header(4, B256::repeat_byte(0xee), U256::from(1));
    let b4_hash = b4.hash();
    manager.handle_headers_response(vec![b4], test_peer()).unwrap();
    assert_eq!(store.head().unwrap(), Some(b2.hash()), "Head should not change");
    assert!(
        store.header(b4_hash).unwrap().is_none(),
        "a header with no parent to verify against must not reach the store"
    );
    assert_eq!(
        store.total_difficulty(b4_hash).unwrap(),
        None,
        "and must not be given a total difficulty"
    );
}

/// The reason case 4 matters. Total difficulty for a parentless header used to
/// be derived from a parent of zero, making it whatever the sender wrote in
/// the `difficulty` field. A peer could therefore claim the heaviest chain in
/// existence for the cost of one header.
#[tokio::test]
async fn a_parentless_header_cannot_claim_the_head_with_any_difficulty() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let genesis_hash = genesis.hash();

    let verifier = Arc::new(HeaderVerifier::new()
        .with_parent_rule(rustock_core::validation::BlockNumberRule)
        .with_parent_rule(rustock_core::validation::ParentHashRule));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    let liar = dummy_header(9_000_000, B256::repeat_byte(0xee), U256::MAX);
    let liar_hash = liar.hash();
    manager.handle_headers_response(vec![liar], test_peer()).unwrap();

    assert_eq!(
        store.head().unwrap(),
        Some(genesis_hash),
        "a header nobody can verify must not move the head, whatever it claims"
    );
    assert!(store.header(liar_hash).unwrap().is_none());
    assert_eq!(store.total_difficulty(liar_hash).unwrap(), None);
}

/// A disconnected run must not bootstrap itself. The first header has no
/// parent we hold; the second's parent is the first. If the first is refused
/// but still seeds a total difficulty, the rest of the run inherits a base
/// this node never verified — the same hole, one block further along.
#[tokio::test]
async fn a_refused_header_does_not_seed_the_rest_of_its_chunk() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let genesis_hash = genesis.hash();

    let verifier = Arc::new(HeaderVerifier::new()
        .with_parent_rule(rustock_core::validation::BlockNumberRule)
        .with_parent_rule(rustock_core::validation::ParentHashRule));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    let orphan = dummy_header(500, B256::repeat_byte(0xee), U256::MAX);
    let child = dummy_header(501, orphan.hash(), U256::from(1));
    let (orphan_hash, child_hash) = (orphan.hash(), child.hash());
    manager.handle_headers_response(vec![orphan, child], test_peer()).unwrap();

    assert!(store.header(orphan_hash).unwrap().is_none());
    assert!(
        store.header(child_hash).unwrap().is_none(),
        "the child's only parent is a header we refused, so it is no better off"
    );
    assert_eq!(store.head().unwrap(), Some(genesis_hash));
}

#[tokio::test]
async fn test_invalid_header_rejected_when_parent_known() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new()
        .with_parent_rule(rustock_core::validation::BlockNumberRule)
        .with_parent_rule(rustock_core::validation::ParentHashRule));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    // Header claims parent is genesis but has wrong block number
    let bad = dummy_header(5, genesis_hash, U256::from(50));
    let bad_hash = bad.hash();
    manager.handle_headers_response(vec![bad], test_peer()).unwrap();

    assert!(store.header(bad_hash).unwrap().is_none(), "Invalid header should be rejected");
    assert_eq!(store.head().unwrap(), Some(genesis_hash));
}

#[tokio::test]
async fn test_parent_is_taken_from_parent_hash_not_from_batch_position() {
    // The mainnet defect. A chunk can contain a fork header at a height it
    // already covers; if the parent is chosen because it is the previous entry
    // at `number - 1`, the next header is verified against the wrong block.
    // Observed on RSK mainnet: #9,236,893 checked against #9,236,891.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new()
        .with_parent_rule(rustock_core::validation::BlockNumberRule)
        .with_parent_rule(rustock_core::validation::ParentHashRule));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    // The real chain: genesis <- a1 <- a2.
    let a1 = dummy_header(1, genesis_hash, U256::from(10));
    manager.handle_headers_response(vec![a1.clone()], test_peer()).unwrap();

    // A competing block at height 1, also building on genesis.
    let mut fork1 = dummy_header(1, genesis_hash, U256::from(11));
    fork1.timestamp = 999;
    assert_ne!(fork1.hash(), a1.hash(), "fork must be a different block");

    // A batch carrying the fork immediately before a2. a2's parent is a1.
    let a2 = dummy_header(2, a1.hash(), U256::from(5));
    let a2_hash = a2.hash();
    manager.handle_headers_response(vec![fork1.clone(), a2.clone()], test_peer()).unwrap();

    assert!(
        store.header(a2_hash).unwrap().is_some(),
        "a2 must be accepted: its parent_hash names a1, which is stored. \
         Verifying it against the fork at the same height rejects valid chain data."
    );
    assert_eq!(
        store.total_difficulty(a2_hash).unwrap(),
        Some(U256::from(16)),
        "TD must accumulate through a1 (1+10+5), not through the fork"
    );
}

#[tokio::test]
async fn test_competing_headers_at_one_height_are_both_kept() {
    // Deduplicating a chunk by block number discards whichever block at a
    // contested height arrives second -- which may be the canonical one.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new()
        .with_parent_rule(rustock_core::validation::BlockNumberRule)
        .with_parent_rule(rustock_core::validation::ParentHashRule));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    let a1 = dummy_header(1, genesis_hash, U256::from(10));
    let mut b1 = dummy_header(1, genesis_hash, U256::from(20));
    b1.timestamp = 777;
    assert_ne!(a1.hash(), b1.hash());

    manager.handle_headers_response(vec![a1.clone(), b1.clone()], test_peer()).unwrap();

    assert!(store.header(a1.hash()).unwrap().is_some(), "first block at height 1 kept");
    assert!(
        store.header(b1.hash()).unwrap().is_some(),
        "the competing block at height 1 must also be kept -- that is what a fork is"
    );
    // Fork choice still picks the heavier one.
    assert_eq!(store.head().unwrap(), Some(b1.hash()), "heavier fork wins");
}

#[tokio::test]
async fn test_difficulty_is_checked_against_the_true_parent() {
    // Reproduces the shape of RSK mainnet #9,236,891/892/893, where the middle
    // block carries an uncle and sits 7s before its child while the grandparent
    // sits 34s before it. Verifying against the grandparent flips the
    // adjustment sign and rejects a valid header.
    use rustock_core::config::ChainConfig;
    use rustock_core::validation::DifficultyRule;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let config = Arc::new(ChainConfig::mainnet());

    // Heights above papyrus200 so the divisor is 400, matching mainnet.
    let base = config.activation_heights.papyrus200 + 1_000_000;
    let step = |d: U256| d / U256::from(400);

    let mut g = dummy_header(base, B256::ZERO, U256::from(6_661_282_993_281_678_603_550u128));
    g.timestamp = 1_789_321_796;
    let g_hash = g.hash();
    store.update_head(&g, g.difficulty).unwrap();

    // Parent: 27s after the grandparent, one uncle, difficulty stepped down.
    let mut parent = dummy_header(base + 1, g_hash, U256::ZERO);
    parent.timestamp = 1_789_321_823;
    parent.uncle_count = 1;
    // (1 + 1 uncle) * 14 = 28 > 27 elapsed  ->  sign +1
    parent.difficulty = g.difficulty + step(g.difficulty);
    let parent_hash = parent.hash();

    // Child: 7s after the parent, no uncles.  (1 + 0) * 14 = 14 > 7  ->  sign +1
    let mut child = dummy_header(base + 2, parent_hash, U256::ZERO);
    child.timestamp = 1_789_321_830;
    child.difficulty = parent.difficulty + step(parent.difficulty);
    let child_hash = child.hash();

    // Against the grandparent the elapsed time would be 34s, so the sign would
    // be -1 and the expected difficulty would come out low. Assert the two
    // really do differ, or the test proves nothing.
    let against_grandparent = g.difficulty - step(g.difficulty);
    assert_ne!(child.difficulty, against_grandparent);

    let verifier = Arc::new(HeaderVerifier::new()
        .with_parent_rule(rustock_core::validation::BlockNumberRule)
        .with_parent_rule(rustock_core::validation::ParentHashRule)
        .with_parent_rule(DifficultyRule { config: config.clone() }));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    // Store the true parent first, as the node would have from an earlier chunk.
    manager.handle_headers_response(vec![parent.clone()], test_peer()).unwrap();
    assert!(store.header(parent_hash).unwrap().is_some(), "parent accepted");

    // A competing block at the parent's height, building on the grandparent
    // 34s later -- so its own difficulty is a valid -1 step. This is the shape
    // that produced the mainnet rejection: its difficulty is exactly the
    // "expected" value that was logged for #9,236,893.
    let mut fork = dummy_header(base + 1, g_hash, against_grandparent);
    fork.timestamp = 1_789_321_830;
    assert_ne!(fork.hash(), parent_hash, "fork must differ from the true parent");

    // The fork arrives immediately before the child. Positionally it looks like
    // the parent -- same height, right order -- but it is a different block.
    manager.handle_headers_response(vec![fork.clone(), child.clone()], test_peer()).unwrap();

    assert!(
        store.header(child_hash).unwrap().is_some(),
        "child must be accepted: its difficulty is a correct +1 step from the \
         block its parent_hash names. Checking it against the fork at the same \
         height yields a -1 step and rejects valid chain data -- and the missing \
         canonical entry at its height is what wedges execution."
    );
}

#[tokio::test]
async fn test_follow_buffer_gap_triggers_refetch_instead_of_stalling() {
    // The silent stall. In follow mode the lowest buffered block is executed
    // only if it builds on the executed head; if it does not, the old code
    // returned and nothing ever fetched the block in between. Later blocks piled
    // up behind the hole and execution stopped permanently -- observed on
    // mainnet as a node that executed nothing for twenty hours while downloading
    // tips the whole time, with no error logged.
    //
    // The resync trigger cannot catch it: that compares the *downloaded* head
    // against peers, and the downloaded head is at the tip.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    // Executed head at #10.
    let mut parent = genesis.clone();
    for n in 1..=10u64 {
        let h = dummy_header(n, parent.hash(), U256::from(1));
        store.put_header(&h).unwrap();
        store.put_canonical_hash(n, h.hash()).unwrap();
        parent = h;
    }
    let head10 = parent.clone();
    store.set_exec_head(head10.hash(), head10.state_root).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;
    service.last_body_height = 99;

    // Buffer #12 and #13 -- #11 never arrived, so nothing links to #10.
    let b11 = dummy_header(11, head10.hash(), U256::from(1));
    let b12 = dummy_header(12, b11.hash(), U256::from(1));
    let b13 = dummy_header(13, b12.hash(), U256::from(1));
    service.follow_buffer.insert(12, (b12.hash(), b12.clone(), vec![], vec![]));
    service.follow_buffer.insert(13, (b13.hash(), b13.clone(), vec![], vec![]));

    // First observation only starts the clock: an out-of-order response may
    // still be on its way.
    service.drain_follow_buffer().await;
    assert_eq!(service.follow_buffer.len(), 2, "a fresh gap must be given time");
    assert!(matches!(service.state, SyncState::Following));

    // Once it has outlived any plausible in-flight response, re-fetch.
    service.follow_gap_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
    service.drain_follow_buffer().await;

    assert!(
        service.follow_buffer.is_empty(),
        "the stale buffer must be dropped so the missing range can be re-fetched"
    );
    assert_eq!(
        service.last_body_height, 10,
        "the body cursor must rewind to the executed head so the sync path \
         re-fetches #11 onward"
    );
    assert!(
        matches!(service.state, SyncState::Idle),
        "must leave follow mode so a sync round can start; staying in Following \
         is what made this stall permanent"
    );
}

#[tokio::test]
async fn test_follow_buffer_keeps_waiting_on_a_same_height_reorg() {
    // The other reason the lowest buffered block may not link: it is the very
    // next block but builds on a different block at our head's height. That is a
    // reorg, handled by the reconcile path, and must NOT trigger a re-fetch --
    // otherwise every tip reorg would throw away the follow buffer.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let a1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&a1).unwrap();
    store.set_exec_head(a1.hash(), a1.state_root).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;
    service.last_body_height = 1;

    // #2 building on a *different* #1.
    let mut fork1 = dummy_header(1, genesis.hash(), U256::from(2));
    fork1.timestamp = 4242;
    let b2 = dummy_header(2, fork1.hash(), U256::from(1));
    service.follow_buffer.insert(2, (b2.hash(), b2.clone(), vec![], vec![]));

    service.drain_follow_buffer().await;

    assert_eq!(service.follow_buffer.len(), 1, "buffer kept: this is a reorg, not a gap");
    assert_eq!(service.last_body_height, 1, "cursor untouched");
    assert!(matches!(service.state, SyncState::Following), "stays in follow mode");
}

#[tokio::test]
async fn test_execution_watchdog_restarts_a_stalled_pipeline() {
    // Nothing in this service measured execution itself. Header download, the
    // "fell behind" check and the resync trigger all compare the *downloaded*
    // head against peers, and that head keeps climbing while execution is
    // stopped -- so every trigger reported health through twenty hours of a node
    // executing nothing.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut parent = genesis.clone();
    for n in 1..=20u64 {
        let h = dummy_header(n, parent.hash(), U256::from(1));
        store.put_header(&h).unwrap();
        store.put_canonical_hash(n, h.hash()).unwrap();
        store.update_head(&h, U256::from(n + 1)).unwrap();
        parent = h;
    }
    // Downloaded to #20, executed only #5.
    let exec = store.canonical_hash(5).unwrap().unwrap();
    let exec_hdr = store.header(exec).unwrap().unwrap();
    store.set_exec_head(exec, exec_hdr.state_root).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;
    service.last_body_height = 20;

    // A fresh observation only starts the clock.
    service.on_tick().await;
    assert!(matches!(service.state, SyncState::Following), "not yet a fault");
    assert_eq!(service.last_body_height, 20);

    // Once it has stood still long enough with blocks waiting, restart.
    service.last_exec_progress = std::time::Instant::now() - std::time::Duration::from_secs(300);
    service.on_tick().await;

    assert_eq!(
        service.last_body_height, 5,
        "the body cursor must rewind to the executed head so the range re-queues"
    );
    assert!(
        !matches!(service.state, SyncState::Following),
        "must leave follow mode so a sync round can start"
    );
}

#[tokio::test]
async fn test_execution_watchdog_is_quiet_when_there_is_nothing_to_execute() {
    // A node at the tip executes nothing because there is nothing to execute.
    // Restarting the pipeline for that would be a permanent loop.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let h1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&h1).unwrap();
    store.put_canonical_hash(1, h1.hash()).unwrap();
    store.update_head(&h1, U256::from(2)).unwrap();
    store.set_exec_head(h1.hash(), h1.state_root).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;
    service.last_body_height = 1;
    service.last_exec_progress = std::time::Instant::now() - std::time::Duration::from_secs(600);

    service.on_tick().await;

    assert!(matches!(service.state, SyncState::Following), "caught up is not stalled");
    assert_eq!(service.last_body_height, 1, "cursor untouched");
}

#[tokio::test]
async fn test_unanswered_follow_body_requests_expire() {
    // The root cause of the stall. A follow-mode body request a peer never
    // answered stayed in the map forever: the block was never re-requested, and
    // both recovery paths stand down while the map is non-empty, so one stuck
    // entry disabled every mechanism that could have noticed.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    let h = dummy_header(1, genesis.hash(), U256::from(1));
    // A fresh request is left alone.
    service.pending_follow_bodies.insert(7, (h.hash(), h.clone(), std::time::Instant::now(), B512::repeat_byte(1)));
    service.on_tick().await;
    assert_eq!(service.pending_follow_bodies.len(), 1, "a fresh request must not be dropped");

    // One that has gone unanswered is dropped, so the block can be re-requested
    // and the recovery paths can see an idle pipeline.
    service.pending_follow_bodies.insert(
        7,
        (h.hash(), h, std::time::Instant::now() - std::time::Duration::from_secs(120), B512::repeat_byte(1)),
    );
    service.on_tick().await;
    assert!(
        service.pending_follow_bodies.is_empty(),
        "an unanswered request must not block the pipeline forever"
    );
}

#[test]
fn test_backlog_decision() {
    // Follow mode cannot execute a backlog already in the store, so a node that
    // executes must clear one before following. This is the decision that made
    // the mainnet stall self-sustaining: both recovery paths rewound the cursor
    // and dropped to Idle, and the next tick saw a small gap and returned to
    // follow mode having executed nothing.
    use super::service::backlog_needs_executing;

    // Blocks downloaded past the executed head: must be executed first.
    assert!(backlog_needs_executing(true, 10, 4));
    assert!(backlog_needs_executing(true, 5, 4), "even one block counts");

    // Caught up: nothing to do.
    assert!(!backlog_needs_executing(true, 4, 4));

    // A node that does not execute cannot fall behind on execution.
    assert!(!backlog_needs_executing(false, 10, 4));
}

// -- SyncHandler tests (event forwarding) --------------------------------

#[tokio::test]
async fn test_sync_handler_forwards_headers() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let h0 = dummy_header(0, B256::ZERO, U256::from(10));
    let resp = rustock_networking::protocol::rsk::BlockHeadersResponse {
        id: 1,
        headers: vec![h0.clone()],
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersResponse(resp)));

    let handler_resp = handler.handle_message(B512::ZERO, &msg);
    assert!(handler_resp.is_none());

    // Event should be forwarded to the channel
    let event = event_rx.try_recv().unwrap();
    match event {
        SyncEvent::HeadersResponse { headers, .. } => {
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].number, 0);
        }
        _ => panic!("Expected HeadersResponse event"),
    }
}

#[tokio::test]
async fn test_sync_handler_forwards_block_hash() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BlockHashResponse;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let resp = BlockHashResponse { id: 5, hash: B256::repeat_byte(0xab) };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashResponse(resp)));

    handler.handle_message(B512::ZERO, &msg);

    match event_rx.try_recv().unwrap() {
        SyncEvent::BlockHashResponse { hash, .. } => {
            assert_eq!(hash, B256::repeat_byte(0xab));
        }
        _ => panic!("Expected BlockHashResponse event"),
    }
}

#[tokio::test]
async fn test_sync_handler_forwards_skeleton() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::SkeletonResponse;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let resp = SkeletonResponse {
        id: 1,
        block_identifiers: vec![
            BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
            BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
        ],
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonResponse(resp)));

    handler.handle_message(B512::ZERO, &msg);

    match event_rx.try_recv().unwrap() {
        SyncEvent::SkeletonResponse { identifiers, .. } => {
            assert_eq!(identifiers.len(), 2);
            assert_eq!(identifiers[1].number, 192);
        }
        _ => panic!("Expected SkeletonResponse event"),
    }
}

// -- State machine tests -------------------------------------------------

#[tokio::test]
async fn test_connection_point_binary_search() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Store genesis only
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    // Simulate: peer is at block 1000, we only have genesis
    let peer = B512::repeat_byte(0x01);
    service.state = SyncState::FindingConnectionPoint {
        peer,
        peer_best: 1000,
        start: 0,
        end: 1000,
        gallop: None,
    };

    // Probe at midpoint 500: we don't have this block hash
    service.on_block_hash_response(B256::repeat_byte(0xff)).await;
    // Range should narrow: start=0, end=500
    if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
        assert_eq!(*start, 0);
        assert_eq!(*end, 500);
    } else {
        panic!("Expected FindingConnectionPoint, got {:?}", service.state);
    }

    // Probe at 250: don't have it
    service.on_block_hash_response(B256::repeat_byte(0xfe)).await;
    if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
        assert_eq!(*start, 0);
        assert_eq!(*end, 250);
    } else {
        panic!("Expected FindingConnectionPoint");
    }

    // Probe at 125: don't have it
    service.on_block_hash_response(B256::repeat_byte(0xfd)).await;
    if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
        assert_eq!(*start, 0);
        assert_eq!(*end, 125);
    } else {
        panic!("Expected FindingConnectionPoint");
    }

    // Continue narrowing... eventually probe at 1
    // Simulate finding genesis hash — we DO have block 0
    let genesis_hash = dummy_header(0, B256::ZERO, U256::from(1)).hash();

    // Set state to final narrowing: range [0, 1]
    service.state = SyncState::FindingConnectionPoint {
        peer,
        peer_best: 1000,
        start: 0,
        end: 1,
        gallop: None,
    };
    // Probe at 0: we have genesis
    service.on_block_hash_response(genesis_hash).await;
    // Connection point = 0, should transition to DownloadingSkeleton
    match &service.state {
        SyncState::DownloadingSkeleton { connection_point, .. } => {
            assert_eq!(*connection_point, 0);
        }
        _ => panic!("Expected DownloadingSkeleton, got {:?}", service.state),
    }

    drop(event_tx); // cleanup
}

#[tokio::test]
async fn test_skeleton_to_headers_transition() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    let peer = B512::repeat_byte(0x01);
    service.state = SyncState::DownloadingSkeleton {
        peer,
        peer_best: 384,
        connection_point: 0,
    };

    // Receive skeleton: [0, 192, 384]
    let skeleton = vec![
        BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
        BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
        BlockIdentifier { hash: B256::repeat_byte(0x03), number: 384 },
    ];
    service.on_skeleton_response(skeleton).await;

    match &service.state {
        SyncState::DownloadingHeaders { tracker, skeleton, .. } => {
            assert_eq!(tracker.next_to_process, 1);
            assert_eq!(skeleton.len(), 3);
        }
        _ => panic!("Expected DownloadingHeaders, got {:?}", service.state),
    }

    drop(event_tx);
}

#[tokio::test]
async fn test_empty_skeleton_returns_to_idle() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    let peer = B512::repeat_byte(0x01);
    service.state = SyncState::DownloadingSkeleton {
        peer,
        peer_best: 100,
        connection_point: 0,
    };

    // Skeleton with only 1 entry → too small → Following
    service.on_skeleton_response(vec![
        BlockIdentifier { hash: B256::ZERO, number: 0 },
    ]).await;

    assert!(matches!(service.state, SyncState::Following));

    drop(event_tx);
}

#[tokio::test]
async fn test_headers_response_advances_chunks() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a small chain: genesis + 4 blocks
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    // Build headers
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    let b3 = dummy_header(3, b2.hash(), U256::from(1));
    let b4 = dummy_header(4, b3.hash(), U256::from(1));

    // Skeleton: [0, 2, 4]
    let skeleton = vec![
        BlockIdentifier { hash: genesis_hash, number: 0 },
        BlockIdentifier { hash: b2.hash(), number: 2 },
        BlockIdentifier { hash: b4.hash(), number: 4 },
    ];

    let peer = B512::repeat_byte(0x01);
    // Register the peer so fill_pipeline can find it
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let mut tracker = PeerChunkTracker::new(skeleton.len());
    // Simulate: chunk 1 assigned to peer, chunk 2 assigned to peer
    let c1 = tracker.next_assignment().unwrap();
    tracker.record_sent(peer, c1);
    let c2 = tracker.next_assignment().unwrap();
    tracker.record_sent(peer, c2);

    service.state = SyncState::DownloadingHeaders {
        peer_best: 4,
        skeleton: skeleton.clone(),
        connection_point: 0,
        tracker,
        pending_next_skeleton: None,
    };

    // Chunk 1: headers for blocks 1-2 (descending from b2)
    service.on_headers_response(peer, vec![b2.clone(), b1.clone()]).await;

    // Should still be in DownloadingHeaders (chunk 2 pending)
    match &service.state {
        SyncState::DownloadingHeaders { tracker, .. } => {
            assert_eq!(tracker.next_to_process, 2);
        }
        _ => panic!("Expected DownloadingHeaders with next_to_process=2, got {:?}", service.state),
    }

    // Chunk 2: headers for blocks 3-4 (descending from b4)
    service.on_headers_response(peer, vec![b4.clone(), b3.clone()]).await;

    // All chunks done → transitions to DownloadingBodies (bodies not yet stored)
    assert!(matches!(service.state, SyncState::DownloadingBodies { .. }),
        "Expected DownloadingBodies after final chunk, got {:?}", service.state);

    // Verify all headers are stored
    assert!(store.header(b1.hash()).unwrap().is_some());
    assert!(store.header(b4.hash()).unwrap().is_some());

    drop(event_tx);
}

#[tokio::test]
async fn test_try_start_sync_when_behind_peer() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 1000,
        total_difficulty: U256::from(1000),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.try_start_sync().await;

    match &service.state {
        SyncState::DownloadingSkeleton { peer_best, connection_point, .. } => {
            assert_eq!(*peer_best, 1000);
            assert_eq!(*connection_point, 0);
        }
        _ => panic!("Expected DownloadingSkeleton, got {:?}", service.state),
    }

    drop(event_tx);
}

#[tokio::test]
async fn test_try_start_sync_already_synced() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 0,
        total_difficulty: U256::from(1),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.try_start_sync().await;

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following when already synced, got {:?}", service.state);

    drop(event_tx);
}

#[tokio::test]
async fn test_timeout_resets_to_idle() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    let peer = B512::repeat_byte(0x01);
    service.state = SyncState::FindingConnectionPoint {
        peer,
        peer_best: 1000,
        start: 0,
        end: 1000,
        gallop: None,
    };
    service.last_progress = Instant::now() - Duration::from_secs(60);

    service.on_tick().await;

    assert!(matches!(service.state, SyncState::Idle),
        "Expected Idle after timeout, got {:?}", service.state);

    drop(event_tx);
}

#[tokio::test]
async fn test_descending_headers_reversed() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    let b3 = dummy_header(3, b2.hash(), U256::from(1));

    manager.handle_headers_response(vec![b3.clone(), b2.clone(), b1.clone()], test_peer()).unwrap();

    assert!(store.header(b1.hash()).unwrap().is_some());
    assert!(store.header(b2.hash()).unwrap().is_some());
    assert!(store.header(b3.hash()).unwrap().is_some());
    assert_eq!(store.head().unwrap(), Some(b3.hash()));
}

#[tokio::test]
async fn test_skeleton_round_transitions_to_next_skeleton() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    let b3 = dummy_header(3, b2.hash(), U256::from(1));
    let b4 = dummy_header(4, b3.hash(), U256::from(1));

    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();
    store.put_total_difficulty(b1.hash(), U256::from(2)).unwrap();
    store.put_total_difficulty(b2.hash(), U256::from(3)).unwrap();
    store.update_head(&b2, U256::from(3)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    let skeleton = vec![
        BlockIdentifier { hash: genesis_hash, number: 0 },
        BlockIdentifier { hash: b2.hash(), number: 2 },
        BlockIdentifier { hash: b4.hash(), number: 4 },
    ];
    let peer = B512::repeat_byte(0x01);
    // Register the peer so the service can find it for the next skeleton
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;
    peer_store.update_metadata(&peer, rustock_networking::peers::PeerMetadata {
        best_number: 10000,
        total_difficulty: U256::from(10000),
        ..Default::default()
    }).await;

    // Set up tracker: chunks 1 already processed, chunk 2 in flight
    let mut tracker = PeerChunkTracker::new(skeleton.len());
    tracker.next_to_assign = 3; // all assigned
    tracker.next_to_process = 2; // chunk 1 already done
    tracker.record_sent(peer, 2); // chunk 2 in flight from peer

    service.state = SyncState::DownloadingHeaders {
        peer_best: 10000,
        skeleton,
        connection_point: 0,
        tracker,
        pending_next_skeleton: None,
    };

    service.on_headers_response(peer, vec![b4.clone(), b3.clone()]).await;

    // Headers complete → transitions to DownloadingBodies since bodies are missing
    match &service.state {
        SyncState::DownloadingBodies { peer_best, .. } => {
            assert_eq!(*peer_best, 10000);
        }
        _ => panic!("Expected DownloadingBodies after completing last chunk, got {:?}", service.state),
    }

    // Simulate body responses to complete the phase. Each answer comes from
    // the peer its request was sent to, which is what the service accepts.
    let pending: Vec<(u64, B512)> =
        if let SyncState::DownloadingBodies { id_index, .. } = &service.state {
            id_index.iter().map(|(id, (_, asked))| (*id, *asked)).collect()
        } else {
            Vec::new()
        };
    for (req_id, asked) in pending {
        service
            .on_body_response(asked, req_id, vec![], vec![], None)
            .await;
    }

    // After all bodies downloaded, should continue to DownloadingSkeleton
    match &service.state {
        SyncState::DownloadingSkeleton { connection_point, .. } => {
            assert_eq!(*connection_point, 4, "Should request next skeleton from our head");
        }
        _ => panic!("Expected DownloadingSkeleton after body download, got {:?}", service.state),
    }

    drop(event_tx);
}

/// How many times `event` has been recorded against `peer`.
///
/// Read through `information()`, the same view `sco_reputationSummary` serves,
/// rather than a test-only accessor -- if the counter is not visible there it
/// is not visible to an operator either.
fn scored(
    scoring: &rustock_networking::scoring::ScoringService,
    peer: B512,
    event: rustock_networking::scoring::EventType,
) -> u32 {
    let label: String =
        peer.as_slice().iter().take(4).map(|b| format!("{b:02x}")).collect();
    scoring.with(|m| {
        m.information()
            .into_iter()
            .find(|e| e.id == label && e.kind == "node")
            .and_then(|e| {
                e.counters
                    .iter()
                    .find(|(n, _)| *n == event.report_name())
                    .map(|(_, c)| *c)
            })
            .unwrap_or(0)
    })
}

/// **A body that does not match its header is charged to whoever sent it.**
///
/// Receipt is the only moment the sender is unambiguous -- by execution time
/// the block has been through a store and a buffer. Two hashes settle it, and
/// the request must stay in flight so the retry asks somebody else rather than
/// the block being stranded. See #114.
#[tokio::test]
async fn a_body_that_does_not_match_its_header_is_charged_and_refetched() {
    use rustock_networking::scoring::{EventType, ScoringService};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&b1).unwrap();

    let scoring = Arc::new(ScoringService::in_memory());
    let mut service = make_service(store.clone());
    service = service.with_scoring(Some(scoring.clone()));

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;

    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(0usize, InFlightBody { req_id: 7, sent: Instant::now(), peer });
    let mut id_index = std::collections::HashMap::new();
    id_index.insert(7u64, (0usize, peer));
    service.state = SyncState::DownloadingBodies {
        peer_best: 10,
        pending_headers: vec![(b1.hash(), b1.clone())],
        next_request: 1,
        in_flight,
        id_index,
    };

    // b1's header commits to an empty body. Send an uncle it never had.
    let bogus_uncle = dummy_header(0, B256::repeat_byte(0xEE), U256::from(1));
    service
        .on_body_response(peer, 7, vec![], vec![bogus_uncle], None)
        .await;

    assert_eq!(
        scored(&scoring, peer, EventType::InvalidBlock),
        1,
        "the sender must be charged for a body that is not the header's"
    );
    assert!(
        store.body(b1.hash()).unwrap().is_none(),
        "a mismatched body must not be stored"
    );
    match &service.state {
        SyncState::DownloadingBodies { in_flight, id_index, .. } => {
            assert_eq!(in_flight.len(), 1, "the request must stay in flight for retry");
            assert!(id_index.contains_key(&7), "and stay routable by its id");
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }
}

/// The matching case: a correct body is accepted, stored, and its supplier
/// remembered so the credit can be paid when the block executes.
#[tokio::test]
async fn a_matching_body_is_stored_and_its_supplier_remembered() {
    use rustock_networking::scoring::{EventType, ScoringService};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&b1).unwrap();

    let scoring = Arc::new(ScoringService::in_memory());
    let mut service = make_service(store.clone());
    service = service.with_scoring(Some(scoring.clone()));

    let peer = B512::repeat_byte(0x02);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;

    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(0usize, InFlightBody { req_id: 7, sent: Instant::now(), peer });
    let mut id_index = std::collections::HashMap::new();
    id_index.insert(7u64, (0usize, peer));
    service.state = SyncState::DownloadingBodies {
        peer_best: 10,
        pending_headers: vec![(b1.hash(), b1.clone())],
        next_request: 1,
        in_flight,
        id_index,
    };

    service
        .on_body_response(peer, 7, vec![], vec![], None)
        .await;

    assert_eq!(
        scored(&scoring, peer, EventType::InvalidBlock),
        0,
        "a correct body is not a fault"
    );
    assert_eq!(
        service.body_providers.get(&1).copied(),
        Some(peer),
        "the supplier must survive receipt, or no credit can be paid later"
    );

    // Nothing is credited until a block actually executes -- copying a body
    // correctly is not evidence that it is a real block.
    assert_eq!(scored(&scoring, peer, EventType::ValidBlock), 0);
    service.credit_executed_bodies(1);
    assert_eq!(
        scored(&scoring, peer, EventType::ValidBlock),
        1,
        "executing to the header's state root is what earns the credit"
    );
    assert!(
        service.body_providers.is_empty(),
        "a credited block must not be credited twice"
    );
}

/// Provenance cannot grow without bound. A halt strands entries above the
/// executed head that will never be credited, and nothing else prunes them.
#[tokio::test]
async fn stranded_provenance_is_bounded() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let mut service = make_service(store);

    for n in 0..25_000u64 {
        service.body_providers.insert(n, B512::repeat_byte(1));
    }
    // Credit nothing: every entry is above the executed head.
    service.credit_executed_bodies(0);
    assert!(
        service.body_providers.len() <= 20_000,
        "stranded provenance must be capped, got {}",
        service.body_providers.len()
    );
}

#[tokio::test]
async fn test_failed_body_send_stays_tracked_for_retry() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    // Peer whose session channel is closed: every send to it fails.
    let peer = B512::repeat_byte(0x01);
    let (tx, rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;
    drop(rx);

    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(0usize, InFlightBody { req_id: 7, sent: Instant::now(), peer }); // b1 in flight
    let mut id_index = std::collections::HashMap::new();
    id_index.insert(7u64, (0usize, peer));
    service.state = SyncState::DownloadingBodies {
        peer_best: 10,
        pending_headers: vec![(b1.hash(), b1.clone()), (b2.hash(), b2.clone())],
        next_request: 1,
        in_flight,
        id_index,
    };

    // b1's body arrives; the service tops up with a request for b2, whose
    // send fails (dead peer). The request must stay tracked so the stalled
    // retry re-attempts it — dropping it would orphan b2 forever and the
    // batch could never complete.
    service
        .on_body_response(B512::repeat_byte(9), 7, vec![], vec![], None)
        .await;

    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert_eq!(
                in_flight.len(),
                1,
                "request with failed send must remain in flight for retry"
            );
        }
        other => panic!("Expected DownloadingBodies, got {:?}", other),
    }
}

#[tokio::test]
async fn test_stalled_body_retry_rotates_across_peers() {
    // A lone stalled body must not be re-sent to the same peer every round:
    // if peers[0] is unresponsive, pinning to it wedges the whole batch. Each
    // retry round should target a different peer.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&b1).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    // Three live peers; keep their receivers so we can see who got the request.
    let mut rxs = std::collections::HashMap::new();
    for i in 0u8..3 {
        let id = B512::repeat_byte(i + 1);
        let (tx, rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
        peer_store.add_peer(id, tx).await;
        rxs.insert(id, rx);
    }

    // One straggler in flight (b1's body), the batch can't finish without it.
    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(
        0usize,
        InFlightBody { req_id: 7, sent: Instant::now(), peer: B512::repeat_byte(1) },
    );
    let mut id_index = std::collections::HashMap::new();
    id_index.insert(7u64, (0usize, B512::repeat_byte(1)));
    service.state = SyncState::DownloadingBodies {
        peer_best: 10,
        pending_headers: vec![(b1.hash(), b1.clone())],
        next_request: 1,
        in_flight,
        id_index,
    };

    // Backdate the lone request so the per-request timeout considers it stale.
    let force_stale = |service: &mut SyncService| {
        if let SyncState::DownloadingBodies { in_flight, .. } = &mut service.state {
            for req in in_flight.values_mut() {
                req.sent = Instant::now()
                    .checked_sub(Duration::from_secs(120))
                    .expect("monotonic clock far enough from origin");
            }
        }
    };

    // Identify which peer received the single retried request this round.
    let receiver_of_round = |rxs: &mut std::collections::HashMap<B512, mpsc::Receiver<_>>| {
        let mut hit = None;
        for (id, rx) in rxs.iter_mut() {
            if rx.try_recv().is_ok() {
                assert!(hit.is_none(), "exactly one peer should get the lone straggler");
                hit = Some(*id);
            }
        }
        hit.expect("some peer must receive the retried request")
    };

    // Each reclaim must move the straggler off the peer it just timed out on,
    // so consecutive rounds always hit a different peer (never pinning).
    force_stale(&mut service);
    service.retry_stale_body_requests().await;
    let first = receiver_of_round(&mut rxs);
    force_stale(&mut service);
    service.retry_stale_body_requests().await;
    let second = receiver_of_round(&mut rxs);
    force_stale(&mut service);
    service.retry_stale_body_requests().await;
    let third = receiver_of_round(&mut rxs);

    assert_ne!(first, second, "retry must move off the timed-out peer");
    assert_ne!(second, third, "retry must keep moving off the timed-out peer");
}

#[tokio::test]
async fn test_body_requests_skip_struck_peers_and_balance() {
    // New body requests must avoid peers over the strike limit (dead/slow) and
    // spread evenly across the responsive ones (least-outstanding assignment).
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut headers = Vec::new();
    let mut parent = genesis.hash();
    for n in 1..=6u64 {
        let h = dummy_header(n, parent, U256::from(1));
        store.put_header(&h).unwrap();
        parent = h.hash();
        headers.push((h.hash(), h));
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    // Two good peers and one "dead" peer marked over the strike limit.
    let good_a = B512::repeat_byte(0x0a);
    let good_b = B512::repeat_byte(0x0b);
    let dead = B512::repeat_byte(0x0d);
    let mut rxs = std::collections::HashMap::new();
    for id in [good_a, good_b, dead] {
        let (tx, rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
        peer_store.add_peer(id, tx).await;
        rxs.insert(id, rx);
    }
    service.body_peer_strikes.insert(dead, 100);

    service.state = SyncState::DownloadingBodies {
        peer_best: 10,
        pending_headers: headers,
        next_request: 0,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    service.send_body_requests().await;

    let count = |id: &B512, rxs: &mut std::collections::HashMap<B512, mpsc::Receiver<_>>| {
        let rx = rxs.get_mut(id).unwrap();
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    };
    assert_eq!(count(&dead, &mut rxs), 0, "struck peer must receive no requests");
    let a = count(&good_a, &mut rxs);
    let b = count(&good_b, &mut rxs);
    assert_eq!(a + b, 6, "all six bodies requested from the responsive peers");
    assert_eq!(a, 3, "load balanced evenly across responsive peers");
    assert_eq!(b, 3, "load balanced evenly across responsive peers");
}

#[tokio::test]
async fn test_late_body_response_on_superseded_id_still_applies() {
    // After a request is retried (new id), a late response to the *original*
    // id must still store the body instead of being discarded as "unknown" —
    // and a second (duplicate) response must be ignored without re-fetching.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    // b1 (idx 0) outstanding on id 7 and already stale; b2 (idx 1) on id 8, fresh.
    let stale = Instant::now().checked_sub(Duration::from_secs(120)).unwrap();
    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(0usize, InFlightBody { req_id: 7, sent: stale, peer });
    in_flight.insert(1usize, InFlightBody { req_id: 8, sent: Instant::now(), peer });
    let mut id_index = std::collections::HashMap::new();
    id_index.insert(7u64, (0usize, peer));
    id_index.insert(8u64, (1usize, peer));
    service.state = SyncState::DownloadingBodies {
        peer_best: 10,
        pending_headers: vec![(b1.hash(), b1.clone()), (b2.hash(), b2.clone())],
        next_request: 2,
        in_flight,
        id_index,
    };

    // Retry: only b1 is stale, so it gets a fresh id; id 7 stays mapped.
    service.retry_stale_body_requests().await;
    let new_id = match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => in_flight[&0].req_id,
        other => panic!("Expected DownloadingBodies, got {:?}", other),
    };
    assert_ne!(new_id, 7, "retry must issue a fresh request id");

    // Late response on the SUPERSEDED id 7 must still store b1. It comes from
    // the peer id 7 was sent to -- the retry went to a fresh id, and the old
    // id keeps its own peer, which is what lets a late answer still land.
    service
        .on_body_response(peer, 7, vec![], vec![], None)
        .await;
    assert!(
        store.body(b1.hash()).unwrap().is_some(),
        "late response on a superseded id must still apply its body"
    );
    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert!(!in_flight.contains_key(&0), "b1 no longer outstanding");
            assert!(in_flight.contains_key(&1), "b2 still outstanding");
        }
        other => panic!("Expected DownloadingBodies, got {:?}", other),
    }

    // Duplicate: the retried id now arrives too — must be ignored, no panic,
    // batch state unchanged (b2 still the only thing outstanding).
    service
        .on_body_response(B512::repeat_byte(9), new_id, vec![], vec![], None)
        .await;
    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert!(!in_flight.contains_key(&0));
            assert!(in_flight.contains_key(&1), "duplicate must not disturb b2");
        }
        other => panic!("Expected DownloadingBodies, got {:?}", other),
    }
}

// -- PeerChunkTracker tests -----------------------------------------------

#[test]
fn test_tracker_new_starts_at_chunk_1() {
    let tracker = PeerChunkTracker::new(5);
    assert_eq!(tracker.next_to_assign, 1);
    assert_eq!(tracker.next_to_process, 1);
    assert_eq!(tracker.total_chunks, 5);
    assert!(!tracker.is_complete());
}

#[test]
fn test_tracker_assignment_sequence() {
    let mut tracker = PeerChunkTracker::new(4); // chunks 1, 2, 3

    assert_eq!(tracker.next_assignment(), Some(1));
    assert_eq!(tracker.next_assignment(), Some(2));
    assert_eq!(tracker.next_assignment(), Some(3));
    assert_eq!(tracker.next_assignment(), None); // all assigned
    assert_eq!(tracker.next_assignment(), None); // still None
}

#[test]
fn test_tracker_record_and_identify_response() {
    let mut tracker = PeerChunkTracker::new(5);
    let peer_a = B512::repeat_byte(0x0A);
    let peer_b = B512::repeat_byte(0x0B);

    tracker.record_sent(peer_a, 1);
    tracker.record_sent(peer_a, 2);
    tracker.record_sent(peer_b, 3);

    // Responses come back in FIFO order per peer
    assert_eq!(tracker.identify_response(&peer_a), Some(1));
    assert_eq!(tracker.identify_response(&peer_b), Some(3));
    assert_eq!(tracker.identify_response(&peer_a), Some(2));

    // No more in flight
    assert_eq!(tracker.identify_response(&peer_a), None);
    assert_eq!(tracker.identify_response(&peer_b), None);
}

#[test]
fn test_tracker_identify_unknown_peer() {
    let mut tracker = PeerChunkTracker::new(3);
    let unknown = B512::repeat_byte(0xFF);
    assert_eq!(tracker.identify_response(&unknown), None);
}

#[test]
fn test_tracker_drain_ready_in_order() {
    let mut tracker = PeerChunkTracker::new(5);
    // Simulate: chunks 1, 2, 3, 4 all buffered
    tracker.buffer_response(B512::ZERO, 1, vec![]);
    tracker.buffer_response(B512::ZERO, 2, vec![]);
    tracker.buffer_response(B512::ZERO, 3, vec![]);
    tracker.buffer_response(B512::ZERO, 4, vec![]);

    let ready = tracker.drain_ready();
    assert_eq!(ready.len(), 4);
    assert_eq!(ready[0].0, 1);
    assert_eq!(ready[1].0, 2);
    assert_eq!(ready[2].0, 3);
    assert_eq!(ready[3].0, 4);
    assert!(tracker.is_complete());
}

#[test]
fn test_tracker_drain_ready_out_of_order() {
    let mut tracker = PeerChunkTracker::new(5);

    // Chunk 3 arrives first — can't process yet
    tracker.buffer_response(B512::ZERO, 3, vec![]);
    let ready = tracker.drain_ready();
    assert!(ready.is_empty());
    assert_eq!(tracker.next_to_process, 1);

    // Chunk 2 arrives — still can't process (waiting for 1)
    tracker.buffer_response(B512::ZERO, 2, vec![]);
    let ready = tracker.drain_ready();
    assert!(ready.is_empty());

    // Chunk 1 arrives — now process 1, 2, 3 consecutively
    tracker.buffer_response(B512::ZERO, 1, vec![]);
    let ready = tracker.drain_ready();
    assert_eq!(ready.len(), 3);
    assert_eq!(ready[0].0, 1);
    assert_eq!(ready[1].0, 2);
    assert_eq!(ready[2].0, 3);
    assert_eq!(tracker.next_to_process, 4);

    // Chunk 4 arrives — immediately ready
    tracker.buffer_response(B512::ZERO, 4, vec![]);
    let ready = tracker.drain_ready();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].0, 4);
    assert!(tracker.is_complete());
}

/// Each drained chunk names **its own** supplier.
///
/// This is the difference between punishing the peer that sent a bad header
/// chunk and punishing whichever peer's response happened to unblock the
/// queue. Chunks are processed in skeleton order, not arrival order, so those
/// are routinely different peers -- and an invalid header is a punishing
/// scoring event, so getting it wrong bans an innocent peer.
#[test]
fn drained_chunks_carry_the_peer_that_sent_them() {
    let mut tracker = PeerChunkTracker::new(4);
    let slow = B512::repeat_byte(0xA1);
    let fast = B512::repeat_byte(0xB2);

    // The fast peer's later chunks arrive first and wait.
    tracker.buffer_response(fast, 2, vec![]);
    tracker.buffer_response(fast, 3, vec![]);
    assert!(tracker.drain_ready().is_empty(), "nothing can be processed before chunk 1");

    // The slow peer's chunk 1 finally arrives and releases all three.
    tracker.buffer_response(slow, 1, vec![]);
    let ready = tracker.drain_ready();
    assert_eq!(ready.len(), 3);
    assert_eq!(ready[0].1, slow, "chunk 1 came from the slow peer");
    assert_eq!(ready[1].1, fast);
    assert_eq!(ready[2].1, fast);
}

#[test]
fn test_tracker_peer_capacity() {
    let mut tracker = PeerChunkTracker::new(20);
    let peer = B512::repeat_byte(0x01);

    // Fresh peer has full capacity
    assert_eq!(tracker.peer_capacity(&peer), 4); // PIPELINE_DEPTH

    // Fill up the pipeline
    tracker.record_sent(peer, 1);
    assert_eq!(tracker.peer_capacity(&peer), 3);
    tracker.record_sent(peer, 2);
    assert_eq!(tracker.peer_capacity(&peer), 2);
    tracker.record_sent(peer, 3);
    assert_eq!(tracker.peer_capacity(&peer), 1);
    tracker.record_sent(peer, 4);
    assert_eq!(tracker.peer_capacity(&peer), 0);

    // Completing a response frees capacity
    tracker.identify_response(&peer);
    assert_eq!(tracker.peer_capacity(&peer), 1);
}

#[test]
fn test_tracker_handle_peer_disconnect() {
    let mut tracker = PeerChunkTracker::new(10);
    let peer_a = B512::repeat_byte(0x0A);
    let peer_b = B512::repeat_byte(0x0B);

    // Assign chunks: peer_a gets 1,2,3 — peer_b gets 4,5,6
    for i in 1..=3 {
        tracker.record_sent(peer_a, i);
    }
    for i in 4..=6 {
        tracker.record_sent(peer_b, i);
    }
    tracker.next_to_assign = 7;

    // Chunk 1 already processed
    tracker.next_to_process = 2;

    // Peer A disconnects — chunks 2, 3 should be reassigned
    tracker.handle_peer_disconnect(&peer_a);

    // next_to_assign should be reset to min(2, 3) = 2
    assert_eq!(tracker.next_to_assign, 2);

    // peer_a should have no in-flight
    assert!(!tracker.in_flight.contains_key(&peer_a));

    // peer_b should be unaffected
    assert_eq!(tracker.in_flight.get(&peer_b).unwrap().len(), 3);
}

#[test]
fn test_tracker_disconnect_with_buffered_chunk() {
    let mut tracker = PeerChunkTracker::new(6);
    let peer = B512::repeat_byte(0x01);

    tracker.record_sent(peer, 1);
    tracker.record_sent(peer, 2);
    tracker.record_sent(peer, 3);
    tracker.next_to_assign = 4;

    // Chunk 2 already buffered (response received but not processed)
    tracker.buffer_response(B512::ZERO, 2, vec![]);

    // Peer disconnects — only chunks 1 and 3 need reassignment (2 is buffered)
    tracker.handle_peer_disconnect(&peer);

    // next_to_assign should be 1 (the minimum un-buffered, un-processed chunk)
    assert_eq!(tracker.next_to_assign, 1);
}

#[test]
fn test_tracker_stalled_peers() {
    let mut tracker = PeerChunkTracker::new(10);
    let peer_a = B512::repeat_byte(0x0A);
    let peer_b = B512::repeat_byte(0x0B);

    tracker.record_sent(peer_a, 1);
    tracker.record_sent(peer_b, 2);
    tracker.record_sent(peer_b, 3);

    // With a zero timeout, both peers count as stalled.
    let mut stalled = tracker.stalled_peers(std::time::Duration::ZERO);
    stalled.sort();
    assert_eq!(stalled, vec![peer_a, peer_b]);

    // A response drains peer_a's queue — it is no longer waiting.
    assert_eq!(tracker.identify_response(&peer_a), Some(1));
    assert_eq!(tracker.stalled_peers(std::time::Duration::ZERO), vec![peer_b]);

    // A response from peer_b refreshes its clock but it still has chunk 3
    // outstanding, so it remains subject to the stall timeout.
    assert_eq!(tracker.identify_response(&peer_b), Some(2));
    assert_eq!(tracker.stalled_peers(std::time::Duration::ZERO), vec![peer_b]);
    assert!(tracker.stalled_peers(std::time::Duration::from_secs(60)).is_empty());
}

#[test]
fn test_tracker_disconnect_clears_stall_tracking() {
    let mut tracker = PeerChunkTracker::new(10);
    let peer = B512::repeat_byte(0x0A);

    tracker.record_sent(peer, 1);
    // Backdate the wait so the stall check is deterministic: stalled_peers uses
    // `elapsed() > timeout`, and elapsed() right after record_sent can be 0ns on
    // a fast machine, making the ZERO-timeout boundary race under load.
    tracker.waiting_since.insert(
        peer,
        std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("system uptime > 1s"),
    );
    assert_eq!(tracker.stalled_peers(std::time::Duration::ZERO), vec![peer]);

    tracker.handle_peer_disconnect(&peer);
    assert!(tracker.stalled_peers(std::time::Duration::ZERO).is_empty());
}

#[tokio::test]
async fn test_stalled_peer_sidelined_and_chunks_reassigned() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    let peer_a = B512::repeat_byte(0x0A);
    let peer_b = B512::repeat_byte(0x0B);
    let (tx_a, _rx_a) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    let (tx_b, mut rx_b) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_a, tx_a).await;
    peer_store.add_peer(peer_b, tx_b).await;

    // Round in flight: peer_a holds chunk 1 (stalled 11s), peer_b holds chunk 2.
    let mut tracker = PeerChunkTracker::new(3);
    tracker.record_sent(peer_a, 1);
    tracker.record_sent(peer_b, 2);
    tracker.next_to_assign = 3;
    tracker.waiting_since.insert(
        peer_a,
        std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(11))
            .expect("system uptime > 11s"),
    );

    service.state = SyncState::DownloadingHeaders {
        peer_best: 384,
        skeleton: vec![
            BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
            BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
            BlockIdentifier { hash: B256::repeat_byte(0x03), number: 384 },
        ],
        connection_point: 0,
        tracker,
        pending_next_skeleton: None,
    };
    service.last_progress = std::time::Instant::now();

    service.on_tick().await;

    // peer_a is sidelined and its chunk handed to peer_b.
    assert!(service.sidelined.contains_key(&peer_a));
    match &service.state {
        SyncState::DownloadingHeaders { tracker, .. } => {
            assert!(!tracker.in_flight.contains_key(&peer_a));
            assert!(tracker.in_flight.get(&peer_b).unwrap().contains(&1));
        }
        other => panic!("Expected DownloadingHeaders, got {:?}", other),
    }
    assert!(rx_b.try_recv().is_ok(), "reassigned chunk request sent to peer_b");

    drop(event_tx);
}

#[test]
fn test_tracker_is_complete() {
    let mut tracker = PeerChunkTracker::new(3); // chunks 1, 2
    assert!(!tracker.is_complete());

    tracker.next_to_process = 2;
    assert!(!tracker.is_complete());

    tracker.next_to_process = 3;
    assert!(tracker.is_complete());
}

// -- Following mode / NewBlockHashes tests --------------------------------

#[tokio::test]
async fn test_small_gap_enters_following_mode() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 10, // only 10 blocks behind (< 24)
        total_difficulty: U256::from(10),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.try_start_sync().await;

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following for small gap, got {:?}", service.state);
}

#[tokio::test]
async fn test_large_gap_enters_skeleton_sync() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 100, // 100 blocks behind (> 24)
        total_difficulty: U256::from(100),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.try_start_sync().await;

    assert!(matches!(service.state, SyncState::DownloadingSkeleton { .. }),
        "Expected DownloadingSkeleton for large gap, got {:?}", service.state);
}

#[tokio::test]
async fn test_new_block_hashes_ignored_during_sync() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    let peer = B512::repeat_byte(0x01);
    service.state = SyncState::DownloadingSkeleton {
        peer,
        peer_best: 1000,
        connection_point: 0,
    };

    // NewBlockHashes should be silently dropped
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: B256::repeat_byte(0xaa), number: 1001 },
    ]).await;

    // State should be unchanged
    assert!(matches!(service.state, SyncState::DownloadingSkeleton { .. }),
        "State should remain DownloadingSkeleton, got {:?}", service.state);
}

#[tokio::test]
async fn test_new_block_hashes_processed_in_following_mode() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);
    service.state = SyncState::Following;

    // Announce a new block
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: B256::repeat_byte(0xbb), number: 1 },
    ]).await;

    // Should have sent a headers request to the peer
    let msg = rx.try_recv();
    assert!(msg.is_ok(), "Expected a headers request message to be sent");

    // Peer metadata should be updated
    let best = peer_store.best_peer().await;
    assert!(best.is_some());
    let (_, meta) = best.unwrap();
    assert_eq!(meta.best_number, 1);
}

#[tokio::test]
async fn test_following_switches_to_sync_on_large_gap() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a small chain so our_height > 0 (check_follow_gap returns early at 0)
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();
    store.put_total_difficulty(b1.hash(), U256::from(2)).unwrap();
    store.put_total_difficulty(b2.hash(), U256::from(3)).unwrap();
    store.update_head(&b2, U256::from(3)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 200, // 198 blocks ahead (> 24)
        total_difficulty: U256::from(200),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    service.check_follow_gap().await;

    assert!(
        matches!(service.state, SyncState::DownloadingSkeleton { .. } | SyncState::FindingConnectionPoint { .. }),
        "Expected DownloadingSkeleton or FindingConnectionPoint after large gap in Following, got {:?}", service.state
    );
}

#[tokio::test]
async fn test_following_stays_when_gap_small() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a small chain so our_height > 0
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_total_difficulty(b1.hash(), U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 5, // only 4 blocks ahead (< 24)
        total_difficulty: U256::from(5),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    service.check_follow_gap().await;

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following to persist with small gap, got {:?}", service.state);
}

#[tokio::test]
async fn test_following_small_gap_requests_missing_headers() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Our head is #1; peer is at #5 (gap of 4, < LONG_SYNC_LIMIT).
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_total_difficulty(b1.hash(), U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let peer_best_hash = B256::repeat_byte(0x05);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 5,
        best_hash: peer_best_hash,
        total_difficulty: U256::from(5),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    service.check_follow_gap().await;

    // Stays in Following, but must proactively request the 4 missing headers
    // (ending at the peer's best hash) rather than stalling.
    assert!(matches!(service.state, SyncState::Following),
        "Expected Following to persist, got {:?}", service.state);
    match rx.try_recv().expect("expected a headers request to be sent on a small gap") {
        P2pMessage::RskMessage(RskMessage { sub_message: RskSubMessage::BlockHeadersRequest(req), .. }) => {
            assert_eq!(req.query.hash, peer_best_hash);
            assert_eq!(req.query.count, 4, "should request exactly the gap (5 - 1)");
        }
        other => panic!("Expected BlockHeadersRequest, got {:?}", other),
    }
}

#[tokio::test]
async fn test_handler_forwards_new_block_hashes() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let blocks = vec![
        BlockIdentifier { hash: B256::repeat_byte(0x01), number: 100 },
        BlockIdentifier { hash: B256::repeat_byte(0x02), number: 101 },
    ];
    let msg = P2pMessage::RskMessage(RskMessage::new(
        RskSubMessage::NewBlockHashes(blocks),
    ));

    let resp = handler.handle_message(B512::repeat_byte(0xaa), &msg);
    assert!(resp.is_none());

    match event_rx.try_recv().unwrap() {
        SyncEvent::NewBlockHashes { peer, identifiers } => {
            assert_eq!(peer, B512::repeat_byte(0xaa));
            assert_eq!(identifiers.len(), 2);
            assert_eq!(identifiers[0].number, 100);
            assert_eq!(identifiers[1].number, 101);
        }
        other => panic!("Expected NewBlockHashes event, got {:?}", other),
    }
}

#[tokio::test]
async fn test_headers_response_in_following_mode() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    let peer = B512::repeat_byte(0x01);

    // Simulate receiving a headers response while in Following mode
    service.on_headers_response(peer, vec![b1]).await;

    // State should remain Following
    assert!(matches!(service.state, SyncState::Following),
        "Expected Following after headers response, got {:?}", service.state);

    // Header should be stored
    assert!(store.header(b1_hash).unwrap().is_some());
    assert_eq!(store.head().unwrap(), Some(b1_hash));
}

#[tokio::test]
async fn test_follow_mode_buffers_out_of_order_body() {
    // A follow-mode gap-pull fires several body requests at once; responses can
    // land out of order. A block whose parent is NOT our executed head must be
    // buffered, never executed against the wrong parent state.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Executed head is #100; #101 is missing, #102 arrives first.
    let h100 = dummy_header(100, B256::repeat_byte(0xaa), U256::from(100));
    let h100_hash = h100.hash();
    store.put_header(&h100).unwrap();
    store.set_exec_head(h100_hash, B256::ZERO).unwrap();

    let h101 = dummy_header(101, h100_hash, U256::from(101));
    let h102 = dummy_header(102, h101.hash(), U256::from(102));
    let h102_hash = h102.hash();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    // Body for #102 arrives while #101 is still missing.
    let req_id = 42u64;
    service.pending_follow_bodies.insert(
        req_id,
        (h102_hash, h102, std::time::Instant::now(), B512::repeat_byte(9)),
    );
    service
        .on_body_response(B512::repeat_byte(9), req_id, vec![], vec![], None)
        .await;

    // #102 must remain buffered (parent #101 is not our head), not executed.
    assert!(service.follow_buffer.contains_key(&102),
        "out-of-order block #102 should be buffered, not executed against #100");
    assert_eq!(service.follow_buffer.len(), 1);
    // exec head must not have advanced past #100.
    assert_eq!(store.exec_head().unwrap().map(|(h, _)| h), Some(h100_hash));
    let _ = h101; // #101 intentionally never delivered in this test
}

#[tokio::test]
async fn test_reconcile_recovers_when_the_fork_has_no_canonical_pointer() {
    // The mainnet wedge of 2026-09-18, reduced. The node executed a2(#2) on a
    // branch the network left. It HAS the winning branch's headers -- b2(#2),
    // b3(#3) -- but never adopted them, so canonical_hash(3) is None and the
    // head never rose above #2. Both of reconcile's signals read the canonical
    // index, so both are blind here, and the node re-asks peers for headers
    // after a block they abandoned. It stalled for three days.
    //
    // The height index sees what the canonical pointer cannot: something is
    // stored at #3 and nothing stored at #3 builds on a2.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.update_head(&b1, U256::from(2)).unwrap();

    // Our branch: a2 on b1, canonical and executed.
    let mut a2 = dummy_header(2, b1_hash, U256::from(1));
    a2.extra_data = vec![0xAA].into();
    let a2_hash = a2.hash();
    store.update_head(&a2, U256::from(3)).unwrap();

    // The network's branch: b2(#2) <- b3(#3). Headers only, never adopted --
    // put_header indexes by height without touching the canonical pointers.
    let mut b2 = dummy_header(2, b1_hash, U256::from(5));
    b2.extra_data = vec![0xBB].into();
    let b2_hash = b2.hash();
    store.put_header(&b2).unwrap();
    let b3 = dummy_header(3, b2_hash, U256::from(5));
    let b3_hash = b3.hash();
    store.put_header(&b3).unwrap();

    // The exact conditions that made the node blind.
    assert_eq!(store.canonical_hash(3).unwrap(), None, "no pointer at #3");
    assert_eq!(store.canonical_hash(2).unwrap(), Some(a2_hash), "we hold #2");
    assert!(store.hashes_at_height(3).unwrap().contains(&b3_hash),
        "but the height index knows about b3");

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(b1.state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    store.set_exec_head(a2_hash, a2.state_root).unwrap();

    // First round adopts the stored lineage, giving #3 a canonical pointer.
    service.reconcile_exec_head_with_canonical().await;
    assert_eq!(store.canonical_hash(3).unwrap(), Some(b3_hash),
        "the winning branch should now be canonical at #3");
    assert_eq!(store.canonical_hash(2).unwrap(), Some(b2_hash),
        "and at #2, down to the fork point");

    // Second round sees an ordinary orphan and rolls execution back.
    service.reconcile_exec_head_with_canonical().await;
    let (rolled, _) = store.exec_head().unwrap().unwrap();
    assert_eq!(rolled, b1_hash,
        "exec head should roll back to the fork point b1, got {rolled:?}");
}

#[tokio::test]
async fn test_reconcile_when_the_forks_parent_was_never_downloaded() {
    // The mainnet stall of 2026-09-21, which is NOT the shape of the test
    // above. There the winning sibling was in our store. Here the network's
    // block at our own height was never downloaded: we hold only its child.
    //
    //   #1  b1              common
    //   #2  a2 canonical, executed      x2 (the network's) NOT IN STORE
    //   #3  c3 stored, parent = x2      -- so the lineage walk cannot reach
    //                                      the fork point
    //
    // Adopting c3's lineage sets a pointer at #3 whose parent is not the
    // canonical #2, which is an inconsistent chain. What must happen instead
    // is that execution retreats to a block the network can extend.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.update_head(&b1, U256::from(2)).unwrap();

    let mut a2 = dummy_header(2, b1_hash, U256::from(1));
    a2.extra_data = vec![0xAA].into();
    let a2_hash = a2.hash();
    store.update_head(&a2, U256::from(3)).unwrap();

    // x2 is the network's #2. Deliberately NOT stored -- only its hash exists,
    // as the parent field of a child we did download.
    let mut x2 = dummy_header(2, b1_hash, U256::from(9));
    x2.extra_data = vec![0xCC].into();
    let x2_hash = x2.hash();

    let c3 = dummy_header(3, x2_hash, U256::from(9));
    store.put_header(&c3).unwrap();

    assert!(store.header(x2_hash).unwrap().is_none(), "the fork's #2 is absent");
    assert_eq!(store.canonical_hash(3).unwrap(), None);

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(b1.state_root.as_slice(), &empty.to_message(trie.as_ref()));
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    store.set_exec_head(a2_hash, a2.state_root).unwrap();

    // Drive several rounds, as the live node would.
    for _ in 0..4 {
        service.reconcile_exec_head_with_canonical().await;
    }

    // At or below b1 -- the network's chain builds on b1 and on everything
    // under it, so any of them lets sync re-request #2 and receive x2.
    //
    // This used to assert exactly b1, i.e. a one-block retreat, and that
    // assertion was the 2026-09-24 stall written down as a requirement. The
    // node cannot know the fork is only one block deep: x2 is missing, which
    // is precisely why `fork_point` cannot answer here. It now retreats
    // `BLIND_RETREAT_DEPTH` blocks instead, which on this three-block fixture
    // reaches genesis.
    let (head, _) = store.exec_head().unwrap().unwrap();
    let exec_number = store.header(head).unwrap().unwrap().number;
    assert!(exec_number <= 1,
        "execution must retreat to at least b1 (#1), the deepest block the \
         network's chain also builds on, so sync can re-request #2 and receive \
         x2; stopped at #{exec_number} ({head:?})");

    // Rolling execution back is only half of it, and asserting only that is why
    // this wedge survived a test written for its own shape. `our_head_number()`
    // -- which chooses where the next skeleton is requested from -- reads
    // `store.head()`, not the exec head. While that still names a2, every round
    // asks peers for headers after a block their chain abandoned, stores the
    // dangling children again, and completes without advancing. Mainnet
    // #9,258,222 looped there for 15 minutes with peers answering in 1s.
    let head_number = store
        .head()
        .unwrap()
        .and_then(|h| store.header(h).unwrap())
        .map(|h| h.number);
    assert_eq!(head_number, Some(exec_number),
        "the head pointer must retreat with execution, or the next skeleton is \
         requested from the orphan and the node re-downloads the same dangling \
         headers");
    assert_ne!(store.canonical_hash(2).unwrap(), Some(a2_hash),
        "the canonical pointer must stop naming the orphan at #2, so the height \
         is downloaded again");
}

/// The mainnet stall of 2026-09-24, at the service level.
///
/// A **three-deep** reorg whose replacement branch was never downloaded:
///
/// ```text
///   #30  f30                      the fork point (canonical, executed)
///   #31  a31 ours       x31 the network's -- NOT IN STORE
///   #32  a32 ours       x32                -- NOT IN STORE
///   #33  a33 ours, executed head  x33      -- NOT IN STORE
///   #34                           c34 stored, parent = x33
/// ```
///
/// Retreating to the orphaned head's parent lands on a32 (#32), which is
/// itself on the abandoned branch. The live node then sat there: a32 is
/// stored and builds on a31, so the orphan check saw a successor extending
/// the head and reported everything fine, while no peer would ever extend it.
/// Twelve minutes, until the network moved 25 blocks ahead and skeleton sync
/// took over.
///
/// The retreat must end up at or below the fork.
#[tokio::test]
async fn test_reconcile_retreats_below_a_three_deep_fork() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // A common chain up to the fork point.
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut parent = genesis.hash();
    let mut fork_hash = parent;
    for n in 1..=30u64 {
        let h = dummy_header(n, parent, U256::from(1));
        store.update_head(&h, U256::from(n + 1)).unwrap();
        parent = h.hash();
        fork_hash = parent;
    }

    // Our branch: three blocks above the fork, all executed.
    let mut ours = fork_hash;
    let mut our_tip = None;
    for n in 31..=33u64 {
        let mut h = dummy_header(n, ours, U256::from(1));
        h.extra_data = vec![0xAA].into();
        store.update_head(&h, U256::from(n + 1)).unwrap();
        ours = h.hash();
        our_tip = Some(h);
    }
    let our_tip = our_tip.unwrap();
    let our_tip_hash = our_tip.hash();

    // The network's branch: three blocks the node never downloaded, and one
    // child of the last of them that it did.
    let mut theirs = fork_hash;
    for n in 31..=33u64 {
        let mut h = dummy_header(n, theirs, U256::from(9));
        h.extra_data = vec![0xCC].into();
        theirs = h.hash(); // deliberately NOT stored
    }
    let c34 = dummy_header(34, theirs, U256::from(9));
    store.put_header(&c34).unwrap();
    assert!(store.header(theirs).unwrap().is_none(), "their #33 is absent");

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(our_tip.state_root.as_slice(), &empty.to_message(trie.as_ref()));
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    store.set_exec_head(our_tip_hash, our_tip.state_root).unwrap();

    service.reconcile_exec_head_with_canonical().await;

    let (exec, _) = store.exec_head().unwrap().unwrap();
    let exec_number = store.header(exec).unwrap().unwrap().number;
    assert!(
        exec_number <= 30,
        "the retreat must end at or below the fork (#30); it stopped at #{exec_number}, \
         which is still on the branch the network abandoned"
    );
    assert!(
        exec_number < 32,
        "#32 is the orphaned head's own parent -- retreating there is the 2026-09-24 bug"
    );

    let head_number = store
        .head()
        .unwrap()
        .and_then(|h| store.header(h).unwrap())
        .map(|h| h.number);
    assert_eq!(head_number, Some(exec_number),
        "the head must retreat with execution, or the next skeleton is requested from \
         a block the network abandoned");
    assert_ne!(store.canonical_hash(33).unwrap(), Some(our_tip_hash),
        "the canonical index must stop naming the orphan");
}

/// Both halves of the fast-forward rule, and neither implies the other.
///
/// `was_executed_locally` says this node validated the block;
/// the trie lookup says the state it produced is still held. A block that
/// passes the first and fails the second must still be executed -- there is
/// no state to adopt.
#[test]
fn fast_forward_needs_the_receipts_and_the_state() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let receipts = vec![rustock_core::Receipt {
        post_tx_state: vec![0x01],
        cumulative_gas_used: 21_000,
        gas_used: 21_000,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        logs: vec![],
        status: true,
    }];

    let hardfork = rustock_execution::RskHardforkConfig::mainnet();
    let number = 9_000_000u64;
    let mut header = dummy_header(number, B256::ZERO, U256::from(1));
    header.state_root = B256::repeat_byte(0x5A);
    header.receipts_root =
        rustock_core::ordered_trie_root(&receipts, hardfork.has_unitrie_state_root(number));
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_receipts(hash, &receipts).unwrap();

    let processor = rustock_execution::BlockProcessor::new(hardfork, store.clone());
    assert!(processor.was_executed_locally(hash), "the receipts vouch for this block");

    // State absent: must execute.
    let empty_trie: Arc<dyn rustock_trie::TrieStore> =
        Arc::new(rustock_trie::MemoryTrieStore::new());
    assert!(
        crate::service::fast_forward_state(&processor, &empty_trie, &header, hash).is_none(),
        "no state to adopt, so the block has to be executed"
    );

    // State present: adopt it.
    let with_state: Arc<dyn rustock_trie::TrieStore> =
        Arc::new(rustock_trie::MemoryTrieStore::new());
    let node = rustock_trie::TrieNode::empty();
    with_state.put(header.state_root.as_slice(), &node.to_message(with_state.as_ref()));
    assert!(
        crate::service::fast_forward_state(&processor, &with_state, &header, hash).is_some(),
        "executed locally and the state is still held: adopt it"
    );}

/// `record_execution` has to report a refused marker, because the caller's
/// behaviour depends on it: on `false` the executed head did not move, so the
/// caller must not claim the block executed and must not advance its in-memory
/// state root past a block the node is not on.
///
/// Mainnet produced exactly this at 14:01:15 on 2026-09-24 -- a reorg landed
/// between executing #9,267,779 and recording it, the store refused the
/// marker, and the node logged `Executed block #9267779` on the next line
/// anyway. The coherence check then had to reload the committed root five
/// seconds later.
#[test]
fn record_execution_reports_whether_the_marker_moved() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let canonical = dummy_header(1, genesis.hash(), U256::from(2));
    store.update_head(&canonical, U256::from(3)).unwrap();

    // A sibling at the same height: stored, but not the canonical block there.
    let mut sibling = dummy_header(1, genesis.hash(), U256::from(2));
    sibling.extra_data = vec![0xEE].into();
    let sibling_hash = sibling.hash();
    store.put_header(&sibling).unwrap();
    assert_eq!(store.canonical_hash(1).unwrap(), Some(canonical.hash()));

    assert!(
        crate::service::record_execution(&store, canonical.hash(), canonical.state_root),
        "the canonical block records"
    );
    assert!(
        !crate::service::record_execution(&store, sibling_hash, sibling.state_root),
        "a block that is not canonical at its height must report a refused marker, \
         not a silent failure the caller reads as success"
    );

    // And the marker really did not move to the sibling.
    let (exec, _) = store.exec_head().unwrap().unwrap();
    assert_eq!(exec, canonical.hash(), "the executed head stays on the canonical block");
}

#[tokio::test]
async fn test_reconcile_leaves_a_genuine_tip_alone() {
    // The same code path must not fire at the tip. Nothing is stored above our
    // head, so there is no evidence of a fork and nothing to reconcile --
    // rolling back here would undo good work every time the node caught up.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.update_head(&b1, U256::from(2)).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(genesis.state_root.as_slice(), &empty.to_message(trie.as_ref()));
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    store.set_exec_head(b1_hash, b1.state_root).unwrap();

    service.reconcile_exec_head_with_canonical().await;

    let (head, _) = store.exec_head().unwrap().unwrap();
    assert_eq!(head, b1_hash, "a node at the tip must not roll itself back");
}

#[tokio::test]
async fn test_reconcile_rolls_back_orphaned_exec_head() {
    // A 1-block tip reorg. We executed #2 = a2 (now orphaned). The canonical
    // chain is b2(#2) <- b3(#3). The reorg can't be seen via canonical_hash(2)
    // (sync never re-fetches the block at our own head); it's seen via the
    // canonical child #3, whose parent is b2, not a2. Exec head must roll back
    // one block to the common ancestor #1.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Common chain: genesis(#0) <- b1(#1).
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.update_head(&b1, U256::from(2)).unwrap();

    // Orphan fork: a2 on top of b1 (what we executed).
    let mut a2 = dummy_header(2, b1_hash, U256::from(1));
    a2.extra_data = vec![0xAA].into();
    let a2_hash = a2.hash();
    store.put_header(&a2).unwrap();
    store.put_total_difficulty(a2_hash, U256::from(3)).unwrap();

    // Canonical fork: b2(#2) <- b3(#3), the heavier chain.
    let mut b2 = dummy_header(2, b1_hash, U256::from(5));
    b2.extra_data = vec![0xBB].into();
    let b2_hash = b2.hash();
    store.put_header(&b2).unwrap();
    store.put_total_difficulty(b2_hash, U256::from(7)).unwrap();
    let b3 = dummy_header(3, b2_hash, U256::from(5));
    store.update_head(&b3, U256::from(12)).unwrap(); // canonical chain head

    assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()),
        "b3 should be the canonical child");

    // The rollback reloads the ancestor's state root from the trie store; make
    // b1's state_root resolve to a node there.
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(b1.state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    // We (wrongly) executed the orphan a2; point the exec head there.
    store.set_exec_head(a2_hash, a2.state_root).unwrap();

    service.reconcile_exec_head_with_canonical().await;

    // Exec head must have rolled back to the common ancestor #1.
    let (rolled_hash, _) = store.exec_head().unwrap().unwrap();
    assert_eq!(rolled_hash, b1_hash,
        "exec head should roll back to common ancestor b1, got {:?}", rolled_hash);
    assert_eq!(service.last_body_height_for_test(), 1,
        "body cursor should follow the rolled-back head");
}

#[tokio::test]
async fn test_follow_mode_tick_reconciles_orphaned_exec_head() {
    // Same 1-block tip reorg as above, but the node is in follow mode -- the
    // state it is in whenever a reorg orphans the tip it just executed.
    //
    // Follow mode used to have no way to notice: the reconcile that rolls the
    // executed head back was reachable only from `try_start_sync`, which runs
    // in `Idle`, so the node stood still until the backlog check or the
    // execution watchdog forced it out. A tick in `Following` must reconcile
    // and hand the chain back to the body pipeline, which is the only path
    // that can re-fetch the canonical blocks.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.update_head(&b1, U256::from(2)).unwrap();

    // Orphan fork: a2 on top of b1 -- the block we executed.
    let mut a2 = dummy_header(2, b1_hash, U256::from(1));
    a2.extra_data = vec![0xAA].into();
    let a2_hash = a2.hash();
    store.put_header(&a2).unwrap();
    store.put_total_difficulty(a2_hash, U256::from(3)).unwrap();

    // Canonical fork: b2(#2) <- b3(#3), heavier.
    let mut b2 = dummy_header(2, b1_hash, U256::from(5));
    b2.extra_data = vec![0xBB].into();
    let b2_hash = b2.hash();
    store.put_header(&b2).unwrap();
    store.put_total_difficulty(b2_hash, U256::from(7)).unwrap();
    let b3 = dummy_header(3, b2_hash, U256::from(5));
    store.update_head(&b3, U256::from(12)).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(b1.state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    store.set_exec_head(a2_hash, a2.state_root).unwrap();
    service.state = SyncState::Following;

    service.on_tick().await;

    let (rolled_hash, _) = store.exec_head().unwrap().unwrap();
    assert_eq!(rolled_hash, b1_hash,
        "a tick in follow mode should roll the orphaned exec head back to b1, got {:?}",
        rolled_hash);
    assert!(matches!(service.state, SyncState::Idle),
        "after rolling back, follow mode must hand over to the body pipeline, state is {:?}",
        std::mem::discriminant(&service.state));
    assert_eq!(service.last_body_height_for_test(), 1,
        "body cursor should follow the rolled-back head");
}

#[tokio::test]
async fn test_follow_mode_tick_keeps_following_when_head_is_canonical() {
    // The reconcile now runs on every follow-mode tick, so it must be inert
    // when the executed head is on the canonical chain: no rollback, and no
    // drop out of follow mode.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.update_head(&b1, U256::from(2)).unwrap();
    let b2 = dummy_header(2, b1_hash, U256::from(1));
    let b2_hash = b2.hash();
    store.update_head(&b2, U256::from(3)).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(b1.state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    // Executed head is b1, and the canonical child b2 builds on it.
    store.set_exec_head(b1_hash, b1.state_root).unwrap();
    service.state = SyncState::Following;

    service.on_tick().await;

    assert_eq!(store.exec_head().unwrap().map(|(h, _)| h), Some(b1_hash),
        "a canonical exec head must not be rolled back");
    assert!(matches!(service.state, SyncState::Following),
        "the node should still be following");
    let _ = b2_hash;
}

#[tokio::test]
async fn test_follow_drain_waits_for_background_execution() {
    // A batch executing in the background commits each block as it goes, so
    // `exec_head` advances in the store while `current_state_root` -- the
    // in-memory root follow mode executes against -- still holds the pre-batch
    // state until `poll_execution` reaps the job on a later tick.
    //
    // In that window a follow-mode block whose parent IS the freshly committed
    // head would pass the link check and execute against an older state,
    // computing a wrong state root for a perfectly valid block. Seen on mainnet
    // at #9238768, which re-executed cleanly from the pipeline two minutes
    // later.
    //
    // The drain must stand down while a batch is executing or parked. Staying
    // buffered is the correct behaviour: `follow_buffer` still holds the block.
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.update_head(&b1, U256::from(2)).unwrap();
    // b2 builds directly on the executed head, so only the guard can hold it.
    let b2 = dummy_header(2, b1_hash, U256::from(1));
    let b2_hash = b2.hash();
    store.update_head(&b2, U256::from(3)).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(b1.state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    store.set_exec_head(b1_hash, b1.state_root).unwrap();
    service.state = SyncState::Following;
    service.follow_buffer.insert(2, (b2_hash, b2, vec![], vec![]));

    // A batch is parked waiting to run: the trie state is not ours to use.
    service.park_empty_batch_for_test();
    service.drain_follow_buffer().await;

    assert!(service.follow_buffer.contains_key(&2),
        "the drain must leave the block buffered while a batch is parked; \
         removing it means execution was attempted against a stale root");
    assert_eq!(store.exec_head().unwrap().map(|(h, _)| h), Some(b1_hash),
        "the executed head must not move while a batch owns the trie state");
}

// -- Peer serving tests (BlockHeadersRequest, BlockHashRequest, SkeletonRequest) --

#[tokio::test]
async fn test_serve_block_hash_request() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BlockHashRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHashRequest { id: 42, height: 1 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));

    let resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(resp.is_some(), "Should respond to BlockHashRequest");

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHashResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 42);
            assert_eq!(r.hash, b1_hash);
        } else {
            panic!("Expected BlockHashResponse");
        }
    } else {
        panic!("Expected RskMessage response");
    }
}

#[tokio::test]
async fn test_serve_block_hash_request_unknown_height() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BlockHashRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHashRequest { id: 99, height: 9999 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for unknown height");
}

#[tokio::test]
async fn test_serve_block_hash_request_height_zero() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BlockHashRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHashRequest { id: 1, height: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for height 0 (matches rskj)");
}

#[tokio::test]
async fn test_serve_headers_request_single() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHeadersRequest {
        id: 7,
        query: BlockHeadersQuery { hash: b1_hash, count: 1 },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHeadersResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 7);
            assert_eq!(r.headers.len(), 1);
            assert_eq!(r.headers[0].number, 1);
        } else {
            panic!("Expected BlockHeadersResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_headers_request_chain_walk() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    let b3 = dummy_header(3, b2.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();
    store.put_header(&b3).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    // Request 3 headers starting from b3 (walking backwards)
    let req = BlockHeadersRequest {
        id: 10,
        query: BlockHeadersQuery { hash: b3.hash(), count: 3 },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHeadersResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 10);
            assert_eq!(r.headers.len(), 3);
            // Headers are returned in descending order (b3, b2, b1)
            assert_eq!(r.headers[0].number, 3);
            assert_eq!(r.headers[1].number, 2);
            assert_eq!(r.headers[2].number, 1);
        } else {
            panic!("Expected BlockHeadersResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_headers_request_unknown_hash() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHeadersRequest {
        id: 1,
        query: BlockHeadersQuery {
            hash: B256::repeat_byte(0xFF),
            count: 10,
        },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for unknown hash");
}

#[tokio::test]
async fn test_serve_headers_request_capped_count() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    store.put_header(&b1).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    // Request 1000 headers but we only have 2 (b1 + genesis)
    let req = BlockHeadersRequest {
        id: 1,
        query: BlockHeadersQuery { hash: b1.hash(), count: 1000 },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHeadersResponse(r) = rsk_msg.sub_message {
            // Should only return what's available (capped at MAX_HEADERS_SERVE=192
            // and chain length = 2)
            assert_eq!(r.headers.len(), 2);
        } else {
            panic!("Expected BlockHeadersResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_skeleton_request() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::SkeletonRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a chain of 500 blocks
    let mut prev_hash = B256::ZERO;
    let mut td = U256::ZERO;
    for i in 0..=500u64 {
        let h = dummy_header(i, prev_hash, U256::from(1));
        let hash = h.hash();
        td += h.difficulty;
        store.put_header(&h).unwrap();
        store.put_canonical_hash(i, hash).unwrap();
        store.put_total_difficulty(hash, td).unwrap();
        if i == 500 {
            store.set_head(hash).unwrap();
        }
        prev_hash = hash;
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = SkeletonRequest { id: 55, start_number: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some(), "Should respond to SkeletonRequest");

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::SkeletonResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 55);
            // Should have entries at 0, 192, 384, and best=500
            assert!(r.block_identifiers.len() >= 3);
            assert_eq!(r.block_identifiers[0].number, 0);
            assert_eq!(r.block_identifiers[1].number, 192);
            assert_eq!(r.block_identifiers[2].number, 384);
            // Last entry should be the best block (500)
            let last = r.block_identifiers.last().unwrap();
            assert_eq!(last.number, 500);
        } else {
            panic!("Expected SkeletonResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_skeleton_request_unknown_start() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::SkeletonRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = SkeletonRequest { id: 1, start_number: 99999 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for unknown start number");
}

#[tokio::test]
async fn test_serve_skeleton_request_at_boundary() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::SkeletonRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a chain of exactly 192 blocks (one skeleton step)
    let mut prev_hash = B256::ZERO;
    let mut td = U256::ZERO;
    for i in 0..=192u64 {
        let h = dummy_header(i, prev_hash, U256::from(1));
        let hash = h.hash();
        td += h.difficulty;
        store.put_header(&h).unwrap();
        store.put_canonical_hash(i, hash).unwrap();
        store.put_total_difficulty(hash, td).unwrap();
        if i == 192 {
            store.set_head(hash).unwrap();
        }
        prev_hash = hash;
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = SkeletonRequest { id: 1, start_number: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::SkeletonResponse(r) = rsk_msg.sub_message {
            // Should have entries at 0 and 192
            assert_eq!(r.block_identifiers.len(), 2);
            assert_eq!(r.block_identifiers[0].number, 0);
            assert_eq!(r.block_identifiers[1].number, 192);
        } else {
            panic!("Expected SkeletonResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_requests_dont_interfere_with_event_forwarding() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHashRequest, BlockHeadersResponse as BHResp};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);
    let peer = B512::repeat_byte(0x01);

    // 1. Serve a block hash request (returns response, no event)
    let req = BlockHashRequest { id: 1, height: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));
    let _resp = handler.handle_message(peer, &msg);
    assert!(event_rx.try_recv().is_err(), "Serving should not forward events");

    // 2. Forward a headers response (no response, forwards event)
    let headers_resp = BHResp { id: 2, headers: vec![genesis.clone()] };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersResponse(headers_resp)));
    let resp = handler.handle_message(peer, &msg);
    assert!(resp.is_none(), "Forwarding should not return a response");
    assert!(event_rx.try_recv().is_ok(), "Should forward the event");
}

// -- Reorg tests ----------------------------------------------------------

/// Like dummy_header but with extra_data to differentiate fork branches.
fn fork_header(number: u64, parent: B256, difficulty: U256, branch: u8) -> Header {
    let mut h = dummy_header(number, parent, difficulty);
    h.extra_data = Bytes::from(vec![branch]);
    h
}

#[tokio::test]
async fn test_new_block_hashes_reorg_candidate_triggers_request() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);
    service.state = SyncState::Following;

    // Announce a competing block at height 1 with a different hash
    let competing_hash = B256::repeat_byte(0xCC);
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: competing_hash, number: 1 },
    ]).await;

    // Should have sent a headers request for the competing chain
    let msg = rx.try_recv();
    assert!(msg.is_ok(), "Should request headers for reorg candidate");
}

#[tokio::test]
async fn test_new_block_hashes_same_hash_ignored() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);
    service.state = SyncState::Following;

    // Announce the SAME hash at height 1 — should be ignored
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: b1_hash, number: 1 },
    ]).await;

    assert!(rx.try_recv().is_err(), "Should not request headers for same hash");
}

#[tokio::test]
async fn test_reorg_via_headers_response_higher_td() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build canonical chain: genesis -> 1A -> 2A
    let genesis = dummy_header(0, B256::ZERO, U256::from(10));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(10)).unwrap();

    let a1 = dummy_header(1, genesis_hash, U256::from(10));
    let a2 = dummy_header(2, a1.hash(), U256::from(10));
    store.put_header(&a1).unwrap();
    store.put_canonical_hash(1, a1.hash()).unwrap();
    store.put_total_difficulty(a1.hash(), U256::from(20)).unwrap();
    store.put_header(&a2).unwrap();
    store.put_canonical_hash(2, a2.hash()).unwrap();
    store.put_total_difficulty(a2.hash(), U256::from(30)).unwrap();
    store.update_head(&a2, U256::from(30)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    // Fork from genesis: 1B -> 2B with higher difficulty
    let b1 = fork_header(1, genesis_hash, U256::from(20), 0xBB);
    let b2 = fork_header(2, b1.hash(), U256::from(20), 0xBB);

    // Receive fork headers (descending order, like real peers send)
    let peer = B512::repeat_byte(0x01);
    service.on_headers_response(peer, vec![b2.clone(), b1.clone()]).await;

    // Fork B has TD = 10 + 20 + 20 = 50 vs chain A's TD = 30
    // Head should switch to fork B
    assert_eq!(store.head().unwrap(), Some(b2.hash()));
    assert_eq!(store.canonical_hash(1).unwrap(), Some(b1.hash()));
    assert_eq!(store.canonical_hash(2).unwrap(), Some(b2.hash()));
}

#[tokio::test]
async fn test_no_reorg_via_headers_response_lower_td() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build canonical chain: genesis -> 1A -> 2A (high difficulty)
    let genesis = dummy_header(0, B256::ZERO, U256::from(10));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(10)).unwrap();

    let a1 = dummy_header(1, genesis_hash, U256::from(20));
    let a2 = dummy_header(2, a1.hash(), U256::from(20));
    store.put_header(&a1).unwrap();
    store.put_canonical_hash(1, a1.hash()).unwrap();
    store.put_total_difficulty(a1.hash(), U256::from(30)).unwrap();
    store.put_header(&a2).unwrap();
    store.put_canonical_hash(2, a2.hash()).unwrap();
    store.put_total_difficulty(a2.hash(), U256::from(50)).unwrap();
    store.update_head(&a2, U256::from(50)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    // Fork from genesis: 1B -> 2B with lower difficulty
    let b1 = fork_header(1, genesis_hash, U256::from(5), 0xBB);
    let b2 = fork_header(2, b1.hash(), U256::from(5), 0xBB);

    let peer = B512::repeat_byte(0x01);
    service.on_headers_response(peer, vec![b2.clone(), b1.clone()]).await;

    // Fork B has TD = 10 + 5 + 5 = 20 vs chain A's TD = 50
    // Head should NOT change
    assert_eq!(store.head().unwrap(), Some(a2.hash()));
    assert_eq!(store.canonical_hash(1).unwrap(), Some(a1.hash()));
    assert_eq!(store.canonical_hash(2).unwrap(), Some(a2.hash()));

    // Fork B headers should still be stored
    assert!(store.header(b1.hash()).unwrap().is_some());
    assert!(store.header(b2.hash()).unwrap().is_some());
}

// ========== Body download tests ==========

#[tokio::test]
async fn test_sync_handler_serves_body_request() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BodyRequest;
    use rustock_core::Transaction;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    // Store a body for genesis
    let tx = Transaction {
        nonce: 42,
        gas_price: U256::from(10),
        gas_limit: U256::from(21000),
        to: Bytes::from(vec![0x12; 20]),
        value: U256::from(100),
        input: Bytes::default(),
        v: 27,
        r: U256::from(88),
        s: U256::from(99),
        cached_rlp: None,
    };
    store.put_body(genesis_hash, &[tx], &[]).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BodyRequest { id: 33, hash: genesis_hash };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req)));

    let resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(resp.is_some(), "Should respond to BodyRequest");

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BodyResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 33);
            assert_eq!(r.transactions.len(), 1);
            assert_eq!(r.transactions[0].nonce, 42);
            assert!(r.uncles.is_empty());
        } else {
            panic!("Expected BodyResponse");
        }
    } else {
        panic!("Expected RskMessage response");
    }
}

#[tokio::test]
async fn test_sync_handler_serves_body_request_not_found() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BodyRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BodyRequest { id: 1, hash: B256::repeat_byte(0xFF) };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond when body not found");
}

#[tokio::test]
async fn test_sync_handler_forwards_body_response() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BodyResponse;
    use crate::events::SyncEvent;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let resp = BodyResponse {
        id: 42,
        transactions: vec![],
        uncles: vec![],
        extension: Some(an_extension(1)),
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyResponse(resp)));

    let handler_resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(handler_resp.is_none());

    match event_rx.try_recv().unwrap() {
        SyncEvent::BodyResponse {
            id,
            transactions,
            uncles,
            extension,
            ..
        } => {
            assert_eq!(id, 42);
            assert!(transactions.is_empty());
            assert!(uncles.is_empty());
            assert_eq!(
                extension,
                Some(an_extension(1)),
                "the extension goes on with the body"
            );
        }
        other => panic!("Expected BodyResponse event, got {:?}", other),
    }
}

#[tokio::test]
async fn test_body_download_state_machine() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    // Trigger body download; peer_best=1 means we're at tip after downloading
    service.start_body_downloads(1).await;

    match &service.state {
        SyncState::DownloadingBodies { pending_headers, .. } => {
            assert_eq!(pending_headers.len(), 1);
            assert_eq!(pending_headers[0].0, b1_hash);
        }
        _ => panic!("Expected DownloadingBodies, got {:?}", service.state),
    }

    // Simulate receiving the body response, from the peer it was asked of.
    let pending = if let SyncState::DownloadingBodies { id_index, .. } = &service.state {
        id_index.iter().next().map(|(id, (_, asked))| (*id, *asked))
    } else {
        None
    };
    if let Some((req_id, asked)) = pending {
        service
            .on_body_response(asked, req_id, vec![], vec![], None)
            .await;
    }

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following after all bodies downloaded, got {:?}", service.state);

    // Body should be stored
    let (txs, ommers) = store.body(b1_hash).unwrap().unwrap();
    assert!(txs.is_empty());
    assert!(ommers.is_empty());
}

#[tokio::test]
async fn test_body_download_all_bodies_present_skips() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    // Pre-store the body
    store.put_body(b1_hash, &[], &[]).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.start_body_downloads(1).await;

    // Should skip directly to Following since all bodies are present
    assert!(matches!(service.state, SyncState::Following),
        "Expected Following when all bodies present, got {:?}", service.state);
}

// ========== TxRelay tests ==========

#[tokio::test]
async fn test_tx_relay_filters_duplicates() {
    use crate::tx_relay::TxRelay;
    use rustock_networking::protocol::rsk::{RskMessage, RskSubMessage};
    use rustock_networking::protocol::{P2pHandler, P2pMessage};
    use alloy_primitives::Bytes;
    use tokio::sync::mpsc;

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_a = alloy_primitives::B512::repeat_byte(0x0a);
    let peer_b = alloy_primitives::B512::repeat_byte(0x0b);
    let (_tx_a, _rx_a) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    let (tx_b, mut rx_b) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_a, _tx_a).await;
    peer_store.add_peer(peer_b, tx_b).await;

    let relay = TxRelay::new(peer_store);
    let tx_data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);

    let msg = P2pMessage::RskMessage(RskMessage::new(
        RskSubMessage::Transactions(vec![tx_data.clone()]),
    ));
    relay.handle_message(peer_a, &msg);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(rx_b.try_recv().is_ok(), "peer B should receive the tx");

    relay.handle_message(peer_a, &msg);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx_b.try_recv().is_err(), "duplicate should be suppressed");
}

#[tokio::test]
async fn test_tx_relay_submit_transaction() {
    use crate::tx_relay::TxRelay;
    use alloy_primitives::Bytes;
    use tokio::sync::mpsc;

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let peer_a = alloy_primitives::B512::repeat_byte(0x0a);
    let (tx_a, mut rx_a) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer_a, tx_a).await;

    let relay = TxRelay::new(peer_store);

    // With no pool the relay still reads the transaction, to report the hash
    // rskj gives it: one rskj cannot read is refused, and never broadcast.
    let junk = Bytes::from(vec![0xca, 0xfe]);
    assert!(relay.submit_transaction(junk).await.is_err());
    assert!(
        rx_a.try_recv().is_err(),
        "what cannot be read is not broadcast"
    );

    let tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(1),
        gas_limit: U256::from(21_000),
        to: Bytes::from(vec![0x12; 20]),
        value: U256::from(1),
        input: Bytes::new(),
        v: 27,
        r: U256::from(1),
        s: U256::from(1),
        cached_rlp: None,
    };
    let mut raw = Vec::new();
    alloy_rlp::Encodable::encode(&tx, &mut raw);
    let hash = relay.submit_transaction(Bytes::from(raw)).await.unwrap();

    assert_eq!(hash, tx.tx_hash());
    assert!(rx_a.try_recv().is_ok(), "peer should receive broadcast");
}

// ========== One-batch-ahead execution pipelining ==========
//
// These tests drive the scheduling logic with a controllable execution step
// (set_test_exec) so they exercise finish_batch / poll_execution without a
// real EVM/trie. The mock blocks each invocation until the test releases it,
// letting the test assert state mid-execution (e.g. that the next batch is
// already downloading).

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

/// Controllable stand-in for block execution. Each invocation records the
/// batch's last block number, then blocks until the test releases it with an
/// outcome (all_ok). Reports completion so the test can deterministically wait
/// before reaping the job.
#[derive(Default)]
struct ExecControllerInner {
    /// Last block number of each batch as it *started* executing, in order.
    started: Vec<u64>,
    /// Number of batches that have finished executing.
    completed: usize,
    /// Pending release tokens: each `Some(all_ok)` releases one waiting batch.
    releases: VecDeque<bool>,
    /// The state root each batch was actually handed, in order.
    received: Vec<rustock_trie::TrieNode>,
}

struct ExecController {
    inner: Mutex<ExecControllerInner>,
    cv: Condvar,
}

impl ExecController {
    fn new() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(ExecControllerInner::default()), cv: Condvar::new() })
    }

    /// Build an ExecFn bound to this controller.
    fn exec_fn(self: &Arc<Self>) -> crate::service::ExecFn {
        let this = self.clone();
        Arc::new(move |state_root, blocks_since_flush, pending: Vec<(B256, Header)>| {
            let last = pending.last().map(|(_, h)| h.number).unwrap_or(0);
            let mut guard = this.inner.lock().unwrap();
            guard.started.push(last);
            guard.received.push(state_root.clone());
            this.cv.notify_all();
            // Wait for a release token.
            while guard.releases.is_empty() {
                guard = this.cv.wait(guard).unwrap();
            }
            let all_ok = guard.releases.pop_front().unwrap();
            guard.completed += 1;
            this.cv.notify_all();
            crate::service::ExecOutcome {
                all_ok,
                new_state_root: state_root,
                blocks_since_flush,
            }
        })
    }

    /// Block until at least `n` batches have *started* executing.
    fn wait_started(&self, n: usize) {
        let mut guard = self.inner.lock().unwrap();
        while guard.started.len() < n {
            guard = self.cv.wait(guard).unwrap();
        }
    }

    /// Block until at least `n` batches have *completed*.
    fn wait_completed(&self, n: usize) {
        let mut guard = self.inner.lock().unwrap();
        while guard.completed < n {
            guard = self.cv.wait(guard).unwrap();
        }
    }

    /// Release one waiting batch with the given outcome.
    fn release(&self, all_ok: bool) {
        let mut guard = self.inner.lock().unwrap();
        guard.releases.push_back(all_ok);
        self.cv.notify_all();
    }

    fn started(&self) -> Vec<u64> {
        self.inner.lock().unwrap().started.clone()
    }

    /// The state roots batches were handed, in order.
    fn received(&self) -> Vec<rustock_trie::TrieNode> {
        self.inner.lock().unwrap().received.clone()
    }
}

/// Store genesis + a linear chain of `count` blocks (headers, canonical map,
/// bodies, TD, head) and return the non-genesis headers in ascending order.
fn store_chain(store: &BlockStore, count: u64) -> Vec<Header> {
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    store.set_exec_head(genesis.hash(), B256::ZERO).unwrap();

    let mut prev = genesis.hash();
    let mut td = U256::from(1);
    let mut headers = Vec::new();
    for n in 1..=count {
        let h = dummy_header(n, prev, U256::from(1));
        let hash = h.hash();
        td += U256::from(1);
        store.put_header(&h).unwrap();
        store.put_canonical_hash(n, hash).unwrap();
        store.put_total_difficulty(hash, td).unwrap();
        store.put_body(hash, &[], &[]).unwrap();
        store.update_head(&h, td).unwrap();
        prev = hash;
        headers.push(h);
    }
    headers
}

fn pending_of(headers: &[Header]) -> Vec<(B256, Header)> {
    headers.iter().map(|h| (h.hash(), h.clone())).collect()
}

fn make_service(store: Arc<BlockStore>) -> SyncService {
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    // SyncEvent channel, not a peer channel -- stays unbounded.
    let (_tx, rx) = mpsc::unbounded_channel();
    SyncService::new(manager, peer_store, rx)
}

/// (a) Execution of batch N runs off the event loop, so batch N+1's download
/// begins (next skeleton requested) while N is still executing.
#[tokio::test]
async fn test_pipeline_next_batch_downloads_while_executing() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let headers = store_chain(&store, 6);

    let ctrl = ExecController::new();
    let mut service = make_service(store.clone());
    service.set_test_exec(ctrl.exec_fn());

    // Register a peer so continue_after_bodies can request the next skeleton.
    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;
    service.peer_store_for_test()
        .update_metadata(&peer, rustock_networking::peers::PeerMetadata {
            best_number: 1000,
            total_difficulty: U256::from(1000),
            ..Default::default()
        })
        .await;

    // Batch N = blocks 1..=3, peer_best ahead so we keep syncing.
    let batch_n = pending_of(&headers[0..3]);
    service.finish_batch(&batch_n, 1000).await;

    // N is executing on the blocking thread.
    ctrl.wait_started(1);
    assert_eq!(ctrl.started(), vec![3]);
    assert!(service.is_executing_for_test(), "batch N should be executing");

    // Meanwhile the next skeleton round was requested (download of N+1 started).
    assert!(matches!(service.state, SyncState::DownloadingSkeleton { .. }),
        "next batch download should start concurrently, got {:?}", service.state);
    assert!(rx.try_recv().is_ok(), "a skeleton request should have been sent");

    ctrl.release(true);
    ctrl.wait_completed(1);
}

/// (b) Depth cap: while N executes, completing N+1's download must NOT start
/// N+2's download. N+1 is parked; only after N finishes does N+1 execute.
#[tokio::test]
async fn test_pipeline_depth_capped_at_one_ahead() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let headers = store_chain(&store, 9);

    let ctrl = ExecController::new();
    let mut service = make_service(store.clone());
    service.set_test_exec(ctrl.exec_fn());

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;
    service.peer_store_for_test()
        .update_metadata(&peer, rustock_networking::peers::PeerMetadata {
            best_number: 1000,
            total_difficulty: U256::from(1000),
            ..Default::default()
        })
        .await;

    // N = 1..=3 starts executing.
    service.finish_batch(&pending_of(&headers[0..3]), 1000).await;
    ctrl.wait_started(1);
    assert!(service.is_executing_for_test());

    // N+1 = 4..=6 finishes downloading while N still executes → parked.
    service.finish_batch(&pending_of(&headers[3..6]), 1000).await;

    // The cap: N+1 must NOT have started executing, and no N+2 download begins.
    assert_eq!(ctrl.started(), vec![3], "N+1 must not execute while N runs");
    assert!(service.has_parked_batch_for_test(), "N+1 should be parked");
    assert!(matches!(service.state, SyncState::Idle),
        "downloading must pause at the cap (no N+2), got {:?}", service.state);

    // on_tick while N still executes must not start N+2 either.
    service.on_tick().await;
    assert!(service.has_parked_batch_for_test());
    assert_eq!(ctrl.started(), vec![3]);

    // Now let N finish: poll_execution should start N+1 and resume downloading.
    ctrl.release(true);   // releases N
    ctrl.wait_completed(1);
    service.await_reapable_execution_for_test().await;
    service.on_tick().await; // reaps N, spawns N+1
    ctrl.wait_started(2);
    assert_eq!(ctrl.started(), vec![3, 6], "N+1 executes only after N completes");
    assert!(!service.has_parked_batch_for_test(), "parked batch consumed");

    ctrl.release(true);   // releases N+1
    ctrl.wait_completed(2);
}

/// (c) An execution failure on batch N halts the sync, does not advance the
/// download cursor past the executed head, and drops any parked batch.
#[tokio::test]
async fn test_pipeline_exec_failure_halts() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let headers = store_chain(&store, 6);

    let ctrl = ExecController::new();
    let mut service = make_service(store.clone());
    service.set_test_exec(ctrl.exec_fn());

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;
    service.peer_store_for_test()
        .update_metadata(&peer, rustock_networking::peers::PeerMetadata {
            best_number: 1000,
            total_difficulty: U256::from(1000),
            ..Default::default()
        })
        .await;

    // N = 1..=3 begins executing; N+1 = 4..=6 gets parked.
    service.finish_batch(&pending_of(&headers[0..3]), 1000).await;
    ctrl.wait_started(1);
    service.finish_batch(&pending_of(&headers[3..6]), 1000).await;
    assert!(service.has_parked_batch_for_test());

    // N fails. poll_execution must halt: the parked batch is dropped (it must
    // not execute on the wrong parent state), nothing is left executing, and
    // the download cursor is reset to the executed head (genesis, #0 — nothing
    // was committed by the mock) so the retry re-downloads/re-executes from
    // there rather than skipping past the failed range. (A halt leaves the
    // service Idle; the very next tick may legitimately restart a fresh round,
    // so we assert the durable halt effects, not the transient Idle state.)
    ctrl.release(false);
    ctrl.wait_completed(1);
    service.await_reapable_execution_for_test().await;
    service.on_tick().await;

    assert!(!service.has_parked_batch_for_test(), "parked batch must be dropped on halt");
    assert!(!service.is_executing_for_test(), "no batch should be executing after halt");
    assert_eq!(service.last_body_height_for_test(), 0,
        "download cursor must reset to executed head, not advance past the failure");
}

/// (d) Across a normal two-batch sequence, both batches execute in order and
/// the execution cursor (exec_head) advances to the last block.
#[tokio::test]
async fn test_pipeline_two_batches_advance_exec_head() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let headers = store_chain(&store, 6);

    // Real-ish exec that advances exec_head to the batch's last block so we
    // can assert cursor progress (the scheduling, not EVM, is under test).
    let store_for_exec = store.clone();
    let exec_fn: crate::service::ExecFn = Arc::new(move |state_root, bsf, pending: Vec<(B256, Header)>| {
        if let Some((hash, h)) = pending.last() {
            let _ = store_for_exec.set_exec_head(*hash, B256::from_slice(&[h.number as u8; 32]));
        }
        crate::service::ExecOutcome { all_ok: true, new_state_root: state_root, blocks_since_flush: bsf }
    });

    let mut service = make_service(store.clone());
    service.set_test_exec(exec_fn);

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;
    service.peer_store_for_test()
        .update_metadata(&peer, rustock_networking::peers::PeerMetadata {
            best_number: 1000,
            total_difficulty: U256::from(1000),
            ..Default::default()
        })
        .await;

    // Batch 1 = 1..=3. Executes (synchronously-ish; mock returns immediately).
    service.finish_batch(&pending_of(&headers[0..3]), 1000).await;
    // Reap batch 1.
    drain_executions(&mut service).await;
    assert_eq!(exec_head_number(&store), 3, "exec head should reach #3 after batch 1");

    // Batch 2 = 4..=6.
    service.finish_batch(&pending_of(&headers[3..6]), 1000).await;
    drain_executions(&mut service).await;
    assert_eq!(exec_head_number(&store), 6, "exec head should reach #6 after batch 2");

    assert_eq!(service.last_body_height_for_test(), 6, "download cursor at #6");
}

/// Poll on_tick until no background execution remains in flight.
async fn drain_executions(service: &mut SyncService) {
    // Bounded by wall-clock, not by iteration count. Execution runs on a
    // background task, so a fixed number of polls is really a bet on how much
    // CPU this process gets -- and on a loaded machine that bet loses, failing
    // the test for reasons that have nothing to do with the code under test.
    // Sleeping rather than only yielding also lets the executor actually run.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if !service.is_executing_for_test() && !service.has_parked_batch_for_test() {
            return;
        }
        service.on_tick().await;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    panic!("executions did not drain within 30s");
}

fn exec_head_number(store: &BlockStore) -> u64 {
    store
        .exec_head()
        .ok()
        .flatten()
        .and_then(|(hash, _)| store.header(hash).ok().flatten())
        .map(|h| h.number)
        .unwrap_or(0)
}

// -- Stage 1/2: the coherence invariant and the Φ watchdog ----------------

/// Build a store holding a linked chain 0..=`len`, with `KEY_HEAD` and the
/// executed head both at the top.
fn linked_chain(len: u64) -> (Arc<BlockStore>, tempfile::TempDir, Vec<Header>) {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let mut headers = Vec::new();
    let mut parent = B256::ZERO;
    for n in 0..=len {
        let h = dummy_header(n, parent, U256::from(1));
        store.update_head(&h, U256::from(n + 1)).unwrap();
        parent = h.hash();
        headers.push(h);
    }
    let top = headers.last().unwrap();
    store.set_exec_head(top.hash(), top.state_root).unwrap();
    (store, dir, headers)
}

fn service_over(store: Arc<BlockStore>) -> SyncService {
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    SyncService::new(manager, peer_store, event_rx)
}

/// Stall 6, end to end.
///
/// `ensure_canonical_lineage` writes a canonical entry above `KEY_HEAD`. Every
/// path that looks for work reads `KEY_HEAD`, so the block is held, linked,
/// valid and unreachable — on mainnet, for three hours with no error logged.
/// Head re-verification walks the index up and makes it reachable again.
#[tokio::test]
async fn head_reverification_recovers_a_block_stranded_above_the_head() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();

    // The stranded block: stored, canonical, linked — but KEY_HEAD stays at #10.
    let stranded = dummy_header(11, top.hash(), U256::from(1));
    store.put_header_with_hash(stranded.hash(), &stranded).unwrap();
    store.put_canonical_hash(11, stranded.hash()).unwrap();
    assert_eq!(store.head().unwrap(), Some(top.hash()), "precondition: head is behind");

    // The invariant sees it immediately.
    let violation = crate::invariant::check(&store, None, crate::Scope::Full).unwrap_err();
    assert_eq!(violation.relation(), "I6");

    let mut service = service_over(store.clone());
    service.last_body_height = 10;
    service.reverify_head_lineage(1);

    assert_eq!(store.head().unwrap(), Some(stranded.hash()), "head did not advance");
    assert_eq!(
        crate::invariant::check(&store, None, crate::Scope::Full),
        Ok(()),
        "the store is still incoherent after re-verification"
    );
    assert!(
        service.last_body_height <= 10,
        "the body cursor must not sit above the block we just made reachable"
    );
}

/// The walk up must stop at the first link that does not hold, or it would
/// adopt a chain the node cannot actually follow.
#[tokio::test]
async fn head_reverification_stops_at_a_broken_link() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();

    let good = dummy_header(11, top.hash(), U256::from(1));
    store.put_header_with_hash(good.hash(), &good).unwrap();
    store.put_canonical_hash(11, good.hash()).unwrap();

    // #12 is canonical and held, but builds on something else entirely.
    let detached = dummy_header(12, B256::repeat_byte(0x77), U256::from(1));
    store.put_header_with_hash(detached.hash(), &detached).unwrap();
    store.put_canonical_hash(12, detached.hash()).unwrap();

    let mut service = service_over(store.clone());
    service.reverify_head_lineage(0);

    assert_eq!(store.head().unwrap(), Some(good.hash()), "walked past a broken link");
}

/// A canonical pointer naming a block we never downloaded (stall 5) must not
/// be walked onto.
#[tokio::test]
async fn head_reverification_does_not_adopt_a_block_we_do_not_hold() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();
    store.put_canonical_hash(11, B256::repeat_byte(0xaa)).unwrap();

    let mut service = service_over(store.clone());
    service.reverify_head_lineage(0);

    assert_eq!(store.head().unwrap(), Some(top.hash()), "adopted a block we do not hold");
}

/// With nothing above the head, the escalation retreats — but only into ground
/// execution has not already covered, so the range is downloaded again without
/// leaving execution stranded above the head.
#[tokio::test]
async fn head_reverification_retreats_when_there_is_nothing_above() {
    let (store, _dir, headers) = linked_chain(10);
    // Execution is back at #5, so there is room to retreat into.
    store.set_exec_head(headers[5].hash(), headers[5].state_root).unwrap();

    let mut service = service_over(store.clone());
    service.last_body_height = 10;
    service.reverify_head_lineage(3);

    assert_eq!(store.head().unwrap(), Some(headers[7].hash()), "did not retreat three blocks");
    assert!(service.last_body_height <= 7);
    assert_eq!(
        crate::invariant::check(&store, None, crate::Scope::Full),
        Ok(()),
        "the retreat left the store incoherent"
    );
}

/// A coherent, caught-up node must not be disturbed by either mechanism.
#[tokio::test]
async fn a_healthy_node_is_left_alone() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();

    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));

    let mut service = service_over(store.clone());
    service.verify_coherence();
    service.reverify_head_lineage(0);
    // No peers, so the watchdog has no target and must not accumulate a stall.
    service.check_phi_progress().await;

    assert_eq!(store.head().unwrap(), Some(top.hash()));
    assert_eq!(service.watchdog.level(), 0);
}

/// The second rung of the ladder has to be a different action from the first,
/// or the escalation is decorative.
#[tokio::test]
async fn the_second_escalation_forces_a_connection_point_search() {
    let (store, _dir, _headers) = linked_chain(10);
    let mut service = service_over(store);
    assert!(!service.force_connection_search);

    // Drive the watchdog to its second rung with a gap that never improves.
    let t0 = std::time::Instant::now();
    let window = std::time::Duration::from_secs(1);
    service.watchdog = ProgressWatchdog::new(window);
    let phi = Phi::new(500, 10, 0, None);
    service.watchdog.observe(phi, t0);
    let first = service.watchdog.observe(phi, t0 + std::time::Duration::from_secs(2));
    let second = service.watchdog.observe(phi, t0 + std::time::Duration::from_secs(4));

    assert!(matches!(first, Some(Escalation::RetreatAndReverify { .. })));
    assert!(matches!(second, Some(Escalation::ResearchConnectionPoint)));
}

/// The upward walk must be bounded, so a damaged index cannot turn every
/// escalation into a full-chain sweep.
#[tokio::test]
async fn head_reverification_bounds_the_upward_walk() {
    let (store, _dir, headers) = linked_chain(10);
    let mut parent = headers.last().unwrap().clone();

    // A linked, canonical, held run far longer than the walk limit.
    for n in 11..=(11 + 5_000u64) {
        let h = dummy_header(n, parent.hash(), U256::from(1));
        store.put_header_with_hash(h.hash(), &h).unwrap();
        store.put_canonical_hash(n, h.hash()).unwrap();
        parent = h;
    }

    let mut service = service_over(store.clone());
    service.reverify_head_lineage(0);

    let head = store.header(store.head().unwrap().unwrap()).unwrap().unwrap();
    assert!(head.number > 10, "the walk made no progress at all");
    assert!(
        head.number <= 10 + 4_096,
        "the walk was not bounded: reached #{}",
        head.number
    );
}

/// The live failure from the first deployment, 2026-09-22 20:32.
///
/// `KEY_HEAD` named a non-canonical block at #9,262,401 while the canonical
/// index held #9,262,401 and #9,262,402, linked. The walk up compared the
/// stranded block's parent against `KEY_HEAD`'s hash, saw a mismatch, and
/// retreated — when everything needed to walk forward was present.
#[tokio::test]
async fn head_reverification_reseats_a_head_that_is_not_canonical_then_walks_up() {
    let (store, _dir, headers) = linked_chain(10);
    let canonical_top = headers.last().unwrap();

    // A sibling at #10, held but not canonical, wrongly named as the head.
    let mut sibling = dummy_header(10, headers[9].parent_hash, U256::from(1));
    sibling.timestamp += 7;
    store.put_header_with_hash(sibling.hash(), &sibling).unwrap();
    store.set_head(sibling.hash()).unwrap();

    // And a block above the canonical head: held, canonical, linked.
    let above = dummy_header(11, canonical_top.hash(), U256::from(1));
    store.put_header_with_hash(above.hash(), &above).unwrap();
    store.put_canonical_hash(11, above.hash()).unwrap();

    let mut service = service_over(store.clone());
    service.reverify_head_lineage(1);

    assert_eq!(
        store.head().unwrap(),
        Some(above.hash()),
        "should have re-seated onto the canonical chain and then walked up"
    );
    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));
}

/// A retreat below the executed head takes execution with it, and the store
/// is coherent at every point an observer can read it.
///
/// **These two tests used to assert the opposite**, and that is the history
/// worth keeping. The original rule was "never retreat below the executed
/// head", written after the first deployment broke I4 — head under execution
/// — within fifteen seconds of its first escalation. The rule was a
/// workaround for a real hazard, and it was expressed as
/// `floor = head.number.min(executed.number)`, which is `head.number`
/// whenever the node is caught up. So the watchdog's first escalation did
/// nothing at all for a caught-up node, which is precisely the node that gets
/// stuck in follow mode. Mainnet 2026-09-24 19:00:48: `escalation 1 ->
/// RetreatAndReverify { blocks: 1 }` against head == executed == #9,268,363,
/// and nothing moved (issue #112).
///
/// The hazard it guarded against is real but is not this function's to solve:
/// `Transition::Retreat` stages the new head and the pulled-down execution in
/// **one batch** through `stage_execution_after_reorg`, so there is no moment
/// at which the head sits under execution. What these now pin is that
/// property, rather than the refusal that stood in for it.
#[tokio::test]
async fn head_reverification_retreat_takes_execution_with_it() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();
    // Executed and head both at #10 — the caught-up shape the old floor made
    // into a no-op.
    store.set_exec_head(top.hash(), top.state_root).unwrap();

    let mut service = service_over(store.clone());
    service.reverify_head_lineage(5);

    let cursor = store.cursor().unwrap().unwrap();
    assert_eq!(cursor.validated_head.number, 5, "the retreat must actually happen");
    assert_eq!(
        cursor.executed.number, 5,
        "execution must come down with the head, not be left above it"
    );
    assert_eq!(
        crate::invariant::check(&store, None, crate::Scope::Full),
        Ok(()),
        "I4 -- executed above head -- is what the old rule was protecting; it must still hold"
    );
}

/// The same when execution started further back: a retreat that passes it
/// still brings it down to the new head.
#[tokio::test]
async fn head_reverification_retreat_past_execution_brings_it_down() {
    let (store, _dir, headers) = linked_chain(10);
    store.set_exec_head(headers[8].hash(), headers[8].state_root).unwrap();

    let mut service = service_over(store.clone());
    service.reverify_head_lineage(5);

    let cursor = store.cursor().unwrap().unwrap();
    assert_eq!(cursor.validated_head.number, 5, "retreated the full five blocks");
    assert_eq!(
        cursor.executed.number, 5,
        "execution was above the new head, so it came down to it"
    );
    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));
}

/// I6 is briefly true on essentially every new tip: a header is canonicalised
/// as soon as it links, and the head only advances once the body is executed.
/// Reporting that would put a warning in the log every few seconds and teach
/// whoever reads it to skip the line — which is the failure this subsystem
/// already had, where a stall printed 450 times and was treated as nothing.
#[tokio::test]
async fn a_transient_violation_is_not_reported() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();

    let above = dummy_header(11, top.hash(), U256::from(1));
    store.put_header_with_hash(above.hash(), &above).unwrap();
    store.put_canonical_hash(11, above.hash()).unwrap();

    let mut service = service_over(store.clone());

    // Seen, clock started, nothing said.
    service.verify_coherence();
    assert!(service.violation_since.is_some(), "the violation was not noticed");
    assert!(service.last_violation_log.is_none(), "a transient violation was reported");

    // Still inside the grace period.
    service.verify_coherence();
    assert!(service.last_violation_log.is_none(), "reported before the grace period elapsed");

    // It clears, as an ordinary tip does.
    store.set_head(above.hash()).unwrap();
    service.verify_coherence();
    assert!(service.violation_since.is_none(), "a cleared violation was not forgotten");
}

/// A violation that outlives the grace period is exactly what the node was
/// blind to for three hours, and must be reported.
///
/// Uses I1 rather than I6: I6 now repairs itself on the tick that finds it, so
/// it can no longer persist — which is the point of the fix, and makes it the
/// wrong relation to test persistence with.
#[tokio::test]
async fn a_persistent_violation_is_reported() {
    let (store, _dir, _headers) = linked_chain(10);
    // A hole at the head's own height: inside the delta window, and not one of
    // the relations with an automatic repair.
    store.delete_canonical_hash(10).unwrap();

    let mut service = service_over(store.clone());
    service.verify_coherence();

    // Backdate the first sighting past the grace period.
    let (id, _) = service.violation_since.clone().unwrap();
    service.violation_since =
        Some((id, std::time::Instant::now() - std::time::Duration::from_secs(120)));

    service.verify_coherence();
    assert!(service.last_violation_log.is_some(), "a three-hour-class violation went unreported");
}

/// A different relation breaking restarts the clock rather than inheriting the
/// previous one's age — otherwise one long-standing violation would make every
/// later one look instantly urgent.
#[tokio::test]
async fn a_different_violation_starts_its_own_clock() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();
    let above = dummy_header(11, top.hash(), U256::from(1));
    store.put_header_with_hash(above.hash(), &above).unwrap();
    store.put_canonical_hash(11, above.hash()).unwrap();

    let mut service = service_over(store.clone());
    service.verify_coherence();
    let (first_id, _) = service.violation_since.clone().unwrap();

    // Resolve I6 and break something else inside the checked window. (Height
    // 5 would be invisible here: the delta scope spans the executed head to
    // the validated head, which is the whole point of it being cheap.)
    store.set_head(above.hash()).unwrap();
    store.delete_canonical_hash(11).unwrap();
    service.verify_coherence();

    let (second_id, _) = service.violation_since.clone().unwrap();
    assert_ne!(first_id, second_id, "the new violation inherited the old identity");
    assert!(service.last_violation_log.is_none(), "reported a freshly-seen violation at once");
}

/// The root cause of stall 6, fixed at its source.
///
/// The orphan-adopt path declares a lineage canonical and, before this, left
/// KEY_HEAD behind it — so the blocks it had just adopted were held, linked,
/// valid and unreachable, because every path that looks for work reads
/// KEY_HEAD.
#[tokio::test]
async fn adopting_a_canonical_lineage_moves_the_head_onto_it() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();

    let a = dummy_header(11, top.hash(), U256::from(1));
    let b = dummy_header(12, a.hash(), U256::from(1));
    for h in [&a, &b] {
        store.put_header_with_hash(h.hash(), h).unwrap();
    }
    // There is no longer an API that writes the lineage without the head:
    // `ensure_canonical_lineage` is crate-private to the storage crate, and
    // `Transition::Adopt` is the only public way in. That is the fix — the
    // state stall 6 lived in is not reachable from here any more.
    let proved = rustock_storage::Validated::prove(&store, b.hash()).unwrap();
    assert_eq!(proved.lineage().len(), 2, "both fork blocks should need canonical entries");
    store.apply(&rustock_storage::Transition::Adopt { head: proved }).unwrap();

    assert_eq!(store.head().unwrap(), Some(b.hash()), "the head did not follow the lineage");
    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));
    let _ = top;
}

/// I6 must be repaired the moment it is seen, not three minutes later when the
/// watchdog gets to it. Waiting made the node sawtooth between the tip and
/// three minutes behind it, because adopting an orphaned tip is routine.
#[tokio::test]
async fn an_i6_violation_is_repaired_on_the_tick_that_finds_it() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();

    let above = dummy_header(11, top.hash(), U256::from(1));
    store.put_header_with_hash(above.hash(), &above).unwrap();
    store.put_canonical_hash(11, above.hash()).unwrap();

    let mut service = service_over(store.clone());
    service.verify_coherence();

    assert_eq!(store.head().unwrap(), Some(above.hash()), "I6 was seen but not repaired");
    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));
}

/// The repair must never invent a chain: a canonical pointer to a block we do
/// not hold stays unrepaired and reported rather than adopted.
#[tokio::test]
async fn the_immediate_repair_never_adopts_a_block_we_do_not_hold() {
    let (store, _dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();
    store.put_canonical_hash(11, B256::repeat_byte(0xaa)).unwrap();

    let mut service = service_over(store.clone());
    service.verify_coherence();

    assert_eq!(store.head().unwrap(), Some(top.hash()), "adopted a block we do not hold");
}

/// Mainnet, 2026-09-23 03:34.
///
/// A reorg orphaned the executed head. The rollback targeted the orphan's own
/// **parent**, which is on the branch being abandoned and therefore not
/// canonical either — so `Transition::Executed` refused the write (correctly),
/// the caller gave up, and the executed head stayed on the orphan. I5 broke
/// within a minute, I7 half an hour later once that branch's state root was no
/// longer in the trie, and the node could not execute another block.
///
/// The guard was right. The target was wrong. Rollback must land on the
/// canonical chain.
#[tokio::test]
async fn rolling_execution_back_lands_on_the_canonical_chain_not_the_orphans_parent() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    // Canonical branch: a1, a2 — each with its own state root.
    let mut a1 = dummy_header(1, genesis.hash(), U256::from(2));
    a1.state_root = B256::repeat_byte(0xA1);
    let mut a2 = dummy_header(2, a1.hash(), U256::from(3));
    a2.state_root = B256::repeat_byte(0xA2);

    // Abandoned branch: b1, b2 — b1 is NOT canonical, which is the whole point.
    let mut b1 = dummy_header(1, genesis.hash(), U256::from(2));
    b1.extra_data = vec![0xBB].into();
    b1.state_root = B256::repeat_byte(0xB1);
    let mut b2 = dummy_header(2, b1.hash(), U256::from(3));
    b2.extra_data = vec![0xBB].into();
    b2.state_root = B256::repeat_byte(0xB2);

    for h in [&a1, &a2, &b1, &b2] {
        store.put_header(h).unwrap();
    }
    store.put_canonical_hash(1, a1.hash()).unwrap();
    store.put_canonical_hash(2, a2.hash()).unwrap();
    store.set_head(a2.hash()).unwrap();

    // Execution stranded on the abandoned branch.
    store.set_exec_head(b2.hash(), b2.state_root).unwrap();

    // The trie holds the canonical state, and deliberately NOT b1's — so a
    // rollback onto the orphan's parent could not succeed even if it were
    // allowed.
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(a1.state_root.as_slice(), &empty.to_message(trie.as_ref()));
    trie.put(genesis.state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);

    assert!(
        service.roll_execution_back(rustock_storage::BlockRef::new(2, b2.hash())),
        "rollback gave up; execution is left stranded on the abandoned branch"
    );

    // Genesis, not a1.
    //
    // a1 is canonical at #1 and its state is present, so a search by HEIGHT
    // would choose it -- and that is precisely the 2026-09-23 bug. a1 is a
    // *sibling* of b1, not an ancestor of b2: this node never executed it, so
    // claiming it as the executed head is a lie the next block discovers as a
    // nonce mismatch. The only block on b2's ancestry that is canonical with
    // state is genesis, the fork point.
    let (exec_hash, exec_root) = store.exec_head().unwrap().unwrap();
    assert_eq!(exec_hash, genesis.hash(), "resumed at a block this node never executed");
    assert_eq!(exec_root, genesis.state_root);
    let _ = (&a1, &a2);
    assert_eq!(
        crate::invariant::check(&store, None, crate::Scope::Full),
        Ok(()),
        "the store is incoherent after the rollback"
    );
}

/// A rollback must not land on a canonical block whose state we no longer
/// hold: that is I7, and the node would fail on its next execution instead of
/// at the moment the decision was made.
#[tokio::test]
async fn rolling_execution_back_skips_heights_whose_state_is_gone() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let mut chain = vec![genesis.clone()];
    for n in 1..=5u64 {
        let mut h = dummy_header(n, chain[(n - 1) as usize].hash(), U256::from(n + 1));
        h.state_root = B256::repeat_byte(n as u8);
        store.update_head(&h, U256::from(n + 1)).unwrap();
        chain.push(h);
    }
    store.set_exec_head(chain[5].hash(), chain[5].state_root).unwrap();

    // Only #2's state survives; #3, #4 and #5 have been collected.
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(chain[2].state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);

    assert!(
        service.roll_execution_back(rustock_storage::BlockRef::new(5, chain[5].hash())),
        "rollback gave up with a usable state at #2"
    );

    let (exec_hash, _) = store.exec_head().unwrap().unwrap();
    assert_eq!(exec_hash, chain[2].hash(), "landed on a height whose state is missing");
}

/// With no usable state anywhere in range, the rollback must say so rather
/// than leave execution somewhere it cannot continue from.
#[tokio::test]
async fn rolling_execution_back_reports_when_no_state_survives() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let mut h = dummy_header(1, genesis.hash(), U256::from(2));
    h.state_root = B256::repeat_byte(0x11);
    store.update_head(&h, U256::from(2)).unwrap();
    store.set_exec_head(h.hash(), h.state_root).unwrap();

    // An empty trie: nothing is resumable.
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);

    assert!(
        !service.roll_execution_back(rustock_storage::BlockRef::new(1, h.hash())),
        "claimed success with no state to resume from"
    );
}

/// Mainnet, 2026-09-23 14:10. The executed head was perfectly canonical — so
/// nothing considered it orphaned — but its state root was no longer in the
/// trie store. I7 reported it every 30 seconds and no recovery path responded,
/// and the node sat in a retry loop failing every block with
/// `NonceTooHigh { state: 0 }`: an account read back empty, which is what a
/// missing trie node looks like.
///
/// A violation nothing acts on is a slower version of no violation at all.
#[tokio::test]
async fn a_missing_state_root_at_the_executed_head_is_repaired_not_just_reported() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let mut chain = vec![genesis.clone()];
    for n in 1..=4u64 {
        let mut h = dummy_header(n, chain[(n - 1) as usize].hash(), U256::from(n + 1));
        h.state_root = B256::repeat_byte(0x40 + n as u8);
        store.update_head(&h, U256::from(n + 1)).unwrap();
        chain.push(h);
    }

    // The executed head IS canonical — I5 is satisfied — but its state is gone.
    store.set_exec_head(chain[4].hash(), chain[4].state_root).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(chain[3].state_root.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie.clone(), empty);

    // Precondition: the invariant sees it, and I5 does not.
    let violation = crate::invariant::check(&store, Some(trie.as_ref()), crate::Scope::Full)
        .unwrap_err();
    assert_eq!(violation.relation(), "I7");

    service.verify_coherence();

    let (exec_hash, exec_root) = store.exec_head().unwrap().unwrap();
    assert_eq!(exec_hash, chain[3].hash(), "execution was not rolled back to usable state");
    assert_eq!(exec_root, chain[3].state_root);
    assert_eq!(
        crate::invariant::check(&store, Some(trie.as_ref()), crate::Scope::Full),
        Ok(()),
        "still incoherent after the repair"
    );
}

/// Mainnet, 2026-09-23 17:21. `Transition::Retreat` rolled the *committed*
/// executed head back on its own — that is what it is for — and the service's
/// *in-memory* state root was never told. Follow mode refused to execute in
/// that state, correctly, but refusing is not recovering, and the body
/// pipeline had no such guard: it executed against the stale root and produced
/// `NonceTooLow { tx: 240848, state: 240849 }`.
///
/// Two representations of one fact, and a code path reading the wrong one.
#[tokio::test]
async fn an_in_memory_state_root_ahead_of_the_committed_one_is_reloaded() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let mut chain = vec![genesis.clone()];
    for n in 1..=3u64 {
        let mut h = dummy_header(n, chain[(n - 1) as usize].hash(), U256::from(n + 1));
        h.state_root = B256::repeat_byte(0x20 + n as u8);
        store.update_head(&h, U256::from(n + 1)).unwrap();
        chain.push(h);
    }

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    // Two distinct, resolvable states: #2's and #3's.
    let committed_node = rustock_trie::TrieNode::empty();
    let committed_root = committed_node.compute_hash(trie.as_ref());
    trie.put(committed_root.as_slice(), &committed_node.to_message(trie.as_ref()));

    // The executed head commits #2 with that root.
    store.set_exec_head(chain[2].hash(), committed_root).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );

    // The service starts with a DIFFERENT in-memory root — the shape the
    // retreat leaves behind.
    let mut stale = rustock_trie::TrieNode::empty();
    stale = stale.put(
        &rustock_trie::TrieKeySlice::from_key(&[1u8, 2, 3]),
        &[9u8; 8],
        trie.as_ref(),
    );
    stale.save(trie.as_ref(), true);
    let stale_root = stale.compute_hash(trie.as_ref());
    assert_ne!(stale_root, committed_root, "fixture did not create a divergence");

    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie.clone(), stale);

    service.resync_state_root_with_exec_head();

    let now = service
        .current_state_root
        .as_ref()
        .map(|r| r.compute_hash(trie.as_ref()));
    assert_eq!(
        now,
        Some(committed_root),
        "the in-memory root was not reloaded from the committed one"
    );
}

/// A reorg at the tip must cost a trie read, not two minutes.
///
/// After a reorg the node has executed the block that just stopped being
/// canonical, so its in-memory root is that orphan's state while the
/// committed root is the rolled-back head's. Follow mode used to refuse
/// to execute in that state -- correctly, since executing against the
/// wrong state computes a wrong root for a valid block -- and then wait.
/// The tick-level reconcile would reload the right root and clear the
/// follow buffer, discarding this very block; the one-block backlog that
/// left is exactly what `leave_follow_if_backlog` tolerates as "a tip
/// about to be executed", so nothing moved until the 120-second progress
/// watchdog escalated. Mainnet, under seven hours: 38 `Sync halted`
/// cycles and 69 watchdog escalations.
///
/// `drain_follow_buffer` is called directly rather than through
/// `on_tick`, so the reload can only have come from `process_single_block`
/// -- going through the tick would let the tick-level reconcile do it and
/// the test would pass either way.
#[tokio::test]
async fn follow_mode_reloads_the_committed_root_instead_of_refusing() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let committed = rustock_trie::TrieNode::empty();
    let committed_root = committed.compute_hash(trie.as_ref());
    trie.put(committed_root.as_slice(), &committed.to_message(trie.as_ref()));
    store.set_exec_head(genesis_hash, committed_root).unwrap();

    // The orphan's state: what executing the block a reorg replaced left
    // behind.
    let mut orphan = rustock_trie::TrieNode::empty();
    orphan = orphan.put(
        &rustock_trie::TrieKeySlice::from_key(&[1u8, 1, 1]),
        &[2u8; 8],
        trie.as_ref(),
    );
    orphan.save(trie.as_ref(), true);
    assert_ne!(orphan.compute_hash(trie.as_ref()), committed_root);

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie.clone(), orphan);
    service.state = SyncState::Following;

    // The replacement block, building on the committed head.
    let next = dummy_header(1, genesis_hash, U256::from(1));
    service.follow_buffer.insert(1, (next.hash(), next, vec![], vec![]));

    service.drain_follow_buffer().await;

    assert_eq!(
        service.current_state_root.as_ref().map(|r| r.compute_hash(trie.as_ref())),
        Some(committed_root),
        "the block was refused instead of reloading the committed root, so recovery \
         waits for the 120s watchdog"
    );
}

/// But not when the block does not build on the committed head: that is a
/// different disagreement, and reloading would be executing a block
/// against a state it was never meant to extend.
#[tokio::test]
async fn follow_mode_still_refuses_a_block_that_is_not_the_committed_head_s_child() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let committed = rustock_trie::TrieNode::empty();
    let committed_root = committed.compute_hash(trie.as_ref());
    trie.put(committed_root.as_slice(), &committed.to_message(trie.as_ref()));
    store.set_exec_head(genesis.hash(), committed_root).unwrap();

    let mut orphan = rustock_trie::TrieNode::empty();
    orphan = orphan.put(
        &rustock_trie::TrieKeySlice::from_key(&[3u8, 3, 3]),
        &[4u8; 8],
        trie.as_ref(),
    );
    orphan.save(trie.as_ref(), true);

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie.clone(), orphan.clone());
    service.state = SyncState::Following;

    // Parent is some other block, not the executed head.
    let stranger = dummy_header(1, B256::repeat_byte(0xAB), U256::from(1));
    service.follow_buffer.insert(1, (stranger.hash(), stranger, vec![], vec![]));

    service.drain_follow_buffer().await;

    assert_eq!(
        service.current_state_root.as_ref().map(|r| r.compute_hash(trie.as_ref())),
        Some(orphan.compute_hash(trie.as_ref())),
        "a block that does not extend the committed head must not cause a reload"
    );
}

/// And it must not churn when they already agree.
#[tokio::test]
async fn a_matching_state_root_is_left_alone() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let node = rustock_trie::TrieNode::empty();
    let root = node.compute_hash(trie.as_ref());
    trie.put(root.as_slice(), &node.to_message(trie.as_ref()));
    store.set_exec_head(genesis.hash(), root).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie.clone(), node);

    service.follow_buffer.insert(
        7,
        (B256::repeat_byte(7), dummy_header(7, B256::ZERO, U256::from(1)), vec![], vec![]),
    );
    service.resync_state_root_with_exec_head();

    assert_eq!(service.follow_buffer.len(), 1, "cleared the buffer when nothing was wrong");
}

/// The 2026-09-24 15:41 stall: follow mode holding canonical headers above the
/// executed head with no bodies, and nothing in flight.
///
/// A body request that is never answered is expired by
/// `expire_stale_follow_bodies` and then re-issued by nobody -- the next tip
/// brings its own header, not the lost one. Every other guard measures a
/// difference that is zero here (the downloaded head *equals* the executed
/// head; the missing blocks are above both), so the node idled 13m40s and
/// escaped only when the network carried it past `LONG_SYNC_LIMIT`.
#[tokio::test]
async fn test_follow_mode_re_requests_bodies_it_is_missing() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    // A canonical chain of five blocks, with bodies only for the first.
    let mut parent = genesis.hash();
    let mut headers = Vec::new();
    for n in 1..=5u64 {
        let h = dummy_header(n, parent, U256::from(1));
        store.update_head(&h, U256::from(n + 1)).unwrap();
        if n == 1 {
            store.put_body(h.hash(), &[], &[]).unwrap();
        }
        parent = h.hash();
        headers.push(h);
    }

    // Executed up to #1; #2..#5 are canonical, header-only, no body.
    store.set_exec_head(headers[0].hash(), headers[0].state_root).unwrap();

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let verifier = Arc::new(HeaderVerifier::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    assert!(
        service.pending_follow_bodies.is_empty(),
        "nothing in flight is the precondition"
    );

    service.fill_follow_body_gap().await;

    assert_eq!(
        service.pending_follow_bodies.len(),
        4,
        "the four canonical blocks above the executed head with no body must be requested"
    );
    // And the requests really went to the wire.
    let mut sent = 0;
    while rx.try_recv().is_ok() {
        sent += 1;
    }
    assert_eq!(sent, 4, "one body request per missing block");
}

/// The guard that keeps this from fighting normal operation: a canonical block
/// with no body is the ordinary state between a header arriving and its body
/// answering, and during that moment the request is outstanding.
#[tokio::test]
async fn test_follow_mode_does_not_pile_on_outstanding_requests() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.update_head(&b1, U256::from(2)).unwrap();
    store.set_exec_head(genesis.hash(), genesis.state_root).unwrap();

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let verifier = Arc::new(HeaderVerifier::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    // A request for #1 is already outstanding.
    service
        .pending_follow_bodies
        .insert(1, (b1.hash(), b1.clone(), Instant::now(), peer));

    service.fill_follow_body_gap().await;

    assert_eq!(service.pending_follow_bodies.len(), 1, "no second request");
    assert!(rx.try_recv().is_err(), "nothing sent while one is in flight");
}

/// Nothing to do when the node holds every body it has a canonical entry for,
/// which is the normal case and must stay silent.
#[tokio::test]
async fn test_follow_mode_gap_fill_is_a_no_op_when_bodies_are_present() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut parent = genesis.hash();
    for n in 1..=3u64 {
        let h = dummy_header(n, parent, U256::from(1));
        store.update_head(&h, U256::from(n + 1)).unwrap();
        store.put_body(h.hash(), &[], &[]).unwrap();
        parent = h.hash();
    }
    store.set_exec_head(genesis.hash(), genesis.state_root).unwrap();

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    let verifier = Arc::new(HeaderVerifier::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    service.fill_follow_body_gap().await;

    assert!(service.pending_follow_bodies.is_empty());
    assert!(rx.try_recv().is_err(), "a healthy follow mode must stay quiet");
}

// ===========================================================================
// Stall 8: a same-height sibling reorg leaves execution on the losing fork
// (issue #112, mainnet 2026-09-24 18:57 UTC)
// ===========================================================================

/// A service with a trie store that holds the state of every `dummy_header`.
///
/// Every `dummy_header` carries `state_root: B256::ZERO`, so putting the empty
/// node under that one key makes `has_state` true for all of them — which is
/// what `choose_resume_point` needs in order to pick a resume point at all.
fn service_with_state(store: Arc<BlockStore>) -> SyncService {
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    trie.put(B256::ZERO.as_slice(), &empty.to_message(trie.as_ref()));

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store,
    );
    SyncService::new(manager, peer_store, event_rx).with_block_processor(processor, trie, empty)
}

/// Two siblings at the tip, one canonical and one executed — the exact shape
/// of the 2026-09-24 18:57 stall. Returns `(store, dir, shared parent, loser,
/// winner)`.
fn tip_sibling_fork(len: u64) -> (Arc<BlockStore>, tempfile::TempDir, Header, Header, Header) {
    let (store, dir, headers) = linked_chain(len);
    let parent = headers.last().unwrap().clone();

    // Same parent, same height, distinguished only by `extra_data` — as the
    // mainnet pair were, down to sharing a timestamp and difficulty.
    let mut loser = dummy_header(len + 1, parent.hash(), U256::from(1));
    loser.extra_data = vec![0xAA].into();
    let mut winner = dummy_header(len + 1, parent.hash(), U256::from(1));
    winner.extra_data = vec![0xBB].into();

    store.put_header(&loser).unwrap();
    store.put_header(&winner).unwrap();
    store.put_body(loser.hash(), &[], &[]).unwrap();
    store.put_body(winner.hash(), &[], &[]).unwrap();

    // The canonical index and the head point at the winner; execution is on
    // the loser. Nothing about the *heights* says anything is wrong.
    store.put_canonical_hash(len + 1, winner.hash()).unwrap();
    store.set_head(winner.hash()).unwrap();
    store.set_exec_head(loser.hash(), loser.state_root).unwrap();

    (store, dir, parent, loser, winner)
}

/// Backdate the outstanding violation's clock so the grace period has passed.
fn age_violation(service: &mut SyncService, by: Duration) {
    if let Some((_, first_seen)) = service.violation_since.as_mut() {
        *first_seen -= by;
    }
}

/// I5 is now an actuator, not only a report.
///
/// On mainnet this state stood for twelve minutes while I5 named it correctly
/// every thirty-five seconds. Every other guard in the service compares block
/// *numbers* — downloaded head against executed head, our height against our
/// peers' — and all of those differences are zero when the fork is one block
/// deep at the tip.
#[tokio::test]
async fn a_tip_sibling_reorg_pulls_execution_back_onto_the_canonical_chain() {
    let (store, _dir, parent, loser, winner) = tip_sibling_fork(9);
    let mut service = service_with_state(store.clone());

    // The state that wedged the node: every height agrees, and the executed
    // head is on the wrong chain.
    let cursor = store.cursor().unwrap().unwrap();
    assert_eq!(cursor.validated_head.number, cursor.executed.number, "same height");
    assert_eq!(cursor.executed.hash, loser.hash());
    assert_eq!(store.canonical_hash(10).unwrap(), Some(winner.hash()));

    let violation = crate::invariant::check(&store, None, crate::Scope::Full).unwrap_err();
    assert_eq!(violation.relation(), "I5", "precondition: {violation}");

    // First tick: the violation is seen, the clock starts, nothing moves.
    service.verify_coherence();
    assert_eq!(
        store.exec_head().unwrap().map(|(h, _)| h),
        Some(loser.hash()),
        "execution must not be moved on the first sighting — a sibling can still flip back"
    );

    // Once it has held past the grace, execution comes back to the shared
    // parent, which is the deepest block both chains agree on.
    age_violation(&mut service, EXECUTION_OFF_CHAIN_GRACE + Duration::from_secs(1));
    service.verify_coherence();

    assert_eq!(
        store.exec_head().unwrap().map(|(h, _)| h),
        Some(parent.hash()),
        "execution should have rolled back to the shared parent"
    );
    assert_eq!(
        crate::invariant::check(&store, None, crate::Scope::Full),
        Ok(()),
        "I5 should be cleared by the repair"
    );
    // And the node is set up to move forward again rather than sit still.
    assert_eq!(service.last_body_height, parent.number);

    // The next tick sees a coherent store and forgets the violation, which is
    // what puts `Coherence restored` in the log.
    service.verify_coherence();
    assert!(
        service.violation_since.is_none(),
        "the violation clock should be cleared once the store is coherent again"
    );
}

/// The thrash guard, from the other side: a sibling that wins the fork back
/// before the grace elapses costs nothing.
#[tokio::test]
async fn a_sibling_that_flips_back_within_the_grace_does_not_move_execution() {
    let (store, _dir, _parent, loser, winner) = tip_sibling_fork(9);
    let mut service = service_with_state(store.clone());

    service.verify_coherence();
    assert!(service.violation_since.is_some(), "the clock is running");

    // The network changes its mind: our executed block is canonical again.
    store.put_canonical_hash(10, loser.hash()).unwrap();
    store.set_head(loser.hash()).unwrap();

    // Even well past the grace, there is nothing to repair.
    age_violation(&mut service, EXECUTION_OFF_CHAIN_GRACE * 10);
    service.verify_coherence();

    assert_eq!(
        store.exec_head().unwrap().map(|(h, _)| h),
        Some(loser.hash()),
        "execution must not move for a fork that resolved in our favour"
    );
    assert!(
        service.violation_since.is_none(),
        "a coherent store clears the violation clock"
    );
    let _ = winner;
}

/// A three-deep reorg resolves to the fork point, not to one block down.
///
/// `choose_resume_point` walks the executed head's *own* ancestry, so it
/// cannot stop on a losing block the way a fixed-depth retreat can — the bug
/// #99 was filed for.
#[tokio::test]
async fn a_three_deep_reorg_rolls_execution_to_the_fork_point() {
    let (store, _dir, headers) = linked_chain(9);
    let fork = headers.last().unwrap().clone();
    let mut service = service_with_state(store.clone());

    // Our branch: three blocks, all executed, none of them canonical any more.
    let mut prev = fork.hash();
    let mut ours = Vec::new();
    for n in 10..=12u64 {
        let mut h = dummy_header(n, prev, U256::from(1));
        h.extra_data = vec![0xAA, n as u8].into();
        store.put_header(&h).unwrap();
        prev = h.hash();
        ours.push(h);
    }

    // The network's branch, which won and is canonical from the fork up.
    let mut prev = fork.hash();
    let mut theirs = Vec::new();
    for n in 10..=12u64 {
        let mut h = dummy_header(n, prev, U256::from(2));
        h.extra_data = vec![0xBB, n as u8].into();
        store.put_header(&h).unwrap();
        store.put_canonical_hash(n, h.hash()).unwrap();
        prev = h.hash();
        theirs.push(h);
    }
    store.set_head(theirs.last().unwrap().hash()).unwrap();
    let top_of_ours = ours.last().unwrap();
    store.set_exec_head(top_of_ours.hash(), top_of_ours.state_root).unwrap();

    service.verify_coherence();
    age_violation(&mut service, EXECUTION_OFF_CHAIN_GRACE + Duration::from_secs(1));
    service.verify_coherence();

    assert_eq!(
        store.exec_head().unwrap().map(|(h, _)| h),
        Some(fork.hash()),
        "execution should land on #9, the deepest block both branches share — \
         not on #11, our own parent, which is on the branch being abandoned"
    );
    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));
}

/// The `RetreatAndReverify` bug: the watchdog's first escalation was a no-op
/// for a caught-up node.
///
/// The floor was `head.number.min(executed.number)`, which is `head.number`
/// whenever the node is caught up — so the depth came out zero and nothing
/// moved. A caught-up node in follow mode is precisely the one that gets
/// stuck, so the first rung of the ladder never did anything in the shape it
/// was most needed for. Mainnet logged `escalation 1 -> RetreatAndReverify
/// { blocks: 1 }` against head == executed == #9,268,363 and moved nothing.
#[tokio::test]
async fn the_watchdog_retreat_moves_a_node_that_is_caught_up() {
    let (store, _dir, headers) = linked_chain(10);
    let mut service = service_with_state(store.clone());

    let before = store.cursor().unwrap().unwrap();
    assert_eq!(
        before.validated_head.number, before.executed.number,
        "precondition: caught up, which is what made the old code a no-op"
    );

    service.reverify_head_lineage(1);

    let after = store.cursor().unwrap().unwrap();
    assert_eq!(after.validated_head.number, 9, "the head must actually retreat");
    assert_eq!(
        after.executed.number, 9,
        "and execution must come with it, or the store is left incoherent"
    );
    assert_eq!(after.validated_head.hash, headers[9].hash());
    assert_eq!(
        crate::invariant::check(&store, None, crate::Scope::Full),
        Ok(()),
        "retreating below execution must not leave the head under it"
    );
    assert!(
        service.last_body_height <= 9,
        "the body cursor must follow the retreat, or the range is never re-fetched"
    );
}

/// The retreat still stops at genesis rather than walking off the bottom.
#[tokio::test]
async fn the_watchdog_retreat_stops_at_genesis() {
    let (store, _dir, _headers) = linked_chain(2);
    let mut service = service_with_state(store.clone());

    service.reverify_head_lineage(50);

    let after = store.cursor().unwrap().unwrap();
    assert_eq!(after.validated_head.number, 0, "clamped to genesis");
    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));
}

/// A failed snapshot sync stays recoverable through the watchdog's retreat.
///
/// Mainnet, 6 November 2026. A light node's snapshot sync gave up after five
/// attempts, leaving genesis, headers from #9,372,260 up that link to nothing
/// below them, and no executed head. The watchdog's first escalation retreated
/// the head one block, and the retreat recorded #9,388,799 as executed: a
/// block nothing had executed, with no state under it. From then on every
/// check found execution stranded, and a restart could not help, because
/// snapshot sync starts only on a node that has executed nothing; it declined,
/// saying ordinary sync was the shorter path. Only a wiped data folder got the
/// node going again.
#[tokio::test]
async fn a_retreat_after_a_failed_snapshot_sync_leaves_it_free_to_try_again() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    // The checkpoint's window: linked to itself and to nothing below, its
    // state roots nowhere in the trie store.
    let mut parent = B256::repeat_byte(0x9a);
    for n in 1_000..=1_010u64 {
        let mut h = dummy_header(n, parent, U256::from(1));
        h.state_root = B256::repeat_byte(0x5a);
        store.update_head(&h, U256::from(n)).unwrap();
        parent = h.hash();
    }
    assert_eq!(store.exec_head().unwrap(), None, "precondition: nothing executed");

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let mut service = service_over(store.clone()).with_trie_store_for_test(trie);

    // The watchdog's first escalation.
    service.reverify_head_lineage(1);

    let head = store.header(store.head().unwrap().unwrap()).unwrap().unwrap();
    assert_eq!(head.number, 1_009, "precondition: the retreat happened");
    assert_eq!(
        store.exec_head().unwrap(),
        None,
        "the retreat recorded as executed a block nothing executed"
    );

    // And the node can still do the one thing that gets it going: try the
    // snapshot again.
    service.start_snap_sync(crate::snap::SnapConfig::default(), Arc::new(HeaderVerifier::new()));
    assert!(
        service.snap_phase().is_some(),
        "snapshot sync declined to start on a node that has executed nothing"
    );
}

/// What a node holds when its snapshot sync failed the final check: a linked
/// chain, nothing executed, and in the trie store the root of the checkpoint's
/// state -- downloaded, never verified, perhaps full of holes. No other block's
/// state is there.
fn chain_with_an_unverified_state(
    len: u64,
    checkpoint: u64,
) -> (Arc<BlockStore>, tempfile::TempDir, Vec<Header>, Arc<dyn rustock_trie::TrieStore>) {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let unverified = B256::repeat_byte(0x77);
    let mut headers = Vec::new();
    let mut parent = B256::ZERO;
    for n in 0..=len {
        let mut h = dummy_header(n, parent, U256::from(1));
        h.state_root = if n == checkpoint { unverified } else { B256::repeat_byte(0x5a) };
        store.update_head(&h, U256::from(n + 1)).unwrap();
        parent = h.hash();
        headers.push(h);
    }
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let root = rustock_trie::TrieNode::empty();
    trie.put(unverified.as_slice(), &root.to_message(trie.as_ref()));
    assert_eq!(store.exec_head().unwrap(), None, "precondition: nothing executed");
    (store, dir, headers, trie)
}

/// A retreat on a node that has executed nothing rolls nothing back.
///
/// Rolling back from the head that stands in for execution walks down to the
/// first block whose state root the trie store holds, and records it as
/// executed. After a snapshot sync that failed its check, that block is the
/// checkpoint, and its state is the one the check refused.
#[tokio::test]
async fn a_retreat_does_not_take_up_a_state_that_failed_its_check() {
    let (store, _dir, headers, trie) = chain_with_an_unverified_state(10, 5);
    let mut service = service_over(store.clone()).with_trie_store_for_test(trie);

    service.reverify_head_lineage(1);

    assert_eq!(store.head().unwrap(), Some(headers[9].hash()), "precondition: the retreat happened");
    assert_eq!(
        store.exec_head().unwrap(),
        None,
        "execution was recorded at a state nothing verified"
    );
}

/// With nothing executed, I5 is the head off the chain, and gets the head's
/// repair rather than execution's.
///
/// The check reads execution as the head when nothing is recorded, so a head
/// that is not canonical reads as execution off the chain. Rolling execution
/// back from there walks down to the unverified state, as above; re-seating
/// the head is what the state calls for.
#[tokio::test]
async fn with_nothing_executed_a_head_off_the_chain_is_reseated_not_rolled_back() {
    let (store, _dir, headers, trie) = chain_with_an_unverified_state(10, 5);
    // The head names a sibling of #10, held but not canonical.
    let mut sibling = dummy_header(10, headers[9].hash(), U256::from(1));
    sibling.extra_data = vec![0xEE].into();
    store.put_header(&sibling).unwrap();
    store.set_head(sibling.hash()).unwrap();
    let violation = crate::invariant::check(&store, None, crate::Scope::Full).unwrap_err();
    assert_eq!(violation.relation(), "I5", "precondition: {violation}");

    let mut service = service_over(store.clone()).with_trie_store_for_test(trie);
    service.verify_coherence();
    age_violation(&mut service, EXECUTION_OFF_CHAIN_GRACE + Duration::from_secs(1));
    service.verify_coherence();

    assert_eq!(
        store.exec_head().unwrap(),
        None,
        "execution was recorded at a state nothing verified"
    );
    assert_eq!(
        store.head().unwrap(),
        Some(headers[10].hash()),
        "the head should be back on the canonical chain"
    );
    assert_eq!(crate::invariant::check(&store, None, crate::Scope::Full), Ok(()));
}

// ── snapshot sync owns the peer set while it runs (#185) ─────────────────────

/// **Header sync first, then state — never the reverse.**
///
/// A snapshot is only trustworthy because the header walk vouches for the
/// checkpoint it hangs from, so the walk must own the peer set until it is
/// done. Measured before this was enforced: on a single peer the ordinary
/// sync's header requests were served, the snapshot session's queued behind
/// them and timed out 12,094 times, and not one state chunk was requested.
#[tokio::test]
async fn opening_a_snapshot_session_stands_the_ordinary_sync_down() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let mut service = make_service(store.clone()).with_trie_store_for_test(Arc::new(
        rustock_trie::MemoryTrieStore::new(),
    ));
    // A round already in flight, as there would be if a snapshot session were
    // opened after ordinary sync had started.
    service.state = SyncState::DownloadingBodies {
        peer_best: 100,
        pending_headers: vec![(genesis.hash(), genesis.clone())],
        next_request: 1,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    service.start_snap_sync(
        crate::snap::SnapConfig { client_enabled: true, ..Default::default() },
        Arc::new(HeaderVerifier::new()),
    );

    assert!(service.is_suspended_for_snap_for_test(), "the session must take the peer set");
    assert!(
        matches!(service.state, SyncState::Idle),
        "an in-flight round must be abandoned, not parked: its answers would be \
         matched against a state machine that is no longer driving"
    );

    // A tick must drive the snapshot session and nothing else.
    service.on_tick().await;
    assert!(
        matches!(service.state, SyncState::Idle),
        "the ordinary state machine must not start a round while suspended"
    );
}

/// The peer set comes back when the session ends, whichever way it ends.
#[tokio::test]
async fn the_ordinary_sync_resumes_when_the_snapshot_session_gives_up() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let mut service = make_service(store.clone()).with_trie_store_for_test(Arc::new(
        rustock_trie::MemoryTrieStore::new(),
    ));
    service.start_snap_sync(
        crate::snap::SnapConfig { client_enabled: true, ..Default::default() },
        Arc::new(HeaderVerifier::new()),
    );
    assert!(service.is_suspended_for_snap_for_test());

    // A session that vanishes by any route other than the handover must not
    // leave the node suspended: that failure is silent and permanent, so the
    // tick carries a guard for it.
    service.fail_snap_for_test();
    service.on_tick().await;

    assert!(
        !service.is_suspended_for_snap_for_test(),
        "a session that gives up must return the peer set, or the node never syncs again"
    );
}

/// A node with genesis and nothing executed, a snapshot sync started on it.
fn snapshot_syncing_node() -> (SyncService, Arc<BlockStore>, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut service = make_service(store.clone()).with_trie_store_for_test(Arc::new(
        rustock_trie::MemoryTrieStore::new(),
    ));
    service.start_snap_sync(
        crate::snap::SnapConfig { client_enabled: true, ..Default::default() },
        Arc::new(HeaderVerifier::new()),
    );
    assert!(service.snap_phase().is_some(), "precondition: a session is running");
    (service, store, dir)
}

/// What failed every attempt on mainnet on 6 November 2026.
fn state_not_whole() -> crate::snap::session::SnapFailure {
    crate::snap::session::SnapFailure::IncompleteState("trie node 0x751b is not in the store".into())
}

/// Fail sessions until no further one opens, and say how many that took.
async fn fail_until_spent(service: &mut SyncService) -> u32 {
    let mut failed = 0;
    while service.snap_phase().is_some() {
        assert!(failed <= crate::service::MAX_SNAP_ATTEMPTS, "sessions kept opening");
        service.fail_snap_session_for_test(state_not_whole()).await;
        failed += 1;
    }
    failed
}

/// Make the waiting try due now.
fn make_the_next_try_due(service: &mut SyncService) {
    let (at, _) = service.snap_retry_for_test();
    assert!(at.is_some(), "no try is waiting");
    *at = Some(Instant::now());
}

/// A node that has executed nothing waits and tries snapshot sync again when
/// its attempts are spent, rather than handing over to an ordinary sync that
/// has nothing to execute from.
///
/// Mainnet, 6 November 2026: after five failed attempts a light node handed
/// over, ordinary sync tried three times to execute #9,372,260 on genesis,
/// said "this node holds headers it has no way to execute", and stopped for
/// good: nothing more would happen until someone restarted it.
#[tokio::test]
async fn a_node_that_executed_nothing_tries_snapshot_sync_again_rather_than_halting() {
    use crate::service::{MAX_SNAP_ATTEMPTS, SNAP_RETRY_FIRST};
    use crate::snap::session::Phase;

    let (mut service, _store, _dir) = snapshot_syncing_node();
    let gate = service.prune_gate();

    assert_eq!(fail_until_spent(&mut service).await, MAX_SNAP_ATTEMPTS);

    // Spent: no session, still standing aside, and another try set.
    assert!(
        service.is_suspended_for_snap_for_test(),
        "handed over to an ordinary sync with nothing to execute from"
    );
    assert!(
        !gate.load(std::sync::atomic::Ordering::Relaxed),
        "pruning was released while the node still waits on a snapshot"
    );
    let (at, next_wait) = service.snap_retry_for_test();
    assert!(at.is_some(), "no further try was set");
    assert_eq!(next_wait, SNAP_RETRY_FIRST * 2, "the wait after this one doubles");

    // A tick before it is due changes nothing. In particular the guard for a
    // node suspended with no session must not take the wait for one.
    service.on_tick().await;
    assert_eq!(service.snap_phase(), None);
    assert!(service.is_suspended_for_snap_for_test(), "the wait was taken for a lost session");

    // Once due, a session opens, and it is a single attempt.
    make_the_next_try_due(&mut service);
    service.on_tick().await;
    assert_eq!(service.snap_phase(), Some(Phase::AwaitingStatus), "the try that was set did not happen");
    assert_eq!(fail_until_spent(&mut service).await, 1, "a later round is one attempt");
    let (at, next_wait) = service.snap_retry_for_test();
    assert!(at.is_some(), "no try was set after the second round");
    assert_eq!(next_wait, SNAP_RETRY_FIRST * 4);
    assert!(service.is_suspended_for_snap_for_test());
}

/// The wait between tries stops growing at a day, so a node keeps trying.
#[tokio::test]
async fn the_wait_between_snapshot_tries_stops_growing_at_a_day() {
    let (mut service, _store, _dir) = snapshot_syncing_node();
    fail_until_spent(&mut service).await;
    for _ in 0..12 {
        make_the_next_try_due(&mut service);
        service.on_tick().await;
        fail_until_spent(&mut service).await;
    }
    let (at, next_wait) = service.snap_retry_for_test();
    assert!(at.is_some(), "the node stopped trying");
    assert_eq!(next_wait, crate::service::SNAP_RETRY_MAX);
}

/// A new try asks every peer again: one set aside may have been set aside
/// through no fault of its own -- the attempts on mainnet failed on a bug in
/// this client -- and it may be the only one serving snapshots.
#[tokio::test]
async fn a_new_snapshot_try_asks_every_peer_again() {
    let (mut service, _store, _dir) = snapshot_syncing_node();
    fail_until_spent(&mut service).await;
    service.snap_avoid_for_test().insert(B512::repeat_byte(7));

    make_the_next_try_due(&mut service);
    service.on_tick().await;

    assert!(service.snap_phase().is_some(), "precondition: the try happened");
    assert!(service.snap_avoid_for_test().is_empty(), "a peer is still set aside");
}

/// A node that has executed something hands over to ordinary sync as before:
/// executing the blocks it is missing is its way forward.
#[tokio::test]
async fn a_node_that_has_executed_still_hands_over_to_ordinary_sync() {
    let (mut service, store, _dir) = snapshot_syncing_node();
    // Execution recorded beyond genesis, as though it had happened meanwhile.
    let one = dummy_header(1, store.head().unwrap().unwrap(), U256::from(1));
    store.update_head(&one, U256::from(2)).unwrap();
    store.set_exec_head(one.hash(), one.state_root).unwrap();

    assert_eq!(fail_until_spent(&mut service).await, crate::service::MAX_SNAP_ATTEMPTS);

    assert!(!service.is_suspended_for_snap_for_test(), "the peer set was not handed back");
    assert!(service.snap_retry_for_test().0.is_none(), "a try was set for a node with a way forward");
}

/// Execution recorded at genesis is execution of nothing, as `start_snap_sync`
/// already reads it: such a node waits and tries again too.
#[tokio::test]
async fn a_node_executed_only_to_genesis_tries_snapshot_sync_again_too() {
    let (mut service, store, _dir) = snapshot_syncing_node();
    let genesis = store.head().unwrap().unwrap();
    store.set_exec_head(genesis, B256::ZERO).unwrap();

    fail_until_spent(&mut service).await;

    assert!(service.is_suspended_for_snap_for_test(), "handed over with nothing to execute from");
    assert!(service.snap_retry_for_test().0.is_some(), "no further try was set");
}

// ── serving headers: the canonical fast path (#185) ──────────────────────────

/// **The fast path must return exactly what the walk returns.** It is an
/// optimisation, not a different answer; a peer cannot tell which path served
/// it and must not need to.
#[tokio::test]
async fn the_canonical_fast_path_matches_the_parent_walk_header_for_header() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let mut parent = B256::ZERO;
    let mut hashes = Vec::new();
    for number in 0..=64u64 {
        let h = dummy_header(number, parent, U256::from(1));
        let hash = h.hash();
        store.put_header(&h).unwrap();
        store.put_canonical_hash(number, hash).unwrap();
        hashes.push(hash);
        parent = hash;
    }

    let top = store.header(hashes[64]).unwrap().unwrap();
    let fast = crate::handler::canonical_run(&store, &top, 32).expect("range is canonical");
    let slow = crate::handler::walk_by_parent(&store, top.clone(), 32);

    assert_eq!(fast.len(), 32);
    assert_eq!(
        fast.iter().map(|h| h.hash()).collect::<Vec<_>>(),
        slow.iter().map(|h| h.hash()).collect::<Vec<_>>(),
        "the two paths must agree exactly, newest first"
    );
    assert_eq!(fast[0].number, 64, "newest first");
    assert_eq!(fast[31].number, 33);
}

/// **A non-canonical start must decline the fast path.** The request names a
/// hash, not a height; answering with canonical headers would serve a chain
/// the peer did not ask for and cannot link to.
#[tokio::test]
async fn a_sibling_start_declines_the_fast_path() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let mut parent = B256::ZERO;
    for number in 0..=32u64 {
        let h = dummy_header(number, parent, U256::from(1));
        store.put_header(&h).unwrap();
        store.put_canonical_hash(number, h.hash()).unwrap();
        parent = h.hash();
    }

    // A sibling at the tip: stored, linked to the same parent, never canonical.
    let canonical_parent = store.canonical_hash(31).unwrap().unwrap();
    let sibling = Header {
        timestamp: 999_999,
        ..dummy_header(32, canonical_parent, U256::from(1))
    };
    store.put_header(&sibling).unwrap();

    assert!(
        crate::handler::canonical_run(&store, &sibling, 16).is_none(),
        "a hash that is not canonical at its height must fall back to the walk"
    );
    // …and the walk still answers it, from the sibling.
    let walked = crate::handler::walk_by_parent(&store, sibling.clone(), 16);
    assert_eq!(walked[0].hash(), sibling.hash());
    assert_eq!(walked.len(), 16);
}

/// **A gap in the canonical index must not become a gap in what is served.**
/// The index can be mid-repair; the link check is what catches it.
#[tokio::test]
async fn a_broken_canonical_index_declines_the_fast_path() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let mut parent = B256::ZERO;
    for number in 0..=64u64 {
        let h = dummy_header(number, parent, U256::from(1));
        store.put_header(&h).unwrap();
        store.put_canonical_hash(number, h.hash()).unwrap();
        parent = h.hash();
    }

    // Point one height at an unrelated block: the hashes still all resolve,
    // and every header is present, so only the link check can catch this.
    let stray = dummy_header(50, B256::repeat_byte(0xEE), U256::from(1));
    store.put_header(&stray).unwrap();
    store.put_canonical_hash(50, stray.hash()).unwrap();

    let top = store.header(store.canonical_hash(64).unwrap().unwrap()).unwrap().unwrap();
    assert!(
        crate::handler::canonical_run(&store, &top, 32).is_none(),
        "a range whose headers do not link must fall back rather than serve a broken chain"
    );
}

// -- Fork discovery ------------------------------------------------------
//
// The scenario these cover is the one that stalled a mainnet node for an
// hour: this node sits on a chain the network has left behind, so every
// header a peer sends names a parent we do not hold. Storing those headers
// unverified is how an unauthenticated header used to reach the store;
// refusing them without doing anything else leaves no way back, because the
// node only ever asks for blocks above its own head and so never requests the
// block where the two chains part.

/// Builds a service whose head is on a chain of its own.
fn service_on_a_minority_chain(
    dir: &tempfile::TempDir,
) -> (SyncService, Arc<SyncManager>, B512, mpsc::UnboundedSender<SyncEvent>) {
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // A short private chain: genesis plus a few blocks only we have.
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut parent = genesis.hash();
    let mut td = U256::from(1);
    for n in 1..=8u64 {
        let h = dummy_header(n, parent, U256::from(10));
        td += U256::from(10);
        store.update_head(&h, td).unwrap();
        parent = h.hash();
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager.clone(), peer_store, event_rx);
    service.state = SyncState::Following;
    (service, manager, B512::repeat_byte(0x07), event_tx)
}

/// Headers built on a chain we do not have, which is what a node on a
/// minority fork receives from every peer.
fn headers_from_another_chain(count: u64) -> Vec<Header> {
    let mut out = Vec::new();
    let mut parent = B256::repeat_byte(0xee); // a block we do not hold
    for n in 0..count {
        let h = dummy_header(900 + n, parent, U256::from(1_000_000));
        parent = h.hash();
        out.push(h);
    }
    out
}

/// The recovery path. Enough unlinkable headers, settled, and the node goes
/// looking for where the two chains diverge — which is the only way back.
#[tokio::test]
async fn a_node_fed_unlinkable_headers_searches_for_the_fork() {
    let dir = tempdir().unwrap();
    let (mut service, manager, peer, _tx) = service_on_a_minority_chain(&dir);

    service.on_headers_response(peer, headers_from_another_chain(6)).await;
    assert!(
        matches!(service.state, SyncState::Following),
        "not before the evidence has settled, got {:?}", service.state
    );

    // Let the settle window pass, then one more batch to reconsider.
    manager.backdate_unlinked(&peer, Duration::from_secs(30));
    service.on_headers_response(peer, headers_from_another_chain(6)).await;

    match &service.state {
        SyncState::FindingConnectionPoint { peer: p, gallop, end, .. } => {
            assert_eq!(*p, peer, "the search must be against the peer that showed us");
            assert_eq!(*gallop, Some(1), "and must start by probing near the head");
            assert_eq!(*end, 8, "galloping down from our own head");
        }
        other => panic!("expected a connection-point search, got {other:?}"),
    }
}

/// And it does not go looking on one stray header, which would let any peer
/// interrupt a healthy node at will.
#[tokio::test]
async fn a_single_stray_header_does_not_start_a_search() {
    let dir = tempdir().unwrap();
    let (mut service, manager, peer, _tx) = service_on_a_minority_chain(&dir);

    service.on_headers_response(peer, headers_from_another_chain(1)).await;
    manager.backdate_unlinked(&peer, Duration::from_secs(300));
    service.on_headers_response(peer, headers_from_another_chain(1)).await;

    assert!(
        matches!(service.state, SyncState::Following),
        "one header is not evidence of a fork, got {:?}", service.state
    );
}

/// None of this may put an unverifiable header into the store, whatever it
/// claims about its own difficulty.
#[tokio::test]
async fn fork_discovery_stores_nothing_unverified() {
    let dir = tempdir().unwrap();
    let (mut service, manager, peer, _tx) = service_on_a_minority_chain(&dir);

    let head_before = manager.store.head().unwrap();
    let foreign = headers_from_another_chain(6);
    service.on_headers_response(peer, foreign.clone()).await;
    manager.backdate_unlinked(&peer, Duration::from_secs(30));
    service.on_headers_response(peer, foreign.clone()).await;

    for h in &foreign {
        assert!(
            manager.store.header(h.hash()).unwrap().is_none(),
            "#{} reached the store without anything to verify it against", h.number
        );
        assert_eq!(manager.store.total_difficulty(h.hash()).unwrap(), None);
    }
    assert_eq!(
        manager.store.head().unwrap(), head_before,
        "the head must not move on headers nobody could verify"
    );
}

/// A sync already in progress is doing this work; a peer sending junk must
/// not be able to derail it.
#[tokio::test]
async fn unlinked_headers_do_not_interrupt_a_sync_in_progress() {
    let dir = tempdir().unwrap();
    let (mut service, manager, peer, _tx) = service_on_a_minority_chain(&dir);

    let busy = SyncState::DownloadingSkeleton {
        peer: B512::repeat_byte(0x02),
        peer_best: 9_000_000,
        connection_point: 8,
    };
    service.state = busy;

    let foreign = headers_from_another_chain(20);
    service.on_headers_response(peer, foreign.clone()).await;
    manager.backdate_unlinked(&peer, Duration::from_secs(300));
    service.on_headers_response(peer, foreign).await;

    assert!(
        matches!(service.state, SyncState::DownloadingSkeleton { .. }),
        "a sync in progress was derailed: {:?}", service.state
    );
}

// -- Chunk identification ------------------------------------------------

/// A skeleton entry for a header, as the peer would have offered it.
fn entry_for(h: &Header) -> BlockIdentifier {
    BlockIdentifier { hash: h.hash(), number: h.number }
}

/// A contiguous run of headers ending at `top`, newest last.
fn run_of(top: u64, len: u64) -> Vec<Header> {
    let mut out = Vec::new();
    let mut parent = B256::repeat_byte(0x11);
    for n in (top + 1 - len)..=top {
        let h = dummy_header(n, parent, U256::from(1));
        parent = h.hash();
        out.push(h);
    }
    out
}

/// The honest case, which matters most: a chunk that really is the answer to
/// the question is still accepted. A matcher that rejects these stalls the
/// download.
#[test]
fn an_honest_chunk_is_identified() {
    let chunk = run_of(500, 20);
    let skeleton = vec![
        entry_for(&run_of(300, 1)[0]),
        entry_for(chunk.last().unwrap()),
        entry_for(&run_of(700, 1)[0]),
    ];
    assert_eq!(
        crate::service::identify_chunk_by_content(&chunk, &skeleton),
        Some(1)
    );
}

/// Order is not something a peer has to get right for us: the matcher works
/// off the highest and lowest numbers, not the position in the vector.
#[test]
fn a_descending_chunk_is_still_identified() {
    let mut chunk = run_of(500, 20);
    let skeleton = vec![entry_for(chunk.last().unwrap())];
    chunk.reverse();
    assert_eq!(
        crate::service::identify_chunk_by_content(&chunk, &skeleton),
        Some(0)
    );
}

/// The point of matching by hash. A chunk from another chain tops out at the
/// right height, and under number-only matching it was accepted as the answer
/// to a question about a different block.
#[test]
fn a_chunk_from_another_chain_at_the_right_height_is_refused() {
    let ours = run_of(500, 20);
    let skeleton = vec![entry_for(ours.last().unwrap())];

    let mut theirs = run_of(500, 20);
    theirs[19] = dummy_header(500, B256::repeat_byte(0xee), U256::from(1));
    assert_ne!(theirs[19].hash(), ours[19].hash(), "different blocks at #500");

    assert_eq!(
        crate::service::identify_chunk_by_content(&theirs, &skeleton),
        None,
        "a matching height is not evidence that this is the chunk we asked for"
    );
}

/// A chunk is a contiguous run. One with a hole covers less than it claims,
/// and accepting it leaves a gap in the canonical index.
#[test]
fn a_chunk_with_a_hole_is_refused() {
    let mut chunk = run_of(500, 20);
    chunk.remove(5);
    let skeleton = vec![entry_for(chunk.last().unwrap())];
    assert_eq!(
        crate::service::identify_chunk_by_content(&chunk, &skeleton),
        None
    );
}

/// Padding a chunk with repeats makes it look longer than the range it spans.
#[test]
fn a_chunk_padded_with_duplicates_is_refused() {
    let mut chunk = run_of(500, 20);
    let dup = chunk[3].clone();
    chunk.insert(4, dup);
    let skeleton = vec![entry_for(chunk.last().unwrap())];
    assert_eq!(
        crate::service::identify_chunk_by_content(&chunk, &skeleton),
        None
    );
}

/// A short chunk is still a contiguous run ending at the entry asked about,
/// so it identifies: peers are allowed to answer with less than was requested.
#[test]
fn a_short_but_contiguous_chunk_is_identified() {
    let chunk = run_of(500, 3);
    let skeleton = vec![entry_for(chunk.last().unwrap())];
    assert_eq!(
        crate::service::identify_chunk_by_content(&chunk, &skeleton),
        Some(0)
    );
}

/// Nothing to identify.
#[test]
fn an_empty_chunk_identifies_nothing() {
    assert_eq!(crate::service::identify_chunk_by_content(&[], &[]), None);
}
/// A head that cannot be reached from the executed head is re-seated onto one
/// that can.
///
/// The node used to report this and do nothing about it: the invariant
/// checker named the break correctly, every tick, while execution asked for
/// the blocks across it, failed, and retried from the same place. Correct
/// diagnosis, no recovery — the node stood still and stayed still.
#[tokio::test]
async fn a_head_unreachable_from_the_executed_head_is_reseated() {
    let (store, _dir, headers) = linked_chain(10);

    // Executed to #5, and the chain is intact to #10.
    let executed = &headers[5];
    store.set_exec_head(executed.hash(), executed.state_root).unwrap();

    // A head far above, with nothing in between: the canonical index has one
    // entry up there and a hole the whole way down.
    let stranded = dummy_header(1_000, B256::repeat_byte(0x99), U256::from(1));
    store.put_header_with_hash(stranded.hash(), &stranded).unwrap();
    store.put_canonical_hash(1_000, stranded.hash()).unwrap();
    store.update_canonical_chain(stranded.hash()).unwrap();
    assert_eq!(store.head().unwrap(), Some(stranded.hash()), "test setup");

    let mut service = service_over(store.clone());
    service.verify_coherence();

    let head = store.head().unwrap().expect("a head");
    assert_ne!(head, stranded.hash(), "the unreachable head must not survive");
    let seated = store.header(head).unwrap().expect("header for the new head");
    assert!(
        (5..=10).contains(&seated.number),
        "the head must land on the contiguous run above the executed head, got #{}",
        seated.number
    );
}

/// The re-seat never moves the head below what has already been executed:
/// that would be undoing work, not repairing a break.
#[tokio::test]
async fn reseating_never_goes_below_the_executed_head() {
    let (store, _dir, headers) = linked_chain(10);
    let executed = &headers[8];
    store.set_exec_head(executed.hash(), executed.state_root).unwrap();

    let stranded = dummy_header(2_000, B256::repeat_byte(0x55), U256::from(1));
    store.put_header_with_hash(stranded.hash(), &stranded).unwrap();
    store.put_canonical_hash(2_000, stranded.hash()).unwrap();
    store.update_canonical_chain(stranded.hash()).unwrap();

    let mut service = service_over(store.clone());
    service.verify_coherence();

    let head = store.head().unwrap().expect("a head");
    let seated = store.header(head).unwrap().expect("header");
    assert!(
        seated.number >= 8,
        "the head must not drop below the executed head #8, got #{}",
        seated.number
    );
}

// -- The prune gate ------------------------------------------------------
//
// Pruning deletes history that only a resync restores, so the question is not
// "is a snapshot sync running right now" but "has this node established that
// none is coming". Those differ exactly at startup, which is when a sweep
// would do the most damage: the node is still finding peers, no session
// exists yet to report itself, and a gate that asks the first question
// answers "no snapshot sync" and lets the sweep run.

/// The gate is shut before anything has been determined.
#[tokio::test]
async fn pruning_is_not_allowed_before_the_node_knows_what_it_is_doing() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let service = SyncService::new(manager, peer_store, event_rx);

    assert!(
        !service.prune_gate().load(std::sync::atomic::Ordering::Relaxed),
        "a freshly built service must not permit pruning: no snapshot session \
         exists yet, and that is not the same as none being due"
    );
}

/// Suspending for a snapshot sync shuts it, and finishing opens it.
#[tokio::test]
async fn the_gate_tracks_the_snapshot_sync_rather_than_its_absence() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    let gate = service.prune_gate();

    service.suspend_ordinary_sync_for_test();
    assert!(!gate.load(std::sync::atomic::Ordering::Relaxed));

    service.resume_ordinary_sync_for_test();
    assert!(
        gate.load(std::sync::atomic::Ordering::Relaxed),
        "once the snapshot sync is over the pruner is free to run"
    );
}

/// A snapshot sync that gives up without ever having suspended anything must
/// still release the gate, or a node that tried and failed to snapshot sync
/// would never prune at all.
#[tokio::test]
async fn giving_up_on_a_snapshot_sync_still_releases_the_gate() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    let gate = service.prune_gate();

    // Never suspended, so `suspended_for_snap` is false throughout.
    service.resume_ordinary_sync_for_test();
    assert!(gate.load(std::sync::atomic::Ordering::Relaxed));
}

// -- A chunk that does not connect ---------------------------------------
//
// Stopping the round and condemning the peer are separate judgements, and
// were once the same one. A chunk can fail to link because the peer served
// junk, or because this node's own head moved under a request already in
// flight — a reorg mid-round, or a late answer from a previous skeleton. The
// observation is identical, so a permanent ban cannot be justified from it.

/// A peer whose chunk does not connect is still usable afterwards.
///
/// `has_good_score()` gates on `InvalidBlock`, `InvalidMessage` and
/// `InvalidHeader`, each with a threshold of one. Charging any of those for
/// this makes the peer unusable for the lifetime of its scoring record, with
/// no decay and no second chance, on evidence that does not identify a
/// culprit.
#[tokio::test]
async fn a_non_connecting_chunk_does_not_ban_the_peer() {
    let scoring = Arc::new(rustock_networking::scoring::ScoringService::in_memory());
    let peer = B512::repeat_byte(0x07);

    // What the sync path now records for this condition.
    scoring.record_peer(peer, rustock_networking::scoring::EventType::UnexpectedMessage);

    assert!(
        scoring.node_is_welcome(peer),
        "a single non-connecting chunk must not make the peer unusable: this node \
         cannot tell the peer's fault from its own head moving"
    );
}

/// The counters that do ban, for contrast — so that this test fails if
/// someone switches the charge back to one of them.
#[tokio::test]
async fn the_banning_counters_still_ban() {
    for event in [
        rustock_networking::scoring::EventType::InvalidHeader,
        rustock_networking::scoring::EventType::InvalidBlock,
        rustock_networking::scoring::EventType::InvalidMessage,
    ] {
        let scoring = Arc::new(rustock_networking::scoring::ScoringService::in_memory());
        let peer = B512::repeat_byte(0x08);
        scoring.record_peer(peer, event);
        assert!(
            !scoring.node_is_welcome(peer),
            "{event:?} is a banning counter; a chunk that does not connect must not \
             be charged to one of these"
        );
    }
}

/// And the peer is kept out of the round it just failed, so a peer doing this
/// every round never gets work — which is the protection the ban used to
/// provide, without the permanence.
#[tokio::test]
async fn a_non_connecting_chunk_sidelines_the_peer() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    let peer = B512::repeat_byte(0x09);
    assert!(!service.sidelined.contains_key(&peer));

    // The sync path inserts exactly this on a chunk that does not connect.
    service
        .sidelined
        .insert(peer, Instant::now() + Duration::from_secs(300));

    assert!(
        service.sidelined.contains_key(&peer),
        "a peer whose chunk did not connect must be skipped for assignment"
    );
    assert!(
        service.sidelined.get(&peer).unwrap() > &Instant::now(),
        "and the sidelining must still be in force"
    );
}

// -- The follow-mode stall -----------------------------------------------
//
// A node in follow mode stops making progress. The watchdog notices, reports
// it correctly, and escalates — setting `force_connection_search` and
// dropping to `Idle` so that a search follows. Then `try_start_sync` ran its
// near-tip shortcut first, returned to `Following`, and never consulted the
// flag. The node re-entered the state it was stuck in, the flag stayed set,
// and the cycle repeated every few minutes. Observed for three hours on
// mainnet, and two hours forty on a test node with a peer 358 blocks ahead
// the whole time.

/// Builds a service whose head is `behind` blocks under a peer's best.
async fn service_behind_peer(behind: u64) -> (SyncService, tempfile::TempDir, B512) {
    let (store, dir, headers) = linked_chain(10);
    let top = headers.last().unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let service = SyncService::new(manager, peer_store.clone(), event_rx);

    let peer = B512::repeat_byte(0x21);
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    peer_store.add_peer(peer, tx).await;
    peer_store
        .update_metadata(
            &peer,
            rustock_networking::peers::PeerMetadata {
                best_number: top.number + behind,
                best_hash: B256::repeat_byte(0xfe),
                total_difficulty: U256::from(1_000_000u64),
                ..Default::default()
            },
        )
        .await;

    (service, dir, peer)
}

/// The escalation must not be swallowed by the near-tip shortcut.
///
/// This is the whole bug: a node a few hundred blocks behind is "near tip" by
/// the gap test, so it took that branch and returned to follow mode — the
/// state the watchdog had just reported as stuck.
#[tokio::test]
async fn a_forced_search_is_not_swallowed_by_the_near_tip_shortcut() {
    // Thirteen, as observed on mainnet: "No progress for 185s: Φ = (behind 13,
    // outstanding 0, oldest 0s)" followed by "Near tip (13 blocks behind),
    // entering follow mode". `LONG_SYNC_LIMIT` is 24, so this is squarely
    // inside the shortcut — which is the point.
    let (mut service, _dir, _peer) = service_behind_peer(13).await;

    // What the watchdog's second rung does.
    service.force_connection_search = true;
    service.state = SyncState::Idle;

    service.try_start_sync().await;

    assert!(
        !matches!(service.state, SyncState::Following),
        "the node returned to follow mode, which is the state the watchdog had just \
         reported as stalled; it must go looking instead. State: {:?}",
        service.state
    );
    assert!(
        !service.force_connection_search,
        "the flag must be consumed, or the next tick escalates again on a stall \
         that was never acted on"
    );
}

/// Without the flag, a near-tip node still follows. The shortcut exists
/// because a node a few blocks behind should not run a skeleton round, and
/// this change must not cost that.
#[tokio::test]
async fn a_near_tip_node_still_follows_when_nothing_is_wrong() {
    let (mut service, _dir, _peer) = service_behind_peer(13).await;
    service.state = SyncState::Idle;

    service.try_start_sync().await;

    assert!(
        matches!(service.state, SyncState::Following),
        "a healthy node near the tip should follow, not start a search: {:?}",
        service.state
    );
}

/// A peer with nothing above us yields no search, forced or not: a search
/// would converge on this node's own head and achieve nothing.
#[tokio::test]
async fn a_forced_search_against_a_peer_with_nothing_above_us_still_follows() {
    let (mut service, _dir, _peer) = service_behind_peer(0).await;
    service.force_connection_search = true;
    service.state = SyncState::Idle;

    service.try_start_sync().await;

    assert!(
        matches!(service.state, SyncState::Following),
        "nothing to search for: {:?}",
        service.state
    );
}

// -- Serving a simulated chain end ---------------------------------------
//
// `--simulate-height` makes this node behave as though the chain ends at a
// given block, so that several clients can be timed against the same fixture.
// A client that can reach past it has not run the test that was intended, so
// the ceiling is enforced on every path a client could use, not only on what
// is announced.

fn handler_capped_at(store: Arc<BlockStore>, ceiling: Option<u64>) -> crate::handler::SyncHandler {
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));
    let (event_tx, _rx) = mpsc::unbounded_channel();
    crate::handler::SyncHandler::new(manager, event_tx).with_serve_ceiling(ceiling)
}

/// A block above the simulated head is not named, even though it is on disk.
#[tokio::test]
async fn a_block_hash_above_the_simulated_head_is_not_served() {
    let (store, _dir, headers) = linked_chain(10);
    let handler = handler_capped_at(store, Some(5));

    assert!(
        handler.serve_block_hash_request_for_test(1, 5).is_some(),
        "the simulated head itself is served"
    );
    assert!(
        handler.serve_block_hash_request_for_test(1, 6).is_none(),
        "#6 is on disk but above the simulated head, so this node must not name it"
    );
    let _ = headers;
}

/// Nor are its headers.
#[tokio::test]
async fn headers_above_the_simulated_head_are_not_served() {
    let (store, _dir, headers) = linked_chain(10);
    let above = headers[7].hash();
    let below = headers[3].hash();
    let handler = handler_capped_at(store, Some(5));

    assert!(handler.serve_headers_request_for_test(1, below, 2).is_some());
    assert!(
        handler.serve_headers_request_for_test(1, above, 2).is_none(),
        "a header request starting above the simulated head must go unanswered"
    );
}

/// Nor its body. The block is in the database; the point is that this node
/// behaves as though the chain ended before it.
#[tokio::test]
async fn a_body_above_the_simulated_head_is_not_served() {
    let (store, _dir, headers) = linked_chain(10);
    for h in &headers {
        store.put_body(h.hash(), &[], &[]).unwrap();
    }
    let handler = handler_capped_at(store, Some(5));

    assert!(handler.serve_body_request_for_test(1, headers[3].hash()).is_some());
    assert!(
        handler.serve_body_request_for_test(1, headers[7].hash()).is_none(),
        "the body is on disk but the block is above the simulated head"
    );
}

/// A skeleton must not name a point above the simulated head: that is how a
/// client discovers what to ask for, so a point above it would send the client
/// after blocks this node will then refuse.
#[tokio::test]
async fn a_skeleton_names_nothing_above_the_simulated_head() {
    let (store, _dir, _headers) = linked_chain(400);
    let handler = handler_capped_at(store, Some(200));

    let msg = handler.serve_skeleton_request_for_test(1, 0).expect("served");
    let rustock_networking::protocol::P2pMessage::RskMessage(m) = msg else {
        panic!("not an rsk message")
    };
    let rustock_networking::protocol::RskSubMessage::SkeletonResponse(r) = m.sub_message else {
        panic!("not a skeleton")
    };
    for id in &r.block_identifiers {
        assert!(
            id.number <= 200,
            "skeleton named #{} above the simulated head of #200",
            id.number
        );
    }
}

/// Without a ceiling, nothing changes.
#[tokio::test]
async fn an_uncapped_node_serves_everything_as_before() {
    let (store, _dir, headers) = linked_chain(10);
    let handler = handler_capped_at(store, None);
    assert!(handler.serve_block_hash_request_for_test(1, 9).is_some());
    assert!(handler.serve_headers_request_for_test(1, headers[9].hash(), 2).is_some());
}

/// `--follow-up false` is an instruction, and it has to cover more than the
/// start of a sync round.
///
/// A header response, a body, an announcement of a new tip: each writes chain
/// data on arrival, without any round having been started. Gating only
/// `try_start_sync` would leave a node that never *begins* a sync but still
/// adopts whatever a peer pushes at it — which is exactly what a server being
/// measured against must not do, because it would no longer be the same
/// fixture for the next client.
///
/// `--read-only` sits behind this rather than replacing it: if a path is
/// missed here the database refuses the write. One is the instruction, the
/// other is what makes a mistake in carrying it out harmless.
#[tokio::test]
async fn serving_only_adopts_nothing_a_peer_pushes() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let genesis_hash = genesis.hash();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager.clone(), peer_store, event_rx)
        .with_follow_up(false);

    // A peer pushes a perfectly good block on top of our head.
    let next = dummy_header(1, genesis_hash, U256::from(10));
    let next_hash = next.hash();
    service
        .handle_event(SyncEvent::HeadersResponse {
            peer: B512::repeat_byte(0x31),
            id: 1,
            headers: vec![next],
        })
        .await;

    assert!(
        store.header(next_hash).unwrap().is_none(),
        "a serving-only node adopted a header a peer pushed at it"
    );
    assert_eq!(
        store.head().unwrap(),
        Some(genesis_hash),
        "and its head moved, so it is no longer the fixture the next client will see"
    );
}

/// With following on, the same push is adopted — so the test above is about
/// the instruction, not about the header being unacceptable.
#[tokio::test]
async fn a_following_node_adopts_the_same_push() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let genesis_hash = genesis.hash();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    let next = dummy_header(1, genesis_hash, U256::from(10));
    let next_hash = next.hash();
    service
        .handle_event(SyncEvent::HeadersResponse {
            peer: B512::repeat_byte(0x31),
            id: 1,
            headers: vec![next],
        })
        .await;

    assert!(
        store.header(next_hash).unwrap().is_some(),
        "the header is acceptable; only the instruction kept it out above"
    );
}

// -- Keeping a peer engaged ----------------------------------------------
//
// rskj refreshes a node's liveness only when a STATUS arrives:
// `SyncPeerStatus.updateActivity` is called from its constructor and from
// `setStatus`, and nowhere else. Block traffic, headers, bodies and
// announcements all leave the clock untouched. After
// `sync.expirationTimePeerStatus` — ten minutes — it drops the node from the
// set it will sync from, while the connection stays up and looks healthy.
//
// rustock sent its status once, at the handshake. Observed: an rskj client
// synced 12,096 blocks, logged "Completed syncing phase" fourteen minutes in,
// and never started another round.

/// The refresh must be well inside rskj's expiry, not merely under it.
#[test]
fn the_status_refresh_is_far_inside_rskj_expiry() {
    let rskj_expiry = Duration::from_secs(10 * 60);
    assert!(
        crate::service::STATUS_REFRESH * 12 < rskj_expiry,
        "a {}s refresh against a {}s expiry leaves no margin for a node that is busy, \
         and the failure is silent: the peer stays connected and simply stops syncing",
        crate::service::STATUS_REFRESH.as_secs(),
        rskj_expiry.as_secs()
    );
    assert_eq!(
        crate::service::STATUS_REFRESH,
        Duration::from_secs(10),
        "rskj broadcasts its own status every 10 seconds; matching it is the point"
    );
}

/// The refreshed status says the same thing the handshake said.
///
/// A server simulating a shorter chain that then refreshed with its real head
/// would tell one peer two different stories about where the chain ends, and
/// the second one would undo the first.
#[tokio::test]
async fn a_refreshed_status_agrees_with_the_simulated_head() {
    let (store, _dir, headers) = linked_chain(20);
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();

    let service = SyncService::new(manager, peer_store, event_rx)
        .with_serve_ceiling(Some(5));

    let status = service.current_status_for_test().expect("a status");
    assert_eq!(
        status.best_block_number, 5,
        "the refresh announced the real head, contradicting the handshake"
    );
    assert_eq!(status.best_block_hash, headers[5].hash());
}

/// Without a ceiling it announces the real head — and follows it.
///
/// Built from the store on each refresh rather than captured at startup,
/// because on a following node the head moves. A status frozen at the height
/// this node had when it started would have a peer believe it had stopped.
#[tokio::test]
async fn a_refreshed_status_tracks_the_head() {
    let (store, _dir, headers) = linked_chain(20);
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let service = SyncService::new(manager, peer_store, event_rx);

    let top = headers.last().unwrap();
    let before = service.current_status_for_test().expect("a status");
    assert_eq!(before.best_block_number, top.number);
    assert!(
        before.total_difficulty.is_some(),
        "the status must carry total difficulty, which is what a peer picks a chain on"
    );
    assert!(
        before.best_block_parent_hash.is_some(),
        "and the parent, or the message is the two-element form and carries no difficulty"
    );

    // The head moves, as it does on a node that is following.
    let next = dummy_header(top.number + 1, top.hash(), U256::from(10));
    let next_td = store.total_difficulty(top.hash()).unwrap().unwrap() + U256::from(10);
    store.update_head(&next, next_td).unwrap();

    let after = service.current_status_for_test().expect("a status");
    assert_eq!(
        after.best_block_number,
        top.number + 1,
        "the refresh still announced the old head, so a peer would think this node \
         had stopped"
    );
    assert_eq!(after.total_difficulty, Some(next_td));
}

/// Headers carrying their uncles must produce the total difficulty rskj
/// computes from bodies: `difficulty + sum(uncle difficulties)`. Without the
/// uncles the same header yields only its own difficulty, which is the
/// undercount `rsk/63` exists to remove.
#[tokio::test]
async fn uncles_sent_with_headers_make_total_difficulty_exact() {
    use rustock_networking::protocol::HeaderWithUncles;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(
        HeaderVerifier::new()
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule),
    );
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    // #1 on the trunk, then #2 absorbing two genuine siblings of #1 worth 7
    // and 5.
    //
    // The uncles are siblings of #1 rather than of genesis, which this fixture
    // used to use. An uncle's parent has to be an ancestor of the block
    // referencing it -- that is what makes it an uncle rather than a header
    // off an unrelated fork -- and genesis has no parent to be one. The old
    // shape passed only because the uncle rule was never run here.
    let commit = |h: &Header, us: &[Header]| -> Header {
        let mut h = h.clone();
        h.uncle_count = us.len() as u64;
        h.ommers_hash = alloy_primitives::keccak256(
            HeaderWithUncles { header: h.clone(), uncles: us.to_vec() }.encoded_uncles(),
        );
        h.cached_hash = None;
        h
    };

    let b1 = commit(&dummy_header(1, genesis_hash, U256::from(10)), &[]);
    let b1_hash = b1.hash();

    let mut uncle_a = dummy_header(1, genesis_hash, U256::from(7));
    uncle_a.gas_used = 1;
    uncle_a.cached_hash = None;
    let mut uncle_b = dummy_header(1, genesis_hash, U256::from(5));
    uncle_b.gas_used = 2;
    uncle_b.cached_hash = None;

    let uncles = vec![uncle_a, uncle_b];
    let b2 = commit(&dummy_header(2, b1_hash, U256::from(10)), &uncles);
    let hash = b2.hash();

    let headers = manager.note_proven_difficulties(vec![
        HeaderWithUncles { header: b1, uncles: Vec::new() },
        HeaderWithUncles { header: b2, uncles },
    ]);
    manager.handle_headers_response(headers, test_peer()).unwrap();

    // 1 (genesis) + 10 + 10 + 7 + 5
    assert_eq!(
        store.total_difficulty(hash).unwrap(),
        Some(U256::from(33)),
        "uncle difficulty is counted, as rskj's getCumulativeDifficulty does"
    );
}

/// Without the uncles, the same header can only yield a lower bound. This is
/// what every `rsk/62` peer leaves us with, and why the fallback is a
/// fallback rather than an equivalent.
#[tokio::test]
async fn headers_without_uncles_yield_only_a_lower_bound() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(
        HeaderVerifier::new()
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule),
    );
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    let mut b1 = dummy_header(1, genesis_hash, U256::from(10));
    b1.uncle_count = 2;
    let hash = b1.hash();
    manager.handle_headers_response(vec![b1], test_peer()).unwrap();

    assert_eq!(
        store.total_difficulty(hash).unwrap(),
        Some(U256::from(11)),
        "1 + 10, with the two uncles' difficulty missing for want of a body"
    );
}

/// A peer may not inflate total difficulty with uncles the header never
/// committed to.
///
/// `cumulative_difficulty()` is the sender's arithmetic over the uncles the
/// sender chose to send. `ommers_hash` is inside what the trunk header's proof
/// of work covers, so a matching list cannot have been added to, dropped from
/// or altered -- and a list that does not match is simply whatever the peer
/// wanted the total to be.
///
/// Unchecked, this needs no mining at all: take real headers off the real
/// chain, attach fabricated uncles, and the total difficulty this node records
/// -- the input to chain selection -- rises by up to the consensus uncle limit.
#[tokio::test]
async fn forged_uncles_do_not_prove_a_difficulty() {
    use rustock_networking::protocol::HeaderWithUncles;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(
        HeaderVerifier::new()
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule),
    );
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    // An honest header committing to no uncles at all...
    let mut b1 = dummy_header(1, genesis_hash, U256::from(10));
    b1.uncle_count = 0;
    b1.ommers_hash = alloy_primitives::keccak256(
        HeaderWithUncles { header: b1.clone(), uncles: Vec::new() }.encoded_uncles(),
    );
    b1.cached_hash = None;
    let hash = b1.hash();

    // ...delivered with a fat uncle bolted on by the sender.
    let forged = HeaderWithUncles {
        header: b1,
        uncles: vec![dummy_header(0, B256::ZERO, U256::from(1_000_000))],
    };
    assert!(!forged.commitment_matches(), "the fixture must be a real forgery");

    let headers = manager.note_proven_difficulties(vec![forged]);
    manager.handle_headers_response(headers, test_peer()).unwrap();

    // 1 (genesis) + 10, and not a unit of the million that was claimed.
    assert_eq!(
        store.total_difficulty(hash).unwrap(),
        Some(U256::from(11)),
        "a forged uncle list must prove nothing; the header still counts for \
         its own difficulty"
    );
}

/// An uncle the header *does* commit to still has to have done the work, and
/// to follow its parent as rskj's uncle rule requires.
///
/// A matching commitment only proves the block's miner chose this list. The
/// uncle's own merged-mining proof of work is what makes the difficulty it
/// states work rather than a number, and a miner is free to commit to an uncle
/// that never had one.
#[tokio::test]
async fn a_committed_uncle_without_proof_of_work_proves_nothing() {
    use rustock_networking::protocol::HeaderWithUncles;

    let verifiers = [
        (HeaderVerifier::new(), 1_020u64),
        (HeaderVerifier::new().with_uncle_rule(NoWorkAt999), 21),
        (HeaderVerifier::new().with_uncle_parent_rule(OffItsParentAt999), 21),
    ];
    for (verifier, total) in verifiers {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();
        let verifier = verifier
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule);
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = SyncManager::new(store.clone(), Arc::new(verifier), peer_store);

        // #1 on the trunk, then #2 naming a genuine sibling of #1 worth 999:
        // its parent is an ancestor, so with no rule against it, it counts.
        let commit = |h: &Header, us: &[Header]| -> Header {
            let mut h = h.clone();
            h.uncle_count = us.len() as u64;
            h.ommers_hash = alloy_primitives::keccak256(
                HeaderWithUncles { header: h.clone(), uncles: us.to_vec() }.encoded_uncles(),
            );
            h.cached_hash = None;
            h
        };
        let b1 = commit(&dummy_header(1, genesis_hash, U256::from(10)), &[]);
        let mut uncle = dummy_header(1, genesis_hash, U256::from(999));
        uncle.gas_used = 1;
        uncle.cached_hash = None;
        let b2 =
            commit(&dummy_header(2, b1.hash(), U256::from(10)), std::slice::from_ref(&uncle));
        let hash = b2.hash();
        let entry = HeaderWithUncles { header: b2, uncles: vec![uncle] };
        assert!(entry.commitment_matches(), "the commitment is honest; the work is not");

        let headers = manager.note_proven_difficulties(vec![
            HeaderWithUncles { header: b1, uncles: Vec::new() },
            entry,
        ]);
        manager.handle_headers_response(headers, test_peer()).unwrap();

        assert_eq!(
            store.total_difficulty(hash).unwrap(),
            Some(U256::from(total)),
            "an uncle is credited exactly when it passes the uncle rules"
        );
    }
}

// ---------------------------------------------------------------------------
// Total difficulty once the body is held. Header-first sync can only bound a
// block's total, because its uncles travel in the body; `total_difficulty`
// settles it once the body is in, crediting the uncles only once they pass
// the whole uncle rule.
// ---------------------------------------------------------------------------

/// A header naming `uncles`: its uncle count and its uncles hash commit to
/// them, as the body check on receipt requires.
fn naming_uncles(mut header: Header, uncles: &[Header]) -> Header {
    header.uncle_count = uncles.len() as u64;
    header.ommers_hash = rustock_execution::processor::compute_ommers_hash(uncles);
    header.cached_hash = None;
    header
}

/// Fails the header whose difficulty is 999, standing in for an uncle whose
/// merged-mining proof of work does not hold.
struct NoWorkAt999;

impl rustock_core::validation::HeaderValidator for NoWorkAt999 {
    fn validate(&self, h: &Header) -> Result<(), rustock_core::validation::ValidationError> {
        if h.difficulty == U256::from(999u64) {
            return Err(rustock_core::validation::ValidationError::BitcoinPowInvalid {
                hash: h.hash(),
                target: U256::ZERO,
            });
        }
        Ok(())
    }
}

/// Fails the header whose difficulty is 999 against its parent, standing in
/// for an uncle whose difficulty is not the one its parent calls for.
struct OffItsParentAt999;

impl rustock_core::validation::ParentHeaderValidator for OffItsParentAt999 {
    fn validate_with_parent(
        &self,
        h: &Header,
        _parent: &Header,
    ) -> Result<(), rustock_core::validation::ValidationError> {
        if h.difficulty == U256::from(999u64) {
            return Err(rustock_core::validation::ValidationError::DifficultyMismatch {
                expected: U256::from(10u64),
                got: h.difficulty,
            });
        }
        Ok(())
    }
}

/// Genesis held whole with a total of 1; #1 on it, worth 10; and two siblings
/// of #1 for a later block to name as uncles, worth `first` and `second`.
fn genesis_and_siblings(store: &BlockStore, first: u64, second: u64) -> (Header, Vec<Header>) {
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(10));
    let uncles = vec![
        dummy_header(1, genesis.hash(), U256::from(first)),
        dummy_header(1, genesis.hash(), U256::from(second)),
    ];
    (b1, uncles)
}

/// Answer each body request the service makes until it makes no more, with no
/// transactions and the uncles `uncles_of` gives the block asked for.
async fn answer_body_requests(service: &mut SyncService, uncles_of: impl Fn(B256) -> Vec<Header>) {
    for _ in 0..16 {
        let asked: Vec<(u64, B256, B512)> = match &service.state {
            SyncState::DownloadingBodies { pending_headers, id_index, .. } => id_index
                .iter()
                .map(|(id, (i, peer))| (*id, pending_headers[*i].0, *peer))
                .collect(),
            _ => return,
        };
        for (id, hash, peer) in asked {
            service
                .on_body_response(peer, id, vec![], uncles_of(hash), None)
                .await;
        }
    }
    panic!("the service kept asking for bodies: {:?}", service.state);
}

/// Catch up #1 to #3 header-first, from a peer that cannot send uncles, then
/// download their bodies, #2's naming `uncles`. Returns the three headers.
async fn caught_up(
    store: &Arc<BlockStore>,
    verifier: HeaderVerifier,
    b1: Header,
    uncles: &[Header],
) -> [Header; 3] {
    let b2 = naming_uncles(dummy_header(2, b1.hash(), U256::from(10)), uncles);
    let b3 = dummy_header(3, b2.hash(), U256::from(10));
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(B512::repeat_byte(0x01), tx).await;
    let manager = Arc::new(SyncManager::new(store.clone(), Arc::new(verifier), peer_store.clone()));
    manager
        .handle_headers_response(vec![b3.clone(), b2.clone(), b1.clone()], test_peer())
        .unwrap();
    assert_eq!(
        store.total_difficulty(b3.hash()).unwrap(),
        Some(U256::from(31)),
        "each total is a bound until the bodies come"
    );

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.start_body_downloads(3).await;
    let named = b2.hash();
    answer_body_requests(&mut service, |hash| {
        if hash == named { uncles.to_vec() } else { Vec::new() }
    })
    .await;
    assert!(matches!(service.state, SyncState::Following), "{:?}", service.state);
    [b1, b2, b3]
}

/// Once a caught-up batch's bodies are in, each total is made exact, oldest
/// first, and every total above an uncle carries it, as rskj's do. A node that
/// never did this ran 6.9 x 10^25 short of rskj after 8,000 mainnet blocks.
#[tokio::test]
async fn a_caught_up_batch_counts_the_uncles_its_bodies_bring() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let (b1, uncles) = genesis_and_siblings(&store, 7, 5);
    let [b1, b2, b3] = caught_up(&store, HeaderVerifier::new(), b1, &uncles).await;

    // 1 + 10; then + 10 + 7 + 5; then + 10.
    assert_eq!(store.total_difficulty(b1.hash()).unwrap(), Some(U256::from(11)));
    assert_eq!(store.total_difficulty(b2.hash()).unwrap(), Some(U256::from(33)));
    assert_eq!(store.total_difficulty(b3.hash()).unwrap(), Some(U256::from(43)));
}

/// A body's uncles count only once they pass the whole uncle rule: the rules
/// an uncle faces on its own, proof of work among them, and those it faces
/// against its parent. The body check on receipt shows only that the block's
/// miner chose them, and an uncle that never did its work would otherwise add
/// what it claims to every total above it.
#[tokio::test]
async fn a_caught_up_body_whose_uncle_did_no_work_adds_no_uncle() {
    let verifiers = [
        HeaderVerifier::new().with_uncle_rule(NoWorkAt999),
        HeaderVerifier::new().with_uncle_parent_rule(OffItsParentAt999),
    ];
    for verifier in verifiers {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let (b1, uncles) = genesis_and_siblings(&store, 7, 999);
        let [_, b2, b3] = caught_up(&store, verifier, b1, &uncles).await;

        // Neither uncle: rskj refuses the whole block over one.
        assert_eq!(store.total_difficulty(b2.hash()).unwrap(), Some(U256::from(21)));
        assert_eq!(store.total_difficulty(b3.hash()).unwrap(), Some(U256::from(31)));
    }
}

/// In follow mode a block's total is settled from the executed head's when its
/// body comes, rather than when a fork announcement next brings its header
/// round again.
#[tokio::test]
async fn a_followed_block_counts_its_uncles_when_its_body_comes() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let (b1, uncles) = genesis_and_siblings(&store, 7, 5);
    let b2 = naming_uncles(dummy_header(2, b1.hash(), U256::from(10)), &uncles);

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let verifier = Arc::new(HeaderVerifier::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    manager.handle_headers_response(vec![b1.clone()], test_peer()).unwrap();
    store.put_body(b1.hash(), &[], &[]).unwrap();
    store.set_exec_head(b1.hash(), B256::ZERO).unwrap();
    manager.handle_headers_response(vec![b2.clone()], test_peer()).unwrap();
    assert_eq!(
        store.total_difficulty(b2.hash()).unwrap(),
        Some(U256::from(21)),
        "a bound until the body comes"
    );

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;
    let peer = B512::repeat_byte(9);
    service
        .pending_follow_bodies
        .insert(7, (b2.hash(), b2.clone(), std::time::Instant::now(), peer));
    service
        .on_body_response(peer, 7, vec![], uncles, None)
        .await;

    assert_eq!(store.total_difficulty(b2.hash()).unwrap(), Some(U256::from(33)));
}

/// A header ingested again with its body held, as a fork announcement does to
/// the last few hundred, is credited the body's uncles only once they pass the
/// whole uncle rule, as settling does.
#[tokio::test]
async fn a_header_ingested_again_credits_only_uncles_that_did_their_work() {
    for (second, total) in [(5u64, 33u64), (999, 21)] {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let (b1, uncles) = genesis_and_siblings(&store, 7, second);
        let b2 = naming_uncles(dummy_header(2, b1.hash(), U256::from(10)), &uncles);
        let verifier = Arc::new(HeaderVerifier::new().with_uncle_rule(NoWorkAt999));
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = SyncManager::new(store.clone(), verifier, peer_store);
        manager.handle_headers_response(vec![b2.clone(), b1.clone()], test_peer()).unwrap();
        store.put_body(b1.hash(), &[], &[]).unwrap();
        store.put_body(b2.hash(), &[], &uncles).unwrap();

        manager.handle_headers_response(vec![b2.clone(), b1.clone()], test_peer()).unwrap();
        assert_eq!(
            store.total_difficulty(b2.hash()).unwrap(),
            Some(U256::from(total)),
            "uncles worth 7 and {second}"
        );
    }
}

/// A held header whose parent is not held keeps the total it has. What the
/// block adds is taken off and added back, so taking off its own difficulty
/// alone counted its uncles twice once its total held them.
#[tokio::test]
async fn a_held_header_without_its_parent_keeps_its_total() {
    use rustock_networking::protocol::HeaderWithUncles;
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let (b1, uncles) = genesis_and_siblings(&store, 7, 5);
    let b2 = naming_uncles(dummy_header(2, b1.hash(), U256::from(10)), &uncles);
    // #2 held with the total that counts its uncles; #1 not held at all.
    store.put_header(&b2).unwrap();
    store.put_total_difficulty(b2.hash(), U256::from(33)).unwrap();

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), Arc::new(HeaderVerifier::new()), peer_store);
    // A peer at `rsk/63` proves what #2 adds, its uncles with it.
    let entries = vec![
        HeaderWithUncles { header: b1, uncles: Vec::new() },
        HeaderWithUncles { header: b2.clone(), uncles },
    ];
    assert!(entries.iter().all(HeaderWithUncles::commitment_matches));
    manager.note_proven_difficulties(entries);

    manager.handle_headers_response(vec![b2.clone()], test_peer()).unwrap();
    assert_eq!(store.total_difficulty(b2.hash()).unwrap(), Some(U256::from(33)));
}

/// An uncle is judged against the uncles its block's ancestors named, so it is
/// not credited while an ancestor's are not held: the rule would read that
/// ancestor as naming none, and pass an uncle it had named already.
#[tokio::test]
async fn an_uncle_is_not_credited_while_an_ancestors_uncles_are_not_held() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let (b1, uncles) = genesis_and_siblings(&store, 7, 5);
    let reused = &uncles[..1];
    // #2 names the uncle and #3 names it again, which the rule refuses -- but
    // only a node holding #2's uncles can see it.
    let b2 = naming_uncles(dummy_header(2, b1.hash(), U256::from(10)), reused);
    let b3 = naming_uncles(dummy_header(3, b2.hash(), U256::from(10)), reused);
    for (header, total) in [(&b1, 11u64), (&b2, 28)] {
        store.put_header(header).unwrap();
        store.put_total_difficulty(header.hash(), U256::from(total)).unwrap();
    }
    store.put_body(b1.hash(), &[], &[]).unwrap();
    store.put_header(&b3).unwrap();

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), Arc::new(HeaderVerifier::new()), peer_store);
    assert!(manager.settle_total_difficulty(b3.hash(), &b3, reused));
    assert_eq!(
        store.total_difficulty(b3.hash()).unwrap(),
        Some(U256::from(38)),
        "#2's uncles are not held, so #3's are not credited"
    );

    // With #2's uncles held, the rule sees the reuse and refuses it.
    store.put_body(b2.hash(), &[], reused).unwrap();
    assert!(manager.settle_total_difficulty(b3.hash(), &b3, reused));
    assert_eq!(store.total_difficulty(b3.hash()).unwrap(), Some(U256::from(38)));

    // And an uncle that no ancestor named is credited: 28 + 10 + 5.
    let fresh = &uncles[1..];
    let b3 = naming_uncles(dummy_header(3, b2.hash(), U256::from(10)), fresh);
    store.put_header(&b3).unwrap();
    assert!(manager.settle_total_difficulty(b3.hash(), &b3, fresh));
    assert_eq!(store.total_difficulty(b3.hash()).unwrap(), Some(U256::from(43)));
}

/// The oldest ancestor the rule walks, seven generations back or genesis, must
/// have its uncles held as much as the nearest.
#[tokio::test]
async fn the_oldest_ancestor_the_uncle_rule_walks_must_be_held_too() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(10));
    store.put_header(&b1).unwrap();
    store.put_total_difficulty(b1.hash(), U256::from(11)).unwrap();
    store.put_body(b1.hash(), &[], &[]).unwrap();
    let uncles = vec![dummy_header(1, genesis.hash(), U256::from(7))];
    let b2 = naming_uncles(dummy_header(2, b1.hash(), U256::from(10)), &uncles);
    store.put_header(&b2).unwrap();

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), Arc::new(HeaderVerifier::new()), peer_store);
    assert!(manager.settle_total_difficulty(b2.hash(), &b2, &uncles));
    assert_eq!(
        store.total_difficulty(b2.hash()).unwrap(),
        Some(U256::from(21)),
        "genesis is within the rule's reach and its uncles are not held"
    );

    store.put_body(genesis.hash(), &[], &[]).unwrap();
    assert!(manager.settle_total_difficulty(b2.hash(), &b2, &uncles));
    assert_eq!(store.total_difficulty(b2.hash()).unwrap(), Some(U256::from(28)));
}

/// A batch stopped by a block that fails consensus validation is not clean,
/// any more than one stopped by a block that fails to execute: rskj treats the
/// block as invalid and stops there.
#[test]
fn a_batch_stopped_by_a_block_that_fails_validation_is_not_clean() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    let root = empty.compute_hash(trie.as_ref());
    trie.put(root.as_slice(), &empty.to_message(trie.as_ref()));

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.set_exec_head(genesis.hash(), root).unwrap();
    // A block with no REMASC transaction, which every block but genesis needs.
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_body(b1.hash(), &[], &[]).unwrap();

    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let block = rustock_core::types::block::Block {
        header: b1.clone(),
        transactions: Vec::new(),
        ommers: Vec::new(),
    };
    assert!(processor.validate_block(&block).is_err(), "the block must fail validation");

    let outcome = crate::service::process_downloaded_blocks(
        &processor,
        trie,
        empty,
        &store,
        None,
        0,
        1,
        &[(b1.hash(), b1)],
        &crate::chain_activity::ChainActivity::new(),
        &crate::gas_price::GasPriceTracker::default(),
    );
    assert!(!outcome.all_ok, "a batch stopped by an invalid block reported itself clean");
    assert_eq!(
        store.exec_head().unwrap().map(|(hash, _)| hash),
        Some(genesis.hash()),
        "and nothing past the invalid block's parent executed"
    );
}

/// One real uncle may not be counted twice.
///
/// After #268 a peer cannot fabricate uncles: the list is bound to the trunk
/// header by `ommers_hash` and each uncle must carry its own proof of work.
/// What that leaves is **reuse** — referencing the same genuine uncle under
/// several blocks and having its difficulty credited once per reference.
///
/// Consensus forbids it (`validateIfUncleWasNeverUsed`). Unchecked, the cap is
/// `uncleListLimit`, so a miner inflates its claim up to elevenfold over the
/// trunk work it actually did.
#[tokio::test]
async fn an_uncle_used_twice_is_only_counted_once() {
    use rustock_networking::protocol::HeaderWithUncles;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    let commit = |h: &Header, us: &[Header]| -> Header {
        let mut h = h.clone();
        h.uncle_count = us.len() as u64;
        h.ommers_hash = alloy_primitives::keccak256(
            HeaderWithUncles { header: h.clone(), uncles: us.to_vec() }.encoded_uncles(),
        );
        h.cached_hash = None;
        h
    };

    // #1 on the trunk, and a genuine sibling of it worth 500. A real uncle's
    // parent has to be an ancestor of the block referencing it, which is what
    // makes it an uncle rather than a block off an unrelated fork.
    let b1 = commit(&dummy_header(1, genesis_hash, U256::from(10)), &[]);
    let b1_hash = b1.hash();
    let mut uncle = dummy_header(1, genesis_hash, U256::from(500));
    uncle.gas_used = 1; // distinguishes it from b1
    uncle.cached_hash = None;

    // #2 legitimately references it; #3 references the very same uncle again.
    let b2 = commit(&dummy_header(2, b1_hash, U256::from(10)), &[uncle.clone()]);
    let b2_hash = b2.hash();
    let b3 = commit(&dummy_header(3, b2_hash, U256::from(10)), &[uncle.clone()]);
    let b3_hash = b3.hash();

    let headers = manager.note_proven_difficulties(vec![
        HeaderWithUncles { header: b1, uncles: Vec::new() },
        HeaderWithUncles { header: b2, uncles: vec![uncle.clone()] },
        HeaderWithUncles { header: b3, uncles: vec![uncle] },
    ]);
    manager.handle_headers_response(headers, test_peer()).unwrap();

    // 1 + 10 + 10 + 500 — the uncle counts under #2 and nowhere else.
    assert_eq!(
        store.total_difficulty(b2_hash).unwrap(),
        Some(U256::from(521)),
        "the first, legitimate reference is credited"
    );
    assert_eq!(
        store.total_difficulty(b3_hash).unwrap(),
        Some(U256::from(531)),
        "the second reference adds only #3's own difficulty, not the uncle's again"
    );
}

/// An uncle older than the generation limit is not credited.
///
/// Consensus bounds how far back a block may reach; without the check, work
/// from arbitrarily deep in the chain can be re-counted at the tip.
#[tokio::test]
async fn an_uncle_beyond_the_generation_limit_is_not_counted() {
    use rustock_networking::protocol::HeaderWithUncles;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let mut parent = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&parent, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = SyncManager::new(store.clone(), verifier, peer_store);

    // A plain chain to #10, so the tip is well past the 7-generation reach.
    let mut entries = Vec::new();
    for n in 1..=10u64 {
        let h = dummy_header(n, parent.hash(), U256::from(10));
        parent = h.clone();
        entries.push(HeaderWithUncles { header: h, uncles: Vec::new() });
    }
    let headers = manager.note_proven_difficulties(entries);
    manager.handle_headers_response(headers, test_peer()).unwrap();
    let tip = parent.hash();
    let before = store.total_difficulty(tip).unwrap().unwrap();

    // #11 reaches back to a sibling of #1 — ten generations, limit is seven.
    let too_old = dummy_header(1, B256::repeat_byte(0xdd), U256::from(5_000));
    let mut b11 = dummy_header(11, tip, U256::from(10));
    b11.uncle_count = 1;
    b11.ommers_hash = alloy_primitives::keccak256(
        HeaderWithUncles { header: b11.clone(), uncles: vec![too_old.clone()] }
            .encoded_uncles(),
    );
    b11.cached_hash = None;
    let b11_hash = b11.hash();

    let headers = manager
        .note_proven_difficulties(vec![HeaderWithUncles { header: b11, uncles: vec![too_old] }]);
    manager.handle_headers_response(headers, test_peer()).unwrap();

    assert_eq!(
        store.total_difficulty(b11_hash).unwrap(),
        Some(before + U256::from(10)),
        "an uncle ten generations back must not bring its 5,000 with it"
    );
}

/// A block whose header determines its body is never asked for.
///
/// This is the whole point of the mechanism, so it is tested at the level
/// where the saving happens: after a pass over the queue the body is in the
/// store and nothing is in flight.
#[tokio::test]
async fn a_derivable_body_is_built_rather_than_requested() {
    use rustock_core::ordered_tx_trie_root;

    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    // An empty block: REMASC alone, no uncles.
    let number = 4_000_000;
    let txs = vec![rustock_core::Transaction::remasc(number)];
    let mut b1 = dummy_header(number, genesis.hash(), U256::from(1));
    b1.transactions_root = ordered_tx_trie_root(&txs, true);
    b1.ommers_hash = rustock_execution::processor::compute_ommers_hash(&[]);
    store.put_header(&b1).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    service.state = SyncState::DownloadingBodies {
        peer_best: number,
        pending_headers: vec![(b1.hash(), b1.clone())],
        next_request: 0,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    service.send_body_requests().await;

    assert_eq!(service.derived_bodies, 1, "the body should have been derived");
    let stored = store.body(b1.hash()).unwrap();
    assert!(stored.is_some(), "a derived body must be stored like any other");
    let (stored_txs, stored_uncles) = stored.unwrap();
    assert_eq!(stored_txs, txs, "and must be the transaction the header commits to");
    assert!(stored_uncles.is_empty());

    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert!(in_flight.is_empty(), "no request should have been sent");
        }
        // Advancing straight out of the batch is also a pass: the one block
        // it held is done.
        other => assert!(
            !matches!(other, SyncState::DownloadingBodies { .. }),
            "unexpected state {other:?}"
        ),
    }
}

/// A block that carries real transactions is still requested, and the
/// refusal is remembered so the predicate is not paid for it twice.
#[tokio::test]
async fn an_underivable_header_is_requested_and_remembered() {
    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    // A header committing to a transaction set that is not REMASC alone.
    let mut b1 = dummy_header(1, genesis.hash(), U256::from(1));
    b1.transactions_root = B256::repeat_byte(0x33);
    store.put_header(&b1).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(peer, tx).await;

    service.state = SyncState::DownloadingBodies {
        peer_best: 1,
        pending_headers: vec![(b1.hash(), b1.clone())],
        next_request: 0,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    service.send_body_requests().await;

    assert_eq!(service.derived_bodies, 0);
    assert!(store.body(b1.hash()).unwrap().is_none(), "nothing may be stored");
    assert!(service.underivable.contains(&b1.hash()), "the refusal is remembered");
    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert_eq!(in_flight.len(), 1, "it must be requested from a peer");
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }
}

/// A body answer is only taken from the peer the request was sent to.
///
/// Request ids are random, so another peer cannot realistically land on one
/// -- but that makes the binding a property of the id generator rather than
/// of this code, and it would fall silently if the generator ever changed.
/// The check is what keeps it true; this is what keeps the check.
#[tokio::test]
async fn a_body_from_a_peer_that_was_not_asked_is_ignored() {
    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&b1).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    let asked = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    peer_store.add_peer(asked, tx).await;

    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(0usize, InFlightBody { req_id: 7, sent: Instant::now(), peer: asked });
    let mut id_index = std::collections::HashMap::new();
    id_index.insert(7u64, (0usize, asked));
    service.state = SyncState::DownloadingBodies {
        peer_best: 1,
        pending_headers: vec![(b1.hash(), b1.clone())],
        next_request: 1,
        in_flight,
        id_index,
    };

    // b1's header commits to an empty body, so this payload is the correct
    // one. It is still refused, because of who sent it.
    let stranger = B512::repeat_byte(0x09);
    service
        .on_body_response(stranger, 7, vec![], vec![], None)
        .await;

    assert!(
        store.body(b1.hash()).unwrap().is_none(),
        "a body from a peer that was not asked must not be stored"
    );
    match &service.state {
        SyncState::DownloadingBodies { in_flight, id_index, .. } => {
            assert!(in_flight.contains_key(&0), "the request must stay outstanding");
            assert!(id_index.contains_key(&7), "and keep its id mapped");
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }

    // The peer that was asked is still able to answer it.
    service
        .on_body_response(asked, 7, vec![], vec![], None)
        .await;
    assert!(
        store.body(b1.hash()).unwrap().is_some(),
        "the genuine answer must still be accepted"
    );
}

// ---------------------------------------------------------------------------
// A header that came compressed takes the extension sent beside its body.
//
// From RSKIP-351 rskj sends a chain's headers compressed: a version-1 or
// version-2 header holds only a commitment to its extension -- the block's
// logs bloom, execution edges and base event -- and the extension comes beside
// the block's body (`BodyResponseMessage`), which rskj sets on the header
// before the block runs (`DownloadingBodiesSyncState.newBody`). While it was
// dropped, testnet's first block after a snapshot whose bloom wasn't empty
// failed `logs bloom mismatch`, its receipts all rskj's.
// ---------------------------------------------------------------------------

/// A version-2 extension whose bloom has one bit set: bit `bit`. Its edges
/// are empty, as rskj emits them on every versioned header while RSKIP144 is
/// active and the block has no sublists; the store's decoder counts on it.
fn an_extension(bit: usize) -> rustock_core::types::header_extension::BlockHeaderExtension {
    let mut logs_bloom = vec![0u8; 256];
    logs_bloom[bit / 8] |= 0x80 >> (bit % 8);
    rustock_core::types::header_extension::BlockHeaderExtension::V2 {
        logs_bloom,
        edges: Some(Vec::new()),
        base_event: Some(Vec::new()),
    }
}

/// `header` as rskj sends it to its peers, holding only the commitment to
/// `extension` in its bloom's slot, with the UMM root and merged-mining fields
/// that every versioned header has, and that the store's decoder counts on.
fn compressed(
    header: Header,
    extension: &rustock_core::types::header_extension::BlockHeaderExtension,
) -> Header {
    let mut slot = Vec::new();
    alloy_rlp::Encodable::encode(&extension.create_extension_data().as_slice(), &mut slot);
    Header {
        logs_bloom: Default::default(),
        extension_data: Some(Bytes::from(slot)),
        version_fields: None,
        umm_root: Some(Bytes::new()),
        bitcoin_merged_mining_header: Some(Bytes::from(vec![0u8; 80])),
        bitcoin_merged_mining_merkle_proof: Some(Bytes::new()),
        bitcoin_merged_mining_coinbase_transaction: Some(Bytes::new()),
        cached_hash: None,
        cached_hash_for_merged_mining: None,
        ..header
    }
}

/// A service over `store` with one peer, `asked`, connected.
async fn service_with_a_peer(store: Arc<BlockStore>, asked: B512) -> SyncService {
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let service = SyncService::new(manager, peer_store.clone(), event_rx);
    let (tx, rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    // Kept open, so that what is sent to the peer has somewhere to go.
    std::mem::forget(rx);
    peer_store.add_peer(asked, tx).await;
    service
}

/// The batch path. A body without the extension its header commits to, or
/// with another, is refused, and the request stays outstanding. With it, the
/// header is stored with its bloom, edges and base event, under the same hash,
/// and the batch carries the completed header to execution.
#[tokio::test]
async fn a_compressed_header_is_stored_with_the_extension_that_came_beside_its_body() {
    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let extension = an_extension(77);
    let b1 = compressed(dummy_header(1, genesis.hash(), U256::from(1)), &extension);
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    let hash = b1.hash();
    for h in [&b1, &b2] {
        store.put_header(h).unwrap();
    }
    assert_eq!(
        store.header(hash).unwrap(),
        Some(b1.clone()),
        "stored as it came"
    );

    let asked = B512::repeat_byte(0x01);
    let mut service = service_with_a_peer(store.clone(), asked).await;
    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(
        0usize,
        InFlightBody {
            req_id: 7,
            sent: Instant::now(),
            peer: asked,
        },
    );
    let mut id_index = std::collections::HashMap::new();
    id_index.insert(7u64, (0usize, asked));
    service.state = SyncState::DownloadingBodies {
        peer_best: 2,
        pending_headers: vec![(hash, b1.clone()), (b2.hash(), b2.clone())],
        next_request: 1,
        in_flight,
        id_index,
    };

    for (sent, why) in [
        (None, "no extension"),
        (Some(an_extension(78)), "another extension"),
    ] {
        service
            .on_body_response(asked, 7, vec![], vec![], sent)
            .await;
        assert!(
            store.body(hash).unwrap().is_none(),
            "{why}: no body is stored"
        );
        assert_eq!(
            store.header(hash).unwrap(),
            Some(b1.clone()),
            "{why}: nor the header changed"
        );
        match &service.state {
            SyncState::DownloadingBodies {
                in_flight,
                id_index,
                ..
            } => {
                assert!(
                    in_flight.contains_key(&0),
                    "{why}: the request stays outstanding"
                );
                assert!(id_index.contains_key(&7), "{why}: and keeps its id");
            }
            other => panic!("expected DownloadingBodies, got {other:?}"),
        }
    }

    service
        .on_body_response(asked, 7, vec![], vec![], Some(extension.clone()))
        .await;
    assert!(store.body(hash).unwrap().is_some(), "the body is stored");
    let stored = store.header(hash).unwrap().expect("the header");
    assert_eq!(stored.extension(), Some(extension.clone()));
    assert_eq!(stored.logs_bloom.as_slice(), extension.logs_bloom());
    assert_eq!(
        stored.hash(),
        hash,
        "the same hash, derived from the fields"
    );
    match &service.state {
        SyncState::DownloadingBodies {
            pending_headers, ..
        } => {
            assert_eq!(
                pending_headers[0].1.extension(),
                Some(extension),
                "the batch runs it"
            );
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }
}

/// Follow mode takes the extension the same way, and buffers the completed
/// header for execution.
#[tokio::test]
async fn a_followed_compressed_header_takes_the_extension_that_came_beside_its_body() {
    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let extension = an_extension(3);
    let b1 = compressed(dummy_header(1, genesis.hash(), U256::from(1)), &extension);
    let hash = b1.hash();
    store.put_header(&b1).unwrap();

    let asked = B512::repeat_byte(0x01);
    let mut service = service_with_a_peer(store.clone(), asked).await;
    service.state = SyncState::Following;
    service
        .pending_follow_bodies
        .insert(7, (hash, b1.clone(), Instant::now(), asked));

    service
        .on_body_response(asked, 7, vec![], vec![], None)
        .await;
    assert!(store.body(hash).unwrap().is_none(), "no body is stored");
    assert!(
        service.pending_follow_bodies.contains_key(&7),
        "it is asked for again"
    );
    assert!(service.follow_buffer.is_empty());

    service
        .on_body_response(asked, 7, vec![], vec![], Some(extension.clone()))
        .await;
    assert!(store.body(hash).unwrap().is_some(), "the body is stored");
    assert_eq!(
        store.header(hash).unwrap().and_then(|h| h.extension()),
        Some(extension.clone())
    );
    assert!(!service.pending_follow_bodies.contains_key(&7));
    // No block has run, so nothing drains the buffer.
    let (buffered, header, ..) = service.follow_buffer.get(&1).expect("buffered");
    assert_eq!((*buffered, header.extension()), (hash, Some(extension)));
}

/// A local block source that has every body, empty.
struct EveryBody;

impl ExternalBlockSource for EveryBody {
    fn body_by_hash(&self, _: B256) -> Option<(Vec<rustock_core::Transaction>, Vec<Header>)> {
        Some((Vec::new(), Vec::new()))
    }
}

/// A body stored beside a header that holds only its commitment -- derived
/// from the header, before that was refused -- is dropped when its batch
/// starts, and asked of a peer, neither derived again nor filled from a local
/// source, which has no extension to give. A header that holds its own fields
/// keeps its body.
#[tokio::test]
async fn a_body_stored_without_its_header_extension_is_asked_for_again() {
    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = compressed(derivable_header(1, genesis.hash()), &an_extension(5));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    let hash = b1.hash();
    for (number, h) in [(1, &b1), (2, &b2)] {
        store.put_header(h).unwrap();
        store.put_canonical_hash(number, h.hash()).unwrap();
        store
            .put_total_difficulty(h.hash(), U256::from(number + 1))
            .unwrap();
    }
    store.update_head(&b2, U256::from(3)).unwrap();
    store
        .put_body(hash, &[rustock_core::Transaction::remasc(1)], &[])
        .unwrap();
    store.put_body(b2.hash(), &[], &[]).unwrap();

    let service = service_with_a_peer(store.clone(), B512::repeat_byte(0x01)).await;
    let mut service = service.with_block_source(Arc::new(EveryBody));
    service.start_body_downloads(2).await;

    assert!(store.body(hash).unwrap().is_none(), "the body is dropped");
    assert!(
        store.body(b2.hash()).unwrap().is_some(),
        "a whole header keeps its body"
    );
    assert_eq!(service.derived_bodies, 0, "and not derived again");
    match &service.state {
        SyncState::DownloadingBodies {
            pending_headers,
            in_flight,
            ..
        } => {
            assert_eq!(pending_headers.len(), 2);
            assert_eq!(in_flight.len(), 1, "it is asked of the peer");
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }
}

/// Follow mode drops such a body too, rather than run the block without its
/// bloom, and asks for it again.
#[tokio::test]
async fn follow_mode_asks_again_for_a_body_stored_without_its_header_extension() {
    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    store.set_exec_head(genesis.hash(), B256::ZERO).unwrap();
    let b1 = compressed(derivable_header(1, genesis.hash()), &an_extension(6));
    let hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, hash).unwrap();
    let stale = [rustock_core::Transaction::remasc(1)];
    store.put_body(hash, &stale, &[]).unwrap();

    let mut service = service_with_a_peer(store.clone(), B512::repeat_byte(0x01)).await;
    service.state = SyncState::Following;
    service.refill_follow_buffer_from_store();
    assert!(
        service.follow_buffer.is_empty(),
        "not run without its bloom"
    );
    assert!(store.body(hash).unwrap().is_none(), "the body is dropped");

    store.put_body(hash, &stale, &[]).unwrap();
    service.fill_follow_body_gap().await;
    assert!(store.body(hash).unwrap().is_none(), "dropped again");
    assert_eq!(
        service.pending_follow_bodies.len(),
        1,
        "and asked of the peer"
    );
}

/// A body is served with its header's extension, as rskj's
/// `NodeBlockProcessor.processBodyRequest` sends it; for a header that holds
/// only the commitment, which has none to send, no body is served.
#[tokio::test]
async fn a_served_body_carries_its_header_extension() {
    use rustock_networking::protocol::rsk::BodyRequest;
    use rustock_networking::protocol::{P2pHandler, P2pMessage, RskMessage, RskSubMessage};

    let store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
    let extension = an_extension(9);
    let whole = compressed(dummy_header(1, B256::ZERO, U256::from(1)), &extension)
        .with_extension(&extension)
        .expect("its own extension");
    let only_committed = compressed(
        dummy_header(2, whole.hash(), U256::from(1)),
        &an_extension(10),
    );
    for h in [&whole, &only_committed] {
        store.put_header(h).unwrap();
        store.put_body(h.hash(), &[], &[]).unwrap();
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);
    let ask = |hash| {
        let req = BodyRequest { id: 33, hash };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req)));
        handler.handle_message(B512::repeat_byte(0x01), &msg)
    };
    match ask(whole.hash()) {
        Some(P2pMessage::RskMessage(RskMessage {
            sub_message: RskSubMessage::BodyResponse(r),
        })) => assert_eq!(r.extension, Some(extension)),
        other => panic!("expected a body, got {other:?}"),
    }
    assert!(
        ask(only_committed.hash()).is_none(),
        "no extension to send beside it"
    );
}

// ---------------------------------------------------------------------------
// A body batch that needs no network must still end.
//
// `DownloadingBodies` is advanced by exactly one thing: a body response. That
// holds only while every pending header is waiting on a peer, and
// `send_body_requests` has two arms that satisfy a header locally and send
// nothing -- the body is already stored, or it is derivable from the header.
// When those absorb the last header the batch is complete, nothing is in
// flight, and no response will ever arrive to notice. On mainnet the node sat
// on a finished batch until the 120s execution watchdog restarted the
// pipeline, 1.9 times an hour.
// ---------------------------------------------------------------------------

/// A header whose body is derivable: it commits to the REMASC transaction
/// alone, which `derivable_body` reconstructs from the header itself.
fn derivable_header(number: u64, parent: B256) -> Header {
    let mut h = dummy_header(number, parent, U256::from(1));
    h.transactions_root =
        rustock_core::ordered_tx_trie_root(&[rustock_core::Transaction::remasc(number)], true);
    h
}

/// Every pending body is derivable, so `send_body_requests` stores them all
/// and sends nothing. With no peer registered at all, the batch cannot be
/// finished by anything arriving from the network -- a tick has to do it.
#[tokio::test]
async fn a_batch_of_derivable_bodies_is_executed_without_any_request() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    store.set_exec_head(genesis.hash(), B256::ZERO).unwrap();

    let b1 = derivable_header(1, genesis.hash());
    let b2 = derivable_header(2, b1.hash());
    for h in [&b1, &b2] {
        store.put_header(h).unwrap();
        store.put_canonical_hash(h.number, h.hash()).unwrap();
    }

    let ctrl = ExecController::new();
    let mut service = make_service(store.clone());
    service.set_test_exec(ctrl.exec_fn());

    service.state = SyncState::DownloadingBodies {
        peer_best: 2,
        pending_headers: pending_of(&[b1.clone(), b2.clone()]),
        next_request: 0,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    // This is the step that used to strand the batch: both bodies are derived
    // and stored, so nothing goes out and nothing is outstanding.
    service.send_body_requests().await;
    assert!(
        store.body(b1.hash()).unwrap().is_some() && store.body(b2.hash()).unwrap().is_some(),
        "both bodies must have been derived from their headers"
    );
    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert!(in_flight.is_empty(), "nothing can be in flight: no request was sent");
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }

    // One tick must notice the batch is complete and hand it to execution.
    ctrl.release(true);
    service.on_tick().await;
    assert!(
        service.is_executing_for_test(),
        "a batch with every body present must have been handed to execution"
    );
    assert!(
        !matches!(service.state, SyncState::DownloadingBodies { .. }),
        "and the state must not still be waiting for a body"
    );
    ctrl.wait_completed(1);
}

/// The same hole reached the other way: the bodies were already in the store,
/// so every pending header takes the "already stored" arm.
#[tokio::test]
async fn a_batch_whose_bodies_are_already_stored_is_executed_without_any_request() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let headers = store_chain(&store, 3);

    let ctrl = ExecController::new();
    let mut service = make_service(store.clone());
    service.set_test_exec(ctrl.exec_fn());

    // `store_chain` stores every body, so no request can be needed.
    service.state = SyncState::DownloadingBodies {
        peer_best: 3,
        pending_headers: pending_of(&headers),
        next_request: 0,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    ctrl.release(true);
    service.on_tick().await;
    assert!(
        service.is_executing_for_test(),
        "a batch with every body in the store must not wait for a response"
    );
    ctrl.wait_completed(1);
}

/// The guard must be narrow. A body that is genuinely missing and not
/// derivable is requested, and while that request is outstanding the tick must
/// leave the batch alone -- finishing it here would hand execution a block
/// whose body has not arrived.
#[tokio::test]
async fn a_batch_still_waiting_on_a_body_is_not_finished_by_a_tick() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    store.set_exec_head(genesis.hash(), B256::ZERO).unwrap();

    // `dummy_header` commits to an empty transaction list, which the REMASC
    // derivation does not reproduce -- so this one has to be asked for.
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1.hash()).unwrap();

    let ctrl = ExecController::new();
    let mut service = make_service(store.clone());
    service.set_test_exec(ctrl.exec_fn());

    let peer = B512::repeat_byte(0x33);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;

    service.state = SyncState::DownloadingBodies {
        peer_best: 1,
        pending_headers: pending_of(std::slice::from_ref(&b1)),
        next_request: 0,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    service.send_body_requests().await;
    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert_eq!(in_flight.len(), 1, "the missing body must have been requested");
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }

    service.on_tick().await;
    assert!(
        matches!(service.state, SyncState::DownloadingBodies { .. }),
        "a batch with an outstanding request must keep waiting"
    );
    assert!(
        store.body(b1.hash()).unwrap().is_none(),
        "and no body may have been invented for it"
    );
}

/// `in_flight` can also be empty because the request loop stopped early: with
/// no peer to take it, nothing is sent and the cursor does not reach the end.
/// That batch is not complete, so the tick must not finish it -- but it must
/// keep trying, so the request goes out once a peer appears.
#[tokio::test]
async fn an_unsendable_batch_is_retried_rather_than_finished() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    store.set_exec_head(genesis.hash(), B256::ZERO).unwrap();

    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1.hash()).unwrap();

    let ctrl = ExecController::new();
    let mut service = make_service(store.clone());
    service.set_test_exec(ctrl.exec_fn());

    service.state = SyncState::DownloadingBodies {
        peer_best: 1,
        pending_headers: pending_of(std::slice::from_ref(&b1)),
        next_request: 0,
        in_flight: std::collections::HashMap::new(),
        id_index: std::collections::HashMap::new(),
    };

    // No peers yet: nothing can be sent.
    service.on_tick().await;
    assert!(
        matches!(service.state, SyncState::DownloadingBodies { .. }),
        "a batch whose body is missing must not be declared complete"
    );

    // A peer arrives. The next tick must get the request out.
    let peer = B512::repeat_byte(0x44);
    let (tx, _rx) = mpsc::channel(rustock_networking::peers::PEER_CHANNEL_CAPACITY);
    service.peer_store_for_test().add_peer(peer, tx).await;
    service.on_tick().await;
    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert_eq!(in_flight.len(), 1, "the tick must resume a batch that could not be sent");
        }
        other => panic!("expected DownloadingBodies, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Follow mode executes a block as its body *arrives*: `drain_follow_buffer`
// is reachable only from `on_body_response`. When something empties the
// buffer for a block whose body has already come and gone -- which
// `resync_state_root_with_exec_head` does, correctly, because what it
// discards was queued against a root that no longer exists -- nothing
// re-queues it, and the block sits until the 120s watchdog.
// ---------------------------------------------------------------------------

/// Genesis + `count` canonical blocks with bodies stored, exec head at
/// genesis, service in follow mode with a matching in-memory root.
fn follow_service_with_canonical_bodies(
    store: &Arc<BlockStore>,
    count: u64,
    missing_body_at: Option<u64>,
) -> (SyncService, Vec<Header>) {
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    let root = empty.compute_hash(trie.as_ref());
    trie.put(root.as_slice(), &empty.to_message(trie.as_ref()));

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    store.put_canonical_hash(0, genesis.hash()).unwrap();
    store.set_exec_head(genesis.hash(), root).unwrap();

    let mut chain = Vec::new();
    let mut prev = genesis.hash();
    for n in 1..=count {
        let h = dummy_header(n, prev, U256::from(1));
        store.update_head(&h, U256::from(n + 1)).unwrap();
        store.put_canonical_hash(n, h.hash()).unwrap();
        if missing_body_at != Some(n) {
            store.put_body(h.hash(), &[], &[]).unwrap();
        }
        prev = h.hash();
        chain.push(h);
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    service.state = SyncState::Following;
    (service, chain)
}

/// A canonical block whose body is already stored, one ahead of the executed
/// head, with an empty follow buffer -- the state the resync leaves behind.
/// No body response is coming, so the tick must find the work itself.
#[tokio::test]
async fn a_tick_requeues_a_canonical_block_whose_body_is_already_stored() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let (mut service, chain) = follow_service_with_canonical_bodies(&store, 1, None);

    assert!(service.follow_buffer.is_empty(), "fixture must start with nothing queued");

    service.refill_follow_buffer_from_store();

    assert_eq!(
        service.follow_buffer.keys().copied().collect::<Vec<_>>(),
        vec![1u64],
        "the canonical block above the executed head must be re-queued from the store"
    );
    assert_eq!(
        service.follow_buffer.get(&1).map(|(h, _, _, _)| *h),
        Some(chain[0].hash()),
        "and it must be the canonical one"
    );
}

/// The refill stops at the backlog follow mode is willing to carry; past that
/// it is `leave_follow_if_backlog`'s job to hand over to the body pipeline.
#[tokio::test]
async fn the_refill_is_bounded_by_the_follow_backlog_tolerance() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let (mut service, _) = follow_service_with_canonical_bodies(&store, 10, None);

    service.refill_follow_buffer_from_store();

    assert_eq!(
        service.follow_buffer.len() as u64,
        crate::service::FOLLOW_BACKLOG_TOLERANCE,
        "follow mode must not hoover up an unbounded backlog"
    );
}

/// A block with no body yet is `fill_follow_body_gap`'s business, not this
/// one's: queueing a bodyless block would hand the drain something it cannot
/// execute.
#[tokio::test]
async fn the_refill_skips_a_block_whose_body_has_not_arrived() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    // The first block's body has not arrived yet.
    let (mut service, _) = follow_service_with_canonical_bodies(&store, 2, Some(1));

    service.refill_follow_buffer_from_store();

    assert!(
        service.follow_buffer.is_empty(),
        "with the lower block's body missing there is nothing executable to queue"
    );
}

/// Running while a batch executes would queue work against a root that
/// `poll_execution` has not installed yet -- the #9238768 state-root mismatch.
#[tokio::test]
async fn the_refill_stands_down_while_a_batch_is_executing() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let (mut service, chain) = follow_service_with_canonical_bodies(&store, 1, None);

    let ctrl = ExecController::new();
    service.set_test_exec(ctrl.exec_fn());
    // Hand a batch to execution; the controller holds it running.
    service.finish_batch(&pending_of(&chain), 1).await;
    assert!(service.is_executing_for_test(), "fixture must leave a batch executing");

    service.refill_follow_buffer_from_store();

    assert!(
        service.follow_buffer.is_empty(),
        "nothing may be queued while a batch is parked or running"
    );

    ctrl.release(true);
    ctrl.wait_completed(1);
}

/// The wiring: `on_tick` must actually call the refill. Block #1 is canonical
/// with a body but does not build on the executed head, so `drain_follow_buffer`
/// parks it rather than running it -- which leaves it visible in the buffer as
/// proof the tick queued it.
#[tokio::test]
async fn the_following_tick_drives_the_refill() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let empty = rustock_trie::TrieNode::empty();
    let root = empty.compute_hash(trie.as_ref());
    trie.put(root.as_slice(), &empty.to_message(trie.as_ref()));

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    store.put_body(genesis.hash(), &[], &[]).unwrap();
    store.put_canonical_hash(0, genesis.hash()).unwrap();
    store.set_exec_head(genesis.hash(), root).unwrap();

    // Canonical, bodied -- but its parent is not the executed head.
    let b1 = dummy_header(1, B256::repeat_byte(0x77), U256::from(1));
    store.update_head(&b1, U256::from(2)).unwrap();
    store.put_canonical_hash(1, b1.hash()).unwrap();
    store.put_body(b1.hash(), &[], &[]).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let mut service = SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie, empty);
    service.state = SyncState::Following;
    assert!(service.follow_buffer.is_empty());

    service.on_tick().await;

    assert!(
        service.follow_buffer.contains_key(&1),
        "the follow-mode tick must re-queue canonical work the node already holds"
    );
}

// ---------------------------------------------------------------------------
// Execute a block against its own parent's state, not against wherever
// execution happens to be standing. rskj's rule; see
// docs/follow-mode-rskj-vs-rustock.md §7.
// ---------------------------------------------------------------------------

/// Build two distinct, resolvable states in `trie` and return their roots.
fn two_states(trie: &Arc<dyn rustock_trie::TrieStore>) -> (B256, B256) {
    let a = rustock_trie::TrieNode::empty();
    let a_root = a.compute_hash(trie.as_ref());
    trie.put(a_root.as_slice(), &a.to_message(trie.as_ref()));

    let mut b = rustock_trie::TrieNode::empty();
    b = b.put(
        &rustock_trie::TrieKeySlice::from_key(&[7u8, 7, 7]),
        &[1u8; 8],
        trie.as_ref(),
    );
    b.save(trie.as_ref(), true);
    let b_root = b.compute_hash(trie.as_ref());
    assert_ne!(a_root, b_root, "fixture needs two different states");
    (a_root, b_root)
}

/// A service wired to `trie`, standing on the state `root`.
fn service_on_state(
    store: &Arc<BlockStore>,
    trie: &Arc<dyn rustock_trie::TrieStore>,
    root: B256,
) -> SyncService {
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_tx, event_rx) = mpsc::unbounded_channel();
    let processor = rustock_execution::BlockProcessor::new(
        rustock_execution::RskHardforkConfig::mainnet(),
        store.clone(),
    );
    let node = rustock_trie::TrieNode::from_message(
        &trie.get(root.as_slice()).unwrap(),
        trie.as_ref(),
    );
    SyncService::new(manager, peer_store, event_rx)
        .with_block_processor(processor, trie.clone(), node)
}

/// The 2026-10-23 #9,350,770 shape: the in-memory root is the state *after*
/// the block about to be executed, because a reorg retreated the committed
/// head without telling it. The batch must run against the parent's state.
#[tokio::test]
async fn a_batch_runs_against_its_parents_state_not_the_in_memory_root() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let (parent_root, stale_root) = two_states(&trie);

    // Parent #1 commits `parent_root`; its child #2 is the block to execute.
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut p = dummy_header(1, genesis.hash(), U256::from(1));
    p.state_root = parent_root;
    store.update_head(&p, U256::from(2)).unwrap();
    store.put_header(&p).unwrap();
    let child = dummy_header(2, p.hash(), U256::from(1));
    store.put_header(&child).unwrap();

    let service = service_on_state(&store, &trie, stale_root);

    let chosen = service.state_for_batch(&pending_of(&[child]));

    assert_eq!(
        chosen.map(|n| n.compute_hash(trie.as_ref())),
        Some(parent_root),
        "the batch must be executed against the state its parent committed, \
         not the in-memory root left behind by a retreat"
    );
}

/// The common case costs nothing and changes nothing: already standing on the
/// parent's state, so there is no substitution to make.
#[tokio::test]
async fn a_batch_already_on_its_parents_state_is_left_alone() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let (parent_root, _) = two_states(&trie);

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut p = dummy_header(1, genesis.hash(), U256::from(1));
    p.state_root = parent_root;
    store.update_head(&p, U256::from(2)).unwrap();
    store.put_header(&p).unwrap();
    let child = dummy_header(2, p.hash(), U256::from(1));

    let service = service_on_state(&store, &trie, parent_root);

    assert!(
        service.state_for_batch(&pending_of(&[child])).is_none(),
        "no substitution is needed when execution is already on the right state"
    );
}

/// A node that has pruned the parent's state, or not executed that far, must
/// fall back rather than refuse. This change removes a way of being wrong; it
/// must not add a way of stopping.
#[tokio::test]
async fn an_unresolvable_parent_state_falls_back_instead_of_refusing() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let (_, stale_root) = two_states(&trie);

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    // The parent claims a state root that is NOT in the trie store.
    let mut p = dummy_header(1, genesis.hash(), U256::from(1));
    p.state_root = B256::repeat_byte(0xAB);
    store.update_head(&p, U256::from(2)).unwrap();
    store.put_header(&p).unwrap();
    let child = dummy_header(2, p.hash(), U256::from(1));

    let service = service_on_state(&store, &trie, stale_root);

    assert!(
        service.state_for_batch(&pending_of(&[child])).is_none(),
        "an unresolvable parent state must fall back to the ambient root"
    );
}

/// Bytes stored under a hash they do not hash to must never be executed
/// against -- that is the consensus error the check exists to prevent.
#[tokio::test]
async fn a_parent_root_whose_entry_does_not_hash_to_it_is_rejected() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let (good_root, stale_root) = two_states(&trie);

    // File the good state's bytes under a hash they do not hash to.
    let liar = B256::repeat_byte(0xCD);
    trie.put(liar.as_slice(), &trie.get(good_root.as_slice()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut p = dummy_header(1, genesis.hash(), U256::from(1));
    p.state_root = liar;
    store.update_head(&p, U256::from(2)).unwrap();
    store.put_header(&p).unwrap();
    let child = dummy_header(2, p.hash(), U256::from(1));

    let service = service_on_state(&store, &trie, stale_root);

    assert!(
        service.state_for_batch(&pending_of(&[child])).is_none(),
        "a trie entry that does not hash to its key must not be executed against"
    );
}

/// The wiring: `spawn_execution` must hand the executor the parent's state,
/// not the ambient root. The unit tests above exercise the choice; this one
/// proves the choice is actually used.
#[tokio::test]
async fn spawn_execution_hands_the_executor_the_parents_state() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let trie = Arc::new(rustock_trie::MemoryTrieStore::new()) as Arc<dyn rustock_trie::TrieStore>;
    let (parent_root, stale_root) = two_states(&trie);

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let mut p = dummy_header(1, genesis.hash(), U256::from(1));
    p.state_root = parent_root;
    store.update_head(&p, U256::from(2)).unwrap();
    store.put_header(&p).unwrap();
    let child = dummy_header(2, p.hash(), U256::from(1));
    store.put_header(&child).unwrap();

    // Standing on the wrong state, as a retreat would leave it.
    let mut service = service_on_state(&store, &trie, stale_root);
    let ctrl = ExecController::new();
    service.set_test_exec(ctrl.exec_fn());
    ctrl.release(true);

    service.finish_batch(&pending_of(&[child]), 2).await;
    ctrl.wait_started(1);

    let got = ctrl.received();
    assert_eq!(got.len(), 1, "exactly one batch should have been executed");
    assert_eq!(
        got[0].compute_hash(trie.as_ref()),
        parent_root,
        "the executor was handed the in-memory root instead of the parent's state, \
         which is how #9,350,770 came to be applied on top of itself"
    );
}
