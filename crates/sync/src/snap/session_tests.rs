//! The session's judgement, tested without a network.
//!
//! These are about *what the client agrees to believe*, so they are written
//! from the attacker's side: a peer offering a chain that does not link, a
//! header that does not validate, a genesis nobody has seen.

use super::server::SnapServer;
use super::session::{Action, Phase, SnapFailure, SnapSession};
use super::SnapConfig;
use alloy_primitives::{Address, B256, U256};
use rustock_core::validation::{HeaderValidator, HeaderVerifier, ValidationError};
use rustock_core::{Block, Header};
use rustock_networking::protocol::snap::{ChunkPayload, SnapChunkRequest};
use rustock_storage::BlockStore;
use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode, TrieStore};
use std::sync::Arc;

/// A rule that refuses everything, standing in for proof of work failing.
struct RefuseEverything;

impl HeaderValidator for RefuseEverything {
    fn validate(&self, _header: &Header) -> Result<(), ValidationError> {
        Err(ValidationError::BitcoinPowInvalid {
            hash: B256::ZERO,
            target: U256::ZERO,
        })
    }
}

/// Refuses only headers below a height, so a checkpoint can pass while a
/// header further down the walk does not.
struct RefuseBelow(u64);

impl HeaderValidator for RefuseBelow {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        if header.number < self.0 {
            return Err(ValidationError::BitcoinPowInvalid {
                hash: header.hash(),
                target: U256::ZERO,
            });
        }
        Ok(())
    }
}

fn header(number: u64, parent: B256, state_root: B256, difficulty: u64) -> Header {
    Header {
        parent_hash: parent,
        ommers_hash: rustock_execution::processor::compute_ommers_hash(&[]),
        beneficiary: Address::ZERO,
        state_root,
        // The roots an empty body actually produces. A header claiming ZERO
        // alongside no transactions is not a block that could exist, and the
        // body check below is right to refuse it.
        transactions_root: rustock_core::ordered_tx_trie_root(&[], true),
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::from(difficulty),
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

fn block(h: Header) -> Block {
    Block { header: h, transactions: Vec::new(), ommers: Vec::new() }
}

/// A chain of `n` blocks from `first_number`, each worth `difficulty`, with
/// their cumulative difficulties.
fn chain(
    first_number: u64,
    n: usize,
    from_parent: B256,
    base_td: u64,
    state_root: B256,
) -> (Vec<Block>, Vec<U256>) {
    let difficulty = 100u64;
    let mut blocks = Vec::new();
    let mut tds = Vec::new();
    let mut parent = from_parent;
    let mut td = base_td;

    for i in 0..n {
        let h = header(first_number + i as u64, parent, state_root, difficulty);
        parent = h.hash();
        td += difficulty;
        tds.push(U256::from(td));
        blocks.push(block(h));
    }
    (blocks, tds)
}

/// The same, each block with one uncle as heavy as itself, and totals that
/// count it as rskj's do.
fn chain_with_uncles(
    first_number: u64,
    n: usize,
    from_parent: B256,
    base_td: u64,
    state_root: B256,
) -> (Vec<Block>, Vec<U256>) {
    let difficulty = 100u64;
    let (mut blocks, mut tds) = (Vec::new(), Vec::new());
    let (mut parent, mut td) = (from_parent, base_td);
    for i in 0..n {
        let number = first_number + i as u64;
        let uncle = header(number - 1, B256::repeat_byte(0x0c), B256::ZERO, difficulty);
        let mut h = header(number, parent, state_root, difficulty);
        h.uncle_count = 1;
        h.ommers_hash = rustock_execution::processor::compute_ommers_hash(std::slice::from_ref(&uncle));
        parent = h.hash();
        td += 2 * difficulty;
        tds.push(U256::from(td));
        blocks.push(Block { header: h, transactions: Vec::new(), ommers: vec![uncle] });
    }
    (blocks, tds)
}

struct Fixture {
    store: Arc<BlockStore>,
    trie: Arc<MemoryTrieStore>,
    state_root: B256,
    trie_root: TrieNode,
    _dir: tempfile::TempDir,
}

/// A node with a genesis and a small state trie to download.
fn fixture(state_keys: usize) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));

    let trie = Arc::new(MemoryTrieStore::new());
    let mut root = TrieNode::empty();
    for i in 0..state_keys {
        let key = [(i >> 8) as u8, i as u8, (i * 3) as u8, (i * 11) as u8];
        let value: Vec<u8> =
            if i % 4 == 0 { vec![i as u8; 80] } else { vec![i as u8, 2, 3] };
        root = root.put(&TrieKeySlice::from_key(&key), &value, trie.as_ref());
    }
    root.save(trie.as_ref(), true);
    let state_root = root.compute_hash(trie.as_ref());

    Fixture { store, trie, state_root, trie_root: root, _dir: dir }
}

impl Fixture {
    /// Records a genesis this node accepts, returning its hash.
    fn with_genesis(&self) -> B256 {
        let genesis = header(0, B256::ZERO, B256::ZERO, 100);
        let hash = genesis.hash();
        self.store.put_header_with_hash(hash, &genesis).expect("genesis");
        // As `setup_genesis` records it: genesis's total difficulty is its own.
        self.store.put_total_difficulty(hash, genesis.difficulty).expect("td");
        self.store.put_canonical_hash(0, hash).expect("index");
        hash
    }

    fn session(&self, verifier: HeaderVerifier) -> SnapSession {
        // A client store: the download writes here, not into the peer's.
        SnapSession::new(
            SnapConfig { client_enabled: true, max_in_flight: 2, chunk_bytes: 600, ..SnapConfig::default() },
            self.store.clone(),
            Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
            Arc::new(verifier),
        )
    }
}

/// Headers from the offered chain, newest first, as a peer answers.
fn headers_for(blocks: &[Block], point: u64, count: u32) -> Vec<Header> {
    let mut out = Vec::new();
    let mut n = point as i64;
    while out.len() < count as usize && n >= 0 {
        if let Some(b) = blocks.iter().find(|b| b.header.number == n as u64) {
            out.push(b.header.clone());
        }
        n -= 1;
    }
    out
}

/// Answers every header and skeleton request the session makes, until it
/// leaves the header phase. Returns the actions it was left with.
fn answer_header_walk(
    session: &mut SnapSession,
    blocks: &[Block],
    mut actions: Vec<Action>,
) -> Vec<Action> {
    for _ in 0..200 {
        if session.phase() != Phase::VerifyingHeaders {
            return actions;
        }
        if actions.is_empty() {
            actions = session.poll();
            if actions.is_empty() {
                return actions;
            }
        }
        let action = actions.remove(0);
        let next = match action {
            Action::RequestHeaders { point, count, .. } => {
                session.on_headers(point, &headers_for(blocks, point, count))
            }
            Action::RequestSkeleton { .. } => session.on_skeleton(&[]),
            other => {
                actions.push(other);
                continue;
            }
        };
        actions.extend(next);
    }
    actions
}

#[test]
fn a_fresh_session_asks_what_peers_can_serve() {
    let f = fixture(10);
    let mut session = f.session(HeaderVerifier::new());
    assert_eq!(session.poll(), vec![Action::RequestStatus]);
    assert_eq!(session.phase(), Phase::AwaitingStatus);
}

/// **The trust ordering.** No state is requested until the header chain has
/// been verified back to something this node already had. A client that got
/// this backwards would spend the download on a stranger's word.
#[test]
fn no_state_is_requested_before_the_headers_are_verified() {
    let f = fixture(60);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 5, genesis, 100, f.state_root);

    let mut session = f.session(HeaderVerifier::new());
    let actions = session.on_status(&blocks, &tds, 5_000, 0);

    assert_eq!(session.phase(), Phase::VerifyingHeaders);
    assert!(
        actions
            .iter()
            .all(|a| matches!(a, Action::RequestHeaders { .. } | Action::RequestSkeleton { .. })),
        "asked for state before verifying headers: {actions:?}"
    );
}

/// **The checkpoint's own proof of work is checked the moment it is offered.**
/// It is the one header the walk never visits as a candidate -- it is only
/// ever the child -- so nothing else would check it.
#[test]
fn a_checkpoint_that_fails_validation_is_refused_at_once() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);

    let verifier = HeaderVerifier::new().with_static_rule(RefuseEverything);
    let mut session = f.session(verifier);
    let actions = session.on_status(&blocks, &tds, 5_000, 0);

    assert_eq!(session.phase(), Phase::Failed);
    assert!(actions.is_empty(), "asked for something after refusing the checkpoint");
    assert!(matches!(session.failure(), Some(SnapFailure::InvalidHeader { .. })));
}

/// And a header further down the walk is refused too, after the checkpoint
/// has been accepted.
#[test]
fn a_header_in_the_walk_that_fails_validation_ends_the_session() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let checkpoint = blocks.last().unwrap().header.number;

    // Everything below the checkpoint fails; the checkpoint itself passes.
    let verifier = HeaderVerifier::new().with_static_rule(RefuseBelow(checkpoint));
    let mut session = f.session(verifier);
    session.on_status(&blocks, &tds, 5_000, 0);
    assert_eq!(session.phase(), Phase::VerifyingHeaders, "{:?}", session.failure());

    let checkpoint = blocks.last().unwrap().header.number;
    session.on_headers(checkpoint, &headers_for(&blocks, checkpoint, checkpoint as u32));

    assert_eq!(session.phase(), Phase::Failed);
    assert!(matches!(session.failure(), Some(SnapFailure::InvalidHeader { .. })));
}

/// Headers that do not link to what has already been verified are refused,
/// even if each one is individually well-formed.
#[test]
fn a_spliced_header_chain_is_refused() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);

    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&blocks, &tds, 5_000, 0);

    // A header from another chain entirely: valid on its own, wrong parent.
    // The pipelined walk does not fail on it -- one peer's junk should not
    // end a session -- it simply never links, so the walk stays where it was
    // and the state download never starts.
    let stranger = header(2, B256::repeat_byte(0x77), f.state_root, 100);
    session.on_headers(2, &[stranger]);

    assert_eq!(session.phase(), Phase::VerifyingHeaders, "a stranger was accepted");
    assert!(session.failure().is_none());

    // And the honest chain is still taken afterwards.
    let checkpoint = blocks.last().unwrap().header.number;
    session.on_headers(checkpoint, &headers_for(&blocks, checkpoint, checkpoint as u32));
    assert_eq!(session.phase(), Phase::DownloadingState, "{:?}", session.failure());
}

/// **Another network's chain is not this one's**, however much work is behind
/// it. Walking back to a genesis this node has never seen must fail, not
/// succeed for having reached block zero.
#[test]
fn a_chain_back_to_a_foreign_genesis_is_refused() {
    let f = fixture(20);
    // Deliberately no genesis recorded: this node knows nothing yet.
    let foreign_genesis = header(0, B256::ZERO, B256::repeat_byte(9), 100);
    let (blocks, tds) = chain(1, 2, foreign_genesis.hash(), 100, f.state_root);

    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&blocks, &tds, 5_000, 0);

    let top = blocks.last().unwrap().header.number;
    let mut all: Vec<Block> = blocks.clone();
    all.insert(0, block(foreign_genesis));
    session.on_headers(top, &headers_for(&all, top, (top + 1) as u32));

    assert_eq!(session.phase(), Phase::Failed);
    // Told apart from merely running out of answers: this one is the peer's
    // doing, and it is charged for it.
    assert_eq!(session.failure(), Some(&SnapFailure::ForeignGenesis));
}

/// **The walk may not vouch for itself.** Headers are written to the store as
/// the walk verifies them, so the test for "a block we already had" must ask
/// something the walk cannot have written: the canonical index. Otherwise a
/// peer could walk the client back to an invented genesis and have the client
/// agree, on the strength of headers it had just been handed.
#[test]
fn the_header_walk_cannot_satisfy_its_own_anchor() {
    let f = fixture(20);
    let foreign_genesis = header(0, B256::ZERO, B256::repeat_byte(9), 100);
    let (blocks, tds) = chain(1, 3, foreign_genesis.hash(), 100, f.state_root);

    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&blocks, &tds, 5_000, 0);

    // Feed the walk down to the foreign genesis, then offer it a second time:
    // by then its header is in the store, written by the walk itself.
    let top = blocks.last().unwrap().header.number;
    let mut all: Vec<Block> = blocks.clone();
    all.insert(0, block(foreign_genesis.clone()));
    session.on_headers(top, &headers_for(&all, top, (top + 1) as u32));
    assert_eq!(session.phase(), Phase::Failed, "the walk vouched for itself");
    assert_eq!(session.failure(), Some(&SnapFailure::ForeignGenesis));

    // And the chain really is in the store by hash -- which is why the check
    // has to look elsewhere.
    assert!(
        f.store.has_block(foreign_genesis.hash()).unwrap(),
        "the test is not exercising what it claims"
    );
}

/// Blocks that do not form a chain are refused before anything expensive
/// happens.
#[test]
fn a_status_whose_blocks_do_not_link_is_refused() {
    let f = fixture(20);
    let (mut blocks, tds) = chain(1, 4, B256::ZERO, 100, f.state_root);
    blocks[2] = block(header(3, B256::repeat_byte(0x55), f.state_root, 100));

    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&blocks, &tds, 5_000, 0);
    assert_eq!(session.failure(), Some(&SnapFailure::BrokenChain));
}

/// Cumulative difficulty has to account for each block's own difficulty. A
/// peer inflating it is claiming work it did not do.
#[test]
fn inflated_difficulty_is_refused() {
    let f = fixture(20);
    let (blocks, mut tds) = chain(1, 4, B256::ZERO, 100, f.state_root);
    tds[2] += U256::from(1_000_000u64);

    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&blocks, &tds, 5_000, 0);
    assert_eq!(session.failure(), Some(&SnapFailure::BadDifficulty));
}

#[test]
fn an_empty_status_is_refused() {
    let f = fixture(10);
    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&[], &[], 0, 0);
    assert_eq!(session.failure(), Some(&SnapFailure::NoCheckpoint));
}

/// The whole sequence: status, header walk to a known block, the state, then
/// the blocks behind the checkpoint.
#[test]
fn a_session_runs_to_completion() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 4, genesis, 100, f.state_root);
    let checkpoint = blocks.last().unwrap().header.clone();

    // The peer keeps its own block store, as a different node would. The
    // client knows only its genesis, so the header walk has real work to do.
    let peer_dir = tempfile::tempdir().expect("tempdir");
    let peer_store = Arc::new(BlockStore::open(peer_dir.path()).expect("open"));
    for (b, td) in blocks.iter().zip(tds.iter()) {
        let hash = b.header.hash();
        peer_store.put_header_with_hash(hash, &b.header).expect("header");
        peer_store.put_canonical_hash(b.header.number, hash).expect("index");
        peer_store.put_total_difficulty(hash, *td).expect("td");
    }

    let mut session = f.session(HeaderVerifier::new());
    let config = SnapConfig {
        server_enabled: true,
        blocks_required: 2,
        block_chunk_size: 2,
        ..SnapConfig::default()
    };

    // A server backed by the peer's copy of the state.
    let server = SnapServer::new(
        peer_store.clone(),
        f.trie.clone() as Arc<dyn TrieStore>,
        config.clone(),
    );

    let mut actions = session.on_status(&blocks, &tds, 8_000, 0);
    assert_eq!(session.phase(), Phase::VerifyingHeaders);

    let mut guard = 0;
    while session.phase() != Phase::Done && session.phase() != Phase::Failed {
        guard += 1;
        assert!(guard < 10_000, "session did not terminate in phase {:?}", session.phase());

        if actions.is_empty() {
            actions = session.poll();
            assert!(!actions.is_empty(), "stuck in phase {:?}", session.phase());
        }

        let action = actions.remove(0);
        let next = match action {
            Action::RequestStatus => session.on_status(&blocks, &tds, 8_000, 0),
            Action::RequestHeaders { point, count, .. } => {
                session.on_headers(point, &headers_for(&blocks, point, count))
            }
            Action::RequestSkeleton { .. } => session.on_skeleton(&[]),
            Action::RequestChunk { from, budget, .. } => {
                let response = server
                    .chunk(&SnapChunkRequest {
                        id: 1,
                        block_number: checkpoint.number,
                        from,
                        chunk_size: budget,
                        state_root: Some(f.state_root),
                    })
                    .expect("server answers");
                session.on_chunk(from, &response.payload, Refusal::None)
            }
            Action::RequestBlocks { block_number } => {
                // Two blocks below the checkpoint, from the offered chain.
                let answer: Vec<Block> = blocks
                    .iter()
                    .filter(|b| b.header.number < block_number)
                    .cloned()
                    .collect();
                let answer_tds: Vec<U256> = blocks
                    .iter()
                    .zip(tds.iter())
                    .filter(|(b, _)| b.header.number < block_number)
                    .map(|(_, td)| *td)
                    .collect();
                session.on_blocks(&answer, &answer_tds)
            }
        };
        actions.extend(next);
    }

    assert_eq!(session.phase(), Phase::Done, "failure: {:?}", session.failure());

    // The checkpoint's state is on disk and whole.
    let (covered, total) = session.state_progress();
    assert_eq!(Some(covered), total);
    assert_eq!(session.checkpoint().map(|h| h.number), Some(checkpoint.number));
}

/// The server-side chunk request for a root this node does not have at that
/// height is declined, not answered with a different state.
#[test]
fn the_server_will_not_substitute_a_different_state() {
    let f = fixture(30);
    let number = 20_000u64;
    let h = header(number, B256::repeat_byte(1), f.state_root, 100);
    let hash = h.hash();
    f.store.put_header_with_hash(hash, &h).expect("header");
    f.store.put_canonical_hash(number, hash).expect("index");

    let server = SnapServer::new(
        f.store.clone(),
        f.trie.clone() as Arc<dyn TrieStore>,
        SnapConfig { server_enabled: true, ..SnapConfig::default() },
    );

    // Asking for a root we do not have at that height.
    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number: number,
            from: 0,
            chunk_size: 512,
            state_root: Some(B256::repeat_byte(0xAB)),
        })
        .expect("an answer");
    match response.payload {
        ChunkPayload::Proved { entries, .. } => {
            assert!(entries.is_empty(), "served a state nobody asked for")
        }
        other => panic!("unexpected payload {other:?}"),
    }

    // The same request naming the right root is served.
    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number: number,
            from: 0,
            chunk_size: 512,
            state_root: Some(f.state_root),
        })
        .expect("an answer");
    match response.payload {
        ChunkPayload::Proved { entries, .. } => assert!(!entries.is_empty()),
        other => panic!("unexpected payload {other:?}"),
    }
    let _ = &f.trie_root;
}

/// Snapshot sync is for a node that has nothing, not one that is behind. A
/// node that has executed blocks catches up the ordinary way rather than
/// throwing away the state it has.
#[test]
fn a_node_that_has_executed_blocks_does_not_snap_sync() {
    use crate::manager::SyncManager;
    use crate::SyncService;
    use rustock_networking::peers::PeerStore;

    let f = fixture(10);
    let number = 500_000u64;
    let h = header(number, B256::repeat_byte(1), f.state_root, 100);
    let hash = h.hash();
    f.store.put_header_with_hash(hash, &h).expect("header");
    f.store.set_exec_head(hash, f.state_root).expect("exec head");

    let manager = Arc::new(SyncManager::new(
        f.store.clone(),
        Arc::new(HeaderVerifier::new()),
        Arc::new(PeerStore::new()),
    ));
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, Arc::new(PeerStore::new()), rx)
        .with_trie_store_for_test(f.trie.clone() as Arc<dyn TrieStore>);

    service.start_snap_sync(SnapConfig::default(), Arc::new(HeaderVerifier::new()));
    assert!(service.snap_phase().is_none(), "snap sync started on a node with state");
}

/// **The blocks behind the checkpoint are never executed**, so nothing
/// downstream would ever notice a body that does not belong to its header.
/// The session checks it, or no one does.
#[test]
fn a_body_that_does_not_match_its_header_is_refused() {
    use rustock_core::Transaction;

    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);

    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&blocks, &tds, 5_000, 0);
    // Anchor the walk: one request covers this whole chain, and its oldest
    // header's parent is our genesis. The actions it produces are the chunk
    // requests -- dropping them would leave every slice marked in flight with
    // nothing coming back.
    let top = blocks.last().unwrap().header.number;
    let started = session.on_headers(top, &headers_for(&blocks, top, top as u32));
    assert_eq!(session.phase(), Phase::DownloadingState, "{:?}", session.failure());

    // Skip ahead to the block phase by finishing the (tiny) state.
    // Here it is enough to call on_blocks directly once the phase allows it:
    // drive the state download to completion first.
    let peer_dir = tempfile::tempdir().expect("tempdir");
    let peer_store = Arc::new(BlockStore::open(peer_dir.path()).expect("open"));
    for (b, td) in blocks.iter().zip(tds.iter()) {
        let hash = b.header.hash();
        peer_store.put_header_with_hash(hash, &b.header).expect("header");
        peer_store.put_canonical_hash(b.header.number, hash).expect("index");
        peer_store.put_total_difficulty(hash, *td).expect("td");
    }
    let server = SnapServer::new(
        peer_store,
        f.trie.clone() as Arc<dyn TrieStore>,
        SnapConfig { server_enabled: true, ..SnapConfig::default() },
    );

    let checkpoint = blocks.last().unwrap().header.number;
    let mut actions = started;
    let mut guard = 0;
    while session.phase() == Phase::DownloadingState {
        guard += 1;
        assert!(guard < 1000, "state download stalled");
        if actions.is_empty() {
            actions = session.poll();
            assert!(!actions.is_empty(), "no work and not finished");
        }
        let action = actions.remove(0);
        if let Action::RequestChunk { from, budget, .. } = action {
            let response = server
                .chunk(&SnapChunkRequest {
                    id: 1,
                    block_number: checkpoint,
                    from,
                    chunk_size: budget,
                    state_root: Some(f.state_root),
                })
                .expect("server answers");
            actions.extend(session.on_chunk(from, &response.payload, Refusal::None));
        }
    }
    assert_eq!(session.phase(), Phase::DownloadingBlocks, "{:?}", session.failure());

    // A genuine header with a transaction it never carried.
    let mut forged = blocks[0].clone();
    forged.transactions.push(Transaction::default());
    session.on_blocks(&[forged], &[tds[0]]);

    assert_eq!(session.phase(), Phase::Failed);
    assert!(
        matches!(session.failure(), Some(SnapFailure::BadBody { what: "transactions", .. })),
        "wrong failure: {:?}",
        session.failure()
    );
}

/// A snapshot's blocks below its checkpoint complete the walk's compressed
/// headers.
///
/// From RSKIP-351 a chain's headers come compressed: a version-1 or version-2
/// header holds only the commitment to its extension, the block's logs bloom,
/// execution edges and base event, and the walk stores it so. The blocks
/// below the checkpoint come whole, and rskj stores each of them whole
/// (`SnapshotProcessor.processSnapBlocksResponse`, then
/// `BlockConnectorHelper.startConnecting`'s `saveBlock`). This node kept the
/// walk's compressed header beside the body: no bloom to answer with, and no
/// extension to send beside the body it serves.
#[test]
fn the_blocks_below_the_checkpoint_complete_the_walks_compressed_headers() {
    use crate::tests::{an_extension, compressed};
    use rustock_core::config::ActivationHeights;

    // Stores that read headers as rskj's regtest does: RSKIP-351 from block 1.
    let regtest_store = |dir: &tempfile::TempDir| {
        Arc::new(
            BlockStore::open(dir.path())
                .expect("open")
                .with_activations(ActivationHeights::regtest()),
        )
    };
    let mut f = fixture(20);
    let dir = tempfile::tempdir().expect("tempdir");
    f.store = regtest_store(&dir);
    f._dir = dir;
    let genesis = f.with_genesis();

    // Each block whole, and its header as the walk is sent it.
    let mut parent = genesis;
    let (mut whole, mut walked, mut tds) = (Vec::new(), Vec::new(), Vec::new());
    for number in 1..=3u64 {
        let extension = an_extension(number as usize);
        let sent = compressed(header(number, parent, f.state_root, 100), &extension);
        let full = sent
            .with_extension(&extension)
            .expect("the extension it names");
        assert_eq!(full.hash(), sent.hash(), "both forms hash alike");
        parent = sent.hash();
        walked.insert(0, sent);
        whole.push(block(full));
        tds.push(U256::from(100 + 100 * number));
    }

    // The status carries the checkpoint, whole; the walk brings the headers
    // under it, compressed.
    let mut session = f.session(HeaderVerifier::new());
    session.on_status(std::slice::from_ref(&whole[2]), &tds[2..], 5_000, 0);
    let started = session.on_headers(3, &walked);
    assert_eq!(
        session.phase(),
        Phase::DownloadingState,
        "{:?}",
        session.failure()
    );
    for b in &whole[..2] {
        let held = f.store.header(b.header.hash()).unwrap().expect("walked");
        assert_eq!(
            held.extension(),
            None,
            "the walk holds #{} compressed",
            b.header.number
        );
    }

    let peer_dir = tempfile::tempdir().expect("tempdir");
    let peer_store = regtest_store(&peer_dir);
    for (b, td) in whole.iter().zip(tds.iter()) {
        let hash = b.header.hash();
        peer_store
            .put_header_with_hash(hash, &b.header)
            .expect("header");
        peer_store
            .put_canonical_hash(b.header.number, hash)
            .expect("index");
        peer_store.put_total_difficulty(hash, *td).expect("td");
    }
    let server = SnapServer::new(
        peer_store,
        f.trie.clone() as Arc<dyn TrieStore>,
        SnapConfig {
            server_enabled: true,
            ..SnapConfig::default()
        },
    );
    let mut actions = started;
    let mut guard = 0;
    while session.phase() == Phase::DownloadingState {
        guard += 1;
        assert!(guard < 1000, "state download stalled");
        if actions.is_empty() {
            actions = session.poll();
            assert!(!actions.is_empty(), "no work and not finished");
        }
        if let Action::RequestChunk { from, budget, .. } = actions.remove(0) {
            let response = server
                .chunk(&SnapChunkRequest {
                    id: 1,
                    block_number: 3,
                    from,
                    chunk_size: budget,
                    state_root: Some(f.state_root),
                })
                .expect("server answers");
            actions.extend(session.on_chunk(from, &response.payload, Refusal::None));
        }
    }
    assert_eq!(
        session.phase(),
        Phase::DownloadingBlocks,
        "{:?}",
        session.failure()
    );

    session.on_blocks(&whole[..2], &tds[..2]);
    assert_eq!(session.phase(), Phase::Done, "{:?}", session.failure());
    for (b, bit) in whole[..2].iter().zip(1..) {
        let held = f.store.header(b.header.hash()).unwrap().expect("held");
        assert_eq!(
            held.extension(),
            Some(an_extension(bit)),
            "#{} is held whole, with the extension its hash commits to",
            b.header.number
        );
    }
}

// ------------------------------------------------------- blaming the peer

use alloy_primitives::B512;
use crate::snap::driver::{Blame, Peers, SnapDriver};
use rustock_networking::protocol::{P2pMessage, RskSubMessage};
use rustock_networking::protocol::snap::Refusal;
use rustock_networking::scoring::EventType;

/// What a driver asked for, and under which id, so a test can answer it.
fn asked(out: &crate::snap::driver::Outbound) -> (u64, &'static str) {
    let P2pMessage::RskMessage(m) = &out.message else { panic!("not an rsk message") };
    match &m.sub_message {
        RskSubMessage::SnapStatusRequest(r) => (r.id, "status"),
        RskSubMessage::BlockHeadersRequest(r) => (r.id, "headers"),
        RskSubMessage::SkeletonRequest(r) => (r.id, "skeleton"),
        RskSubMessage::SnapChunkRequest(r) => (r.id, "chunk"),
        RskSubMessage::SnapBlocksRequest(r) => (r.id, "blocks"),
        other => panic!("unexpected request {other:?}"),
    }
}

/// A driver whose session has been driven to the state-download phase, with a
/// chunk request outstanding. Returns the driver, the peers, and the
/// (id, offset) of that outstanding request.
fn driver_awaiting_a_chunk(
    f: &Fixture,
    blocks: &[Block],
    tds: &[U256],
    peers: &[B512],
) -> (SnapDriver, u64, u64, B512) {
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));

    let mut out = driver.poll(peers);
    let (status_id, kind) = asked(&out[0]);
    assert_eq!(kind, "status");
    // Answer from the peer each request was addressed to: the driver only
    // accepts an answer from the peer it asked.
    let to = out[0].peer;
    out = driver.on_status(status_id, to, blocks, tds, 8_000, 0, peers);

    // Walk the headers down to genesis, answering from the offered chain.
    let mut guard = 0;
    loop {
        guard += 1;
        assert!(guard < 100, "header walk did not finish");
        let (id, kind) = asked(&out[0]);
        if kind == "chunk" {
            break;
        }
        let to = out[0].peer;
        let P2pMessage::RskMessage(m) = &out[0].message else { unreachable!() };
        out = match m.sub_message.clone() {
            RskSubMessage::BlockHeadersRequest(req) => {
                // The walk files a request by the height it fills; answer it
                // from the offered chain, newest first.
                let point = blocks
                    .iter()
                    .find(|b| b.header.hash() == req.query.hash)
                    .map_or(0, |b| b.header.number);
                driver.on_headers(id, to, &headers_for(blocks, point, req.query.count), peers)
            }
            RskSubMessage::SkeletonRequest(_) => {
                driver.on_skeleton(id, to, &[], peers)
            }
            other => panic!("unexpected request {other:?}"),
        };
        assert!(!out.is_empty(), "the walk stalled");
    }

    let P2pMessage::RskMessage(m) = &out[0].message else { unreachable!() };
    let RskSubMessage::SnapChunkRequest(req) = &m.sub_message else { unreachable!() };
    (driver, req.id, req.from, out[0].peer)
}

/// **The point of the whole exercise.** A peer whose chunk fails its proof is
/// named and charged. Refusing bad data without charging anyone costs the
/// sender nothing, so it can do it again immediately, forever.
#[test]
fn a_peer_whose_chunk_fails_its_proof_is_charged() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    assert!(driver.take_blame().is_empty(), "nobody should owe anything yet");

    // A genuine chunk with one byte flipped, from a peer we can name.
    let liar = server;
    let mut payload = served_chunk(&f, from);
    tamper(&mut payload);
    driver.on_chunk(id, liar, &payload, Refusal::None, &peers);

    let blame = driver.take_blame();
    assert_eq!(blame.len(), 1, "expected exactly one charge, got {blame:?}");
    assert_eq!(blame[0].peer, liar, "charged the wrong peer");
    assert_eq!(blame[0].event, EventType::InvalidMessage);
}

/// A chunk from a peer that was never asked is not taken, however well it is
/// formed. Accepting it would consume the request and leave the genuine
/// answer, when it came, to be dropped as unknown.
#[test]
fn a_chunk_from_a_peer_that_was_not_asked_is_ignored() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.take_blame();

    let interloper = B512::repeat_byte(77);
    assert_ne!(interloper, server);
    let mut payload = served_chunk(&f, from);
    tamper(&mut payload);

    // Tampered, so if it were taken at all the sender would be charged.
    driver.on_chunk(id, interloper, &payload, Refusal::None, &peers);
    assert!(
        driver.take_blame().is_empty(),
        "a chunk from a peer that was not asked should be ignored, not judged"
    );

    // And the request is still outstanding: the same tampered payload from
    // the peer that *was* asked is taken, and charged. Only a live request
    // can produce that.
    driver.on_chunk(id, server, &payload, Refusal::None, &peers);
    let blame = driver.take_blame();
    assert_eq!(blame.len(), 1, "the request should still have been in flight");
    assert_eq!(blame[0].peer, server);
}

/// A peer that serves honestly owes nothing. An implementation that charged on
/// every answer would ban the network.
#[test]
fn an_honest_peer_is_never_charged() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.take_blame();

    driver.on_chunk(id, server, &served_chunk(&f, from), Refusal::None, &peers);
    assert!(driver.take_blame().is_empty(), "charged an honest peer");
}

/// A peer declining to serve is behaving correctly -- it may have pruned the
/// state, or be on another chain. It is dropped from the rotation, not
/// punished: punishing it would teach the network to stop offering.
#[test]
fn a_peer_that_declines_is_dropped_not_punished() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, _from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.take_blame();

    let pruned = server;
    let declined = ChunkPayload::Proved { entries: Vec::new(), witness: Vec::new() };
    driver.on_chunk(id, pruned, &declined, Refusal::None, &peers);

    assert!(driver.take_blame().is_empty(), "punished a peer for declining");
    assert!(driver.unhelpful().contains(&pruned), "kept asking a peer that cannot serve");
}

/// An rskj peer sending a chunk that does not rebuild is charged like any
/// other bad data. Reading their format does not mean trusting it.
#[test]
fn an_rskj_chunk_that_does_not_rebuild_is_charged() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, _from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.take_blame();

    // A well-formed but empty rskj blob: it decodes and rebuilds to nothing
    // like the state root.
    let liar = server;
    let blob = rustock_trie::snapshot_legacy::encode_blob(&Default::default());
    driver.on_chunk(id, liar, &ChunkPayload::Legacy(blob.into()), Refusal::None, &peers);

    let blame = driver.take_blame();
    assert_eq!(blame.len(), 1, "got {blame:?}");
    assert_eq!(blame[0].peer, liar);
    assert_eq!(blame[0].event, EventType::InvalidMessage);
}

/// An rskj chunk of the fixture's state, as an rskj server answers `from`.
fn rskj_chunk(f: &Fixture, from: u64, cell: u64) -> ChunkPayload {
    use rustock_trie::snapshot_legacy::{encode_blob, legacy_chunk};
    let root: [u8; 32] = f.state_root.into();
    let chunk = legacy_chunk(&root, from, from + cell, f.trie.as_ref()).expect("a chunk");
    ChunkPayload::Legacy(encode_blob(&chunk).into())
}

/// An honest rskj chunk is kept, moves the download as far as it reached,
/// and costs its sender nothing.
#[test]
fn an_honest_rskj_chunk_is_kept_and_not_charged() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.take_blame();

    driver.on_chunk(id, server, &rskj_chunk(&f, from, 4_000), Refusal::None, &peers);

    assert!(driver.take_blame().is_empty(), "an honest rskj peer was charged");
    let (covered, total) = driver.state_progress();
    assert!(covered > 0, "the chunk moved nothing");
    assert_eq!(
        total,
        Some(rustock_trie::snapshot::total_size(&f.trie_root, f.trie.as_ref())),
        "the size of the trie comes from the rebuilt root, not the peer's hint"
    );
}

/// An rskj chunk that answers another offset is charged: its nodes are
/// genuine, but it is not an answer to the question, any more than a proved
/// chunk for the wrong offset is.
#[test]
fn an_rskj_chunk_for_another_offset_is_charged() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.take_blame();

    let total = rustock_trie::snapshot::total_size(&f.trie_root, f.trie.as_ref());
    let elsewhere = rskj_chunk(&f, from + total / 2, 1_000);
    driver.on_chunk(id, server, &elsewhere, Refusal::None, &peers);

    let blame = driver.take_blame();
    assert_eq!(blame.len(), 1, "got {blame:?}");
    assert_eq!(blame[0].peer, server);
    assert_eq!(blame[0].event, EventType::InvalidMessage);
    assert_eq!(driver.state_progress().0, 0, "a chunk for another offset moved the download");
}

/// An rskj chunk with nothing of its own -- what rskj answers when the node at
/// the offset outruns its cell -- is not held against the peer, and the node,
/// which rskj sends whole on the stack it hands back, is kept.
#[test]
fn an_rskj_chunk_with_nothing_of_its_own_is_not_charged() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.take_blame();

    // A one-byte cell: no node fits, so the chunk carries only the path to it.
    let nothing = rskj_chunk(&f, from, 1);
    let ChunkPayload::Legacy(blob) = &nothing else { unreachable!() };
    let chunk = rustock_trie::snapshot_legacy::decode_blob(blob).expect("decodes");
    assert!(chunk.nodes.is_empty() && !chunk.post_root.is_empty(), "not the chunk this test is about");

    driver.on_chunk(id, server, &nothing, Refusal::None, &peers);
    assert!(driver.take_blame().is_empty(), "charged a peer for the offset it was asked");
    assert!(!driver.unhelpful().contains(&server), "stopped asking a peer that can serve");
    assert!(driver.state_progress().0 > 0, "the node at the offset, sent whole, was not kept");
}

/// **Answers that move nothing end the session**, however well they rebuild.
/// Each was taken as progress and reset the count of answers in a row that
/// added nothing, so a session whose answers no longer moved it asked again
/// forever: testnet's stood at 94% for hours. They count now, and the session
/// gives up, as it does when every answer declines.
#[test]
fn answers_that_move_nothing_end_the_session() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let mut session = f.session(HeaderVerifier::new());
    session.on_status(&blocks, &tds, 5_000, 0);
    let top = blocks.last().unwrap().header.number;
    let mut actions = session.on_headers(top, &headers_for(&blocks, top, top as u32));
    assert_eq!(
        session.phase(),
        Phase::DownloadingState,
        "{:?}",
        session.failure()
    );

    // Every request gets the chunk for the trie's first 2,000 bytes: genuine,
    // and taken, but after the first time it holds nothing not already held.
    let first = rskj_chunk(&f, 0, 2_000);
    let mut answers = 0;
    while session.phase() == Phase::DownloadingState {
        if actions.is_empty() {
            actions = session.poll();
        }
        let Some(Action::RequestChunk { from, .. }) = actions.pop() else {
            panic!("nothing asked, and the session still downloading");
        };
        answers += 1;
        assert!(answers < 1_000, "the session never gave up");
        actions.extend(session.on_chunk(from, &first, Refusal::None));
    }
    assert!(
        matches!(session.failure(), Some(SnapFailure::NoProgress(_))),
        "{:?}",
        session.failure()
    );
    assert!(answers > 64, "gave up after {answers} answers");
}

/// The chunk requests among a batch of outbound messages: id, offset, peer.
fn chunk_requests(out: &[super::driver::Outbound]) -> Vec<(u64, u64, B512)> {
    out.iter()
        .filter_map(|o| {
            let P2pMessage::RskMessage(m) = &o.message else { return None };
            let RskSubMessage::SnapChunkRequest(req) = &m.sub_message else { return None };
            Some((req.id, req.from, o.peer))
        })
        .collect()
}

/// After an rskj chunk the session asks for the offset just past where it
/// stopped, which only an rskj server takes; a server that refuses the offset
/// as off its grid gets the cell next, not the same offset again.
#[test]
fn an_offset_refused_as_off_the_grid_is_asked_on_the_grid_next() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let peers = vec![B512::repeat_byte(1), B512::repeat_byte(2)];

    let (mut driver, id, from, server) = driver_awaiting_a_chunk(&f, &blocks, &tds, &peers);
    driver.on_chunk(id, server, &rskj_chunk(&f, from, 2_000), Refusal::None, &peers);
    let (cursor, _) = driver.state_progress();
    assert!(cursor > 0, "the chunk moved nothing");
    // Let whatever else the setup left outstanding time out, so the budget
    // has room for the request this is about. Timing out is charged; that is
    // not what this test is about.
    driver.expire(std::time::Instant::now() + std::time::Duration::from_secs(60));
    driver.take_blame();
    let out = driver.poll(&peers);

    let exact = chunk_requests(&out);
    let &(id, asked, peer) = exact
        .iter()
        .find(|(_, asked, _)| *asked == cursor + 1)
        .unwrap_or_else(|| panic!("nothing asked just past the cursor {cursor}: {exact:?}"));
    assert_ne!(asked % 100_000, 0, "the exact offset happens to be on the grid; the test proves nothing");

    let refused = ChunkPayload::Proved { entries: Vec::new(), witness: Vec::new() };
    let out = driver.on_chunk(id, peer, &refused, Refusal::OffsetNotOnGrid, &peers);
    assert!(driver.take_blame().is_empty(), "a refusal about the offset was charged");
    let next = chunk_requests(&out);
    assert!(
        next.iter().any(|(_, asked, _)| *asked == cursor / 100_000 * 100_000),
        "the refused offset was not replaced by its cell: {next:?}"
    );
    assert!(
        next.iter().all(|(_, asked, _)| *asked != cursor + 1),
        "the refused offset was asked again: {next:?}"
    );
}

/// A peer that offers a chain which does not link is charged for the status,/// A peer that offers a chain which does not link is charged for the status,
/// not merely ignored.
#[test]
fn a_peer_offering_a_broken_chain_is_charged() {
    let f = fixture(20);
    let (mut blocks, tds) = chain(1, 4, B256::ZERO, 100, f.state_root);
    blocks[2] = block(header(3, B256::repeat_byte(0x55), f.state_root, 100));

    let peers = vec![B512::repeat_byte(1)];
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));
    let out = driver.poll(&peers);
    let (id, _) = asked(&out[0]);

    let liar = out[0].peer;
    driver.on_status(id, liar, &blocks, &tds, 5_000, 0, &peers);

    let blame = driver.take_blame();
    assert_eq!(blame.len(), 1, "got {blame:?}");
    assert_eq!(blame[0].peer, liar);
    assert_eq!(blame[0].event, EventType::InvalidMessage);
}

/// A header that fails proof of work is charged as a bad header, which scores
/// differently from a merely malformed message.
#[test]
fn a_peer_serving_an_unmined_header_is_charged_for_the_header() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let checkpoint = blocks.last().unwrap().header.number;
    let peers = vec![B512::repeat_byte(1)];

    let mut driver =
        SnapDriver::new(f.session(HeaderVerifier::new().with_static_rule(RefuseBelow(checkpoint))));
    let out = driver.poll(&peers);
    let (status_id, _) = asked(&out[0]);
    let out = driver.on_status(status_id, peers[0], &blocks, &tds, 5_000, 0, &peers);
    driver.take_blame();

    let (headers_id, kind) = asked(&out[0]);
    assert_eq!(kind, "headers");
    let liar = out[0].peer;
    driver.on_headers(headers_id, liar, &[blocks[blocks.len() - 2].header.clone()], &peers);

    let blame = driver.take_blame();
    assert_eq!(blame.len(), 1, "got {blame:?}");
    assert_eq!(blame[0].peer, liar);
    assert_eq!(blame[0].event, EventType::InvalidHeader);
}

/// A request nobody answered is the peer's fault too, or a slow peer would
/// hold work forever at no cost.
#[test]
fn a_timed_out_request_is_charged() {
    let f = fixture(20);
    let peers = vec![B512::repeat_byte(1)];
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));
    driver.poll(&peers);

    let long_after = std::time::Instant::now() + std::time::Duration::from_secs(600);
    assert_eq!(driver.expire(long_after), 1, "the request should have expired");

    let blame: Vec<Blame> = driver.take_blame();
    assert_eq!(blame.len(), 1);
    assert_eq!(blame[0].peer, peers[0]);
    assert_eq!(blame[0].event, EventType::TimeoutMessage);
}

// ------------------------------------------------ who is asked for what

/// The header walk asks ordinary peers. Its header and skeleton requests are
/// messages every peer serves, and with only the `snap` peers to ask, the walk
/// stalled for good on mainnet when the one peer that had offered the
/// checkpoint stopped answering, with fifteen other peers connected.
#[test]
fn the_header_walk_asks_peers_without_snap() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let server = B512::repeat_byte(1);
    let plain = B512::repeat_byte(2);
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));

    let out = driver.poll(Peers { snap: &[server], uncles: &[], any: &[server, plain] });
    let (status_id, kind) = asked(&out[0]);
    assert_eq!(kind, "status");
    assert_eq!(out[0].peer, server, "a status request goes only to a snap peer");

    // Only an ordinary peer is left to ask, as when the server stops answering.
    let only_plain = Peers { snap: &[], uncles: &[], any: &[plain] };
    let out = driver.on_status(status_id, server, &blocks, &tds, 5_000, 0, only_plain);
    assert!(!out.is_empty(), "the walk stalled with an ordinary peer to ask");
    for request in &out {
        let (_, kind) = asked(request);
        assert!(matches!(kind, "headers" | "skeleton"), "asked an ordinary peer for a {kind}");
        assert_eq!(request.peer, plain);
    }
}

/// A snapshot message never goes to a peer that did not announce `snap`: rskj
/// closes the connection on a message id it does not know, so asking the wrong
/// peer would lose it.
#[test]
fn snapshot_requests_go_only_to_snap_peers() {
    let f = fixture(20);
    let server = B512::repeat_byte(1);
    let plain = B512::repeat_byte(2);
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));

    let out = driver.poll(Peers { snap: &[], uncles: &[plain], any: &[plain] });
    assert!(out.is_empty(), "asked a peer without snap for a snapshot message");
    assert!(driver.outstanding_ids().is_empty());

    let out = driver.poll(Peers { snap: &[server], uncles: &[], any: &[server, plain] });
    let (_, kind) = asked(&out[0]);
    assert_eq!(kind, "status");
    assert_eq!(out[0].peer, server);
}

/// A request that nobody connected can take is handed back, not lost: once a
/// peer that can take it is there, it is asked.
#[test]
fn a_request_nobody_can_take_is_asked_once_somebody_can() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let server = B512::repeat_byte(1);
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));

    let out = driver.poll(&[server]);
    let (status_id, _) = asked(&out[0]);
    let nobody_for_headers = Peers { snap: &[server], uncles: &[], any: &[] };
    let out = driver.on_status(status_id, server, &blocks, &tds, 5_000, 0, nobody_for_headers);
    assert!(out.is_empty());
    assert!(
        driver.outstanding_ids().is_empty(),
        "a request that was never sent still counts against the budget"
    );

    let plain = B512::repeat_byte(2);
    let out = driver.poll(Peers { snap: &[], uncles: &[], any: &[plain] });
    assert!(!out.is_empty(), "the walk's requests were lost");
    assert!(out.iter().all(|request| request.peer == plain));
}

/// An empty answer hands its range back, to be asked of somebody else.
///
/// Left marked as asked, it never was again. When the range was the walk's
/// frontier, as here, nothing could move the walk past it.
#[test]
fn an_empty_header_answer_is_asked_again() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 4, genesis, 100, f.state_root);
    let mut session = f.session(HeaderVerifier::new());

    let first = session.on_status(&blocks, &tds, 8_000, 0);
    assert_eq!(session.phase(), Phase::VerifyingHeaders);
    let asked = first
        .iter()
        .find(|a| matches!(a, Action::RequestHeaders { .. }))
        .cloned()
        .expect("the walk asks for headers");
    let Action::RequestHeaders { point, .. } = asked else { unreachable!() };

    let again = session.on_headers(point, &[]);
    assert!(again.contains(&asked), "the range was not asked for again: {again:?}");
}

/// A peer that left a request unanswered sits out while somebody else can be
/// asked. On mainnet about half the peers never answered a header request,
/// and each one's turn in the rotation cost the walk thirty seconds.
#[test]
fn a_peer_that_left_a_request_unanswered_sits_out() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 3, genesis, 100, f.state_root);
    let server = B512::repeat_byte(1);
    let silent = B512::repeat_byte(2);
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));

    let out = driver.poll(&[server]);
    let (status_id, _) = asked(&out[0]);
    // At first only `silent` can be asked for headers, and it answers nothing.
    let only_silent = Peers { snap: &[server], uncles: &[], any: &[silent] };
    let out = driver.on_status(status_id, server, &blocks, &tds, 5_000, 0, only_silent);
    assert!(!out.is_empty() && out.iter().all(|request| request.peer == silent));
    let later = std::time::Instant::now() + std::time::Duration::from_secs(31);
    assert_eq!(driver.expire(later), out.len());

    let out = driver.poll(Peers { snap: &[server], uncles: &[], any: &[server, silent] });
    assert!(!out.is_empty(), "the walk's requests were not asked again");
    assert!(
        out.iter().all(|request| request.peer == server),
        "a peer that answered nothing was asked again with another peer to ask"
    );
}

/// But a peer sitting out is still asked when nobody else can be: a slow peer
/// beats none, and a sync left with only such peers must still finish.
#[test]
fn a_peer_sitting_out_is_asked_when_nobody_else_can_be() {
    let f = fixture(20);
    let peers = vec![B512::repeat_byte(1)];
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));
    driver.poll(&peers);
    let later = std::time::Instant::now() + std::time::Duration::from_secs(31);
    assert_eq!(driver.expire(later), 1);

    let out = driver.poll(&peers);
    assert_eq!(out.len(), 1, "the request was not asked again");
    assert_eq!(out[0].peer, peers[0]);
}

/// Serves a real chunk for `from` out of the fixture's trie.
fn served_chunk(f: &Fixture, from: u64) -> ChunkPayload {
    let root_message = f.trie.get(f.state_root.as_slice()).expect("root");
    let root = TrieNode::from_message(&root_message, f.trie.as_ref());
    let proof = rustock_trie::snapshot_proof::prove_chunk(&root, from, 600, f.trie.as_ref());
    ChunkPayload::Proved {
        entries: proof
            .entries
            .iter()
            .map(|e| rustock_networking::protocol::snap::SnapEntry {
                message: e.message.clone().into(),
                long_values: e.long_values.iter().map(|v| v.clone().into()).collect(),
            })
            .collect(),
        witness: proof.witness.iter().map(|w| w.clone().into()).collect(),
    }
}

/// Flips a bit in the middle of a chunk, so every node is genuine but one.
fn tamper(payload: &mut ChunkPayload) {
    let ChunkPayload::Proved { entries, .. } = payload else { panic!("not a proved chunk") };
    assert!(!entries.is_empty(), "nothing to tamper with");
    let victim = entries.len() / 2;
    let mut bytes = entries[victim].message.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    entries[victim].message = bytes.into();
}

/// **One peer must not be able to end snapshot sync.** A malformed status used
/// to fail the session, and nothing ever started another: a single bad message
/// from a single peer turned the feature off for the life of the process, at
/// no cost to the sender.
#[tokio::test]
async fn a_bad_peer_does_not_end_snapshot_sync() {
    use crate::events::SyncEvent;
    use crate::manager::SyncManager;
    use crate::snap::session::Phase;
    use crate::SyncService;
    use rustock_networking::peers::PeerStore;

    let f = fixture(20);
    f.with_genesis();
    // A chain whose blocks do not link: refused on sight.
    let (mut blocks, tds) = chain(1, 4, B256::ZERO, 100, f.state_root);
    blocks[2] = block(header(3, B256::repeat_byte(0x55), f.state_root, 100));

    let peers = Arc::new(PeerStore::new());
    let liar = B512::repeat_byte(9);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    // A snapshot session only ever talks to peers that announced `snap`;
    // the service filters on it, so the fixture has to say so.
    peers
        .add_peer_with(
            liar,
            tx,
            rustock_networking::handshake::PeerCapabilities { rsk_version: 62, snap: true },
        )
        .await;

    let manager = Arc::new(SyncManager::new(
        f.store.clone(),
        Arc::new(HeaderVerifier::new()),
        peers.clone(),
    ));
    let (_event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peers, event_rx)
        .with_trie_store_for_test(f.trie.clone() as Arc<dyn TrieStore>);

    service.start_snap_sync(SnapConfig::default(), Arc::new(HeaderVerifier::new()));
    assert_eq!(service.snap_phase(), Some(Phase::AwaitingStatus));

    // The driver has to have asked before an answer means anything.
    service.on_tick().await;

    // Answer with the broken chain, as the lying peer.
    service
        .handle_event(SyncEvent::SnapStatusResponse {
            peer: liar,
            id: service.snap_request_id_for_test().expect("a status request is outstanding"),
            blocks: blocks.clone(),
            difficulties: tds.clone(),
            trie_size: 5_000,
            chunk_grid: 0,
        })
        .await;

    // The session failed, and another one took its place rather than the
    // feature switching itself off.
    assert!(
        service.snap_phase().is_some(),
        "one bad status ended snapshot sync for good"
    );
    assert_eq!(service.snap_phase(), Some(Phase::AwaitingStatus));
    assert!(service.snap_attempts_for_test() >= 2, "no second attempt was made");
}

/// The charge must actually reach peer scoring. The driver naming a culprit is
/// only useful if the service hands it to the thing that punishes.
#[tokio::test]
async fn a_charge_reaches_peer_scoring() {
    use crate::events::SyncEvent;
    use crate::manager::SyncManager;
    use crate::SyncService;
    use rustock_networking::peers::PeerStore;
    use rustock_networking::scoring::ScoringService;

    let f = fixture(20);
    f.with_genesis();
    let (mut blocks, tds) = chain(1, 4, B256::ZERO, 100, f.state_root);
    blocks[2] = block(header(3, B256::repeat_byte(0x55), f.state_root, 100));

    let peers = Arc::new(PeerStore::new());
    let liar = B512::repeat_byte(9);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    // A snapshot session only ever talks to peers that announced `snap`;
    // the service filters on it, so the fixture has to say so.
    peers
        .add_peer_with(
            liar,
            tx,
            rustock_networking::handshake::PeerCapabilities { rsk_version: 62, snap: true },
        )
        .await;

    let scoring = Arc::new(ScoringService::in_memory());
    let before = scoring.with(|m| m.node_has_good_reputation(liar));
    assert!(before, "a peer starts in good standing");

    let manager = Arc::new(SyncManager::new(
        f.store.clone(),
        Arc::new(HeaderVerifier::new()),
        peers.clone(),
    ));
    let (_event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peers, event_rx)
        .with_trie_store_for_test(f.trie.clone() as Arc<dyn TrieStore>)
        .with_scoring(Some(scoring.clone()));

    service.start_snap_sync(SnapConfig::default(), Arc::new(HeaderVerifier::new()));
    service.on_tick().await;

    let id = service.snap_request_id_for_test().expect("a status request is outstanding");
    service
        .handle_event(SyncEvent::SnapStatusResponse {
            peer: liar,
            id,
            blocks,
            difficulties: tds,
            trie_size: 5_000,
            chunk_grid: 0,
        })
        .await;

    // The peer now carries a recorded InvalidMessage and a negative score.
    let info = scoring.with(|m| m.information());
    let entry = info
        .iter()
        .find(|i| i.kind == "node" && i.counters.iter().any(|(_, n)| *n > 0))
        .unwrap_or_else(|| panic!("no peer was scored at all: {info:?}"));

    assert!(
        entry.counters.iter().any(|(name, n)| *name == "invalidMessages" && *n > 0),
        "the charge did not land as an invalid message: {:?}",
        entry.counters
    );
    assert!(entry.score < 0, "a charged peer should have lost points: {}", entry.score);
}

/// **The in-flight budget must bound what is outstanding, not what is issued
/// per poll.**
///
/// The session is polled every tick and knows only what work remains, so left
/// to itself it hands back a fresh budget's worth each time. Measured against
/// a real server before this was enforced: ~3,000 requests outstanding against
/// a budget of 8, every one aging out at the 30s timeout and being reissued
/// while the server's answers arrived long after the client had given up on
/// them. See #185.
#[test]
fn outstanding_snap_requests_never_exceed_the_budget() {
    let f = fixture(64);
    let genesis = f.with_genesis();
    // A chain deep enough that the walk has far more points to ask for than
    // the budget allows, which is the condition that grew the queue.
    let (blocks, tds) = chain(1, 4_000, genesis, 100, f.state_root);
    let peers: Vec<B512> = (1..=3).map(B512::repeat_byte).collect();
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));

    // Answer the status so the session enters the header walk, then poll
    // repeatedly **without answering anything**, as a tick loop would.
    let out = driver.poll(&peers);
    let (status_id, kind) = asked(&out[0]);
    assert_eq!(kind, "status");
    driver.on_status(status_id, peers[0], &blocks, &tds, 8_000, 0, &peers);

    // The walk's budget: two for each peer it can ask, never less than
    // `max_in_flight` (which `Fixture::session` sets to 2).
    let budget = 2usize.max(2 * peers.len());
    // Poll *and* feed responses back, so the response handlers are exercised
    // too -- capping only `poll` left those five paths issuing a fresh
    // budget's worth each.
    for tick in 0..200 {
        driver.poll(&peers);
        if let Some(id) = driver.outstanding_ids().first().copied() {
            // An empty answer: rejected, the request released, the handler's
            // own asking path taken.
            driver.on_headers(id, peers[0], &[], &peers);
        }
        assert!(
            driver.outstanding_ids().len() <= budget,
            "tick {tick}: {} requests outstanding against a budget of {budget}",
            driver.outstanding_ids().len()
        );
    }
}

/// The header walk's budget is per peer, since every peer serves headers.
/// Held to the eight a state download is allowed, forty peers sat mostly
/// idle on mainnet through a walk of hours.
#[test]
fn the_header_walk_asks_more_of_more_peers() {
    let f = fixture(64);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 4_000, genesis, 100, f.state_root);
    let peers: Vec<B512> = (1..=10).map(B512::repeat_byte).collect();
    let mut driver = SnapDriver::new(f.session(HeaderVerifier::new()));

    let out = driver.poll(&peers);
    let (status_id, _) = asked(&out[0]);
    let mut out = driver.on_status(status_id, peers[0], &blocks, &tds, 8_000, 0, &peers);

    // Answer the skeletons honestly, so the walk knows more points than any
    // budget allows, and leave the header requests outstanding.
    for _ in 0..10 {
        let mut next = Vec::new();
        for request in &out {
            let P2pMessage::RskMessage(m) = &request.message else { continue };
            let RskSubMessage::SkeletonRequest(r) = &m.sub_message else { continue };
            let ids: Vec<rustock_networking::protocol::BlockIdentifier> = blocks
                .iter()
                .map(|b| &b.header)
                .filter(|h| h.number % 192 == 0)
                .filter(|h| h.number >= r.start_number && h.number <= r.start_number + 3_840)
                .map(|h| rustock_networking::protocol::BlockIdentifier { number: h.number, hash: h.hash() })
                .collect();
            next.extend(driver.on_skeleton(r.id, request.peer, &ids, &peers));
        }
        if next.is_empty() {
            break;
        }
        out = next;
    }

    let outstanding = driver.outstanding_ids().len();
    assert!(outstanding > 2, "held to a state download's budget: {outstanding} outstanding");
    assert!(outstanding <= 2 * peers.len(), "{outstanding} outstanding, more than two per peer");
}

/// **A refused claim leaves nothing behind.** Making the checkpoint this
/// node's own -- its total difficulty, the canonical index under it, the head
/// -- waits until the work the walk established bounds the claim. Written
/// first and refused after, the next session's walk found the checkpoint
/// already canonical, stopped there at once, and took the claim that had just
/// been refused: on mainnet a second attempt "verified" the chain in four
/// seconds.
#[test]
fn a_refused_claim_leaves_nothing_behind() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    // A chain that links, with totals that agree with each other, all raised
    // by the same million: more work than the chain carries.
    let (blocks, tds) = chain(1, 4, genesis, 1_000_000, f.state_root);
    let checkpoint = blocks.last().unwrap().header.clone();

    let mut session = f.session(HeaderVerifier::new());
    let actions = session.on_status(&blocks, &tds, 8_000, 0);
    assert_eq!(session.phase(), Phase::VerifyingHeaders);
    let Some(Action::RequestHeaders { point, count, .. }) =
        actions.into_iter().find(|a| matches!(a, Action::RequestHeaders { .. }))
    else {
        panic!("the walk asks for headers");
    };
    session.on_headers(point, &headers_for(&blocks, point, count));
    assert!(
        matches!(session.failure(), Some(SnapFailure::OverstatedDifficulty { .. })),
        "{:?}",
        session.failure()
    );

    assert_eq!(
        f.store.canonical_hash(checkpoint.number).unwrap(),
        None,
        "the refused checkpoint was indexed as canonical"
    );
    assert_ne!(f.store.head().unwrap(), Some(checkpoint.hash()), "it became the head");
    assert_eq!(
        f.store.total_difficulty(checkpoint.hash()).unwrap(),
        None,
        "the refused claim was recorded as this node's own"
    );
}

/// **While a session holds the peer set, the ordinary sync takes no chain
/// data.** A late answer to one of the session's own header requests, after
/// it timed out, is a stretch of the very chain being walked. Handed to the
/// ordinary sync, which writes what it is given, one put canonical pointers a
/// thousand blocks deep into a mainnet walk, and the walk took them for
/// ground this node already held.
#[tokio::test]
async fn the_ordinary_sync_takes_no_headers_during_a_snapshot_session() {
    use crate::events::SyncEvent;
    use crate::manager::SyncManager;
    use crate::SyncService;
    use rustock_networking::peers::PeerStore;

    let f = fixture(20);
    let genesis = f.with_genesis();
    f.store.put_total_difficulty(genesis, U256::from(100u64)).expect("td");
    f.store.set_head(genesis).expect("head");
    let (blocks, _) = chain(1, 3, genesis, 100, f.state_root);

    let peers = Arc::new(PeerStore::new());
    let peer = B512::repeat_byte(9);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    peers
        .add_peer_with(
            peer,
            tx,
            rustock_networking::handshake::PeerCapabilities { rsk_version: 62, snap: true },
        )
        .await;
    let manager = Arc::new(SyncManager::new(
        f.store.clone(),
        Arc::new(HeaderVerifier::new()),
        peers.clone(),
    ));
    let (_event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peers, event_rx)
        .with_trie_store_for_test(f.trie.clone() as Arc<dyn TrieStore>);
    service.start_snap_sync(SnapConfig::default(), Arc::new(HeaderVerifier::new()));
    service.on_tick().await;

    // Headers that link to this node's genesis, under an id nobody awaits.
    service
        .handle_event(SyncEvent::HeadersResponse {
            peer,
            id: 0x5eed,
            headers: blocks.iter().map(|b| b.header.clone()).collect(),
        })
        .await;

    assert_eq!(f.store.head().unwrap(), Some(genesis), "the ordinary sync moved the head");
    assert_eq!(
        f.store.canonical_hash(1).unwrap(),
        None,
        "the ordinary sync wrote the canonical index"
    );
}

/// With a checkpoint configured, a session bounds the peer's claim before it
/// commits to the header walk.
///
/// The walk costs about twenty-five minutes on a mainnet chain, all of it on
/// the strength of the offer being answered here. This is the test that the
/// gate is actually reached rather than merely implemented.
#[test]
fn a_checkpoint_gates_the_walk() {
    use rustock_core::checkpoint::MAINNET_CHECKPOINT;

    let cp = MAINNET_CHECKPOINT;
    let f = fixture(4);
    let mut session = SnapSession::new(
        SnapConfig {
            client_enabled: true,
            checkpoint: Some(cp),
            // The gate is opt-in: a checkpoint alone no longer arms it, since
            // bounding without sampling secures nothing.
            checkpoint_defence: rustock_core::checkpoint::CheckpointDefence {
                verify_hash: false,
                bound_work: true,
            },
            ..SnapConfig::default()
        },
        f.store.clone(),
        Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
        Arc::new(rustock_core::validation::HeaderVerifier::new()),
    );

    // A peer offers a checkpoint above the shipped one, so the claim cannot be
    // settled by arithmetic and must be sampled.
    let offered = block(header(cp.number + 50_000, B256::ZERO, f.state_root, 100));
    let actions = session.on_status(
        std::slice::from_ref(&offered),
        &[cp.cumulative_difficulty],
        1024,
        0,
    );

    assert_eq!(
        session.phase(),
        Phase::SamplingClaim,
        "a claim above the checkpoint must be sampled before the walk starts"
    );
    assert!(
        !actions.is_empty(),
        "the gate must ask for something rather than stalling"
    );
}

/// Builds a gated session offering a checkpoint `window` blocks above the
/// shipped one, and reports the phase the status left it in.
#[cfg(test)]
fn phase_for_window(window: u64, peer_serves_uncles: bool) -> Phase {
    use rustock_core::checkpoint::MAINNET_CHECKPOINT;

    let cp = MAINNET_CHECKPOINT;
    let f = fixture(4);
    let mut session = SnapSession::new(
        SnapConfig {
            client_enabled: true,
            checkpoint: Some(cp),
            checkpoint_defence: rustock_core::checkpoint::CheckpointDefence {
                verify_hash: false,
                bound_work: true,
            },
            ..SnapConfig::default()
        },
        f.store.clone(),
        Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
        Arc::new(rustock_core::validation::HeaderVerifier::new()),
    );
    session.set_peer_serves_uncles(peer_serves_uncles);
    let offered = block(header(cp.number + window, B256::ZERO, f.state_root, 100));
    let _ = session.on_status(
        std::slice::from_ref(&offered),
        &[cp.cumulative_difficulty],
        1024,
        0,
    );
    session.phase()
}

/// Over a short window, a peer that serves uncle headers is walked rather than
/// sampled.
///
/// Each sampled height costs one message, so below `WALK_INSTEAD_BELOW` the
/// gate spends a walk's worth of requests to see a fraction of the data — and
/// ends with a bound where the walk, fed uncles, ends with the exact number.
#[test]
fn a_short_window_walks_a_peer_that_serves_uncles() {
    let window = crate::sampler::WALK_INSTEAD_BELOW - 1_000;
    assert_eq!(
        phase_for_window(window, true),
        Phase::VerifyingHeaders,
        "under the crossover an rsk/63 peer should be walked, not sampled"
    );
}

/// The same window, but the peer speaks `rsk/62`.
///
/// The crossover turns on the capability, not the window. Walking an rsk/62
/// peer sums header difficulty alone, which is a *lower* bound on the chain's
/// work — worse than the gate's upper one, not better.
#[test]
fn a_short_window_still_samples_a_peer_without_uncles() {
    let window = crate::sampler::WALK_INSTEAD_BELOW - 1_000;
    assert_eq!(
        phase_for_window(window, false),
        Phase::SamplingClaim,
        "without the uncle capability the walk cannot establish the work, so sample"
    );
}

/// Past the crossover the walk costs more requests than the gate and vastly
/// more bytes, so sampling is right again even for a peer that serves uncles.
#[test]
fn a_long_window_samples_even_a_peer_that_serves_uncles() {
    let window = crate::sampler::WALK_INSTEAD_BELOW + 50_000;
    assert_eq!(
        phase_for_window(window, true),
        Phase::SamplingClaim,
        "above the crossover sampling is the cheaper vetting, uncles or not"
    );
}

/// Without a checkpoint — any chain but mainnet — the walk runs as before.
#[test]
fn no_checkpoint_means_no_gate() {
    let f = fixture(4);
    let mut session = SnapSession::new(
        SnapConfig { client_enabled: true, checkpoint: None, ..SnapConfig::default() },
        f.store.clone(),
        Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
        Arc::new(rustock_core::validation::HeaderVerifier::new()),
    );
    let offered = block(header(500, B256::ZERO, f.state_root, 100));
    let _ = session.on_status(std::slice::from_ref(&offered), &[U256::from(1u64)], 1024, 0);
    assert_ne!(
        session.phase(),
        Phase::SamplingClaim,
        "a chain with no checkpoint must not be gated against one"
    );
}
/// A whole session against an honest peer, on a node that already holds part
/// of the chain, must not trip the difficulty check.
///
/// The arithmetic this guards is in
/// `header_tests::the_established_difficulty_counts_from_genesis_not_from_the_anchor`;
/// this is the end-to-end statement that an honest peer completes. Note the
/// walk tests `is_ours` only at run boundaries, so with a chain this short it
/// consumes the whole run and anchors at genesis regardless -- which is why
/// the unit test above carries the real case.
#[test]
fn an_honest_peer_completes_when_this_node_already_holds_part_of_the_chain() {
    let f = fixture(250);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 6, genesis, 100, f.state_root);
    let checkpoint = blocks.last().unwrap().header.clone();

    // This node already holds the first three blocks, with their total
    // difficulties, so the walk anchors at #3 rather than at genesis.
    for (b, td) in blocks.iter().zip(tds.iter()).take(3) {
        let hash = b.header.hash();
        f.store.put_header_with_hash(hash, &b.header).expect("header");
        f.store.put_canonical_hash(b.header.number, hash).expect("index");
        f.store.put_total_difficulty(hash, *td).expect("td");
    }

    let peer_dir = tempfile::tempdir().expect("tempdir");
    let peer_store = Arc::new(BlockStore::open(peer_dir.path()).expect("open"));
    for (b, td) in blocks.iter().zip(tds.iter()) {
        let hash = b.header.hash();
        peer_store.put_header_with_hash(hash, &b.header).expect("header");
        peer_store.put_canonical_hash(b.header.number, hash).expect("index");
        peer_store.put_total_difficulty(hash, *td).expect("td");
    }

    let mut session = f.session(HeaderVerifier::new());
    let config = SnapConfig {
        server_enabled: true,
        blocks_required: 2,
        block_chunk_size: 2,
        ..SnapConfig::default()
    };
    let server = SnapServer::new(
        peer_store.clone(),
        f.trie.clone() as Arc<dyn TrieStore>,
        config.clone(),
    );

    // The peer states the truth throughout.
    let mut actions = session.on_status(&blocks, &tds, 8_000, 0);
    let mut guard = 0;
    while session.phase() != Phase::Done && session.phase() != Phase::Failed {
        guard += 1;
        assert!(guard < 10_000, "session did not terminate in phase {:?}", session.phase());
        if actions.is_empty() {
            actions = session.poll();
            assert!(!actions.is_empty(), "stuck in phase {:?}", session.phase());
        }
        let action = actions.remove(0);
        let next = match action {
            Action::RequestStatus => session.on_status(&blocks, &tds, 8_000, 0),
            Action::RequestHeaders { point, count, .. } => {
                session.on_headers(point, &headers_for(&blocks, point, count))
            }
            Action::RequestSkeleton { .. } => session.on_skeleton(&[]),
            Action::RequestChunk { from, budget, .. } => {
                let response = server
                    .chunk(&SnapChunkRequest {
                        id: 1,
                        block_number: checkpoint.number,
                        from,
                        chunk_size: budget,
                        state_root: Some(f.state_root),
                    })
                    .expect("server answers");
                session.on_chunk(from, &response.payload, Refusal::None)
            }
            Action::RequestBlocks { block_number } => {
                let answer: Vec<Block> = blocks
                    .iter()
                    .filter(|b| b.header.number < block_number)
                    .cloned()
                    .collect();
                let answer_tds: Vec<U256> = blocks
                    .iter()
                    .zip(tds.iter())
                    .filter(|(b, _)| b.header.number < block_number)
                    .map(|(_, td)| *td)
                    .collect();
                session.on_blocks(&answer, &answer_tds)
            }
        };
        actions.extend(next);
    }

    assert!(
        !matches!(session.failure(), Some(SnapFailure::OverstatedDifficulty { .. })),
        "an honest peer was refused because the walk anchored above genesis: {:?}",
        session.failure()
    );
    assert_eq!(session.phase(), Phase::Done, "failure: {:?}", session.failure());
}

/// A server simulating a short chain must not offer a state above it.
///
/// The checkpoint is derived from the head, so without a ceiling a server
/// told the chain ends at #1,000,000 would still offer the state at
/// #9,275,000 — and a client could snap-sync straight past the end it was
/// told about, which is not the test anyone asked for.
#[test]
fn a_simulated_chain_end_bounds_the_snapshot_offered() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    let (blocks, tds) = chain(1, 40, genesis, 100, f.state_root);
    for (b, td) in blocks.iter().zip(tds.iter()) {
        let hash = b.header.hash();
        f.store.put_header_with_hash(hash, &b.header).expect("header");
        f.store.put_canonical_hash(b.header.number, hash).expect("index");
        f.store.put_total_difficulty(hash, *td).expect("td");
        f.store.put_body(hash, &b.transactions, &b.ommers).expect("body");
    }
    let top = blocks.last().unwrap().header.hash();
    f.store.update_head(&blocks.last().unwrap().header, *tds.last().unwrap()).unwrap();
    let _ = top;

    let capped = SnapServer::new(
        f.store.clone(),
        f.trie.clone() as Arc<dyn TrieStore>,
        SnapConfig {
            server_enabled: true,
            checkpoint_distance: 10,
            serve_ceiling: Some(20),
            ..SnapConfig::default()
        },
    );

    if let Some(status) = capped.status(&rustock_networking::protocol::snap::SnapStatusRequest { id: 1 }) {
        let offered = status.blocks.last().expect("a checkpoint").header.number;
        assert!(
            offered <= 20,
            "offered the state at #{offered}, above the simulated chain end of #20"
        );
    }
}

/// A status response whose totals count the uncles — which is what a correct
/// peer sends — must be accepted. Checking the growth against the header
/// difficulty alone rejected every honest RSK peer, because an RSK chain
/// absorbs roughly one uncle per block.
#[test]
fn offered_totals_may_grow_by_more_than_the_header_difficulty() {
    let parent = header(100, B256::ZERO, B256::ZERO, 1000);
    let parent_hash = parent.hash();
    let uncle = header(99, B256::ZERO, B256::ZERO, 400);
    let mut child = header(101, parent_hash, B256::ZERO, 1000);
    child.uncle_count = 1;

    let blocks = vec![
        Block { header: parent, transactions: vec![], ommers: vec![] },
        Block { header: child, transactions: vec![], ommers: vec![uncle] },
    ];
    // 1000 (the child) + 400 (its uncle) = 1400.
    let difficulties = vec![U256::from(5000u64), U256::from(6400u64)];

    assert!(
        super::session::check_chain_shape(&blocks, &difficulties).is_ok(),
        "the uncle's difficulty counts toward the total"
    );
}

/// **An honest claim counts the uncles a header walk never sees.** rskj peers
/// send no uncles with headers, so the walk counts each block's own
/// difficulty: on mainnet, a little over half the work. Checked against that
/// and the checkpoint's own uncles, every honest claim was refused -- mainnet's
/// #9381160 carries 6.24e28, its headers alone 3.54e28 -- and the peer making
/// it was charged for a lie it had not told.
#[test]
fn an_honest_claim_counts_the_uncles_a_header_walk_never_sees() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    // Each block has an uncle as heavy as itself: half the work is in uncles.
    let (blocks, tds) = chain_with_uncles(1, 4, genesis, 100, f.state_root);
    let mut session = f.session(HeaderVerifier::new());
    let actions = session.on_status(&blocks, &tds, 8_000, 0);
    answer_header_walk(&mut session, &blocks, actions);
    assert_eq!(session.failure(), None);
    assert_eq!(session.phase(), Phase::DownloadingState);
}

/// And what the walk allows for the uncles it did not see is a bound, not a
/// pass: a claim beyond what they could add is refused.
#[test]
fn a_claim_beyond_what_the_unseen_uncles_could_add_is_refused() {
    let f = fixture(20);
    let genesis = f.with_genesis();
    // Totals far past what four uncles could weigh, even each at the floor.
    let (blocks, tds) = chain_with_uncles(1, 4, genesis, 1_000_000_000_000_000_000, f.state_root);
    let mut session = f.session(HeaderVerifier::new());
    let actions = session.on_status(&blocks, &tds, 8_000, 0);
    answer_header_walk(&mut session, &blocks, actions);
    assert!(
        matches!(session.failure(), Some(SnapFailure::OverstatedDifficulty { .. })),
        "{:?}",
        session.failure()
    );
}

/// The check still has teeth: a total that grows by the wrong amount is
/// refused, so a peer cannot inflate its claimed work.
#[test]
fn offered_totals_that_do_not_match_the_contribution_are_refused() {
    let parent = header(100, B256::ZERO, B256::ZERO, 1000);
    let parent_hash = parent.hash();
    let uncle = header(99, B256::ZERO, B256::ZERO, 400);
    let mut child = header(101, parent_hash, B256::ZERO, 1000);
    child.uncle_count = 1;

    let blocks = vec![
        Block { header: parent, transactions: vec![], ommers: vec![] },
        Block { header: child, transactions: vec![], ommers: vec![uncle] },
    ];
    // Claims far more work than the block and its uncle actually carry.
    let difficulties = vec![U256::from(5000u64), U256::from(99_000u64)];

    assert_eq!(
        super::session::check_chain_shape(&blocks, &difficulties),
        Err(SnapFailure::BadDifficulty)
    );
}

/// The ascent engages only when it is asked for *and* the peer can serve it.
///
/// `forward_headers` alone is not enough: the walk totals cumulative difficulty
/// exactly and cannot do that without the uncles, so an `rsk/62` peer must get
/// the descending walk however the node is configured. Getting this backwards
/// would compute a lower bound and call it exact.
mod ascent_tests {
    use super::*;

    fn session_with(forward: bool, peer_serves_uncles: bool) -> (SnapSession, Fixture) {
        let f = fixture(4);
        // A real node sets its head to genesis at startup (`setup_genesis`),
        // which is the ground the ascent stands on.
        let genesis = f.with_genesis();
        f.store.set_head(genesis).expect("head");
        let mut session = SnapSession::new(
            SnapConfig { client_enabled: true, forward_headers: forward, ..SnapConfig::default() },
            f.store.clone(),
            Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
            Arc::new(rustock_core::validation::HeaderVerifier::new()),
        );
        session.set_peer_serves_uncles(peer_serves_uncles);
        (session, f)
    }

    fn offer(session: &mut SnapSession, f: &Fixture) {
        let offered = block(header(5_000, B256::ZERO, f.state_root, 100));
        let _ = session.on_status(
            std::slice::from_ref(&offered),
            &[U256::from(1_000u64)],
            1024,
            0,
        );
    }

    #[test]
    fn an_rsk63_peer_is_ascended_when_forward_headers_is_on() {
        let (mut session, f) = session_with(true, true);
        offer(&mut session, &f);
        assert_eq!(
            session.phase(),
            Phase::AscendingHeaders,
            "asked for, and the peer can serve the uncles it needs"
        );
    }

    #[test]
    fn an_rsk62_peer_falls_back_to_the_descending_walk() {
        let (mut session, f) = session_with(true, false);
        offer(&mut session, &f);
        assert_eq!(
            session.phase(),
            Phase::VerifyingHeaders,
            "without uncles the ascent would compute a lower bound and call it exact"
        );
    }

    #[test]
    fn the_descending_walk_remains_the_default() {
        let (mut session, f) = session_with(false, true);
        offer(&mut session, &f);
        assert_eq!(
            session.phase(),
            Phase::VerifyingHeaders,
            "a peer that could serve the ascent does not by itself select it"
        );
    }

    /// A bare header answer during the ascent hands its range back.
    ///
    /// The ascent asks for headers with their uncles, and the driver strikes a
    /// request off as soon as any header answer to it arrives. Bare headers
    /// are no use to the ascent, and they were dropped with the range still
    /// marked as asked: nothing timed it out and nothing asked again, so one
    /// stray answer stopped the ascent at that height.
    #[test]
    fn a_bare_header_answer_during_the_ascent_is_asked_again() {
        let (mut session, f) = session_with(true, true);
        let offered = block(header(5_000, B256::ZERO, f.state_root, 100));
        let asks_for_the_top = |actions: &[Action]| {
            actions
                .iter()
                .any(|a| matches!(a, Action::RequestHeaders { point: 5_000, .. }))
        };
        let first = session.on_status(
            std::slice::from_ref(&offered),
            &[U256::from(1_000u64)],
            1024,
            0,
        );
        assert_eq!(session.phase(), Phase::AscendingHeaders);
        assert!(
            asks_for_the_top(&first),
            "the chunk under the target: {first:?}"
        );

        let again = session.on_headers(5_000, &[]);
        assert!(
            asks_for_the_top(&again),
            "asked for again after a bare answer: {again:?}"
        );
    }
}

/// The gate and the ascent coexist: passing the gate must land in the phase the
/// session was configured for, not always the descending walk.
///
/// `--checkpoint-bound-work` defaults on, so with `forward_headers` the gate
/// runs *first* and then hands over. Hard-coding `VerifyingHeaders` at that
/// hand-off built an ascent and silently never ran it.
#[test]
fn a_passed_gate_hands_over_to_the_ascent_not_the_walk() {
    use rustock_core::checkpoint::MAINNET_CHECKPOINT;

    let cp = MAINNET_CHECKPOINT;
    let f = fixture(4);
    let genesis = f.with_genesis();
    f.store.set_head(genesis).expect("head");

    let mut session = SnapSession::new(
        SnapConfig {
            client_enabled: true,
            forward_headers: true,
            checkpoint: Some(cp),
            checkpoint_defence: rustock_core::checkpoint::CheckpointDefence {
                verify_hash: false,
                bound_work: true,
            },
            ..SnapConfig::default()
        },
        f.store.clone(),
        Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
        Arc::new(rustock_core::validation::HeaderVerifier::new()),
    );
    session.set_peer_serves_uncles(true);

    // Above the checkpoint, so the gate engages rather than being skipped.
    let offered = block(header(cp.number + 500_000, B256::ZERO, f.state_root, 100));
    let _ = session.on_status(
        std::slice::from_ref(&offered),
        &[cp.cumulative_difficulty],
        1024,
        0,
    );
    assert_eq!(session.phase(), Phase::SamplingClaim, "the gate runs first");
    assert_eq!(
        session.header_phase_for_test(),
        Phase::AscendingHeaders,
        "and hands over to the ascent, not the walk"
    );
}

/// An offered header's proof of work is checked against the difficulty it
/// states, so a peer can name any height for next to nothing. The gate takes
/// on a window of [`crate::sampler::MAX_SAMPLED_WINDOW`] above the checkpoint
/// and refuses one wider, rather than ask for skeletons up to it for ever.
#[test]
fn a_state_further_above_the_checkpoint_than_a_chain_can_be_is_refused() {
    use crate::sampler::MAX_SAMPLED_WINDOW;
    use rustock_core::checkpoint::MAINNET_CHECKPOINT;

    let cp = MAINNET_CHECKPOINT;
    for (window, refused) in [
        (MAX_SAMPLED_WINDOW, false),
        (MAX_SAMPLED_WINDOW + 1, true),
        (1 << 62, true),
    ] {
        let f = fixture(4);
        let genesis = f.with_genesis();
        f.store.set_head(genesis).expect("head");
        let mut session = SnapSession::new(
            SnapConfig {
                client_enabled: true,
                checkpoint: Some(cp),
                checkpoint_defence: rustock_core::checkpoint::CheckpointDefence {
                    verify_hash: false,
                    bound_work: true,
                },
                ..SnapConfig::default()
            },
            f.store.clone(),
            Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
            Arc::new(rustock_core::validation::HeaderVerifier::new()),
        );
        let offered = block(header(cp.number + window, B256::ZERO, f.state_root, 100));
        let _ = session.on_status(
            std::slice::from_ref(&offered),
            &[cp.cumulative_difficulty],
            1024,
            0,
        );
        if refused {
            assert_eq!(
                session.failure(),
                Some(&SnapFailure::ImplausibleHeight {
                    window,
                    most: MAX_SAMPLED_WINDOW
                })
            );
        } else {
            assert_eq!(
                session.phase(),
                Phase::SamplingClaim,
                "{:?}",
                session.failure()
            );
        }
    }
}
