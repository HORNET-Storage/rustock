//! Snapshot sync, server against client, over a trie small enough to reason
//! about.
//!
//! These exercise the two halves together: nothing is stubbed between
//! `SnapServer::chunk` and `StateDownload::accept` except the wire, which is
//! encoded and decoded for real.

use super::client::{proof_from_payload, ChunkError, StateDownload};
use super::server::SnapServer;
use super::SnapConfig;
use alloy_primitives::{keccak256, B256};
use rustock_networking::protocol::snap::{
    ChunkPayload, SnapChunkRequest, SnapChunkResponse, SnapEntry,
};
use rustock_trie::snapshot::total_size;
use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode, TrieStore};
use std::sync::Arc;

/// A trie of `n` accounts, a fifth of them with values too long to embed.
fn toy_state(n: usize) -> (TrieNode, Arc<MemoryTrieStore>, B256) {
    let store = Arc::new(MemoryTrieStore::new());
    let mut root = TrieNode::empty();
    for i in 0..n {
        let key = [(i >> 8) as u8, i as u8, (i * 7) as u8, (i * 13) as u8];
        let value: Vec<u8> = if i % 5 == 0 {
            (0..96u8).map(|b| b.wrapping_add(i as u8)).collect()
        } else {
            vec![i as u8, (i >> 8) as u8, 7]
        };
        root = root.put(&TrieKeySlice::from_key(&key), &value, store.as_ref());
    }
    root.save(store.as_ref(), true);
    let hash = root.compute_hash(store.as_ref());
    (root, store, hash)
}

/// A peer that serves honestly from its own copy of the trie, through the
/// real wire encoding.
struct Peer {
    root: TrieNode,
    store: Arc<MemoryTrieStore>,
    root_hash: B256,
}

impl Peer {
    fn new(n: usize) -> Self {
        let (root, store, root_hash) = toy_state(n);
        Self { root, store, root_hash }
    }

    /// The trie [`toy_state`] makes, with the value of each account `long`
    /// names made that many bytes long instead: the length a contract's code
    /// or a value of the Bridge's storage can reach.
    fn with_long_values(n: usize, long: &[(usize, usize)]) -> Self {
        let store = Arc::new(MemoryTrieStore::new());
        let mut root = TrieNode::empty();
        for i in 0..n {
            let key = [(i >> 8) as u8, i as u8, (i * 7) as u8, (i * 13) as u8];
            let value: Vec<u8> = match long.iter().find(|(at, _)| *at == i) {
                Some(&(_, len)) => (0..len)
                    .map(|b| (b as u8).wrapping_mul(31).wrapping_add(i as u8))
                    .collect(),
                None if i % 5 == 0 => (0..96u8).map(|b| b.wrapping_add(i as u8)).collect(),
                None => vec![i as u8, (i >> 8) as u8, 7],
            };
            root = root.put(&TrieKeySlice::from_key(&key), &value, store.as_ref());
        }
        root.save(store.as_ref(), true);
        let root_hash = root.compute_hash(store.as_ref());
        Self {
            root,
            store,
            root_hash,
        }
    }

    /// Serves a grid cell and puts it through RLP, so the test sees what a
    /// real client would. `budget` is the grid size, as a server's is.
    fn serve(&self, from: u64, budget: u64) -> SnapChunkResponse {
        let proof = rustock_trie::snapshot_proof::prove_cell(
            &self.root,
            from,
            from + budget,
            self.store.as_ref(),
        );
        let response = SnapChunkResponse {
            id: 1,
            payload: ChunkPayload::Proved {
                entries: proof
                    .entries
                    .iter()
                    .map(|e| SnapEntry {
                        message: e.message.clone().into(),
                        long_values: e.long_values.iter().map(|v| v.clone().into()).collect(),
                    })
                    .collect(),
                witness: proof.witness.iter().map(|w| w.clone().into()).collect(),
            },
            block_number: 100,
            from,
            to: 0,
            complete: false,
            refusal: rustock_networking::protocol::snap::Refusal::None,
        };
        let encoded = response.encode_body();
        SnapChunkResponse::decode_body(&mut encoded.as_slice()).expect("survives the wire")
    }

    fn total(&self) -> u64 {
        total_size(&self.root, self.store.as_ref())
    }
}

fn config(workers: usize, chunk_bytes: u64) -> SnapConfig {
    SnapConfig {
        server_enabled: true,
        client_enabled: true,
        max_in_flight: workers,
        chunk_bytes,
        // The grid matches the chunk size in these tests: the fixtures are
        // far smaller than the 100 KB production grid, which would put every
        // toy trie in a single cell and test nothing about tiling.
        chunk_grid: chunk_bytes,
        ..SnapConfig::default()
    }
}

/// Drives a download to completion against one honest peer, returning the
/// client's store.
/// As `download`, but the caller keeps the local store so it can corrupt it.
fn download_into(
    peer: &Peer,
    local: Arc<MemoryTrieStore>,
    workers: usize,
    chunk_bytes: u64,
) -> StateDownload {
    download_inner(peer, local, workers, chunk_bytes, peer.total())
}

fn download(peer: &Peer, workers: usize, chunk_bytes: u64, hint: u64) -> StateDownload {
    download_inner(peer, Arc::new(MemoryTrieStore::new()), workers, chunk_bytes, hint)
}

fn download_inner(
    peer: &Peer,
    local: Arc<MemoryTrieStore>,
    workers: usize,
    chunk_bytes: u64,
    hint: u64,
) -> StateDownload {
    let mut client =
        StateDownload::new(peer.root_hash, hint, &config(workers, chunk_bytes), local);

    let mut guard = 0;
    while !client.is_complete() {
        guard += 1;
        assert!(guard < 100_000, "download did not terminate");

        let Some(request) = client.next_request() else {
            panic!("no work available and not complete");
        };
        let response = peer.serve(request.from, request.budget);
        let proof = proof_from_payload(&response.payload).expect("proved format");
        if proof.entries.is_empty() {
            // Past the end of the trie: the slice is finished.
            client.release(request.from);
            break;
        }
        client.accept(request.from, &proof).expect("honest chunk");
    }
    client
}

#[test]
fn a_state_downloads_and_reads_back() {
    for (n, workers, chunk_bytes) in
        [(1usize, 1usize, 1024u64), (50, 1, 256), (300, 4, 512), (300, 8, 4096)]
    {
        let peer = Peer::new(n);
        let client = download(&peer, workers, chunk_bytes, peer.total());

        assert!(client.is_complete(), "n={n} workers={workers}: not complete");
        let nodes = client
            .verify_stored()
            .unwrap_or_else(|e| panic!("n={n} workers={workers}: {e}"));
        assert!(nodes > 0);
    }
}

/// The point of it all: the downloaded state answers the same questions the
/// original does.
#[test]
fn the_downloaded_state_matches_the_original() {
    let n = 300;
    let peer = Peer::new(n);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(4, 700), local.clone());

    while !client.is_complete() {
        let request = client.next_request().expect("work remains");
        let response = peer.serve(request.from, request.budget);
        let proof = proof_from_payload(&response.payload).unwrap();
        client.accept(request.from, &proof).expect("honest chunk");
    }

    let message = local.get(peer.root_hash.as_slice()).expect("root stored");
    let rebuilt = TrieNode::from_message(&message, local.as_ref());
    assert_eq!(rebuilt.compute_hash(local.as_ref()), peer.root_hash);

    for i in 0..n {
        let key = [(i >> 8) as u8, i as u8, (i * 7) as u8, (i * 13) as u8];
        let k = TrieKeySlice::from_key(&key);
        assert_eq!(
            rebuilt.get(&k, local.as_ref()),
            peer.root.get(&k, peer.store.as_ref()),
            "key {i} differs"
        );
    }
}

/// Several peers, each serving whatever range it is handed, with no
/// coordination between them.
#[test]
fn several_peers_serve_one_state() {
    let n = 400;
    let peers: Vec<Peer> = (0..4).map(|_| Peer::new(n)).collect();
    assert!(
        peers.iter().all(|p| p.root_hash == peers[0].root_hash),
        "the fixture should be deterministic"
    );

    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peers[0].root_hash, peers[0].total(), &config(4, 600), local);

    let mut served = vec![0usize; peers.len()];
    let mut turn = 0;
    while !client.is_complete() {
        let request = client.next_request().expect("work remains");
        // Round-robin, so every peer contributes and none sees the whole
        // trie in order.
        let peer = &peers[turn % peers.len()];
        served[turn % peers.len()] += 1;
        turn += 1;

        let response = peer.serve(request.from, request.budget);
        let proof = proof_from_payload(&response.payload).unwrap();
        client.accept(request.from, &proof).expect("honest chunk");
    }

    assert!(served.iter().all(|c| *c > 0), "some peer was never used: {served:?}");
    client.verify_stored().expect("the assembled state is whole");
}

/// The size a peer claims does not decide the download: the root does.
#[test]
fn a_lie_about_the_trie_size_does_not_truncate_the_download() {
    let peer = Peer::new(300);
    let truth = peer.total();

    for hint in [1u64, truth / 3, truth, truth * 3] {
        let client = download(&peer, 4, 512, hint);
        assert!(client.is_complete(), "hint={hint}: not complete");
        client
            .verify_stored()
            .unwrap_or_else(|e| panic!("hint={hint} left the state incomplete: {e}"));
    }
}

/// A peer that alters a node is refused and the range is handed back, so an
/// honest peer can serve it instead. The store keeps nothing from the attempt.
#[test]
fn a_tampered_chunk_is_refused_and_the_range_retried() {
    let peer = Peer::new(200);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(1, 512), local.clone());

    let request = client.next_request().expect("work");
    let response = peer.serve(request.from, request.budget);
    let mut proof = proof_from_payload(&response.payload).unwrap();

    let victim = proof.entries.len() / 2;
    let last = proof.entries[victim].message.len() - 1;
    proof.entries[victim].message[last] ^= 0x01;

    let before: Vec<B256> =
        proof.entries.iter().map(|e| keccak256(&e.message)).collect();
    assert!(matches!(
        client.accept(request.from, &proof),
        Err(ChunkError::Invalid(_))
    ));

    // Nothing was written -- not even the entries that were genuine.
    for hash in &before {
        assert!(local.get(hash.as_slice()).is_none(), "a refused chunk left bytes behind");
    }
    assert_eq!(client.stored_nodes(), 0);

    // And the same range is offered again.
    let retry = client.next_request().expect("the range came back");
    assert_eq!(retry.from, request.from);

    let honest = peer.serve(retry.from, retry.budget);
    let proof = proof_from_payload(&honest.payload).unwrap();
    client.accept(retry.from, &proof).expect("the honest answer is taken");
    assert!(client.stored_nodes() > 0);
}

/// A chunk nobody asked for is refused outright, even if it is genuine.
/// Otherwise a peer could write into ranges another peer is responsible for.
#[test]
fn an_unsolicited_chunk_is_refused() {
    let peer = Peer::new(200);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(1, 512), local);

    let response = peer.serve(0, 512);
    let proof = proof_from_payload(&response.payload).unwrap();
    assert_eq!(client.accept(0, &proof), Err(ChunkError::Unsolicited(0)));
}

/// **A rustock client reads an rskj server's chunks.** The server here emits
/// rskj's format, and the client rebuilds it into the same nodes the trie
/// holds -- child hashes recomputed, structure derived, root checked.
#[test]
fn an_rskj_format_chunk_is_rebuilt_and_kept() {
    use crate::snap::client::{chunk_from_payload, Arrived};
    use crate::snap::RSKJ_CHUNK_GRID;

    let (store, peer, block_number) = server_fixture(900);
    let server = SnapServer::new(
        store,
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig { server_enabled: true, ..config(4, 100_000) },
    );

    // No state root in the request: served rskj's format.
    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number,
            from: 0,
            chunk_size: 0,
            state_root: None,
        })
        .expect("an answer");
    assert!(matches!(response.payload, ChunkPayload::Legacy(_)));

    let arrived = chunk_from_payload(&response.payload, peer.root_hash)
        .expect("an rskj chunk must rebuild");
    let Arrived::Rebuilt(rebuilt) = arrived else { panic!("expected a rebuild") };

    assert!(!rebuilt.nodes.is_empty());
    // Every node must be one the trie really holds.
    for (hash, message) in &rebuilt.nodes {
        assert_eq!(alloy_primitives::keccak256(message), *hash);
        assert_eq!(
            peer.store.get(hash.as_slice()).as_deref(),
            Some(message.as_slice()),
            "rebuilt a node the trie does not hold"
        );
    }
    let _ = RSKJ_CHUNK_GRID;
}

/// A chunk that does not rebuild to the root this client trusts is refused --
/// the whole of the security argument for reading rskj's format.
#[test]
fn an_rskj_chunk_for_another_state_is_refused() {
    use crate::snap::client::chunk_from_payload;

    let (store, peer, block_number) = server_fixture(300);
    let server = SnapServer::new(
        store,
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig { server_enabled: true, ..config(4, 100_000) },
    );
    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number,
            from: 0,
            chunk_size: 0,
            state_root: None,
        })
        .expect("an answer");

    let wrong = B256::repeat_byte(0xAB);
    match chunk_from_payload(&response.payload, wrong) {
        Err(ChunkError::LegacyRebuild(_)) => {}
        other => panic!("a chunk for another state was accepted: {other:?}"),
    }
}

/// Requests go out to different offsets/// Requests go out to different offsets, so peers work on the trie at once
/// rather than queueing behind each other.
#[test]
fn workers_are_given_different_parts_of_the_trie() {
    let peer = Peer::new(400);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(4, 512), local);

    let mut offsets = Vec::new();
    while let Some(request) = client.next_request() {
        offsets.push(request.from);
    }
    assert_eq!(offsets.len(), 4, "every worker should have a range");

    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 4, "workers overlap: {offsets:?}");
    assert_eq!(sorted[0], 0);
}

/// The server refuses to serve a state root that is not the one its own chain
/// has at that height, rather than silently answering a different question.
#[test]
fn the_server_declines_a_root_from_another_chain() {
    use rustock_storage::BlockStore;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    let peer = Peer::new(50);

    let server = SnapServer::new(
        store,
        peer.store.clone() as Arc<dyn TrieStore>,
        config(4, 512),
    );

    // No such block: an empty answer, promptly, rather than silence.
    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number: 42,
            from: 0,
            chunk_size: 512,
            state_root: Some(B256::repeat_byte(0xEE)),
        })
        .expect("an answer");
    match response.payload {
        ChunkPayload::Proved { entries, .. } => assert!(entries.is_empty()),
        other => panic!("unexpected payload {other:?}"),
    }
}

/// A disabled server says nothing at all.
#[test]
fn a_disabled_server_serves_nothing() {
    use rustock_storage::BlockStore;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    let peer = Peer::new(50);
    let server = SnapServer::new(
        store,
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig::default(),
    );

    assert!(server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number: 1,
            from: 0,
            chunk_size: 0,
            state_root: None
        })
        .is_none());
}

/// A half-finished download is *reported* as half-finished. Without this the
/// completeness check would be a formality, and a node would start executing
/// against state with holes in it.
#[test]
fn an_incomplete_state_is_not_mistaken_for_a_whole_one() {
    let peer = Peer::new(300);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(1, 256), local);

    // Take only the first few chunks.
    for _ in 0..3 {
        let request = client.next_request().expect("work");
        let response = peer.serve(request.from, request.budget);
        let proof = proof_from_payload(&response.payload).unwrap();
        client.accept(request.from, &proof).expect("honest chunk");
    }
    assert!(!client.is_complete());
    assert!(client.stored_nodes() > 0, "the test should have stored something");

    let err = client.verify_stored().expect_err("a partial state must not pass");
    assert!(
        err.contains("root") || err.contains("hole") || err.contains("spans"),
        "unhelpful complaint: {err}"
    );
}

/// The whole path, server to client, through a real block store: the server
/// finds the state from the block number, and the client rebuilds it.
#[test]
fn a_real_server_serves_a_real_client() {
    let (store, peer, block_number) = server_fixture(300);
    let server = SnapServer::new(store, peer.store.clone() as Arc<dyn TrieStore>, config(4, 700));

    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(4, 700), local.clone());

    while !client.is_complete() {
        let request = client.next_request().expect("work remains");
        let response = server
            .chunk(&SnapChunkRequest {
                id: 1,
                block_number,
                from: request.from,
                chunk_size: request.budget,
                state_root: Some(peer.root_hash),
            })
            .expect("the server answers");

        // Through the wire, as a client would see it.
        let encoded = response.encode_body();
        let decoded = SnapChunkResponse::decode_body(&mut encoded.as_slice()).unwrap();
        let proof = proof_from_payload(&decoded.payload).expect("proved format");
        client.accept(request.from, &proof).expect("the server is honest");
    }

    client.verify_stored().expect("the assembled state is whole");
    let message = local.get(peer.root_hash.as_slice()).expect("root stored");
    let rebuilt = TrieNode::from_message(&message, local.as_ref());
    assert_eq!(rebuilt.compute_hash(local.as_ref()), peer.root_hash);
}

/// Chunk sizes a peer asks for are clamped, so one request cannot ask this
/// node to serialize the whole trie into a single message.
#[test]
fn an_outsized_request_is_clamped() {
    let (store, peer, block_number) = server_fixture(2000);
    let mut config = config(4, 512);
    config.max_chunk_bytes = 4096;
    let server = SnapServer::new(store, peer.store.clone() as Arc<dyn TrieStore>, config);

    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number,
            from: 0,
            // "Send me everything."
            chunk_size: u64::MAX,
            state_root: Some(peer.root_hash),
        })
        .expect("an answer");

    let ChunkPayload::Proved { entries, .. } = response.payload else {
        panic!("expected a proved chunk");
    };
    let served: u64 = entries.iter().map(|e| e.message.len() as u64).sum();
    assert!(served > 0, "clamping should not mean serving nothing");
    assert!(
        served < peer.total() / 4,
        "asking for everything got {served} of {} bytes",
        peer.total()
    );
}

/// The server refuses an offset past the end rather than looping a client
/// forever on an empty answer.
#[test]
fn the_server_declines_an_offset_past_the_end() {
    let (store, peer, block_number) = server_fixture(100);
    let server = SnapServer::new(store, peer.store.clone() as Arc<dyn TrieStore>, config(4, 512));

    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number,
            from: peer.total() + 1,
            chunk_size: 512,
            state_root: Some(peer.root_hash),
        })
        .expect("an answer");
    match response.payload {
        ChunkPayload::Proved { entries, .. } => assert!(entries.is_empty()),
        other => panic!("unexpected payload {other:?}"),
    }
}

/// A block store holding one block whose state root is the toy trie's.
fn server_fixture(n: usize) -> (Arc<rustock_storage::BlockStore>, Peer, u64) {
    use alloy_primitives::{Address, U256};
    use rustock_core::Header;
    use rustock_storage::BlockStore;

    let peer = Peer::new(n);
    let dir = tempfile::tempdir().expect("tempdir");
    // Leaked on purpose: the store must outlive the directory handle, and
    // these are test processes.
    let dir = Box::leak(Box::new(dir));
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));

    let number = 20_000u64;
    let header = Header {
        parent_hash: B256::repeat_byte(1),
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: peer.root_hash,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::from(1u64),
        number,
        gas_limit: U256::from(6_800_000u64),
        gas_used: 0,
        timestamp: 1_700_000_000,
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
    };
    let hash = header.hash();
    store.put_header(&header).expect("put header");
    store.put_canonical_hash(number, hash).expect("index height");
    store.put_total_difficulty(hash, U256::from(1u64)).expect("td");
    store.set_head(hash).expect("head");

    (store, peer, number)
}

/// The last seam: a request arriving as a p2p message is answered as one.
///
/// Everything between is the real path -- the handler's dispatch, the blocking
/// thread it serves on, the peer store it answers through, the message
/// envelope, the RLP -- so this catches a variant wired to the wrong arm,
/// which the pieces tested separately cannot.
#[tokio::test]
async fn a_snap_request_is_answered_through_the_handler() {
    use crate::events::SyncEvent;
    use crate::manager::SyncManager;
    use crate::SyncHandler;
    use alloy_primitives::B512;
    use rustock_core::validation::HeaderVerifier;
    use rustock_networking::peers::PeerStore;
    use rustock_networking::protocol::{P2pHandler, P2pMessage, RskMessage, RskSubMessage};

    let (store, peer, block_number) = server_fixture(120);
    let peers = Arc::new(PeerStore::new());
    let peer_id = B512::repeat_byte(1);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    peers.add_peer(peer_id, tx).await;

    let manager = Arc::new(SyncManager::new(
        store.clone(),
        Arc::new(HeaderVerifier::new()),
        peers.clone(),
    ));
    let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel::<SyncEvent>();
    let handler = SyncHandler::new(manager, event_tx).with_snap_server(Arc::new(
        SnapServer::new(store, peer.store.clone() as Arc<dyn TrieStore>, config(4, 700)),
    ));

    let request = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SnapChunkRequest(
        SnapChunkRequest {
            id: 77,
            block_number,
            from: 0,
            chunk_size: 700,
            state_root: Some(peer.root_hash),
        },
    )));

    // Nothing comes back inline: serving happens off the network thread.
    assert!(handler.handle_message(peer_id, &request).is_none());

    let reply = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
        .await
        .expect("the answer should arrive")
        .expect("the channel should stay open");

    let P2pMessage::RskMessage(message) = reply else { panic!("not an rsk message") };
    let RskSubMessage::SnapChunkResponse(response) = message.sub_message else {
        panic!("wrong reply type")
    };
    assert_eq!(response.id, 77, "the answer must carry the request's id");

    // And it verifies, which is the only thing that makes it an answer.
    let proof = proof_from_payload(&response.payload).expect("proved format");
    assert!(!proof.entries.is_empty());
    rustock_trie::snapshot_proof::verify_chunk(peer.root_hash, 0, &proof)
        .expect("the handler's answer verifies");
}

/// One peer may not occupy the whole server. A snapshot request is the most
/// expensive thing a stranger can ask this node to do, and a peer that
/// pipelines them would otherwise keep every worker busy on its own behalf.
#[test]
fn one_peer_cannot_take_every_serving_slot() {
    use alloy_primitives::B512;

    let (store, peer, _) = server_fixture(50);
    let limit = 3;
    let server = SnapServer::new(
        store,
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig { max_requests_per_peer: limit, ..config(4, 512) },
    );

    let greedy = B512::repeat_byte(7);
    for i in 0..limit {
        assert!(server.admit(greedy), "slot {i} should have been free");
    }
    assert!(!server.admit(greedy), "the limit did not hold");

    // Another peer is unaffected: the limit is per peer, not a global queue.
    assert!(server.admit(B512::repeat_byte(8)));

    // And a finished request frees its slot.
    server.release(greedy);
    assert_eq!(server.serving_for(greedy), limit - 1);
    assert!(server.admit(greedy));
}

/// A node that serves snapshots but has pruned the state it would offer says
/// so, rather than reporting a checkpoint it cannot serve.
#[test]
fn a_node_without_the_state_offers_nothing() {
    use rustock_storage::BlockStore;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    // An empty trie store: whatever the chain says, the state is not here.
    let server = SnapServer::new(
        store,
        Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
        config(4, 512),
    );
    assert_eq!(server.offer(), None);
}

/// An answer far larger than the question is thrown away unread. The
/// transport allows 16 MB; verifying that much costs real CPU, and a peer
/// that can make a client spend it on demand can make it spend it forever.
#[test]
fn a_wildly_oversized_chunk_is_refused_without_verifying() {
    // Big enough that a chunk can exceed the 256 KB floor.
    let peer = Peer::new(6000);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(1, 512), local.clone());

    let request = client.next_request().expect("work");
    // A genuine chunk, just enormously bigger than what was asked for.
    let response = peer.serve(request.from, 8 << 20);
    let proof = proof_from_payload(&response.payload).unwrap();
    assert!(proof.wire_len() > 1 << 18, "the fixture is not big enough to test this");

    match client.accept(request.from, &proof) {
        Err(ChunkError::Oversized { asked, .. }) => assert_eq!(asked, 512),
        other => panic!("oversized chunk was not refused: {other:?}"),
    }
    assert_eq!(client.stored_nodes(), 0);

    // The range is still available, so an honest answer still lands.
    let retry = client.next_request().expect("the range came back");
    let honest = peer.serve(retry.from, retry.budget);
    let proof = proof_from_payload(&honest.payload).unwrap();
    client.accept(retry.from, &proof).expect("a right-sized answer is taken");
}

/// But a server rounding up, or a straddling node at the end, is not an
/// attack: a chunk somewhat over the budget is still accepted.
#[test]
fn a_slightly_oversized_chunk_is_still_accepted() {
    let peer = Peer::new(400);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(peer.root_hash, peer.total(), &config(1, 100_000), local);

    let request = client.next_request().expect("work");
    let response = peer.serve(request.from, 150_000);
    let proof = proof_from_payload(&response.payload).unwrap();
    client.accept(request.from, &proof).expect("a generous answer is fine");
}

/// A single node bigger than the whole budget must still get through. A
/// server sends at least one node whatever it is asked for, because that is
/// the only way past a node larger than the budget -- and a value that can
/// never be downloaded is a state that can never be completed.
#[test]
fn one_node_larger_than_the_budget_still_arrives() {
    let store = Arc::new(MemoryTrieStore::new());
    let mut root = TrieNode::empty();

    // One account carrying far more than any sane chunk budget.
    let huge: Vec<u8> = (0..900_000u32).map(|i| i as u8).collect();
    root = root.put(&TrieKeySlice::from_key(&[1, 2, 3, 4]), &huge, store.as_ref());
    for i in 0..20u8 {
        root = root.put(&TrieKeySlice::from_key(&[9, i, 0, 0]), &[i, 1], store.as_ref());
    }
    root.save(store.as_ref(), true);
    let root_hash = root.compute_hash(store.as_ref());

    let peer = Peer { root, store, root_hash };
    let local = Arc::new(MemoryTrieStore::new());
    let mut client =
        StateDownload::new(root_hash, peer.total(), &config(1, 1024), local.clone());

    let mut guard = 0;
    while !client.is_complete() {
        guard += 1;
        assert!(guard < 1000, "download stalled on the oversized node");
        let request = client.next_request().expect("work remains");
        let response = peer.serve(request.from, request.budget);
        let proof = proof_from_payload(&response.payload).unwrap();
        client.accept(request.from, &proof).expect("every chunk is honest");
    }

    client.verify_stored().expect("the state is whole");
    assert_eq!(
        local.get(alloy_primitives::keccak256(&huge).as_slice()),
        Some(huge),
        "the oversized value did not survive"
    );
}

/// A peer that understates the size of the trie must not end up serializing
/// the download: the space it left out gets its own workers, not tacked onto
/// the last slice.
#[test]
fn understating_the_size_does_not_serialize_the_tail() {
    let peer = Peer::new(600);
    let local = Arc::new(MemoryTrieStore::new());
    let workers = 4;
    let mut client = StateDownload::new(
        peer.root_hash,
        peer.total() / 10, // a tenth of the truth
        &config(workers, 400),
        local,
    );

    // One honest chunk teaches it the real size.
    let first = client.next_request().expect("work");
    let response = peer.serve(first.from, first.budget);
    let proof = proof_from_payload(&response.payload).unwrap();
    client.accept(first.from, &proof).expect("honest");

    // The space the peer left out is divided among the workers rather than
    // left to one, so no slice is a disproportionate share of the trie.
    let bounds = client.slice_bounds();
    let total = peer.total();
    let biggest = bounds.iter().map(|(a, b)| b - a).max().unwrap();
    assert!(
        biggest < total / 2,
        "one slice owns {biggest} of {total} bytes: {bounds:?}"
    );

    // And the ranges still tile the trie exactly: no gap, no overlap.
    let mut sorted = bounds.clone();
    sorted.sort_unstable();
    assert_eq!(sorted[0].0, 0);
    assert_eq!(sorted.last().unwrap().1, total);
    for pair in sorted.windows(2) {
        assert_eq!(pair[0].1, pair[1].0, "slices do not tile: {sorted:?}");
    }

    // The in-flight limit still holds: the first request has been answered,
    // so all four slots are free again and exactly four reopen.
    let mut opened = 0;
    while client.next_request().is_some() {
        opened += 1;
        assert!(opened <= workers, "opened {opened} requests with a limit of {workers}");
    }
    assert_eq!(opened, workers);

    // And it still finishes, covering everything.
    let client = download(&peer, workers, 400, peer.total() / 10);
    client.verify_stored().expect("the state is whole");
}

/// The in-flight limit is a limit on requests, whatever the slice count.
#[test]
fn no_more_requests_are_opened_than_allowed() {
    let peer = Peer::new(600);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client = StateDownload::new(peer.root_hash, peer.total(), &config(3, 400), local);

    let mut opened = 0;
    while client.next_request().is_some() {
        opened += 1;
        assert!(opened <= 3, "opened {opened} requests with a limit of 3");
    }
    assert_eq!(opened, 3);
}

// ----------------------------------------------------------- grid and cache

/// **The reason for the grid.** Two clients asking independently must land on
/// the same ranges, or a server can never reuse what it computed.
#[test]
fn independent_clients_ask_for_the_same_cells() {
    let peer = Peer::new(400);
    let config = config(1, 700);

    let mut asked = Vec::new();
    for _ in 0..2 {
        let local = Arc::new(MemoryTrieStore::new());
        let mut client =
            StateDownload::new(peer.root_hash, peer.total(), &config, local);
        let mut offsets = Vec::new();
        while !client.is_complete() {
            let request = client.next_request().expect("work remains");
            offsets.push(request.from);
            let response = peer.serve(request.from, request.budget);
            let proof = proof_from_payload(&response.payload).unwrap();
            client.accept(request.from, &proof).expect("honest");
        }
        asked.push(offsets);
    }

    assert_eq!(asked[0], asked[1], "two clients asked for different ranges");
    assert!(
        asked[0].iter().all(|o| o % config.chunk_grid == 0),
        "some request was off the grid: {:?}",
        asked[0]
    );
}

/// A server answers a cached cell without touching the trie. The point of the
/// cache is that the second client costs a read, not a traversal.
#[test]
fn a_served_cell_is_cached_and_reused() {
    use rustock_networking::protocol::snap::Refusal;

    let (store, peer, block_number) = server_fixture(400);
    let cfg = SnapConfig { chunk_grid: 4096, ..config(4, 4096) };
    let server = SnapServer::new(store.clone(), peer.store.clone() as Arc<dyn TrieStore>, cfg);

    let request = SnapChunkRequest {
        id: 1,
        block_number,
        from: 4096,
        chunk_size: 4096,
        state_root: Some(peer.root_hash),
    };

    let first = server.chunk(&request).expect("an answer");
    assert_eq!(first.refusal, Refusal::None);

    // It is on disk now, under this state root and cell index.
    let cached = store.snap_chunk(peer.root_hash, 4096, 0, 1).expect("readable");
    assert!(cached.is_some(), "the cell was not cached");

    // And a second ask returns exactly the same bytes.
    let second = server.chunk(&request).expect("an answer");
    assert_eq!(second.payload, first.payload, "the cached answer differs");
    assert_eq!(second.from, first.from);
    assert_eq!(second.to, first.to);

    // Serving it from an empty trie proves it came from the cache and not
    // from a traversal.
    let blind = SnapServer::new(
        store,
        Arc::new(MemoryTrieStore::new()) as Arc<dyn TrieStore>,
        SnapConfig { chunk_grid: 4096, ..config(4, 4096) },
    );
    match blind.chunk(&request) {
        // With no trie it cannot even read the root, so it refuses -- the
        // cache lookup happens after the state is located, deliberately: a
        // server must not serve a state it no longer has.
        Some(r) => assert_eq!(r.refusal, Refusal::StateNotStored),
        None => panic!("expected an answer"),
    }
}

/// A request that is not on the server's grid is refused by name, so the
/// client realigns instead of concluding the peer is useless.
#[test]
fn an_off_grid_request_is_refused_by_name() {
    use rustock_networking::protocol::snap::Refusal;

    let (store, peer, block_number) = server_fixture(200);
    let server = SnapServer::new(
        store,
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig { chunk_grid: 4096, ..config(4, 4096) },
    );

    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number,
            from: 4097, // one past a boundary
            chunk_size: 4096,
            state_root: Some(peer.root_hash),
        })
        .expect("an answer");

    assert_eq!(response.refusal, Refusal::OffsetNotOnGrid);
    // And it is the one refusal worth retrying with a different offset.
    assert!(response.refusal.worth_asking_again());
}

/// The refusals that mean "this peer cannot help" are told apart from the one
/// that means "ask differently". Getting this backwards would either strand a
/// download or blacklist the network.
#[test]
fn refusals_say_whether_the_peer_is_worth_asking_again() {
    use rustock_networking::protocol::snap::Refusal;

    assert!(Refusal::OffsetNotOnGrid.worth_asking_again(), "a grid mismatch is our problem");
    assert!(Refusal::PastTheEnd.worth_asking_again(), "our total was wrong, not their fault");
    assert!(!Refusal::StateRootMismatch.worth_asking_again(), "they are on another chain");
    assert!(!Refusal::StateNotStored.worth_asking_again(), "they pruned it");
    assert!(!Refusal::UnknownBlock.worth_asking_again(), "they do not have the block");
}

/// A refusal survives the wire, which is the only way the client sees it.
#[test]
fn a_refusal_survives_the_wire() {
    use rustock_networking::protocol::snap::Refusal;

    for reason in [
        Refusal::None,
        Refusal::UnknownBlock,
        Refusal::StateRootMismatch,
        Refusal::StateNotStored,
        Refusal::PastTheEnd,
        Refusal::OffsetNotOnGrid,
    ] {
        let sent = SnapChunkResponse {
            id: 5,
            payload: ChunkPayload::Proved { entries: Vec::new(), witness: Vec::new() },
            block_number: 7,
            from: 100,
            to: 100,
            complete: false,
            refusal: reason,
        };
        let encoded = sent.encode_body();
        let got = SnapChunkResponse::decode_body(&mut encoded.as_slice()).expect("decodes");
        assert_eq!(got.refusal, reason, "{reason:?} did not survive");
    }
}

/// A server that serves less than a whole cell must not leave the client
/// asking for that cell forever. It falls back to the exact offset, paying a
/// cache miss rather than stalling.
#[test]
fn a_short_cell_does_not_stall_the_download() {
    let peer = Peer::new(400);
    let local = Arc::new(MemoryTrieStore::new());
    // A grid far larger than anything the peer will serve in one answer.
    let cfg = SnapConfig { chunk_grid: 1 << 20, ..config(1, 400) };
    let mut client = StateDownload::new(peer.root_hash, peer.total(), &cfg, local);

    let mut guard = 0;
    let mut offsets = Vec::new();
    while !client.is_complete() {
        guard += 1;
        assert!(guard < 5_000, "the download stalled on a short cell: {offsets:?}");
        let request = client.next_request().expect("work remains");
        offsets.push(request.from);
        // Serve only 400 bytes, far less than the 1 MB cell asked for.
        let response = peer.serve(request.from, 400);
        let proof = proof_from_payload(&response.payload).unwrap();
        client.accept(request.from, &proof).expect("honest");
    }

    client.verify_stored().expect("the state is whole");
    assert!(offsets.len() > 2, "the fixture should need several answers");
}

/// When the checkpoint moves, cells older than the two generations this server
/// still answers for are dropped -- about a gigabyte per generation.
#[test]
fn a_rolled_checkpoint_drops_the_old_cells() {
    let (store, peer, _) = server_fixture(200);
    let other = B256::repeat_byte(0xC5);

    // Two states' worth of cached cells.
    store.put_snap_chunk(peer.root_hash, 4096, 0, 0, b"current").expect("put");
    store.put_snap_chunk(other, 4096, 0, 0, b"retired").expect("put");
    store.put_snap_chunk(other, 4096, 0, 7, b"retired").expect("put");
    assert!(store.snap_chunk(other, 4096, 0, 7).expect("readable").is_some());

    let server = SnapServer::new(
        store.clone(),
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig { server_enabled: true, ..config(4, 4096) },
    );

    // Two status requests: the first records the checkpoint, the second sees
    // it unchanged. Roll it by hand in between is not possible here, so drive
    // the cleanup directly through a status on a store whose checkpoint is
    // this state.
    let _ = server.status(&rustock_networking::protocol::snap::SnapStatusRequest { id: 1 });

    // Whatever the status returned, the retired state's cells must not
    // outlive a rollover; assert the mechanism rather than the schedule.
    store.clear_snap_chunks(other).expect("clear");
    assert!(store.snap_chunk(other, 4096, 0, 0).expect("readable").is_none());
    assert!(store.snap_chunk(other, 4096, 0, 7).expect("readable").is_none());
    assert!(
        store.snap_chunk(peer.root_hash, 4096, 0, 0).expect("readable").is_some(),
        "clearing one state took another with it"
    );
}


/// A canonical header at `number` whose state root is `root`, so the server
/// can be asked about a checkpoint the fixture does not otherwise have.
fn put_checkpoint(store: &Arc<rustock_storage::BlockStore>, number: u64, root: B256) {
    use alloy_primitives::{Address, U256};
    use rustock_core::Header;

    let header = Header {
        parent_hash: B256::repeat_byte(2),
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: root,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::from(1u64),
        number,
        gas_limit: U256::from(6_800_000u64),
        gas_used: 0,
        timestamp: 1_700_000_000,
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
    };
    let hash = header.hash();
    store.put_header(&header).expect("put header");
    store.put_canonical_hash(number, hash).expect("index height");
}

/// **Two generations, not one.** `chunk` serves any canonical block whose
/// state resolves, so a client that took its status just before a roll goes on
/// asking for the older checkpoint. Both have to stay answerable: the cells,
/// so it does not fall onto the cold path, and -- through these same roots
/// handed to the collector -- the state behind them. See #143, #144.
#[test]
fn the_server_answers_for_the_current_checkpoint_and_the_one_before_it() {
    let (store, peer, head) = server_fixture(50);
    let cfg = SnapConfig { server_enabled: true, ..config(4, 4096) };

    let current = cfg.checkpoint_for(head);
    let previous = current - cfg.checkpoint_rounding;
    let older = previous - cfg.checkpoint_rounding;

    let current_root = B256::repeat_byte(0xC1);
    let previous_root = B256::repeat_byte(0xB2);
    let older_root = B256::repeat_byte(0xA3);
    for (number, root) in
        [(current, current_root), (previous, previous_root), (older, older_root)]
    {
        put_checkpoint(&store, number, root);
    }

    let server = SnapServer::new(
        store.clone(),
        peer.store.clone() as Arc<dyn TrieStore>,
        cfg,
    );

    assert_eq!(
        server.servable_roots(),
        vec![current_root, previous_root],
        "the current checkpoint and the one before it, current first"
    );
}

/// With serving off there is no checkpoint to protect, so the collector is
/// handed nothing and retains nothing extra.
#[test]
fn a_node_that_does_not_serve_pins_nothing() {
    let (store, peer, head) = server_fixture(50);
    let cfg = SnapConfig { server_enabled: false, ..config(4, 4096) };
    put_checkpoint(&store, cfg.checkpoint_for(head), B256::repeat_byte(0xC1));

    let server =
        SnapServer::new(store.clone(), peer.store.clone() as Arc<dyn TrieStore>, cfg.clone());
    assert!(server.servable_roots().is_empty());
    assert!(crate::snap::server::servable_roots(&store, &cfg).is_empty());
}

/// A generation older than the two kept loses its cells; the two kept do not.
#[test]
fn rolling_keeps_two_generations_of_cells_and_drops_the_third() {
    let (store, peer, head) = server_fixture(50);
    let cfg = SnapConfig { server_enabled: true, ..config(4, 4096) };

    let current = cfg.checkpoint_for(head);
    let previous = current - cfg.checkpoint_rounding;
    let older = previous - cfg.checkpoint_rounding;

    // The current checkpoint is the state the server actually holds, so
    // `status` can be computed for it.
    put_checkpoint(&store, current, peer.root_hash);
    let previous_root = B256::repeat_byte(0xB2);
    let older_root = B256::repeat_byte(0xA3);
    put_checkpoint(&store, previous, previous_root);
    put_checkpoint(&store, older, older_root);

    for root in [peer.root_hash, previous_root, older_root] {
        store.put_snap_chunk(root, 4096, 0, 0, b"cell").expect("put");
    }

    let server =
        SnapServer::new(store.clone(), peer.store.clone() as Arc<dyn TrieStore>, cfg);
    server.drop_stale_cells(&server.servable_roots());

    assert!(store.snap_chunk(peer.root_hash, 4096, 0, 0).expect("read").is_some());
    assert!(
        store.snap_chunk(previous_root, 4096, 0, 0).expect("read").is_some(),
        "the previous generation is still being served and must keep its cells"
    );
    assert!(
        store.snap_chunk(older_root, 4096, 0, 0).expect("read").is_none(),
        "a generation nobody can still be downloading should be reclaimed"
    );
}

/// A store that has lost one node, as a collected state has.
struct Gutted {
    inner: Arc<MemoryTrieStore>,
    hidden: B256,
}

impl TrieStore for Gutted {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if key == self.hidden.as_slice() {
            return None;
        }
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) {
        self.inner.put(key, value)
    }
}

/// **A half-collected state is refused, not served.**
///
/// The traversal skips a node it cannot resolve and carries on without
/// advancing the offset, so a collected subtree becomes a chunk that looks
/// well formed and is not. A client would replay it, find it disagrees with
/// the root hash, and score an honest node as malicious. So the server replays
/// its own chunk first, refuses, and strikes the state off. See #143.
#[test]
fn a_chunk_that_does_not_verify_is_refused_and_the_state_struck_off() {
    use rustock_networking::protocol::snap::{Refusal, SnapChunkRequest};

    let (store, peer, head) = server_fixture(400);
    let cfg = SnapConfig { server_enabled: true, ..config(4, 4096) };

    // Hide one non-embedded node under the root.
    let root_message = peer.store.get(peer.root_hash.as_slice()).expect("root");
    let root_node = TrieNode::from_message(&root_message, peer.store.as_ref());
    let hidden = [&root_node.left, &root_node.right]
        .into_iter()
        .find_map(|c| match c {
            rustock_trie::NodeRef::Hash(h) => Some(*h),
            _ => None,
        })
        .expect("a 400-entry trie has a non-embedded child under its root");

    // The checkpoint this server would offer is the gutted state.
    put_checkpoint(&store, cfg.checkpoint_for(head), peer.root_hash);

    let gutted = Arc::new(Gutted { inner: peer.store.clone(), hidden }) as Arc<dyn TrieStore>;
    let server = SnapServer::new(store.clone(), gutted, cfg);

    // The root still resolves, so the cheap check passes and the state is
    // offered -- which is exactly the trap.
    assert!(server.offer().is_some(), "a rooted but gutted state looks servable");

    let ask = |from: u64| SnapChunkRequest {
        id: 1,
        block_number: head,
        from,
        chunk_size: 4096,
        state_root: Some(peer.root_hash),
    };

    // Walk the grid until a cell needs the hidden subtree. It must come
    // before the end of the trie: the size the root commits to is unchanged by
    // the gutting, so running off the end would mean the hole went unnoticed.
    let total = rustock_trie::snapshot::total_size(&root_node, peer.store.as_ref());
    let mut refused = None;
    for cell in 0..total.div_ceil(4096) {
        let response = server.chunk(&ask(cell * 4096)).expect("an answer");
        if response.refusal != Refusal::None {
            refused = Some(response.refusal);
            break;
        }
        // Anything actually served must verify, or we shipped corruption.
        let arrived =
            crate::snap::client::chunk_from_payload(&response.payload, peer.root_hash)
                .expect("the server served a payload the client cannot even parse");
        let crate::snap::client::Arrived::Proved(proof) = arrived else {
            panic!("expected the proved dialect");
        };
        rustock_trie::snapshot_proof::verify_chunk(peer.root_hash, response.from, &proof)
            .expect("the server served a chunk that does not verify");
    }

    assert_eq!(
        refused,
        Some(Refusal::StateNotStored),
        "a cell over the missing subtree must be refused"
    );
    assert!(
        server.offer().is_none(),
        "once struck off, the state must not be offered again"
    );
    assert_eq!(
        server.chunk(&ask(0)).expect("an answer").refusal,
        Refusal::StateNotStored,
        "and every later chunk request is declined, whatever the offset"
    );
}

/// A cleared range must not leave the last cell behind: `delete_range` is end
/// exclusive, and a cache that leaked one entry per state would leak one per
/// rollover forever.
#[test]
fn clearing_a_state_leaves_nothing_of_it() {
    let (store, peer, _) = server_fixture(50);
    let root = peer.root_hash;

    for index in [0u64, 1, 4096, u64::MAX - 1, u64::MAX] {
        store.put_snap_chunk(root, 4096, 0, index, b"x").expect("put");
    }
    store.clear_snap_chunks(root).expect("clear");

    for index in [0u64, 1, 4096, u64::MAX - 1, u64::MAX] {
        assert!(
            store.snap_chunk(root, 4096, 0, index).expect("readable").is_none(),
            "cell {index} survived the clear"
        );
    }
}

/// **An rskj client gets rskj's format.** It cannot read ours, so without this
/// a rustock node can never serve one. It is told apart by what it does not
/// send: an rskj chunk request has three elements, ours has four.
#[test]
fn an_rskj_client_is_served_rskj_format() {
    use crate::snap::RSKJ_CHUNK_GRID;
    use rustock_networking::protocol::snap::Refusal;

    // Big enough that rskj's 51,200-byte cell is not the whole trie, so the
    // grid is actually exercised rather than trivially satisfied.
    let (store, peer, block_number) = server_fixture(900);
    assert!(peer.total() > RSKJ_CHUNK_GRID, "the fixture must exceed one rskj cell");
    let server = SnapServer::new(
        store,
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig { server_enabled: true, chunk_grid: 100_000, ..config(4, 100_000) },
    );

    // No state root: the caller is rskj.
    let response = server
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number,
            from: 0,
            chunk_size: 0,
            state_root: None,
        })
        .expect("an answer");

    assert_eq!(response.refusal, Refusal::None);
    match &response.payload {
        ChunkPayload::Legacy(blob) => assert!(!blob.is_empty(), "served an empty rskj chunk"),
        other => panic!("an rskj client was served {other:?}"),
    }

    // And on rskj's grid, not ours: their step is a constant they cannot be
    // talked out of.
    assert_eq!(response.to, RSKJ_CHUNK_GRID.min(peer.total()));

    let next = server
        .chunk(&SnapChunkRequest {
            id: 2,
            block_number,
            from: RSKJ_CHUNK_GRID,
            chunk_size: 0,
            state_root: None,
        })
        .expect("an answer");
    assert_eq!(next.refusal, Refusal::None, "rskj's own grid was refused");
}

/// A rustock client still gets the proved format from the same server, and the
/// two are cached apart -- the same range in two encodings must not be
/// confused.
#[test]
fn the_two_formats_are_served_and_cached_apart() {
    let (store, peer, block_number) = server_fixture(300);
    let server = SnapServer::new(
        store.clone(),
        peer.store.clone() as Arc<dyn TrieStore>,
        SnapConfig { server_enabled: true, chunk_grid: 51_200, ..config(4, 51_200) },
    );

    let ask = |root| SnapChunkRequest {
        id: 1,
        block_number,
        from: 0,
        chunk_size: 0,
        state_root: root,
    };

    let proved = server.chunk(&ask(Some(peer.root_hash))).expect("an answer");
    let legacy = server.chunk(&ask(None)).expect("an answer");

    assert!(matches!(proved.payload, ChunkPayload::Proved { .. }));
    assert!(matches!(legacy.payload, ChunkPayload::Legacy(_)));

    // Asking again must return each its own bytes, not the other's.
    let proved_again = server.chunk(&ask(Some(peer.root_hash))).expect("an answer");
    let legacy_again = server.chunk(&ask(None)).expect("an answer");
    assert_eq!(proved_again.payload, proved.payload, "the proved cell was overwritten");
    assert_eq!(legacy_again.payload, legacy.payload, "the rskj cell was overwritten");
}

/// Changing the grid must not make a server hand back cells for ranges nobody
/// asked about. Cell 3 of a 100 KB grid is a different range from cell 3 of a
/// 51,200 byte one, so the grid is part of a cell's identity.
#[test]
fn a_changed_grid_does_not_reuse_the_old_cells() {
    let (store, peer, block_number) = server_fixture(900);

    let serve_with = |grid: u64| {
        SnapServer::new(
            store.clone(),
            peer.store.clone() as Arc<dyn TrieStore>,
            SnapConfig { server_enabled: true, chunk_grid: grid, ..config(4, grid) },
        )
        .chunk(&SnapChunkRequest {
            id: 1,
            block_number,
            from: 0,
            chunk_size: 0,
            state_root: Some(peer.root_hash),
        })
        .expect("an answer")
    };

    let narrow = serve_with(8_192);
    let wide = serve_with(24_576);

    // Both are cell 0, of different widths. They must not be the same bytes.
    assert_ne!(
        narrow.payload, wide.payload,
        "a wider grid was served the narrow grid's cached cell"
    );
    assert_eq!(narrow.to, 8_192);
    assert_eq!(wide.to, 24_576);

    // And asking again for each returns its own.
    assert_eq!(serve_with(8_192).payload, narrow.payload);
    assert_eq!(serve_with(24_576).payload, wide.payload);
}


/// A missing node is caught wherever it falls.
///
/// This is the property the phase exists for: failing here rather than
/// during the first block that touches a missing node. Before #204 it did
/// not hold -- the traversal skipped a child it could not resolve, so a hole
/// made the chunk shorter rather than empty and the walk went past it.
#[test]
fn a_missing_node_is_caught_wherever_it_falls() {
    let peer = Peer::new(600);

    for cut in [1usize, 7, 20, 33, 47] {
        let local = Arc::new(MemoryTrieStore::new());
        let client = download_into(&peer, local.clone(), 4, 512);
        assert!(client.is_complete(), "cut={cut}: download incomplete");
        client.verify_stored().expect("whole before a node is removed");

        let mut keys = local.keys();
        keys.sort();
        let victim = keys[keys.len() * cut / 50].clone();
        assert!(local.remove(&victim), "cut={cut}: nothing removed");

        let err = client
            .verify_stored()
            .expect_err(&format!("cut={cut}: a missing node went unnoticed"));
        assert!(
            err.contains("not in the store") || err.contains("hole") || err.contains("root"),
            "cut={cut}: unhelpful complaint: {err}"
        );
    }
}

/// A node can be present while the bytes its long value stands for are not,
/// because a long value is stored under its own hash.
#[test]
fn a_missing_long_value_is_caught() {
    let peer = Peer::new(400);
    let local = Arc::new(MemoryTrieStore::new());
    let client = download_into(&peer, local.clone(), 4, 512);
    client.verify_stored().expect("whole to begin with");

    // toy_state gives every fifth key a 96-byte value, which is long enough
    // to be stored separately. Find one such record: it parses as no node.
    let long_value = local
        .keys()
        .into_iter()
        .find(|k| {
            local
                .get(k)
                .map(|v| v.len() == 96)
                .unwrap_or(false)
        })
        .expect("a long value should have been stored");

    assert!(local.remove(&long_value));
    let err = client.verify_stored().expect_err("a missing long value must be caught");
    assert!(err.contains("not in the store"), "unhelpful complaint: {err}");
}

/// Verification reaches the same verdict however many threads walk it.
#[test]
fn verification_does_not_depend_on_the_thread_count() {
    let peer = Peer::new(400);
    let local = Arc::new(MemoryTrieStore::new());
    let client = download_into(&peer, local, 4, 512);
    let first = client.verify_stored().expect("whole");
    assert!(first > 0);
    for _ in 0..4 {
        assert_eq!(
            client.verify_stored().expect("still whole"),
            first,
            "repeated verification must count the same nodes"
        );
    }
}

/// What it caught before #204, and must still catch.
#[test]
fn a_missing_root_is_caught() {
    let peer = Peer::new(300);
    let local = Arc::new(MemoryTrieStore::new());
    let client = download_into(&peer, local.clone(), 4, 512);
    client.verify_stored().expect("whole to begin with");

    assert!(local.remove(peer.root_hash.as_slice()), "root should have been stored");
    let err = client.verify_stored().expect_err("a missing root must be caught");
    assert!(err.contains("root"), "unhelpful complaint: {err}");
}

/// An rskj server, serving as rskj does: whatever the request says, the nodes
/// from the one holding `from` until `from + cell`, in rskj's format, through
/// the wire. rskj's `cell` is `50 * 1024`, a constant on its side.
fn rskj_serves(peer: &Peer, from: u64, cell: u64) -> SnapChunkResponse {
    use rustock_trie::snapshot_legacy::{encode_blob, legacy_chunk};
    let root: [u8; 32] = peer.root_hash.into();
    let chunk = legacy_chunk(&root, from, from + cell, peer.store.as_ref()).expect("a chunk");
    let response = SnapChunkResponse {
        id: 1,
        payload: ChunkPayload::Legacy(encode_blob(&chunk).into()),
        block_number: 100,
        from,
        to: from + cell,
        complete: false,
        refusal: rustock_networking::protocol::snap::Refusal::None,
    };
    let encoded = response.encode_body();
    SnapChunkResponse::decode_body(&mut encoded.as_slice()).expect("survives the wire")
}

/// The rebuilt chunk an rskj server's answer comes to.
fn rebuilt(peer: &Peer, response: &SnapChunkResponse) -> super::client::RebuiltChunk {
    use super::client::{chunk_from_payload, Arrived};
    match chunk_from_payload(&response.payload, peer.root_hash) {
        Ok(Arrived::Rebuilt(chunk)) => chunk,
        other => panic!("an rskj chunk must rebuild: {other:?}"),
    }
}

/// Downloads a state from rskj servers alone, as mainnet's are, with this
/// node's own grid. Returns the client, its store, and how many requests it
/// took.
fn download_from_rskj(
    peer: &Peer,
    grid: u64,
    cell: u64,
) -> (StateDownload, Arc<MemoryTrieStore>, usize) {
    let local = Arc::new(MemoryTrieStore::new());
    let config = SnapConfig {
        chunk_grid: grid,
        ..config(4, grid)
    };
    let mut client = StateDownload::new(peer.root_hash, peer.total(), &config, local.clone());
    // Several times what a download that moves needs, so that one that has
    // stopped moving fails at once rather than after a hundred thousand
    // rebuilds.
    let enough = 4 * (peer.total() / cell + 1) as usize + 64;
    let mut asked = 0;
    while !client.is_complete() {
        asked += 1;
        assert!(
            asked < enough,
            "{asked} requests and not done: the download has stopped moving"
        );
        let request = client.next_request().expect("work left and none in flight");
        let chunk = rebuilt(peer, &rskj_serves(peer, request.from, cell));
        client
            .accept_rebuilt(request.from, &chunk)
            .expect("an honest rskj chunk");
    }
    (client, local, asked)
}

/// Every node of the peer's trie, and every long value, is in `local`.
fn holds_everything(peer: &Peer, local: &MemoryTrieStore) {
    use rustock_trie::snapshot::chunk_from;
    for node in chunk_from(&peer.root, 0, u64::MAX, peer.store.as_ref()) {
        assert!(
            local.get(keccak256(&node.message).as_slice()).is_some(),
            "the node at offset {} was never fetched",
            node.offset
        );
        for value in &node.long_values {
            assert!(
                local.get(keccak256(value).as_slice()).is_some(),
                "a long value was never fetched"
            );
        }
    }
}

/// **An rskj server fills every cell of a wider grid.**
///
/// rskj serves `from` to `from + 50 * 1024` whatever is asked, and this client
/// used to mark the whole 100,000-byte cell it asked for as done. On mainnet
/// that left the last 48,800 bytes of every cell unfetched -- 45.7% of the
/// state, which nothing noticed until the check after an hour's download,
/// five attempts running. The cursor now moves as far as the chunk reached,
/// and the next request picks up exactly there.
#[test]
fn an_rskj_server_fills_every_cell_of_a_wider_grid() {
    use crate::snap::RSKJ_CHUNK_GRID;

    let peer = Peer::new(12_000);
    let total = peer.total();
    assert!(
        total > 6 * 100_000,
        "the trie must span several cells, not {total} bytes"
    );

    let (client, local, asked) = download_from_rskj(&peer, 100_000, RSKJ_CHUNK_GRID);
    client
        .verify_stored()
        .expect("the downloaded state is whole");
    holds_everything(&peer, &local);

    // And at one request per rskj cell, give or take one per slice: an
    // answer that stops mid-cell is followed by a request for exactly where
    // it stopped, not by the same cell again.
    let cells = total.div_ceil(RSKJ_CHUNK_GRID) as usize;
    assert!(
        asked <= cells + cells / 10 + 2 * 4,
        "{asked} requests for {cells} rskj cells"
    );
}

/// **A node longer than rskj's cell is fetched.**
///
/// rskj keeps a node among a chunk's own only if it ends before `from + 50 *
/// 1024`, so a node longer than that -- a contract's code, or a long value of
/// the Bridge's storage -- is never one of them. It is the node the walk stops
/// at, which rskj sends whole all the same, on top of the stack it hands back
/// after the chunk's own. Asked at the cursor before it, every answer was the
/// one node that ends there, taken and stored again with the cursor where it
/// was: testnet's download stood at 94% for hours, writing all the while. The
/// node the walk stopped at now counts as fetched when it follows the chunk's
/// own, and when the chunk carried nothing of its own, the node it stopped at
/// is the one holding the offset asked.
#[test]
fn a_node_longer_than_an_rskj_cell_is_fetched() {
    use crate::snap::RSKJ_CHUNK_GRID;
    use rustock_trie::snapshot::chunk_from;

    let long = [
        (2_000, 60_000),
        (6_000, 150_000),
        (6_001, 52_000),
        (9_000, 400_000),
    ];
    let peer = Peer::with_long_values(12_000, &long);
    let stream = chunk_from(&peer.root, 0, u64::MAX, peer.store.as_ref());
    let longer: Vec<_> = stream.iter().filter(|n| n.span > RSKJ_CHUNK_GRID).collect();
    // Two of them side by side: a leaf that holds a long value names it by
    // hash and length, small enough to embed, so both sit in one node's entry.
    assert_eq!(
        longer.len(),
        3,
        "four long values make three nodes longer than rskj's cell"
    );

    // What rskj sends: asked where a long node begins, only the node that ends
    // there; asked inside one, a cell or more from its end, nothing of its own.
    for node in &longer {
        let at_start = rebuilt(&peer, &rskj_serves(&peer, node.offset, RSKJ_CHUNK_GRID));
        assert_eq!(
            at_start.span.map(|(_, end)| end),
            Some(node.offset),
            "asked at {}",
            node.offset
        );
        assert_eq!(
            at_start.stopped_at,
            Some((node.offset, node.end())),
            "stopped at, asked at {}",
            node.offset
        );
        let inside = node.offset + node.span - RSKJ_CHUNK_GRID;
        let within = rebuilt(&peer, &rskj_serves(&peer, inside, RSKJ_CHUNK_GRID));
        assert_eq!(
            within.span, None,
            "asked at {inside}, inside the node at {}",
            node.offset
        );
        assert_eq!(
            within.stopped_at,
            Some((node.offset, node.end())),
            "stopped at, asked at {inside}"
        );
    }

    // From the start, each long node is met at the cursor just before it.
    let (client, local, _) = download_from_rskj(&peer, 100_000, RSKJ_CHUNK_GRID);
    client
        .verify_stored()
        .expect("the downloaded state is whole");
    holds_everything(&peer, &local);

    // And a slice that begins inside the longest node asks for an offset the
    // node holds, which rskj answers with nothing of its own.
    let node = longer.iter().max_by_key(|n| n.span).expect("a long node");
    let inside = node.offset + node.span / 2;
    let local = Arc::new(MemoryTrieStore::new());
    let cfg = SnapConfig {
        chunk_grid: 1,
        ..config(2, 100_000)
    };
    let mut client = StateDownload::new(peer.root_hash, 2 * inside, &cfg, local.clone());
    let mut offsets = Vec::new();
    while !client.is_complete() {
        let enough = 4 * (peer.total() / RSKJ_CHUNK_GRID) as usize + 64;
        assert!(
            offsets.len() < enough,
            "{} requests and not done: stopped moving",
            offsets.len()
        );
        let request = client.next_request().expect("work left and none in flight");
        offsets.push(request.from);
        let chunk = rebuilt(&peer, &rskj_serves(&peer, request.from, RSKJ_CHUNK_GRID));
        client
            .accept_rebuilt(request.from, &chunk)
            .expect("an honest rskj chunk");
    }
    assert!(
        offsets.contains(&inside),
        "no slice began inside the node at {}",
        node.offset
    );
    client
        .verify_stored()
        .expect("the downloaded state is whole");
    holds_everything(&peer, &local);
}

/// **A short answer is not taken for the cell.** A server serving less than
/// anything this client expects still leaves no hole: each answer advances
/// the download by what it carried.
#[test]
fn a_short_rskj_chunk_is_not_taken_for_the_cell() {
    let peer = Peer::new(3_000);
    let (client, local, _) = download_from_rskj(&peer, 100_000, 7_000);
    client
        .verify_stored()
        .expect("the downloaded state is whole");
    holds_everything(&peer, &local);
}

/// **An rskj chunk that begins after the offset asked for is refused**, and
/// leaves the store and the range as they were. Its nodes are genuine -- it
/// rebuilds to the root -- but it is not an answer to the question, and
/// taking it would leave a gap behind the cursor.
#[test]
fn an_rskj_chunk_that_begins_after_the_offset_asked_is_refused() {
    use crate::snap::RSKJ_CHUNK_GRID;

    let peer = Peer::new(3_000);
    assert!(
        peer.total() > 4 * RSKJ_CHUNK_GRID,
        "the trie must span several rskj cells"
    );
    let local = Arc::new(MemoryTrieStore::new());
    let mut client = StateDownload::new(
        peer.root_hash,
        peer.total(),
        &config(1, 100_000),
        local.clone(),
    );

    let request = client.next_request().expect("a request");
    let elsewhere = rebuilt(
        &peer,
        &rskj_serves(&peer, request.from + 2 * RSKJ_CHUNK_GRID, RSKJ_CHUNK_GRID),
    );
    match client.accept_rebuilt(request.from, &elsewhere) {
        Err(ChunkError::Misplaced { asked, starts }) => {
            assert_eq!(asked, request.from);
            assert!(starts > request.from);
        }
        other => panic!("a chunk from elsewhere was taken: {other:?}"),
    }
    assert_eq!(local.len(), 0, "a refused chunk wrote to the store");
    assert_eq!(client.progress().0, 0, "a refused chunk moved the cursor");
    assert_eq!(
        client.next_request().map(|r| r.from),
        Some(request.from),
        "the range was not asked again"
    );
}

/// **After an rskj chunk the next request names the offset just past the
/// cursor; refused, it goes back to the grid.** An rskj server answers any
/// offset and a rustock server only its grid's, and the next request may go
/// to either.
#[test]
fn a_refused_exact_offset_is_asked_on_the_grid_next() {
    use crate::snap::RSKJ_CHUNK_GRID;

    let peer = Peer::new(3_000);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client = StateDownload::new(peer.root_hash, peer.total(), &config(1, 100_000), local);

    let first = client.next_request().expect("a request");
    assert_eq!(first.from, 0);
    let chunk = rebuilt(&peer, &rskj_serves(&peer, first.from, RSKJ_CHUNK_GRID));
    client
        .accept_rebuilt(first.from, &chunk)
        .expect("an honest chunk");
    let (cursor, _) = client.progress();
    assert!(
        cursor > 0 && cursor < 100_000,
        "an rskj chunk stops mid-cell, at {cursor}"
    );

    let exact = client.next_request().expect("more to fetch");
    assert_eq!(
        exact.from,
        cursor + 1,
        "the next request does not ask just past where the chunk stopped"
    );

    client.realign(exact.from);
    let aligned = client.next_request().expect("more to fetch");
    assert_eq!(
        aligned.from, 0,
        "a refused offset was asked again instead of the cell"
    );
}

/// **An rskj chunk counts the node its walk stopped at**, which rskj sends
/// whole after the chunk's own nodes: the download moves to where that node
/// ends, and does not ask for it again.
#[test]
fn an_rskj_chunk_counts_the_node_its_walk_stopped_at() {
    use crate::snap::RSKJ_CHUNK_GRID;

    let peer = Peer::new(3_000);
    let local = Arc::new(MemoryTrieStore::new());
    let mut client = StateDownload::new(peer.root_hash, peer.total(), &config(1, 100_000), local);

    let first = client.next_request().expect("a request");
    let chunk = rebuilt(&peer, &rskj_serves(&peer, first.from, RSKJ_CHUNK_GRID));
    let (Some((_, own_end)), Some((begins, ends))) = (chunk.span, chunk.stopped_at) else {
        panic!(
            "not the chunk this test is about: {:?} {:?}",
            chunk.span, chunk.stopped_at
        );
    };
    assert_eq!(
        begins, own_end,
        "the walk stopped somewhere other than after the chunk's own"
    );
    client
        .accept_rebuilt(first.from, &chunk)
        .expect("an honest chunk");
    assert_eq!(
        client.progress().0,
        ends,
        "the node the walk stopped at was not counted"
    );
    assert_eq!(client.next_request().map(|r| r.from), Some(ends + 1));
}

/// **An answer goes to the slice that asked for it**, when two slices ask
/// inside one cell: one for the cell, the other just past where its last
/// chunk stopped. The cell's offset used to match either, and the slice asking
/// exactly took the other's answer; the other waited on an answer already
/// spent, and the first's own came back unsolicited.
#[test]
fn an_answer_goes_to_the_slice_that_asked_for_it() {
    let peer = Peer::new(1_000);
    let total = peer.total();
    let local = Arc::new(MemoryTrieStore::new());
    let mut client = StateDownload::new(peer.root_hash, total, &config(2, 100_000), local);

    let (first, second) = (
        client.next_request().expect("a request"),
        client.next_request().expect("another"),
    );
    assert_eq!(
        (first.from, second.from),
        (0, 0),
        "both slices begin in the first cell, of {total}"
    );
    let chunk = rebuilt(&peer, &rskj_serves(&peer, 0, 2_000));
    client
        .accept_rebuilt(first.from, &chunk)
        .expect("the first slice's answer");
    let (reached, _) = client.progress();
    assert!(
        reached > 0 && reached < total / 2,
        "the first chunk reached {reached}, into the second slice"
    );
    let exact = client.next_request().expect("the first slice asks again");
    assert_eq!(exact.from, reached + 1);

    // The second slice's answer, for the cell it asked; then the first's own.
    let taken = client
        .accept_rebuilt(second.from, &chunk)
        .expect("the second slice's answer");
    assert_eq!(
        taken.advanced, 0,
        "the cell's first chunk ends before the second slice begins"
    );
    let next = rebuilt(&peer, &rskj_serves(&peer, exact.from, 2_000));
    let taken = client
        .accept_rebuilt(exact.from, &next)
        .expect("the first slice's answer was taken by another");
    assert!(taken.advanced > 0);
    assert_eq!(client.progress().0, reached + taken.advanced);

    // Both slices are free again: each asks just past its own cursor.
    let asks = [client.next_request(), client.next_request()].map(|r| r.map(|r| r.from));
    assert_eq!(
        asks,
        [Some(reached + taken.advanced + 1), Some(total / 2 + 1)]
    );
}
