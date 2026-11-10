//! Telling peers about new blocks, as rskj does.
//!
//! A block this node mined goes out whole to a few peers and as its hash to
//! the rest (`EthereumImpl.addNewMinedBlock` through
//! `ChannelManagerImpl.broadcastBlock`). A block it took from a peer at the
//! tip goes out as its hash to the peers not known to hold it
//! (`MessageVisitor.relayBlock`). A peer that hears a hash it lacks asks for
//! the block with `GetBlockMessage`, which `SyncHandler` answers.

use alloy_primitives::{B256, B512};
use rustock_core::Block;
use rustock_networking::peers::PeerStore;
use rustock_networking::protocol::{BlockIdentifier, P2pMessage, RskMessage, RskSubMessage};
use std::collections::HashSet;
use tracing::trace;

/// Which peers get a mined block whole and which get its hash: rskj
/// `ChannelManagerImpl.broadcastBlock` (L194-222). The peers are shuffled, and
/// the first `(int) Math.floor(Math.sqrt(peers.size()))` get the block; the
/// rest get a `NewBlockHashesMessage` naming it.
pub fn broadcast_split<R: rand::Rng + ?Sized>(
    mut peers: Vec<B512>,
    rng: &mut R,
) -> (Vec<B512>, Vec<B512>) {
    use rand::seq::SliceRandom;
    peers.shuffle(rng);
    let whole = (peers.len() as f64).sqrt().floor() as usize;
    let hashes = peers.split_off(whole);
    (peers, hashes)
}

fn new_block_hashes(hash: B256, number: u64) -> P2pMessage {
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::NewBlockHashes(vec![
        BlockIdentifier { hash, number },
    ])))
}

/// Sends a block this node mined to every connected peer: rskj
/// `EthereumImpl.addNewMinedBlock` (L60-68), which calls `broadcastBlock` for
/// a mined block once it is in the store, best or not. Returns the peers that
/// got it whole.
pub async fn broadcast_block(peer_store: &PeerStore, block: &Block) -> Vec<B512> {
    let peers = peer_store.peers().await;
    let (whole, hashes) = broadcast_split(peers, &mut rand::thread_rng());
    let hash = block.hash();
    let number = block.header.number;
    trace!(
        target: "rustock::sync",
        "Mined block #{number} to {} peer(s) whole and {} by hash",
        whole.len(),
        hashes.len()
    );
    let message = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::Block(Box::new(
        block.clone(),
    ))));
    for peer in &whole {
        peer_store.send_to_peer(peer, message.clone()).await;
    }
    let announcement = new_block_hashes(hash, number);
    for peer in &hashes {
        peer_store.send_to_peer(peer, announcement.clone()).await;
    }
    whole
}

/// What this node does with a block it mined once the block is stored, best
/// or not: send it to the peers, as rskj's `EthereumImpl.addNewMinedBlock`
/// (L60-68) does through [`broadcast_block`]. The miner commits from a
/// blocking thread, so the sending is handed to `runtime`.
pub fn on_mined(
    peer_store: std::sync::Arc<PeerStore>,
    runtime: tokio::runtime::Handle,
) -> impl Fn(&Block) + Send + Sync {
    move |block: &Block| {
        let peer_store = peer_store.clone();
        let block = block.clone();
        runtime.spawn(async move {
            broadcast_block(&peer_store, &block).await;
        });
    }
}

/// Announces a block taken from a peer to every connected peer not known to
/// hold it: rskj `MessageVisitor.relayBlock` (L265-276), a
/// `NewBlockHashesMessage` to the known peers less those
/// `BlockNodeInformation.getNodesByBlock` names. Returns how many it went to.
pub(crate) async fn relay_block(
    peer_store: &PeerStore,
    holders: &HashSet<B512>,
    hash: B256,
    number: u64,
) -> usize {
    let announcement = new_block_hashes(hash, number);
    let mut sent = 0;
    for peer in peer_store.peers().await {
        if !holders.contains(&peer) && peer_store.send_to_peer(&peer, announcement.clone()).await {
            sent += 1;
        }
    }
    trace!(target: "rustock::sync", "Relayed #{number} {hash:?} to {sent} peer(s)");
    sent
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use tokio::sync::mpsc;

    fn peer(n: u8) -> B512 {
        B512::repeat_byte(n)
    }

    /// rskj sends the whole block to the floor of the square root of the
    /// peer count, and the hash to everyone else, each peer once.
    #[test]
    fn the_whole_block_goes_to_the_square_root_of_the_peers() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for (count, whole) in [
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 2),
            (8, 2),
            (9, 3),
            (24, 4),
            (25, 5),
        ] {
            let peers: Vec<B512> = (1..=count).map(peer).collect();
            let (to_whole, to_hash) = broadcast_split(peers.clone(), &mut rng);
            assert_eq!(to_whole.len(), whole, "{count} peers");
            assert_eq!(to_hash.len(), count as usize - whole, "{count} peers");
            let mut all: Vec<B512> = to_whole.iter().chain(&to_hash).copied().collect();
            all.sort();
            assert_eq!(all, peers, "{count} peers: each once");
        }
    }

    /// Shuffled first, as rskj shuffles them, so the same few peers are not
    /// always the ones that get the block whole.
    #[test]
    fn the_peers_that_get_the_whole_block_are_drawn_at_random() {
        let peers: Vec<B512> = (1..=16).map(peer).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let drawn: HashSet<Vec<B512>> = (0..20)
            .map(|_| broadcast_split(peers.clone(), &mut rng).0)
            .collect();
        assert!(drawn.len() > 1, "twenty draws all chose {drawn:?}");
    }

    fn block(number: u64) -> Block {
        let header = crate::tests::dummy_header(
            number,
            B256::repeat_byte(1),
            alloy_primitives::U256::from(1u64),
        );
        Block {
            header,
            transactions: Vec::new(),
            ommers: Vec::new(),
        }
    }

    async fn store_of(count: u8) -> (PeerStore, Vec<(B512, mpsc::Receiver<P2pMessage>)>) {
        let store = PeerStore::new();
        let mut inboxes = Vec::new();
        for n in 1..=count {
            let (tx, rx) = mpsc::channel(16);
            store.add_peer(peer(n), tx).await;
            inboxes.push((peer(n), rx));
        }
        (store, inboxes)
    }

    #[tokio::test]
    async fn a_mined_block_reaches_every_peer_once() {
        let (store, mut inboxes) = store_of(9).await;
        let mined = block(42);
        let whole: HashSet<B512> = broadcast_block(&store, &mined).await.into_iter().collect();
        assert_eq!(whole.len(), 3, "the square root of nine");
        for (id, inbox) in &mut inboxes {
            let Ok(P2pMessage::RskMessage(message)) = inbox.try_recv() else {
                panic!("{id:?} got nothing");
            };
            match message.sub_message {
                RskSubMessage::Block(got) => {
                    assert!(whole.contains(id), "{id:?} got the block but was not drawn");
                    assert_eq!(got.hash(), mined.hash());
                }
                RskSubMessage::NewBlockHashes(ids) => {
                    assert!(
                        !whole.contains(id),
                        "{id:?} was drawn but got only the hash"
                    );
                    assert_eq!(
                        ids,
                        vec![BlockIdentifier {
                            hash: mined.hash(),
                            number: 42
                        }]
                    );
                }
                other => panic!("{id:?} got {other:?}"),
            }
            assert!(inbox.try_recv().is_err(), "{id:?} heard of the block twice");
        }
    }

    /// The miner commits from a blocking thread: the block still reaches every
    /// peer.
    #[tokio::test]
    async fn a_block_mined_on_a_blocking_thread_reaches_every_peer() {
        let (store, mut inboxes) = store_of(4).await;
        let on_mined = on_mined(
            std::sync::Arc::new(store),
            tokio::runtime::Handle::current(),
        );
        let mined = block(7);
        tokio::task::spawn_blocking(move || on_mined(&mined))
            .await
            .unwrap();
        for (id, inbox) in &mut inboxes {
            let heard =
                tokio::time::timeout(std::time::Duration::from_secs(10), inbox.recv()).await;
            assert!(matches!(heard, Ok(Some(_))), "{id:?} heard nothing");
        }
    }

    #[tokio::test]
    async fn a_relayed_block_skips_the_peers_that_hold_it() {
        let (store, mut inboxes) = store_of(4).await;
        let holders = HashSet::from([peer(1), peer(3)]);
        let hash = B256::repeat_byte(0xab);
        assert_eq!(relay_block(&store, &holders, hash, 7).await, 2);
        for (id, inbox) in &mut inboxes {
            let got = inbox.try_recv();
            if holders.contains(id) {
                assert!(got.is_err(), "{id:?} holds the block and was told of it");
                continue;
            }
            let Ok(P2pMessage::RskMessage(message)) = got else {
                panic!("{id:?} was not told");
            };
            let RskSubMessage::NewBlockHashes(ids) = message.sub_message else {
                panic!("{id:?} got another message");
            };
            assert_eq!(ids, vec![BlockIdentifier { hash, number: 7 }]);
        }
    }
}
