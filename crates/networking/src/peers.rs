use tracing::warn;
use std::collections::HashMap;
use tokio::sync::{Mutex, mpsc};
use alloy_primitives::{B512, U256, B256};
use crate::protocol::P2pMessage;

/// Metadata about a connected peer.
#[derive(Debug, Clone, Default)]
pub struct PeerMetadata {
    pub best_number: u64,
    pub best_hash: B256,
    pub total_difficulty: U256,
    pub client_id: String,
    /// The peer's remote IP, when the connection path knew one.
    ///
    /// Peer scoring records every event against the node id **and** the
    /// address (rskj's `recordEvent(id, address, ...)`), because a peer that
    /// reconnects with a freshly generated node id keeps its address. The
    /// sync layer only ever holds a node id, so the address has to be
    /// reachable from here.
    pub address: Option<std::net::IpAddr>,
    /// Lowest block this peer says it can serve.
    ///
    /// `None` means it did not say, which must be read as "serves everything"
    /// rather than "serves nothing": every rskj peer looks like this, and so
    /// does every rustock peer before the first status arrives. Treating
    /// silence as a refusal would empty the peer set.
    pub earliest_block: Option<u64>,
}

struct PeerState {
    caps: crate::handshake::PeerCapabilities,
    sender: mpsc::Sender<P2pMessage>,
    metadata: PeerMetadata,
}

/// Depth of each peer's outbound queue.
///
/// This was previously an unbounded channel, which let a peer that completed the
/// handshake and then simply stopped reading drive our memory arbitrarily high:
/// transaction and block broadcast fan out to every connected peer, so the queue
/// for one stalled peer grows for as long as the node keeps producing traffic.
/// A bounded queue converts that into backpressure we can act on -- we drop the
/// message, and the peer falls behind rather than the node falling over.
pub const PEER_CHANNEL_CAPACITY: usize = 1024;

/// Thread-safe store for tracking active peer connections and their outbound senders.
#[derive(Default)]
pub struct PeerStore {
    connected_peers: Mutex<HashMap<B512, PeerState>>,
}

impl PeerStore {
    pub fn new() -> Self {
        Self { connected_peers: Mutex::new(HashMap::new()) }
    }

    /// Attempts to add a peer to the store. Returns true if it was newly added.
    pub async fn add_peer(&self, id: B512, sender: mpsc::Sender<P2pMessage>) -> bool {
        self.add_peer_with(id, sender, Default::default()).await
    }

    /// As [`Self::add_peer`], recording what the peer said it speaks.
    pub async fn add_peer_with(
        &self,
        id: B512,
        sender: mpsc::Sender<P2pMessage>,
        caps: crate::handshake::PeerCapabilities,
    ) -> bool {
        let mut peers = self.connected_peers.lock().await;
        use std::collections::hash_map::Entry;
        match peers.entry(id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
                e.insert(PeerState { sender, metadata: PeerMetadata::default(), caps });
                true
            }
        }
    }

    /// Records a peer's new lower bound, leaving the rest of its metadata be.
    pub async fn set_earliest_block(&self, id: &B512, earliest: u64) {
        if let Some(p) = self.connected_peers.lock().await.get_mut(id) {
            p.metadata.earliest_block = Some(earliest);
        }
    }

    /// What this peer said it speaks.
    pub async fn capabilities(
        &self,
        id: &B512,
    ) -> Option<crate::handshake::PeerCapabilities> {
        self.connected_peers.lock().await.get(id).map(|p| p.caps)
    }

    /// Peers that negotiated the served-range extension.
    ///
    /// The gate on every `BlockRangeUpdate`: an rskj peer that received one
    /// would throw out of `MessageType.valueOfType` and close the connection,
    /// so a peer is sent one only once it has said it understands it.
    pub async fn peers_understanding_block_range(&self) -> Vec<B512> {
        self.connected_peers
            .lock()
            .await
            .iter()
            .filter(|(_, p)| p.caps.understands_block_range())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Peers that announced the `snap` capability.
    ///
    /// The gate on all six snapshot messages, for the same reason as
    /// `peers_understanding_block_range`: rskj resolves an incoming id through
    /// `MessageType.valueOfType`, which throws on an unknown one, and the
    /// connection is dropped during decoding. A peer that did not negotiate
    /// `snap` therefore does not ignore a snapshot request -- it disconnects.
    /// Spreading requests over every connected peer costs peers rather than
    /// spreading load.
    pub async fn peers_serving_snapshots(&self) -> Vec<B512> {
        self.connected_peers
            .lock()
            .await
            .iter()
            .filter(|(_, p)| p.caps.snap)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Peers that can be asked for headers with their uncles.
    ///
    /// The snapshot ascent asks only these: it needs each header's uncles, and
    /// only a peer at `rsk/63` sends them. The descending walk asks anyone.
    pub async fn peers_sending_header_uncles(&self) -> Vec<B512> {
        self.connected_peers
            .lock()
            .await
            .iter()
            .filter(|(_, p)| p.caps.understands_header_uncles())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Whether this peer can serve a block at `number`.
    ///
    /// A peer that never stated a range serves everything: that is what every
    /// rskj peer looks like, and what a rustock peer looks like until its
    /// first status arrives. Reading silence as a refusal would empty the peer
    /// set on a network where most peers do not speak the extension yet.
    ///
    /// Only the lower bound is enforced. The upper bound is a snapshot that
    /// trails the peer's real head, so a peer merely late with an
    /// announcement is still worth asking -- geth makes the same distinction,
    /// treating the floor as exact and the ceiling as loose.
    pub async fn serves(&self, id: &B512, number: u64) -> bool {
        self.connected_peers
            .lock()
            .await
            .get(id)
            .map(|p| p.metadata.earliest_block.is_none_or(|e| number >= e))
            .unwrap_or(false)
    }

    /// Those of `candidates` that can serve a block at `number`.
    pub async fn peers_serving(&self, candidates: &[B512], number: u64) -> Vec<B512> {
        let peers = self.connected_peers.lock().await;
        candidates
            .iter()
            .filter(|id| {
                peers
                    .get(*id)
                    .map(|p| p.metadata.earliest_block.is_none_or(|e| number >= e))
                    .unwrap_or(false)
            })
            .copied()
            .collect()
    }

    /// Updates the metadata for a peer.
    ///
    /// The **address is preserved** when the incoming metadata has none. Only
    /// the connection path knows a peer's address; the callers that update
    /// chain-tip metadata (a new `Status`, a `NewBlockHashes`) build a fresh
    /// `PeerMetadata` and would otherwise erase it on the first message after
    /// the handshake -- which would silently reduce peer scoring to node ids
    /// only.
    pub async fn update_metadata(&self, id: &B512, mut metadata: PeerMetadata) {
        let mut peers = self.connected_peers.lock().await;
        if let Some(state) = peers.get_mut(id) {
            if metadata.address.is_none() {
                metadata.address = state.metadata.address;
            }
            state.metadata = metadata;
        }
    }

    /// The peer's remote address, if the connection path recorded one.
    pub async fn address(&self, id: &B512) -> Option<std::net::IpAddr> {
        let peers = self.connected_peers.lock().await;
        peers.get(id).and_then(|s| s.metadata.address)
    }

    /// Returns the metadata for a specific peer.
    pub async fn metadata(&self, id: &B512) -> Option<PeerMetadata> {
        let peers = self.connected_peers.lock().await;
        peers.get(id).map(|s| s.metadata.clone())
    }

    /// Finds the best peer to sync from based on total difficulty.
    pub async fn best_peer(&self) -> Option<(B512, PeerMetadata)> {
        let peers = self.connected_peers.lock().await;
        peers.iter()
            .max_by_key(|(_, s)| s.metadata.total_difficulty)
            .map(|(id, s)| (*id, s.metadata.clone()))
    }

    /// Removes a peer from the store.
    pub async fn remove_peer(&self, id: &B512) {
        self.connected_peers.lock().await.remove(id);
    }

    /// Checks if a peer is already connected.
    pub async fn is_connected(&self, id: &B512) -> bool {
        self.connected_peers.lock().await.contains_key(id)
    }

    /// Sends a message to a specific peer.
    pub async fn send_to_peer(&self, id: &B512, msg: P2pMessage) -> bool {
        let peers = self.connected_peers.lock().await;
        if let Some(state) = peers.get(id) {
            // try_send never awaits: a peer that has stopped reading must not be
            // able to stall the caller or grow its queue without limit. A full
            // queue means the peer is not keeping up, so the message is dropped.
            match state.sender.try_send(msg) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(target: "rustock::net", "Outbound queue full for peer {:?}; dropping message", id);
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        } else {
            false
        }
    }

    /// Returns a list of all connected peer IDs.
    pub async fn peers(&self) -> Vec<B512> {
        self.connected_peers.lock().await.keys().cloned().collect()
    }
    
    /// Returns the number of active peer connections.
    pub async fn count(&self) -> usize {
        self.connected_peers.lock().await.len()
    }

    /// Broadcasts a message to all connected peers except those in `exclude`.
    /// Returns the number of peers the message was sent to.
    pub async fn broadcast(&self, msg: P2pMessage, exclude: &[B512]) -> usize {
        let peers = self.connected_peers.lock().await;
        peers.iter()
            .filter(|(id, _)| !exclude.contains(id))
            .filter(|(_, state)| state.sender.try_send(msg.clone()).is_ok())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, B512, U256};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_get_best_peer_by_total_difficulty() {
        let store = PeerStore::new();
        let peer_a = B512::repeat_byte(0x0a);
        let peer_b = B512::repeat_byte(0x0b);
        let (tx_a, _rx_a) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        let (tx_b, _rx_b) = mpsc::channel(PEER_CHANNEL_CAPACITY);

        store.add_peer(peer_a, tx_a).await;
        store.add_peer(peer_b, tx_b).await;

        store.update_metadata(&peer_a, PeerMetadata {
            total_difficulty: U256::from(100),
            best_number: 10,
            ..Default::default()
        }).await;
        store.update_metadata(&peer_b, PeerMetadata {
            total_difficulty: U256::from(200),
            best_number: 20,
            ..Default::default()
        }).await;

        let best = store.best_peer().await.unwrap();
        assert_eq!(best.0, peer_b, "peer B has higher TD");

        store.update_metadata(&peer_a, PeerMetadata {
            total_difficulty: U256::from(300),
            best_number: 10,
            ..Default::default()
        }).await;

        let best = store.best_peer().await.unwrap();
        assert_eq!(best.0, peer_a, "peer A now has higher TD");
    }

    #[tokio::test]
    async fn test_get_best_peer_empty() {
        let store = PeerStore::new();
        assert!(store.best_peer().await.is_none());
    }

    #[tokio::test]
    async fn test_update_and_get_metadata() {
        let store = PeerStore::new();
        let peer_id = B512::repeat_byte(0x01);
        let (tx, _rx) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        store.add_peer(peer_id, tx).await;

        let metadata = PeerMetadata {
            best_number: 42,
            best_hash: B256::repeat_byte(0x11),
            total_difficulty: U256::from(999),
            client_id: "test".to_string(),
            address: Some("203.0.113.1".parse().unwrap()),
        earliest_block: None,
        };
        store.update_metadata(&peer_id, metadata.clone()).await;

        let retrieved = store.metadata(&peer_id).await.unwrap();
        assert_eq!(retrieved.best_number, 42);
        assert_eq!(retrieved.best_hash, B256::repeat_byte(0x11));
        assert_eq!(retrieved.total_difficulty, U256::from(999));
        assert_eq!(retrieved.client_id, "test");

        let unknown = B512::repeat_byte(0xff);
        assert!(store.metadata(&unknown).await.is_none());
    }

    #[tokio::test]
    async fn test_peer_store_flow() {
        let store = PeerStore::new();
        let id1 = B512::repeat_byte(0x01);
        let id2 = B512::repeat_byte(0x02);
        let (tx1, mut rx1) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        let (tx2, _rx2) = mpsc::channel(PEER_CHANNEL_CAPACITY);

        // Add
        assert!(store.add_peer(id1, tx1).await);
        assert!(store.add_peer(id2, tx2).await);
        assert!(!store.add_peer(id1, mpsc::channel(PEER_CHANNEL_CAPACITY).0).await); // Duplicate

        assert_eq!(store.count().await, 2);
        assert!(store.is_connected(&id1).await);
        
        // Get peers
        let peers = store.peers().await;
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&id1));
        assert!(peers.contains(&id2));

        // Send
        assert!(store.send_to_peer(&id1, P2pMessage::Ping).await);
        let msg = rx1.recv().await.unwrap();
        assert!(matches!(msg, P2pMessage::Ping));

        // Remove
        store.remove_peer(&id1).await;
        assert_eq!(store.count().await, 1);
        assert!(!store.is_connected(&id1).await);
        assert!(!store.send_to_peer(&id1, P2pMessage::Ping).await);
    }

    #[tokio::test]
    async fn test_broadcast_sends_to_all_except_excluded() {
        let store = PeerStore::new();
        let id1 = B512::repeat_byte(0x01);
        let id2 = B512::repeat_byte(0x02);
        let id3 = B512::repeat_byte(0x03);
        let (tx1, mut rx1) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        let (tx2, mut rx2) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        let (tx3, mut rx3) = mpsc::channel(PEER_CHANNEL_CAPACITY);

        store.add_peer(id1, tx1).await;
        store.add_peer(id2, tx2).await;
        store.add_peer(id3, tx3).await;

        let sent = store.broadcast(P2pMessage::Ping, &[id2]).await;
        assert_eq!(sent, 2);

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_err());
        assert!(rx3.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_empty_exclude() {
        let store = PeerStore::new();
        let id1 = B512::repeat_byte(0x01);
        let id2 = B512::repeat_byte(0x02);
        let (tx1, mut rx1) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        let (tx2, mut rx2) = mpsc::channel(PEER_CHANNEL_CAPACITY);

        store.add_peer(id1, tx1).await;
        store.add_peer(id2, tx2).await;

        let sent = store.broadcast(P2pMessage::Ping, &[]).await;
        assert_eq!(sent, 2);

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }
}

#[cfg(test)]
mod served_range_tests {
    use super::*;

    async fn store_with(earliest: Option<u64>) -> (PeerStore, B512) {
        let store = PeerStore::new();
        let id = B512::repeat_byte(0x01);
        let (tx, _rx) = mpsc::channel(1);
        store.add_peer(id, tx).await;
        store
            .update_metadata(
                &id,
                PeerMetadata { earliest_block: earliest, ..Default::default() },
            )
            .await;
        (store, id)
    }

    /// The rule everything else rests on: a peer that never stated a range
    /// serves everything.
    ///
    /// Every rskj peer looks like this, and so does every rustock peer until
    /// its first status arrives. Reading silence as a refusal would empty the
    /// peer set on a network where almost nobody speaks the extension yet.
    #[tokio::test]
    async fn a_peer_that_said_nothing_serves_everything() {
        let (store, id) = store_with(None).await;
        assert!(store.serves(&id, 0).await);
        assert!(store.serves(&id, 9_000_000).await);
    }

    /// A pruned peer is not asked for what it threw away.
    #[tokio::test]
    async fn a_pruned_peer_is_not_asked_below_its_floor() {
        let (store, id) = store_with(Some(9_275_000)).await;
        assert!(!store.serves(&id, 9_000_000).await, "below the floor");
        assert!(store.serves(&id, 9_275_000).await, "the floor itself is held");
        assert!(store.serves(&id, 9_280_000).await, "and everything above it");
    }

    /// Filtering keeps the peers that can help and drops only those that
    /// certainly cannot.
    #[tokio::test]
    async fn filtering_keeps_the_silent_and_the_capable() {
        let store = PeerStore::new();
        let (silent, pruned, archival) = (
            B512::repeat_byte(0x01),
            B512::repeat_byte(0x02),
            B512::repeat_byte(0x03),
        );
        for (id, earliest) in [(silent, None), (pruned, Some(9_275_000)), (archival, Some(0))] {
            let (tx, _rx) = mpsc::channel(1);
            store.add_peer(id, tx).await;
            store
                .update_metadata(
                    &id,
                    PeerMetadata { earliest_block: earliest, ..Default::default() },
                )
                .await;
        }

        let all = vec![silent, pruned, archival];
        let deep = store.peers_serving(&all, 9_000_000).await;
        assert!(deep.contains(&silent) && deep.contains(&archival));
        assert!(!deep.contains(&pruned), "the pruned peer cannot answer this");

        let shallow = store.peers_serving(&all, 9_280_000).await;
        assert_eq!(shallow.len(), 3, "near the tip everyone can answer");
    }

    /// An update narrows what a peer is asked for, without a reconnection.
    #[tokio::test]
    async fn a_range_update_takes_effect_immediately() {
        let (store, id) = store_with(None).await;
        assert!(store.serves(&id, 100).await);
        store.set_earliest_block(&id, 9_275_000).await;
        assert!(!store.serves(&id, 100).await);
    }
}

#[cfg(test)]
mod snap_capability_tests {
    use super::*;
    use crate::handshake::PeerCapabilities;

    fn caps(snap: bool) -> PeerCapabilities {
        PeerCapabilities { rsk_version: 62, snap }
    }

    async fn store_with(peers: &[(u8, bool)]) -> (PeerStore, Vec<B512>) {
        let store = PeerStore::new();
        let mut ids = Vec::new();
        for (tag, snap) in peers {
            let id = B512::repeat_byte(*tag);
            let (tx, _rx) = mpsc::channel(4);
            store.add_peer_with(id, tx, caps(*snap)).await;
            ids.push(id);
        }
        (store, ids)
    }

    /// The six snapshot messages must go only to peers that announced `snap`.
    /// rskj closes the connection on an unknown message id, so asking the
    /// wrong peer loses it rather than merely wasting a request.
    #[tokio::test]
    async fn only_snap_capable_peers_are_offered_for_snapshot_work() {
        let (store, ids) = store_with(&[(1, true), (2, false), (3, true), (4, false)]).await;

        let mut serving = store.peers_serving_snapshots().await;
        serving.sort();
        let mut want = vec![ids[0], ids[2]];
        want.sort();

        assert_eq!(serving, want, "only the snap-capable peers");
        assert_eq!(store.peers().await.len(), 4, "all four are still connected");
    }

    /// With nobody snap-capable the answer is an empty set, not everyone.
    /// Falling back to all peers is what would disconnect them.
    #[tokio::test]
    async fn no_snap_capable_peers_yields_nothing_rather_than_everyone() {
        let (store, _) = store_with(&[(1, false), (2, false)]).await;
        assert!(store.peers_serving_snapshots().await.is_empty());
        assert_eq!(store.peers().await.len(), 2);
    }

    /// The two capability gates are independent: `snap` is its own
    /// announcement and does not follow from the rsk protocol version.
    #[tokio::test]
    async fn the_snap_gate_is_independent_of_the_rsk_version() {
        let store = PeerStore::new();
        let id = B512::repeat_byte(9);
        let (tx, _rx) = mpsc::channel(4);
        // rsk/63 -- understands the range extension -- but no snap capability.
        store
            .add_peer_with(id, tx, PeerCapabilities { rsk_version: 63, snap: false })
            .await;

        assert_eq!(store.peers_understanding_block_range().await, vec![id]);
        assert!(
            store.peers_serving_snapshots().await.is_empty(),
            "rsk/63 does not imply snap"
        );
    }

    /// Headers with their uncles come only from `rsk/63` peers, and `snap`
    /// says nothing about it either way.
    #[tokio::test]
    async fn header_uncles_are_asked_only_of_rsk63_peers() {
        let store = PeerStore::new();
        let (tx, _rx) = mpsc::channel(4);
        let rsk63 = B512::repeat_byte(1);
        let rsk62_snap = B512::repeat_byte(2);
        store
            .add_peer_with(
                rsk63,
                tx.clone(),
                PeerCapabilities {
                    rsk_version: 63,
                    snap: false,
                },
            )
            .await;
        store
            .add_peer_with(
                rsk62_snap,
                tx,
                PeerCapabilities {
                    rsk_version: 62,
                    snap: true,
                },
            )
            .await;

        assert_eq!(store.peers_sending_header_uncles().await, vec![rsk63]);
        assert_eq!(store.peers_serving_snapshots().await, vec![rsk62_snap]);
    }
}
