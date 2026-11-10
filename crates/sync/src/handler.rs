use crate::events::SyncEvent;
use crate::manager::SyncManager;
use alloy_primitives::{Address, B512};
use crate::snap::server::SnapServer;
use rustock_networking::protocol::{
    BlockHashResponse, BlockHeadersResponse, BlockHeadersWithUnclesResponse, BlockIdentifier,
    BodyResponse, HeaderWithUncles,
    P2pHandler, P2pMessage, RskMessage, RskSubMessage, SkeletonResponse,
};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Skeleton step size (must match rskj's chunkSize = 192).
const SKELETON_STEP: u64 = 192;

/// Maximum skeleton entries per response (matches rskj's maxSkeletonChunks = 20).
const MAX_SKELETON_ENTRIES: usize = 20;

/// Maximum headers to serve in a single response.
const MAX_HEADERS_SERVE: u32 = 192;

/// What a snap answer is expected to weigh, for rate limiting.
///
/// Only state is metered. A status or a block range is small, infrequent, and
/// already bounded by the concurrency limit; metering them would complicate
/// the accounting for nothing.
#[derive(Debug, Clone, Copy)]
enum Cost {
    Small,
    Chunk,
}

/// Dispatches inbound messages to the state machine channel and serves
/// data to peers (headers, block hashes, skeletons).
pub struct SyncHandler {
    manager: Arc<SyncManager>,
    event_tx: mpsc::UnboundedSender<SyncEvent>,
    /// Present only when this node serves snapshots. Absent is the default
    /// and costs nothing: snap requests are then simply not answered, which
    /// is what a node without the feature looks like from outside.
    snap: Option<Arc<SnapServer>>,
    /// Attached after the handler is shared, which is when the node knows
    /// whether it was asked to serve snapshots.
    snap_late: std::sync::RwLock<Option<Arc<SnapServer>>>,
    /// Highest block this node will serve or name, when it has been told to
    /// behave as though the chain ends there (`--simulate-height`).
    ///
    /// Enforced on every path a client could use to reach past it, not only
    /// on what is announced: a client that can fetch a block above the
    /// simulated head has not run the test that was intended, and the result
    /// is not comparable with one that could not.
    serve_ceiling: Option<u64>,
    /// Which checkpoint-based defences this node runs.
    ///
    /// The cheap refutation runs whenever either switch is on. It costs
    /// nothing and follows from having a checkpoint at all: a peer at a height
    /// at or below it, claiming more work than exists there, is refuted by
    /// arithmetic whatever else the node is doing.
    ///
    /// What it must not be is the *only* check, which `NONE` prevents. Alone
    /// it secures nothing -- an attacker claims a height above the checkpoint
    /// and steps around it for free -- and leaving it always-on made the gate
    /// look armed when it was not.
    checkpoint_defence: rustock_core::checkpoint::CheckpointDefence,
    /// The checkpoint the defences run against, or `None` on a chain that
    /// ships none.
    ///
    /// Network-scoped on purpose. A checkpoint is a statement about one chain;
    /// applying mainnet's to a testnet peer is a category error that happens to
    /// be harmless only because testnet totals are too small to trip it.
    checkpoint: Option<rustock_core::checkpoint::DifficultyCheckpoint>,
    /// Coinbases whose blocks are not taken from a peer that sends them
    /// whole: rskj's `peer.bannedMiners` (`NodeMessageHandler.bannedMiners`).
    banned_miners: HashSet<Address>,
}

/// rskj's `peer.bannedMiners` entries as its `NodeMessageHandler` reads them,
/// `new RskAddress(String)` each (L134-136): a `0x` prefix dropped, an odd
/// number of digits read with a leading zero (`HexUtils.stringHexToByteArray`),
/// and anything but 20 bytes refused, which keeps rskj from starting.
pub fn parse_banned_miners(entries: &[String]) -> Result<HashSet<Address>, String> {
    entries
        .iter()
        .map(|entry| {
            let digits = entry.strip_prefix("0x").unwrap_or(entry);
            let digits = if digits.len() % 2 == 1 {
                format!("0{digits}")
            } else {
                digits.to_string()
            };
            // Checked here, so a second `0x` is refused as rskj's decoder
            // refuses it rather than dropped as `hex::decode` would.
            if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("{entry:?} is not hex"));
            }
            let bytes = alloy_primitives::hex::decode(&digits)
                .map_err(|e| format!("{entry:?} is not hex: {e}"))?;
            if bytes.len() != Address::len_bytes() {
                let len = bytes.len();
                return Err(format!("{entry:?} is {len} bytes; an address is 20"));
            }
            Ok(Address::from_slice(&bytes))
        })
        .collect()
}

impl SyncHandler {
    pub fn new(manager: Arc<SyncManager>, event_tx: mpsc::UnboundedSender<SyncEvent>) -> Self {
        Self {
            manager,
            event_tx,
            snap: None,
            snap_late: std::sync::RwLock::new(None),
            serve_ceiling: None,
            checkpoint_defence: rustock_core::checkpoint::CheckpointDefence::NONE,
            checkpoint: None,
            banned_miners: HashSet::new(),
        }
    }

    /// The checkpoint to judge claims against. Without one, nothing is
    /// refuted however the defences are configured.
    pub fn with_checkpoint(
        mut self,
        checkpoint: Option<rustock_core::checkpoint::DifficultyCheckpoint>,
    ) -> Self {
        self.checkpoint = checkpoint;
        self
    }

    /// Run these checkpoint defences. See [`Self::checkpoint_defence`].
    pub fn with_checkpoint_defence(
        mut self,
        defence: rustock_core::checkpoint::CheckpointDefence,
    ) -> Self {
        self.checkpoint_defence = defence;
        self
    }

    /// Serve nothing above `height`. See [`Self::serve_ceiling`].
    pub fn with_serve_ceiling(mut self, height: Option<u64>) -> Self {
        self.serve_ceiling = height;
        self
    }

    /// Refuse a block a peer sends whole when its coinbase is one of these:
    /// rskj's `peer.bannedMiners`. See [`parse_banned_miners`].
    pub fn with_banned_miners(mut self, banned_miners: HashSet<Address>) -> Self {
        self.banned_miners = banned_miners;
        self
    }

    /// Whether a block at this height may be named or served.
    fn may_serve(&self, number: u64) -> bool {
        self.serve_ceiling.is_none_or(|c| number <= c)
    }

    /// The height this node speaks for: the simulated one, or its real head.
    fn effective_head(&self) -> Option<u64> {
        let store = &self.manager.store;
        let real = store
            .head()
            .ok()?
            .and_then(|h| store.header(h).ok()?)
            .map(|h| h.number)?;
        Some(match self.serve_ceiling {
            Some(c) => real.min(c),
            None => real,
        })
    }

    /// Serve snapshots of this node's state to peers that ask.
    pub fn with_snap_server(mut self, snap: Arc<SnapServer>) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Same, for a handler already shared behind an `Arc`.
    ///
    /// Installed once at startup, before any peer is connected, so the
    /// lock is uncontended and the read on the message path stays cheap.
    pub fn attach_snap_server(&self, snap: Arc<SnapServer>) {
        if let Ok(mut slot) = self.snap_late.write() {
            *slot = Some(snap);
        }
    }

    fn snap_server(&self) -> Option<Arc<SnapServer>> {
        if let Some(snap) = &self.snap {
            return Some(snap.clone());
        }
        self.snap_late.read().ok()?.clone()
    }

    /// Answers a snap request off the network thread.
    ///
    /// Serving state is disk-bound -- on a cold store a single chunk is most
    /// of a second -- and this is called from inside the peer's async task.
    /// Doing the work here would block not just that peer but every other task
    /// sharing the runtime worker: a node that serves snapshots would stop
    /// following the chain while it did. So the work goes to a blocking thread
    /// and the answer is sent when it is ready, which is also what rskj does
    /// (`scheduleJob`).
    ///
    /// Returns `None` always: the reply does not travel back through the
    /// handler's return value.
    fn serve_snap<F>(&self, peer: B512, cost: Cost, reply: F) -> Option<P2pMessage>
    where
        F: FnOnce(&SnapServer) -> Option<RskSubMessage> + Send + 'static,
    {
        let server = self.snap_server()?;

        // Charged before the slot is taken, so a peer over its rate does not
        // sit on one while it waits.
        let wait = match cost {
            Cost::Small => std::time::Duration::ZERO,
            Cost::Chunk => match server.allowance(peer, server.chunk_cost()) {
                crate::snap::rate::Allowance::Now => std::time::Duration::ZERO,
                crate::snap::rate::Allowance::After(d) => d,
                crate::snap::rate::Allowance::Refuse => {
                    trace!(
                        target: "rustock::snap",
                        "refusing a chunk to {:?}: over its rate", &peer.0[..4]
                    );
                    return None;
                }
            },
        };

        if !server.admit(peer) {
            trace!(
                target: "rustock::snap",
                "refusing a snap request from {:?}: already serving its limit", &peer.0[..4]
            );
            return None;
        }

        let peer_store = self.manager.peer_store.clone();
        tokio::spawn(async move {
            // Backpressure, not an error: a peer over its rate is slowed
            // rather than told no, which needs nothing of the protocol and
            // throttles the peer through the slots it is holding.
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            let serving = server.clone();
            let built = tokio::task::spawn_blocking(move || {
                let answer = reply(&serving);
                serving.release(peer);
                answer
            })
            .await;

            match built {
                Ok(Some(sub)) => {
                    peer_store
                        .send_to_peer(&peer, P2pMessage::RskMessage(RskMessage::new(sub)))
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    // The slot is released inside the blocking closure, which
                    // did not run to completion; release it here too.
                    server.release(peer);
                    warn!(target: "rustock::snap", "serving a snap request failed: {e}");
                }
            }
        });
        None
    }

    /// Respond to a BodyRequest by looking up the block and returning its body.
    #[cfg(test)]
    pub(crate) fn serve_body_request_for_test(
        &self,
        id: u64,
        hash: alloy_primitives::B256,
    ) -> Option<P2pMessage> {
        self.serve_body_request(id, hash)
    }

    #[cfg(test)]
    pub(crate) fn serve_headers_request_for_test(
        &self,
        id: u64,
        hash: alloy_primitives::B256,
        count: u32,
    ) -> Option<P2pMessage> {
        self.serve_headers_request(id, hash, count)
    }

    #[cfg(test)]
    pub(crate) fn serve_block_hash_request_for_test(&self, id: u64, h: u64) -> Option<P2pMessage> {
        self.serve_block_hash_request(id, h)
    }

    #[cfg(test)]
    pub(crate) fn serve_skeleton_request_for_test(&self, id: u64, s: u64) -> Option<P2pMessage> {
        self.serve_skeleton_request(id, s)
    }

    fn serve_body_request(
        &self,
        request_id: u64,
        hash: alloy_primitives::B256,
    ) -> Option<P2pMessage> {
        let store = &self.manager.store;
        // Above the simulated head this node has nothing to say, even though
        // the block is on disk.
        let header = store.header(hash).ok().flatten();
        if let Some(h) = &header {
            if !self.may_serve(h.number) {
                return None;
            }
        }
        // rskj `NodeBlockProcessor.processBodyRequest` sends the header's
        // RSKIP-351 extension beside the body, which a peer needs for a
        // header it got compressed. A header that holds only its commitment
        // has none to send, and a body without it is no use to the peer.
        let extension = match &header {
            Some(h) if h.extension_data.is_some() => return None,
            Some(h) => h.extension(),
            None => None,
        };
        let (transactions, uncles) = store.body(hash).ok()??;

        trace!(
            target: "rustock::sync",
            "Serving block body for {:?} ({} txs, {} uncles)",
            hash, transactions.len(), uncles.len()
        );

        let resp = BodyResponse {
            id: request_id,
            transactions,
            uncles,
            extension,
        };
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::BodyResponse(resp),
        )))
    }

    /// Answer a `GetBlockMessage` with the whole block: rskj
    /// `NodeBlockProcessor.processGetBlock` (L147-157), which answers from any
    /// chain it holds, and first remembers that the asker holds the block now,
    /// so it is not announced back to it.
    ///
    /// A peer sends one to the node that announced a block it lacks
    /// (`processNewBlockHashesMessage`), so without an answer this node's
    /// announcements could not be followed. A block whose header this node
    /// holds compressed has no full form to send, and one without its body is
    /// not whole; neither is answered, as rskj answers nothing for a block it
    /// lacks.
    fn serve_get_block(&self, peer: B512, hash: alloy_primitives::B256) -> Option<P2pMessage> {
        let store = &self.manager.store;
        let header = store.header(hash).ok()??;
        if !self.may_serve(header.number) || header.extension_data.is_some() {
            return None;
        }
        let (transactions, ommers) = store.body(hash).ok()??;
        self.manager.note_block_holder(hash, peer);
        trace!(
            target: "rustock::sync",
            "Serving block #{} {:?} to {:?}",
            header.number, hash, &peer.0[..4]
        );
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::Block(Box::new(rustock_core::Block {
                header,
                transactions,
                ommers,
            })),
        )))
    }

    /// Respond to a BlockHeadersRequest by walking backwards from the given
    /// hash, collecting up to `count` headers (same logic as rskj).
    fn serve_headers_request(
        &self,
        request_id: u64,
        hash: alloy_primitives::B256,
        count: u32,
    ) -> Option<P2pMessage> {
        let count = count.min(MAX_HEADERS_SERVE);
        let store = &self.manager.store;

        let first = store.header(hash).ok()??;
        if !self.may_serve(first.number) {
            return None;
        }
        let mut headers = canonical_run(store, &first, count)
            .unwrap_or_else(|| walk_by_parent(store, first, count));
        // A run walks downward from `first`, so nothing in it can exceed a
        // ceiling the first header already satisfies -- but the filter is
        // cheap and states the invariant rather than relying on it.
        headers.retain(|h| self.may_serve(h.number));

        trace!(
            target: "rustock::sync",
            "Serving {} headers (starting from {:?})",
            headers.len(), hash
        );

        let resp = BlockHeadersResponse {
            id: request_id,
            headers,
        };
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::BlockHeadersResponse(resp),
        )))
    }

    /// Respond to a `BlockHeadersWithUnclesRequest`: the same run of headers
    /// the plain request would return, each paired with the uncle headers it
    /// references.
    ///
    /// The uncles come out of the body, or once the body is gone, out of the
    /// freezer's uncle store, which keeps them by height for the canonical
    /// chain: where a snapshot sync puts the uncles it was sent for every
    /// block it fetched no body for. Served from bodies alone, a node that
    /// synced so could not serve the sync it had just done (#270). A block
    /// whose uncles this node holds in neither place ends the run -- never an
    /// empty uncle list, which would be a quiet lie about the chain's work.
    /// Peers learn which blocks are answerable from the served range this
    /// node announces.
    fn serve_headers_with_uncles_request(
        &self,
        request_id: u64,
        hash: alloy_primitives::B256,
        count: u32,
    ) -> Option<P2pMessage> {
        let count = count.min(MAX_HEADERS_SERVE);
        let store = &self.manager.store;

        let first = store.header(hash).ok()??;
        if !self.may_serve(first.number) {
            return None;
        }
        let mut headers = canonical_run(store, &first, count)
            .unwrap_or_else(|| walk_by_parent(store, first, count));
        headers.retain(|h| self.may_serve(h.number));

        let mut entries: Vec<HeaderWithUncles> = Vec::with_capacity(headers.len());
        for header in headers {
            let uncles = if header.uncle_count == 0 {
                Vec::new()
            } else {
                match crate::total_difficulty::held_uncles(store, header.hash(), &header) {
                    Some(uncles) => uncles,
                    None => break,
                }
            };

            let entry = HeaderWithUncles { header, uncles };
            // Never put on the wire a pairing this node cannot itself justify:
            // the receiver refuses it at the parse boundary anyway, and a
            // mismatch here means our own stored body disagrees with our own
            // stored header.
            if !entry.commitment_matches() {
                warn!(
                    target: "rustock::sync",
                    "Refusing to serve #{}: stored uncles do not match its ommers hash",
                    entry.header.number
                );
                break;
            }
            entries.push(entry);
        }

        if entries.is_empty() {
            return None;
        }

        trace!(
            target: "rustock::sync",
            "Serving {} headers with uncles (starting from {:?})",
            entries.len(), hash
        );

        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::BlockHeadersWithUnclesResponse(BlockHeadersWithUnclesResponse {
                id: request_id,
                entries,
            }),
        )))
    }

    /// Respond to a BlockHashRequest by looking up the canonical hash at the
    /// requested height.
    fn serve_block_hash_request(
        &self,
        request_id: u64,
        height: u64,
    ) -> Option<P2pMessage> {
        if height == 0 || !self.may_serve(height) {
            return None;
        }
        let hash = self.manager.store.canonical_hash(height).ok()??;
        trace!(
            target: "rustock::sync",
            "Serving block hash for height #{}: {:?}",
            height, hash
        );
        let resp = BlockHashResponse {
            id: request_id,
            hash,
        };
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::BlockHashResponse(resp),
        )))
    }

    /// Respond to a SkeletonRequest by constructing evenly-spaced block
    /// identifiers from the requested start (matching rskj's algorithm).
    fn serve_skeleton_request(
        &self,
        request_id: u64,
        start_number: u64,
    ) -> Option<P2pMessage> {
        let store = &self.manager.store;

        // Verify we have the starting block
        if !self.may_serve(start_number) {
            return None;
        }
        store.canonical_hash(start_number).ok()??;

        let best_number = self.effective_head()?;

        let skeleton_start = (start_number / SKELETON_STEP) * SKELETON_STEP;
        let max_skeleton_number = best_number.min(
            skeleton_start + SKELETON_STEP * MAX_SKELETON_ENTRIES as u64,
        );

        let mut identifiers = Vec::new();
        let mut n = skeleton_start;
        while n < max_skeleton_number {
            if let Ok(Some(hash)) = store.canonical_hash(n) {
                identifiers.push(BlockIdentifier { hash, number: n });
            }
            n += SKELETON_STEP;
        }

        // Always include the best block (or the last skeleton point if equal)
        let last_number = best_number.min(n);
        if let Ok(Some(hash)) = store.canonical_hash(last_number) {
            if identifiers.last().is_none_or(|last| last.number != last_number) {
                identifiers.push(BlockIdentifier {
                    hash,
                    number: last_number,
                });
            }
        }

        if identifiers.is_empty() {
            return None;
        }

        trace!(
            target: "rustock::sync",
            "Serving skeleton ({} entries, #{} -> #{})",
            identifiers.len(),
            identifiers.first().map(|b| b.number).unwrap_or(0),
            identifiers.last().map(|b| b.number).unwrap_or(0)
        );

        let resp = SkeletonResponse {
            id: request_id,
            block_identifiers: identifiers,
        };
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::SkeletonResponse(resp),
        )))
    }
}

impl P2pHandler for SyncHandler {
    fn handle_message(&self, id: B512, msg: &P2pMessage) -> Option<P2pMessage> {
        if let P2pMessage::RskMessage(m) = msg {
            match &m.sub_message {
                RskSubMessage::Status(s) => {
                    trace!(
                        target: "rustock::sync",
                        "Received status from peer {:?}: #{} (TD: {:?})",
                        id,
                        s.best_block_number,
                        s.total_difficulty
                    );
                    let claimed = s.total_difficulty.unwrap_or_default();

                    // The cheapest check there is: a peer claiming more work
                    // than the shipped checkpoint allows, for a height at or
                    // below the checkpoint, is refuted by arithmetic. No
                    // requests, no sampling, no round trips.
                    //
                    // Recorded rather than acted on beyond a warning: the
                    // metadata is what peer selection reads, so refusing to
                    // store it is enough to stop this node syncing from the
                    // peer. Disconnecting is the scoring layer's decision.
                    if self.checkpoint_defence.any()
                        && refuted_by_checkpoint(
                            self.checkpoint.as_ref(),
                            claimed,
                            s.best_block_number,
                        )
                    {
                        warn!(
                            target: "rustock::sync",
                            "Peer {:?} claims total difficulty {} at #{}, which is more than \
                             the checkpoint at #{} permits; not syncing from it",
                            &id.0[..4],
                            claimed,
                            s.best_block_number,
                            self.checkpoint.as_ref().map_or(0, |cp| cp.number)
                        );
                        // Refusing to record the metadata is what stops this
                        // node syncing from the peer: peer selection reads
                        // exactly that. Scoring lives in the service, which
                        // this handler does not reach.
                    } else {

                        let metadata = rustock_networking::peers::PeerMetadata {
                            best_number: s.best_block_number,
                            best_hash: s.best_block_hash,
                            total_difficulty: claimed,
                            client_id: "".to_string(),
                            address: None,
                            // `None` from an rskj peer, which has not been
                            // asked and must keep meaning "ask me anything".
                            earliest_block: s.earliest_block,
                        };
                        let peer_store = self.manager.peer_store.clone();
                        tokio::spawn(async move {
                            peer_store.update_metadata(&id, metadata).await;
                        });
                    }
                }
                RskSubMessage::BlockRangeUpdate(range) => {
                    // A peer narrowing or extending what it serves, without a
                    // reconnection. A pruning node's floor rises continuously,
                    // so a figure fixed at handshake time goes stale within
                    // minutes; this is what keeps it current.
                    debug!(
                        target: "rustock::sync",
                        "Peer {:?} now serves #{}..#{}",
                        &id.0[..4], range.earliest_block, range.latest_block
                    );
                    let peer_store = self.manager.peer_store.clone();
                    let peer = id;
                    let earliest = range.earliest_block;
                    tokio::spawn(async move {
                        peer_store.set_earliest_block(&peer, earliest).await;
                    });
                }
                RskSubMessage::BlockHashResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::BlockHashResponse {
                        peer: id,
                        hash: r.hash,
                    });
                }
                RskSubMessage::SkeletonResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::SkeletonResponse {
                        peer: id,
                        id: r.id,
                        identifiers: r.block_identifiers.clone(),
                    });
                }
                RskSubMessage::BlockHeadersResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::HeadersResponse {
                        peer: id,
                        id: r.id,
                        headers: r.headers.clone(),
                    });
                }
                RskSubMessage::BlockHeadersWithUnclesResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::HeadersWithUnclesResponse {
                        peer: id,
                        id: r.id,
                        entries: r.entries.clone(),
                    });
                }
                RskSubMessage::NewBlockHashes(blocks) => {
                    let _ = self.event_tx.send(SyncEvent::NewBlockHashes {
                        peer: id,
                        identifiers: blocks.clone(),
                    });
                }
                RskSubMessage::Block(block) => {
                    // rskj `NodeMessageHandler.allowByMinerNotBanned`
                    // (L244-256), which `controlMessageIngress` asks before the
                    // block is queued: one mined by a banned coinbase is not
                    // taken. An empty coinbase is rskj's null address, which
                    // no listed address is, the zero address included.
                    let banned = block
                        .header
                        .coinbase()
                        .filter(|miner| self.banned_miners.contains(miner));
                    if let Some(miner) = banned {
                        trace!(
                            target: "rustock::sync",
                            "Received block mined by banned miner {miner} from peer {:?}, not taken",
                            &id.0[..4]
                        );
                        return None;
                    }
                    let _ = self.event_tx.send(SyncEvent::NewBlock {
                        peer: id,
                        block: block.clone(),
                    });
                }

                RskSubMessage::BodyResponse(r) => {
                    trace!(
                        target: "rustock::sync",
                        "Received BodyResponse id={} ({} txs, {} uncles) from {:?}",
                        r.id, r.transactions.len(), r.uncles.len(), &id.0[..4]
                    );
                    let _ = self.event_tx.send(SyncEvent::BodyResponse {
                        peer: id,
                        id: r.id,
                        transactions: r.transactions.clone(),
                        uncles: r.uncles.clone(),
                        extension: r.extension.clone(),
                    });
                }

                // --- Serve data to peers ---
                RskSubMessage::BlockHeadersRequest(r) => {
                    return self.serve_headers_request(r.id, r.query.hash, r.query.count);
                }
                RskSubMessage::BlockHeadersWithUnclesRequest(r) => {
                    return self.serve_headers_with_uncles_request(
                        r.id,
                        r.query.hash,
                        r.query.count,
                    );
                }
                RskSubMessage::BlockHashRequest(r) => {
                    return self.serve_block_hash_request(r.id, r.height);
                }
                RskSubMessage::SkeletonRequest(r) => {
                    return self.serve_skeleton_request(r.id, r.start_number);
                }
                RskSubMessage::BodyRequest(r) => {
                    return self.serve_body_request(r.id, r.hash);
                }
                RskSubMessage::GetBlock(hash) => {
                    return self.serve_get_block(id, *hash);
                }

                // --- Snapshot sync ---
                RskSubMessage::SnapStatusRequest(r) => {
                    let r = r.clone();
                    return self.serve_snap(id, Cost::Small, move |s| {
                        s.status(&r).map(|m| RskSubMessage::SnapStatusResponse(Box::new(m)))
                    });
                }
                RskSubMessage::SnapChunkRequest(r) => {
                    let r = r.clone();
                    return self.serve_snap(id, Cost::Chunk, move |s| {
                        s.chunk(&r).map(|m| RskSubMessage::SnapChunkResponse(Box::new(m)))
                    });
                }
                RskSubMessage::SnapBlocksRequest(r) => {
                    let r = r.clone();
                    return self.serve_snap(id, Cost::Small, move |s| {
                        s.blocks(&r).map(|m| RskSubMessage::SnapBlocksResponse(Box::new(m)))
                    });
                }
                RskSubMessage::SnapStatusResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::SnapStatusResponse {
                        peer: id,
                        id: r.id,
                        blocks: r.blocks.clone(),
                        difficulties: r.difficulties.clone(),
                        trie_size: r.trie_size,
                        chunk_grid: r.chunk_grid,
                    });
                }
                RskSubMessage::SnapChunkResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::SnapChunkResponse {
                        peer: id,
                        id: r.id,
                        from: r.from,
                        payload: r.payload.clone(),
                        refusal: r.refusal,
                    });
                }
                RskSubMessage::SnapBlocksResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::SnapBlocksResponse {
                        peer: id,
                        id: r.id,
                        blocks: r.blocks.clone(),
                        difficulties: r.difficulties.clone(),
                    });
                }

                _ => {}
            }
        }
        None
    }
}

/// The old walk: one dependent point lookup per header.
///
/// Still the fallback, and still correct for any chain. It is what
/// [`canonical_run`] declines to do when the range is not plainly canonical.
pub(crate) fn walk_by_parent(
    store: &rustock_storage::BlockStore,
    first: rustock_core::Header,
    count: u32,
) -> Vec<rustock_core::Header> {
    let mut headers = vec![first.clone()];
    let mut current = first;
    for _ in 1..count {
        match store.header(current.parent_hash) {
            Ok(Some(parent)) => {
                current = parent.clone();
                headers.push(parent);
            }
            _ => break,
        }
    }
    headers
}

/// The same run, fetched in parallel, when the range is canonical.
///
/// # Why this exists
///
/// Walking by parent hash is a chain of *dependent* reads: the next hash is
/// not known until the current header has been read, so the device sees one
/// outstanding request at a time. Measured serving a real snapshot-syncing
/// client: 933 KB/s over **loopback** with the server CPU at 12% — disk-bound
/// at queue depth 1. See #185.
///
/// Heights are not dependent on each other. `CF_NUMBERS` turns the run into a
/// set of hashes with one ordered cursor, and those hashes are then fetched
/// concurrently.
///
/// # Why it verifies rather than trusts
///
/// The request names a **hash**, not a height, and the chain asked for may be
/// a sibling rather than the canonical one. Serving canonical headers for a
/// non-canonical request would answer a question nobody asked, with a chain
/// the peer cannot link to what it already has.
///
/// So this returns `None` — and the caller falls back to the honest walk —
/// unless every one of these holds:
///
/// - the starting hash **is** the canonical block at its own height;
/// - every height in the range resolved to a hash;
/// - every header was present;
/// - and each header's `parent_hash` is the next one down, checked link by
///   link. The canonical index can be mid-repair, and a gap in it must not
///   become a gap in what is served.
pub(crate) fn canonical_run(
    store: &rustock_storage::BlockStore,
    first: &rustock_core::Header,
    count: u32,
) -> Option<Vec<rustock_core::Header>> {
    let top = first.number;
    // Genesis is its own floor; a short run near it is not worth the setup.
    if count < 8 || top < count as u64 {
        return None;
    }
    if store.canonical_hash(top).ok()?? != first.hash() {
        return None;
    }

    // One call, so a frozen run is answered from the flat files without
    // resolving a hash per height.
    let fetched = store.canonical_headers_descending(top, count as usize);

    let mut headers = Vec::with_capacity(count as usize);
    for slot in fetched {
        headers.push(slot?);
    }

    // Link check. Cheap next to the reads, and the only thing standing between
    // a stale index and a chain that does not join up.
    for pair in headers.windows(2) {
        if pair[0].parent_hash != pair[1].hash() || pair[0].number != pair[1].number + 1 {
            return None;
        }
    }
    Some(headers)
}


/// Whether a peer's advertised total difficulty is already impossible.
///
/// Only the free case: a claim for a height at or below the checkpoint, where
/// the work is known exactly and nothing may exceed it. Heights above the
/// checkpoint need sampling (`crate::sampler`), which costs requests.
///
/// Gated on *either* switch, not on `bound_work` alone. It costs nothing and
/// it is the arithmetic consequence of having a checkpoint at all, so any node
/// that uses its checkpoint for anything should refuse a claim the checkpoint
/// already disproves. What must not happen is this running as the *only*
/// check, which is what `CheckpointDefence::NONE` prevents: alone it secures
/// nothing, because an attacker sidesteps it by claiming a height above the
/// checkpoint.
fn refuted_by_checkpoint(
    checkpoint: Option<&rustock_core::checkpoint::DifficultyCheckpoint>,
    claimed: alloy_primitives::U256,
    height: u64,
) -> bool {
    checkpoint.is_some_and(|cp| {
        crate::sampler::ChainSampler::refuted_by_checkpoint_alone(cp, claimed, height)
    })
}

#[cfg(test)]
mod checkpoint_scope_tests {
    use super::refuted_by_checkpoint;
    use alloy_primitives::U256;
    use rustock_core::checkpoint::MAINNET_CHECKPOINT;

    /// A claim the mainnet checkpoint disproves is refused when that
    /// checkpoint is the one in force.
    #[test]
    fn the_mainnet_checkpoint_refutes_an_impossible_mainnet_claim() {
        let cp = MAINNET_CHECKPOINT;
        let claim = cp.cumulative_difficulty * U256::from(2);
        assert!(refuted_by_checkpoint(Some(&cp), claim, cp.number - 1));
    }

    /// The same claim is not refused on a chain that ships no checkpoint.
    ///
    /// This is why the checkpoint is plumbed in rather than read from a
    /// constant. `--checkpoint-bound-work` defaults on, so a hard-coded
    /// `MAINNET_CHECKPOINT` here would arm mainnet's view of history against
    /// every testnet and regtest peer. It happens to be harmless today only
    /// because those chains' totals are too small to trip it, which is luck
    /// rather than design.
    #[test]
    fn no_checkpoint_refutes_nothing() {
        let cp = MAINNET_CHECKPOINT;
        let claim = cp.cumulative_difficulty * U256::from(2);
        assert!(!refuted_by_checkpoint(None, claim, cp.number - 1));
    }
}
