//! Turning a [`SnapSession`]'s decisions into messages, and answers back into
//! decisions.
//!
//! The session says *what* it wants; this says *to whom*, and remembers what
//! was asked so an answer can be matched to a question.
//!
//! # Why the request id matters
//!
//! A chunk response echoes the offset it claims to answer. Reading that field
//! would let a peer answer a question nobody asked -- serving the cheap start
//! of the trie over and over while a range it was actually assigned goes
//! unfilled. So the offset is taken from this node's own record of the
//! request, keyed by id, and the echoed field is used for nothing.

use super::session::{Action, ChunkFault, Phase, SnapFailure, SnapSession};
use rustock_networking::scoring::EventType;
use alloy_primitives::{B256, B512, U256};
use rustock_core::{Block, Header};
use rustock_networking::protocol::snap::{
    ChunkPayload, Refusal, SnapBlocksRequest, SnapChunkRequest, SnapStatusRequest,
};
use rustock_networking::protocol::{
    BlockHeadersQuery, BlockHeadersRequest, BlockIdentifier, P2pMessage, RskMessage,
    RskSubMessage,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// How long to wait on a snap request before offering the work elsewhere.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a peer that left a request unanswered sits out, doubling for each
/// further one it leaves in a row, up to [`BENCH_MAX`].
const BENCH: Duration = Duration::from_secs(60);
const BENCH_MAX: Duration = Duration::from_secs(16 * 60);
/// Benched peers held before those whose time is up are swept out, so the
/// record stays bounded however many peers come and go.
const BENCH_SWEEP: usize = 1024;

/// rskj reads request ids through Java's signed long, so an id above 2^63
/// comes back sign-mangled.
fn fresh_id() -> u64 {
    rand::random::<u64>() & 0x7FFF_FFFF_FFFF_FFFF
}

/// What an outstanding request was for, so a late or missing answer can be
/// put back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Status,
    /// A header range, remembered by the height it fills and how it was
    /// asked, so an unanswered one can be asked again.
    Headers { point: u64, from: B256, count: u32 },
    /// Block identifiers from a height upward.
    Skeleton { start: u64 },
    Chunk { from: u64 },
    Blocks,
}

struct InFlight {
    what: Pending,
    peer: B512,
    sent: Instant,
}

/// A message to send, and the peer to send it to.
pub struct Outbound {
    pub peer: B512,
    pub message: P2pMessage,
}

/// Who can be sent what.
///
/// The six snapshot messages go only to peers that announced `snap`: rskj
/// resolves an incoming id through `MessageType.valueOfType`, which throws on an
/// unknown one, and closes the connection, so sending one to anyone else loses
/// the peer. The header walk's requests are the ordinary header and skeleton
/// messages, which every peer serves, so they go to anyone -- except during the
/// ascent, which asks for headers with their uncles and so needs `rsk/63`.
///
/// Every request used to go to the `snap` peers alone. On mainnet those are
/// few, and when the one that offered the checkpoint stopped answering, the
/// walk stalled for good forty headers in, nine million short of genesis,
/// with fifteen ordinary peers connected that could have served it.
#[derive(Debug, Clone, Copy)]
pub struct Peers<'a> {
    /// Peers that announced `snap`.
    pub snap: &'a [B512],
    /// Peers that can be asked for headers with their uncles (`rsk/63`).
    pub uncles: &'a [B512],
    /// Every connected peer.
    pub any: &'a [B512],
}

impl<'a> Peers<'a> {
    /// One set of peers for every kind of request.
    pub fn all(peers: &'a [B512]) -> Self {
        Self {
            snap: peers,
            uncles: peers,
            any: peers,
        }
    }

    fn is_empty(&self) -> bool {
        self.snap.is_empty() && self.uncles.is_empty() && self.any.is_empty()
    }
}

impl<'a> From<&'a [B512]> for Peers<'a> {
    fn from(peers: &'a [B512]) -> Self {
        Self::all(peers)
    }
}

impl<'a> From<&'a Vec<B512>> for Peers<'a> {
    fn from(peers: &'a Vec<B512>) -> Self {
        Self::all(peers)
    }
}

impl<'a, const N: usize> From<&'a [B512; N]> for Peers<'a> {
    fn from(peers: &'a [B512; N]) -> Self {
        Self::all(peers)
    }
}

/// Something a peer did that it should be charged for.
///
/// The driver names the peer and the offence; applying it is the caller's,
/// because scoring is a node-wide policy and this is one download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blame {
    pub peer: B512,
    pub event: EventType,
    /// Why, for the log line that accompanies the punishment.
    pub why: String,
}

/// What a session-level failure says about the peer that caused it.
///
/// `None` means the failure was not that peer's doing: running out of answers
/// is nobody's fault in particular, and a state this node failed to store is
/// this node's problem.
fn blame_for(failure: &SnapFailure) -> Option<EventType> {
    match failure {
        SnapFailure::InvalidHeader { .. } => Some(EventType::InvalidHeader),
        SnapFailure::BadBody { .. } => Some(EventType::InvalidBlock),
        SnapFailure::NoCheckpoint
        | SnapFailure::BrokenChain
        | SnapFailure::BadDifficulty
        | SnapFailure::ForeignGenesis
        | SnapFailure::BadChunk(_) => Some(EventType::InvalidMessage),
        // Claiming more work than the chain it served can carry is a lie about
        // the chain, not a malformed message, and the peer is answerable for
        // it.
        SnapFailure::OverstatedDifficulty { .. } => Some(EventType::InvalidBlock),
        // So is offering a height no chain this build can follow has reached.
        SnapFailure::ImplausibleHeight { .. } => Some(EventType::InvalidBlock),
        // Not answering is the peer's choice and its problem. Treating
        // silence as blameless would make stalling a free way past the gate.
        SnapFailure::UnsubstantiatedClaim { .. } => Some(EventType::InvalidMessage),
        SnapFailure::NoCommonAncestor
        | SnapFailure::NoProgress(_)
        | SnapFailure::IncompleteState(_) => None,
    }
}

pub struct SnapDriver {
    session: SnapSession,
    in_flight: HashMap<u64, InFlight>,
    /// Rotated through so one peer is not asked for everything.
    next_peer: usize,
    /// Offences waiting to be charged, oldest first.
    blame: Vec<Blame>,
    /// Peers not worth asking again: they speak the older chunk format, or
    /// keep declining. Not an accusation -- just a note to stop wasting
    /// requests on them.
    unhelpful: std::collections::HashSet<B512>,
    /// Peers that left a request unanswered: how many in a row, and until
    /// when they sit out.
    ///
    /// On mainnet about half the peers connected never answered a header
    /// request at all. The rotation gave each its turn regardless, and every
    /// turn cost thirty seconds of a request the walk was waiting on. A
    /// peer's time out ends, so one that was only slow for a while is asked
    /// again; and any answer clears it.
    benched: HashMap<B512, (u32, Instant)>,
}

impl SnapDriver {
    pub fn new(session: SnapSession) -> Self {
        Self {
            session,
            in_flight: HashMap::new(),
            next_peer: 0,
            blame: Vec::new(),
            unhelpful: std::collections::HashSet::new(),
            benched: HashMap::new(),
        }
    }

    /// Ids of requests currently outstanding.
    #[cfg(test)]
    pub(crate) fn outstanding_ids(&self) -> Vec<u64> {
        self.in_flight.keys().copied().collect()
    }

    /// Offences to charge, taken once.
    pub fn take_blame(&mut self) -> Vec<Blame> {
        std::mem::take(&mut self.blame)
    }

    /// Peers this session has stopped asking. Carried across a restart so a
    /// new session does not rediscover them one timeout at a time.
    pub fn unhelpful(&self) -> &std::collections::HashSet<B512> {
        &self.unhelpful
    }

    /// Start a session already knowing which peers not to bother.
    pub fn avoiding(mut self, peers: std::collections::HashSet<B512>) -> Self {
        self.unhelpful = peers;
        self
    }

    /// Which peer, if any, caused the session to fail -- and what it cost.
    fn charge(&mut self, peer: B512, event: EventType, why: impl Into<String>) {
        let why = why.into();
        debug!(target: "rustock::snap", "charging {:?}: {why}", &peer.0[..4]);
        self.blame.push(Blame { peer, event, why });
    }

    /// Note the session's own verdict against whoever answered last.
    fn charge_for_failure(&mut self, peer: B512) {
        let Some(failure) = self.session.failure().cloned() else { return };
        if let Some(event) = blame_for(&failure) {
            self.charge(peer, event, failure.to_string());
        }
    }

    /// Read what the last chunk answer was worth, and act on it.
    fn charge_for_chunk(&mut self, peer: B512) {
        match self.session.take_chunk_fault() {
            Some(ChunkFault::Misbehaved(e)) => {
                let event = match e {
                    super::client::ChunkError::Unsolicited(_) => EventType::UnexpectedMessage,
                    _ => EventType::InvalidMessage,
                };
                self.charge(peer, event, e.to_string());
            }
            // Neither of these is misbehaviour. A pruned peer declining is
            // behaving correctly, and an rskj peer is speaking the protocol it
            // knows. Punishing either would teach the network to stop
            // offering; the right response is to stop asking.
            // Not about the peer: our offset did not suit it, and another
            // will. It keeps its place in the rotation.
            Some(ChunkFault::Realign) => {}
            // A rebuild that did not reach the root is bad data like any
            // other, even though it cannot say which node was wrong.
            Some(ChunkFault::BadRebuild) => {
                self.charge(peer, EventType::InvalidMessage, "an rskj chunk did not rebuild");
            }
            Some(ChunkFault::Declined) => {
                if self.unhelpful.insert(peer) {
                    debug!(
                        target: "rustock::snap",
                        "no longer asking {:?} for state", &peer.0[..4]
                    );
                }
            }
            None => {}
        }
    }

    pub fn phase(&self) -> Phase {
        self.session.phase()
    }

    pub fn session(&self) -> &SnapSession {
        &self.session
    }

    /// End the session as a failure, for tests of what follows one.
    #[cfg(test)]
    pub(crate) fn fail_for_test(&mut self, why: super::session::SnapFailure) {
        self.session.fail_for_test(why);
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.session.phase(), Phase::Done | Phase::Failed)
    }

    /// Bytes of state downloaded, and the total once it is known.
    pub fn state_progress(&self) -> (u64, Option<u64>) {
        self.session.state_progress()
    }

    /// The block whose state this session is downloading.
    pub fn checkpoint(&self) -> Option<&Header> {
        self.session.checkpoint()
    }

    /// Give up on requests nobody answered, so the work can go to someone
    /// else. Returns how many were reclaimed.
    pub fn expire(&mut self, now: Instant) -> usize {
        let stale: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, r)| now.duration_since(r.sent) > REQUEST_TIMEOUT)
            .map(|(id, _)| *id)
            .collect();

        for id in &stale {
            if let Some(request) = self.in_flight.remove(id) {
                debug!(
                    target: "rustock::snap",
                    "snap request {id} to {:?} timed out", &request.peer.0[..4]
                );
                let peer = request.peer;
                self.release(request.what);
                self.charge(peer, EventType::TimeoutMessage, "snap request timed out");
                self.bench(peer, now);
            }
        }
        stale.len()
    }

    /// Sit `peer` out after a request it left unanswered.
    fn bench(&mut self, peer: B512, now: Instant) {
        if self.benched.len() >= BENCH_SWEEP {
            self.benched.retain(|_, (_, until)| *until > now);
        }
        let (strikes, until) = self.benched.entry(peer).or_insert((0, now));
        *strikes = strikes.saturating_add(1);
        *until = now
            + BENCH
                .saturating_mul(1 << (*strikes - 1).min(4))
                .min(BENCH_MAX);
    }

    /// Of `peers`, those not sitting out -- or all of them, if every one is.
    /// Asking a peer that was slow beats asking nobody, and a sync left with
    /// only such peers must still finish.
    fn available(&self, peers: &[B512], now: Instant) -> Vec<B512> {
        let ready: Vec<B512> = peers
            .iter()
            .copied()
            .filter(|p| self.benched.get(p).is_none_or(|(_, until)| now >= *until))
            .collect();
        if ready.is_empty() {
            peers.to_vec()
        } else {
            ready
        }
    }

    fn release(&mut self, what: Pending) {
        match what {
            Pending::Status => {}
            Pending::Headers { point, from, count } => {
                self.session.release_header_request(point, from, count)
            }
            Pending::Skeleton { start } => self.session.release_skeleton_request(start),
            Pending::Chunk { from } => self.session.release_chunk(from),
            Pending::Blocks => self.session.release_blocks(),
        }
    }

    /// Drop everything outstanding with a peer that has gone away.
    pub fn forget_peer(&mut self, peer: &B512) {
        let theirs: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, r)| r.peer == *peer)
            .map(|(id, _)| *id)
            .collect();
        for id in theirs {
            if let Some(request) = self.in_flight.remove(&id) {
                self.release(request.what);
            }
        }
    }

    /// Ask for whatever the session wants next, spreading the requests over
    /// the peers that can take each kind.
    pub fn poll<'p>(&mut self, peers: impl Into<Peers<'p>>) -> Vec<Outbound> {
        let peers = peers.into();
        if peers.is_empty() || self.is_finished() {
            return Vec::new();
        }
        let actions = self.ask(peers);
        self.dispatch(actions, peers)
    }

    /// Ask the session for work, having first told it how much is already
    /// outstanding.
    ///
    /// Every path that can produce requests goes through here or through
    /// [`Self::note`]. Capping only `poll` left the five response handlers
    /// issuing a fresh budget's worth each, which is how ~1,100 requests
    /// ended up outstanding against a budget of 8. See #185.
    fn ask(&mut self, peers: Peers<'_>) -> Vec<Action> {
        self.note(peers);
        self.session.poll()
    }

    /// Tell the session, before it decides what to ask for, what is already
    /// outstanding and how many peers its header requests can go to.
    fn note(&mut self, peers: Peers<'_>) {
        self.session.note_in_flight(self.in_flight.len());
        let now = Instant::now();
        let headers = self.available(peers.any, now).len();
        let uncles = self.available(peers.uncles, now).len();
        self.session.note_header_peers(headers, uncles);
    }

    /// The snapshot peers worth asking for state, which is all of them minus
    /// the ones that have already said they cannot serve it.
    fn worth_asking(&self, peers: &[B512]) -> Vec<B512> {
        let willing: Vec<B512> =
            peers.iter().copied().filter(|p| !self.unhelpful.contains(p)).collect();
        // If that leaves nobody, ask anyway rather than stall: a peer that
        // declined one range may serve another, and being wrong here costs a
        // round trip where giving up costs the sync.
        if willing.is_empty() {
            peers.to_vec()
        } else {
            willing
        }
    }

    fn dispatch(&mut self, actions: Vec<Action>, peers: Peers<'_>) -> Vec<Outbound> {
        let mut out = Vec::new();
        if actions.is_empty() {
            return out;
        }
        // The ascent asks for headers with their uncles, which only `rsk/63`
        // peers understand. The descending walk and the sampling gate ask for
        // plain headers, which every peer serves.
        let now = Instant::now();
        let header_peers = self.available(
            if self.session.phase() == Phase::AscendingHeaders {
                peers.uncles
            } else {
                peers.any
            },
            now,
        );
        let snap_peers = self.available(&self.worth_asking(peers.snap), now);
        for action in actions {
            let id = fresh_id();
            let (what, sub) = match action {
                Action::RequestStatus => (
                    Pending::Status,
                    RskSubMessage::SnapStatusRequest(SnapStatusRequest { id }),
                ),
                Action::RequestHeaders { from, count, point } => (
                    Pending::Headers { point, from, count },
                    RskSubMessage::BlockHeadersRequest(BlockHeadersRequest {
                        id,
                        query: BlockHeadersQuery { hash: from, count },
                    }),
                ),
                Action::RequestSkeleton { start } => (
                    Pending::Skeleton { start },
                    RskSubMessage::SkeletonRequest(
                        rustock_networking::protocol::SkeletonRequest { id, start_number: start },
                    ),
                ),
                Action::RequestChunk { block_number, state_root, from, budget } => (
                    Pending::Chunk { from },
                    RskSubMessage::SnapChunkRequest(SnapChunkRequest {
                        id,
                        block_number,
                        from,
                        chunk_size: budget,
                        state_root: Some(state_root),
                    }),
                ),
                Action::RequestBlocks { block_number } => (
                    Pending::Blocks,
                    RskSubMessage::SnapBlocksRequest(SnapBlocksRequest { id, block_number }),
                ),
            };

            let candidates: &[B512] = match what {
                Pending::Headers { .. } | Pending::Skeleton { .. } => &header_peers,
                Pending::Status | Pending::Chunk { .. } | Pending::Blocks => &snap_peers,
            };
            if candidates.is_empty() {
                // Nobody connected can be sent this one. Hand it back, so it is
                // asked again once somebody can take it, rather than lose it.
                self.release(what);
                continue;
            }
            let peer = candidates[self.next_peer % candidates.len()];
            self.next_peer = self.next_peer.wrapping_add(1);

            trace!(target: "rustock::snap", "asking {:?} for {what:?} (request {id})", &peer.0[..4]);
            self.in_flight.insert(id, InFlight { what, peer, sent: Instant::now() });
            out.push(Outbound {
                peer,
                message: P2pMessage::RskMessage(RskMessage::new(sub)),
            });
        }
        out
    }

    /// Passed through to the session before the status is handled: the
    /// service is the only place a peer's capabilities can be looked up.
    pub fn set_peer_serves_uncles(&mut self, yes: bool) {
        self.session.set_peer_serves_uncles(yes);
    }

    pub fn on_status<'p>(
        &mut self,
        id: u64,
        sender: B512,
        blocks: &[Block],
        difficulties: &[U256],
        trie_size: u64,
        grid: u64,
        peers: impl Into<Peers<'p>>,
    ) -> Vec<Outbound> {
        if !self.answers(id, sender, |p| matches!(p, Pending::Status)) {
            return Vec::new();
        }
        let peers = peers.into();
        self.note(peers);
        let actions = self.session.on_status(blocks, difficulties, trie_size, grid);
        self.charge_for_failure(sender);
        self.dispatch(actions, peers)
    }

    pub fn on_headers<'p>(
        &mut self,
        id: u64,
        sender: B512,
        headers: &[Header],
        peers: impl Into<Peers<'p>>,
    ) -> Vec<Outbound> {
        let Some(point) = self.in_flight.get(&id).and_then(|r| match r.what {
            Pending::Headers { point, .. } if r.peer == sender => Some(point),
            _ => None,
        }) else {
            return Vec::new();
        };
        self.in_flight.remove(&id);
        self.benched.remove(&sender);
        trace!(
            target: "rustock::snap",
            "{} header(s) from {:?} for #{point} (request {id})",
            headers.len(),
            &sender.0[..4]
        );

        let peers = peers.into();
        self.note(peers);
        let actions = self.session.on_headers(point, headers);
        self.charge_for_failure(sender);
        self.dispatch(actions, peers)
    }

    /// Headers that arrived with the uncles they reference.
    ///
    /// The walk's whole job is to establish how much work stands behind the
    /// checkpoint, and in RSK that work includes every uncle the chain
    /// absorbed. Fed bare headers the walk can only compute a lower bound; fed
    /// these it computes the figure rskj computes.
    pub fn on_headers_with_uncles<'p>(
        &mut self,
        id: u64,
        sender: B512,
        entries: &[rustock_networking::protocol::HeaderWithUncles],
        peers: impl Into<Peers<'p>>,
    ) -> Vec<Outbound> {
        let Some(point) = self.in_flight.get(&id).and_then(|r| match r.what {
            Pending::Headers { point, .. } if r.peer == sender => Some(point),
            _ => None,
        }) else {
            return Vec::new();
        };
        self.in_flight.remove(&id);
        self.benched.remove(&sender);

        let peers = peers.into();
        self.note(peers);
        let actions = self.session.on_headers_with_uncles(point, entries);
        self.charge_for_failure(sender);
        self.dispatch(actions, peers)
    }

    /// Block identifiers: where to ask, nothing more.
    ///
    /// Only as many as an answer to the request can hold, and only where it
    /// can hold them ([`as_rskj_answers`]): the walk, the ascent and the
    /// sampling gate each keep what they are given, so how much that is is
    /// not the peer's to choose.
    pub fn on_skeleton<'p>(
        &mut self,
        id: u64,
        sender: B512,
        identifiers: &[BlockIdentifier],
        peers: impl Into<Peers<'p>>,
    ) -> Vec<Outbound> {
        let start = match self.in_flight.get(&id).map(|r| r.what) {
            Some(Pending::Skeleton { start }) => start,
            _ => 0,
        };
        if !self.answers(id, sender, |p| matches!(p, Pending::Skeleton { .. })) {
            return Vec::new();
        }
        let identifiers = as_rskj_answers(start, identifiers);
        trace!(
            target: "rustock::snap",
            "skeleton of {} point(s) from {:?}, #{:?}..#{:?} (request {id})",
            identifiers.len(),
            &sender.0[..4],
            identifiers.first().map(|i| i.number),
            identifiers.last().map(|i| i.number)
        );
        let peers = peers.into();
        self.note(peers);
        let actions = self.session.on_skeleton(&identifiers);
        self.charge_for_failure(sender);
        self.dispatch(actions, peers)
    }

    /// A chunk answer.
    ///
    /// The offset comes from this node's record of the request, never from
    /// the response.
    pub fn on_chunk<'p>(
        &mut self,
        id: u64,
        sender: B512,
        payload: &ChunkPayload,
        refusal: Refusal,
        peers: impl Into<Peers<'p>>,
    ) -> Vec<Outbound> {
        if self.in_flight.get(&id).is_some_and(|r| r.peer != sender) {
            debug!(
                target: "rustock::snap",
                "chunk {id} answered by {:?}, which was not asked", &sender.0[..4]
            );
            return Vec::new();
        }
        let Some(request) = self.in_flight.remove(&id) else {
            debug!(target: "rustock::snap", "chunk answer to unknown request {id}");
            return Vec::new();
        };
        self.benched.remove(&sender);
        let Pending::Chunk { from } = request.what else {
            warn!(target: "rustock::snap", "request {id} was not a chunk request");
            self.release(request.what);
            return Vec::new();
        };

        // Taken only from the peer it was asked of. A chunk is verified
        // before it is used, so a stray one cannot corrupt the download --
        // but accepting it would still let an unasked peer consume the
        // request and leave the genuine answer to be dropped as unknown.
        let peers = peers.into();
        self.note(peers);

        // The chunk that completes the download also verifies it, and that
        // walk takes about ten minutes on a mainnet state: single-threaded,
        // CPU-bound, and -- until this -- on a runtime worker, where it
        // stopped every other task on that thread from running. The node
        // looked hung, peers timed out, and nothing in the log said why
        // (#187).
        //
        // `block_in_place` hands the worker's other tasks to a different
        // thread for the duration instead of restructuring the session into
        // an async state machine. It requires the multi-threaded runtime,
        // which is the one this node builds.
        let actions = tokio::task::block_in_place(|| {
            self.session.on_chunk(from, payload, refusal)
        });
        self.charge_for_chunk(sender);
        self.charge_for_failure(sender);
        self.dispatch(actions, peers)
    }

    pub fn on_blocks<'p>(
        &mut self,
        id: u64,
        sender: B512,
        blocks: &[Block],
        difficulties: &[U256],
        peers: impl Into<Peers<'p>>,
    ) -> Vec<Outbound> {
        if !self.answers(id, sender, |p| matches!(p, Pending::Blocks)) {
            return Vec::new();
        }
        let peers = peers.into();
        self.note(peers);
        let actions = self.session.on_blocks(blocks, difficulties);
        self.charge_for_failure(sender);
        self.dispatch(actions, peers)
    }

    /// Consumes an outstanding request if it is the kind expected.
    /// Whether `id` is an outstanding request of the wanted kind that
    /// `sender` was actually asked. Consumes it when so.
    ///
    /// The sender is part of the match, not a detail: a request is addressed
    /// to one peer, and an answer from anyone else is unsolicited however
    /// well-formed it looks. Request ids are random, so a third party cannot
    /// realistically land on one -- but then the binding rests on a property
    /// of the id generator rather than on this code, and would fall silently
    /// if that generator ever changed.
    fn answers(&mut self, id: u64, sender: B512, want: impl Fn(Pending) -> bool) -> bool {
        match self.in_flight.get(&id) {
            Some(request) if request.peer != sender => {
                debug!(
                    target: "rustock::snap",
                    "request {id} answered by {:?}, which was not asked", &sender.0[..4]
                );
                false
            }
            Some(request) if want(request.what) => {
                self.in_flight.remove(&id);
                self.benched.remove(&sender);
                true
            }
            Some(_) => {
                debug!(target: "rustock::snap", "request {id} answered with the wrong message");
                false
            }
            None => false,
        }
    }

    /// Headers arriving through the ordinary sync path may or may not belong
    /// to this session; this says whether the id is one of ours.
    pub fn awaits_headers(&self, id: u64) -> bool {
        matches!(self.in_flight.get(&id).map(|r| r.what), Some(Pending::Headers { .. }))
    }

    /// The same for skeletons, which the ordinary sync also uses.
    pub fn awaits_skeleton(&self, id: u64) -> bool {
        matches!(self.in_flight.get(&id).map(|r| r.what), Some(Pending::Skeleton { .. }))
    }

    /// The state root being downloaded, once one has been offered.
    pub fn state_root(&self) -> Option<B256> {
        self.session.checkpoint().map(|h| h.state_root)
    }
}

/// What an answer to a skeleton request from `start` can hold, as rskj's
/// `processSkeletonRequest` and this node's own server build one: the grid
/// points from `start`'s chunk on, [`SKELETON_POINTS`] at most, then the
/// best block, no further on than the next of them would have been. So no
/// more than `SKELETON_POINTS + 1` identifiers, and none outside that
/// stretch; anything else is dropped.
///
/// [`SKELETON_POINTS`]: super::headers::SKELETON_POINTS
fn as_rskj_answers(start: u64, identifiers: &[BlockIdentifier]) -> Vec<BlockIdentifier> {
    use super::headers::{HEADER_CHUNK, SKELETON_POINTS};
    let first = start - start % HEADER_CHUNK;
    let last = first.saturating_add(HEADER_CHUNK * SKELETON_POINTS);
    identifiers
        .iter()
        .filter(|i| (first..=last).contains(&i.number))
        .take(SKELETON_POINTS as usize + 1)
        .cloned()
        .collect()
}

#[cfg(test)]
mod skeleton_answer_tests {
    use super::super::headers::{HEADER_CHUNK, SKELETON_POINTS};
    use super::*;

    fn at(number: u64) -> BlockIdentifier {
        BlockIdentifier {
            hash: B256::with_last_byte(number as u8),
            number,
        }
    }

    /// What rskj sends for a request from #9,020,000 to a peer at #9,030,000:
    /// twenty grid points from #9,019,968, then its best block's stand-in at
    /// the end of the stretch. All of it passes.
    #[test]
    fn an_answer_as_rskj_builds_one_is_taken_whole() {
        let first = 9_020_000 - 9_020_000 % HEADER_CHUNK;
        let mut sent: Vec<BlockIdentifier> = (0..SKELETON_POINTS)
            .map(|k| at(first + k * HEADER_CHUNK))
            .collect();
        sent.push(at(first + SKELETON_POINTS * HEADER_CHUNK));
        assert_eq!(as_rskj_answers(9_020_000, &sent), sent);
        // A peer whose best block falls inside the stretch ends there.
        let short = vec![
            at(first),
            at(first + HEADER_CHUNK),
            at(first + HEADER_CHUNK + 77),
        ];
        assert_eq!(as_rskj_answers(9_020_000, &short), short);
    }

    /// Identifiers outside the stretch, and any past the most an answer
    /// holds, are not passed on to keep.
    #[test]
    fn an_answer_holds_no_more_than_rskj_would_send() {
        let first = 9_020_000 - 9_020_000 % HEADER_CHUNK;
        let flood: Vec<BlockIdentifier> = (0..100_000).map(|k| at(first + k)).collect();
        let kept = as_rskj_answers(9_020_000, &flood);
        assert_eq!(kept.len() as u64, SKELETON_POINTS + 1);
        let far = vec![at(first - 1), at(first), at(1 << 62), at(u64::MAX)];
        assert_eq!(as_rskj_answers(9_020_000, &far), vec![at(first)]);
        assert_eq!(
            as_rskj_answers(u64::MAX, &[at(u64::MAX)]),
            vec![at(u64::MAX)]
        );
    }
}
