//! One snapshot sync, start to finish.
//!
//! The session is a state machine with no I/O and no clock: it is asked what
//! to do next, told what arrived, and says when it is finished. Everything
//! about peers -- choosing them, timing them out, scoring them -- belongs to
//! the caller. That split is deliberate: the part that decides whether to
//! trust a state should be readable in one sitting and testable without a
//! network.
//!
//! # The order of things, and why
//!
//! 1. **Ask for a status.** A peer names a checkpoint block and the 400
//!    blocks before it. None of it is believed yet.
//! 2. **Verify the headers back to something known.** Each header is checked
//!    under the consensus rules, including merged-mining proof of work, and
//!    linked to its child by hash. The walk ends at a block this node already
//!    has -- for a fresh node, genesis. Until this finishes, the checkpoint
//!    is a stranger's claim; after it, forging one costs what it costs to mine
//!    the chain.
//! 3. **Download the state** under that header's `state_root`, every chunk
//!    proved on arrival.
//! 4. **Download the bodies** of the blocks behind the checkpoint, because
//!    contracts can read recent block data and the state alone would not be
//!    enough to execute what comes next.
//!
//! Step 2 before step 3 is the whole trust argument. A client that downloads
//! first and verifies the header chain afterwards has spent an hour on
//! whatever a stranger sent it; one that verifies first spends the hour only
//! on a chain with real work behind it.

use std::time::{Duration, Instant};
use super::client::{ChunkError, StateDownload};
use super::SnapConfig;
use alloy_primitives::{B256, U256};
use rustock_core::validation::HeaderVerifier;
use rustock_core::{Block, Header};
use rustock_networking::protocol::snap::{ChunkPayload, Refusal};
use rustock_networking::protocol::BlockIdentifier;
use rustock_storage::BlockStore;
use rustock_trie::TrieStore;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// How many peers may answer the header walk with nothing before the session
/// concludes the chain does not connect to ours.
const EMPTY_HEADER_REPLIES_ALLOWED: u32 = 5;

/// Header requests the walk may have outstanding for each peer that can take
/// them.
///
/// Header and skeleton requests are messages every peer serves, so their
/// budget grows with the peers there are, where a state download is held to
/// `SnapConfig::max_in_flight` by the few peers that serve state. On mainnet
/// that budget of eight left forty peers mostly idle through a walk of
/// hours. Two keeps a peer busy while its last answer is on the way, without
/// queueing work behind a slow one.
const HEADER_REQUESTS_PER_PEER: usize = 2;
/// And never more than this in all, however many peers there are.
const MAX_HEADER_REQUESTS: usize = 64;

/// Chunk answers in a row that add nothing before the session gives up.
///
/// A peer declining to serve is ordinary -- it may be pruned, or on another
/// chain -- and the range simply goes to someone else. But if *every* answer
/// declines, re-asking is a hot loop that never ends, so the session stops
/// and lets the caller try a different set of peers.
const FRUITLESS_CHUNKS_ALLOWED: u32 = 64;

/// What the session wants done. The caller turns these into messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Ask a peer which state it can serve.
    RequestStatus,
    /// Ask for headers below `from`, walking toward genesis.
    ///
    /// `point` is the height the walk filed the request under, so an answer
    /// can be matched to the range it fills without trusting anything in it.
    RequestHeaders { from: B256, count: u32, point: u64 },
    /// Ask for block identifiers from this height upward, to learn where to
    /// ask for headers without waiting for the walk to get there.
    RequestSkeleton { start: u64 },
    /// Ask for a range of the state.
    RequestChunk { block_number: u64, state_root: B256, from: u64, budget: u64 },
    /// Ask for the 400 blocks below `block_number`.
    RequestBlocks { block_number: u64 },
}

/// Why a session gave up. Every one of these is a reason to stop listening to
/// the peer that caused it, which is the caller's decision to make.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapFailure {
    #[error("the peer offered no checkpoint block")]
    NoCheckpoint,
    #[error("the offered blocks do not form a chain")]
    BrokenChain,
    #[error("header #{number} failed validation: {reason}")]
    InvalidHeader { number: u64, reason: String },
    #[error("cumulative difficulty does not increase across the offered blocks")]
    BadDifficulty,
    #[error("the header walk ran out of answers before meeting a block we have")]
    NoCommonAncestor,
    #[error("the chain leads back to a genesis this node has never seen")]
    ForeignGenesis,
    #[error("a chunk was refused: {0}")]
    BadChunk(#[from] ChunkError),
    #[error("the downloaded state is not whole: {0}")]
    IncompleteState(String),
    #[error("{0} chunk requests in a row came back with nothing usable")]
    NoProgress(u32),
    #[error(
        "the peer claimed cumulative difficulty {claimed} at the checkpoint but the chain          it served carries at most {ceiling}"
    )]
    OverstatedDifficulty { claimed: U256, ceiling: U256 },
    #[error("the peer would not substantiate its claimed difficulty: {why}")]
    UnsubstantiatedClaim { why: String },
    #[error("block #{number}: the {what} are not the ones its header commits to")]
    BadBody { number: u64, what: &'static str },
}

/// What an answer revealed about the peer that sent it.
///
/// The distinction that matters is between a peer that *misbehaved* and one
/// that simply could not help. Both end the same way for the download -- the
/// range goes back in the queue -- but only the first should cost the peer
/// anything. A pruned node declining to serve state it no longer has is
/// behaving correctly, and punishing it would teach the network to stop
/// offering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkFault {
    /// The chunk failed its proof, or was not an answer to the question asked.
    Misbehaved(ChunkError),
    /// The peer cannot serve this range: pruned, or on another chain.
    Declined,
    /// The peer could not answer *this* request, but could answer another --
    /// our offset was not on its grid, or past an end we had wrong. About the
    /// request, not the peer, so it keeps its place in the rotation.
    Realign,
    /// The peer's rskj-format chunk did not rebuild to the state root. It is
    /// misbehaviour like any other bad chunk, but named apart because the
    /// failure says less about which node was wrong: a rebuild proves itself
    /// at the root, not node by node.
    BadRebuild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting to hear what any peer can serve.
    AwaitingStatus,
    /// Bounding the peer's claimed cumulative difficulty before committing to
    /// the walk.
    ///
    /// The walk costs about two hours and twenty gigabytes on a
    /// mainnet chain, all of it on the strength of a checkpoint this peer
    /// offered. Sampling a few hundred headers first turns that into a
    /// verdict up front.
    SamplingClaim,
    /// Walking the header chain back toward a block we already trust.
    VerifyingHeaders,
    /// Establishing the chain by ascending from ground already held, the
    /// alternative to `VerifyingHeaders`. See `super::forward`.
    AscendingHeaders,
    /// Downloading the state under the checkpoint's root.
    DownloadingState,
    /// Filling in the block bodies behind the checkpoint.
    DownloadingBlocks,
    /// The state is whole and the blocks are in.
    Done,
    /// Something failed; the caller should start over with another peer.
    Failed,
}

pub struct SnapSession {
    config: SnapConfig,
    store: Arc<BlockStore>,
    trie: Arc<dyn TrieStore>,
    verifier: Arc<HeaderVerifier>,

    phase: Phase,
    failure: Option<SnapFailure>,

    /// Requests this session has outstanding, as last reported by the driver.
    /// See [`Self::note_in_flight`].
    in_flight: usize,
    /// Peers that can take header requests, and those that can take them
    /// with uncles, as last counted by the driver. See
    /// [`Self::note_header_peers`].
    header_peers: usize,
    uncle_peers: usize,
    /// The block whose state is being downloaded, once one has been offered.
    checkpoint: Option<Header>,
    /// Its cumulative difficulty, as offered and then vouched for by the
    /// header walk.
    checkpoint_td: U256,
    /// The blocks that came with the status, held until the header walk
    /// vouches for the chain they sit on.
    offered: Vec<(Block, U256)>,
    /// The pipelined walk from the checkpoint down to ground we already
    /// trust. Replaces a serial chain of 48,000 round trips.
    walk: Option<super::headers::HeaderWalk>,
    /// Consecutive peers that answered the header walk with nothing.
    empty_header_replies: u32,

    download: Option<StateDownload>,
    /// Chunk answers in a row that added nothing.
    fruitless_chunks: u32,
    /// What the last chunk answer revealed, until someone reads it.
    chunk_fault: Option<ChunkFault>,
    /// The oldest block number whose body is still wanted.
    blocks_wanted_to: u64,
    /// The next `SnapBlocks` request to make, walking backwards.
    blocks_cursor: u64,
    blocks_in_flight: bool,
    /// Bounds the peer's claimed cumulative difficulty before the walk is
    /// committed to. `None` once the verdict is in.
    gate: Option<crate::sampler::SamplingGate>,
    /// The uncle lists seen so far, so the full uncle rule can run on a node
    /// that has no bodies. See [`crate::uncle_guard`].
    uncle_guard: crate::uncle_guard::UncleGuard,
    /// The ascending walk, when `SnapConfig::forward_headers` chose it.
    /// Mutually exclusive with `walk`.
    ascent: Option<super::forward::ForwardSync>,
    /// Whether this session's peer negotiated `rsk/63` and will send uncle
    /// headers alongside trunk headers.
    ///
    /// Set by the service, which is where a peer's capabilities can be looked
    /// up. It decides whether the sampling gate is worth running at all: see
    /// [`crate::sampler::WALK_INSTEAD_BELOW`].
    peer_serves_uncles: bool,
    /// When the current phase began, and when it last said so.
    phase_started: Instant,
    last_report: Instant,
    /// Block answers in a row that added nothing.
    fruitless_blocks: u32,
}

impl SnapSession {
    pub fn new(
        config: SnapConfig,
        store: Arc<BlockStore>,
        trie: Arc<dyn TrieStore>,
        verifier: Arc<HeaderVerifier>,
    ) -> Self {
        Self {
            config,
            store,
            trie,
            verifier,
            phase: Phase::AwaitingStatus,
            failure: None,
            in_flight: 0,
            header_peers: 0,
            uncle_peers: 0,
            checkpoint: None,
            checkpoint_td: U256::ZERO,
            offered: Vec::new(),
            walk: None,
            empty_header_replies: 0,
            download: None,
            fruitless_chunks: 0,
            chunk_fault: None,
            blocks_wanted_to: 0,
            blocks_cursor: 0,
            blocks_in_flight: false,
            gate: None,
            uncle_guard: crate::uncle_guard::UncleGuard::new(),
            ascent: None,
            peer_serves_uncles: false,
            phase_started: Instant::now(),
            last_report: Instant::now(),
            fruitless_blocks: 0,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn failure(&self) -> Option<&SnapFailure> {
        self.failure.as_ref()
    }

    pub fn checkpoint(&self) -> Option<&Header> {
        self.checkpoint.as_ref()
    }

    /// What the last chunk answer revealed about its sender, once.
    ///
    /// Drained rather than read, so a fault is attributed to exactly one peer:
    /// the caller knows who answered, and this knows what the answer was worth.
    pub fn take_chunk_fault(&mut self) -> Option<ChunkFault> {
        self.chunk_fault.take()
    }

    /// Bytes of state covered, and the total once it is known.
    pub fn state_progress(&self) -> (u64, Option<u64>) {
        self.download.as_ref().map_or((0, None), |d| d.progress())
    }

    /// The oldest block whose body is worth asking for.
    ///
    /// Never below one: block zero is genesis, which any node that can
    /// validate a chain already has.
    fn blocks_floor(&self) -> u64 {
        self.blocks_wanted_to.max(1)
    }

    fn fail(&mut self, why: SnapFailure) -> Vec<Action> {
        warn!(target: "rustock::snap", "snapshot sync failed: {why}");
        self.failure = Some(why);
        self.set_phase(Phase::Failed);
        Vec::new()
    }

    /// What to do now. Safe to call as often as the caller likes: it returns
    /// only work that is not already outstanding.
    /// Tell this session how many of its requests are still outstanding.
    ///
    /// The session knows what work remains; only the driver knows what has
    /// been sent. Every path that can produce new requests passes through
    /// `poll`, so recording the count here -- rather than capping at each of
    /// the six dispatch sites -- means no path can bypass the budget.
    ///
    /// The first attempt capped only `SnapDriver::poll`, and the five response
    /// handlers went on issuing a fresh budget's worth each: still ~1,100
    /// outstanding against a budget of 8. See #185.
    pub fn note_in_flight(&mut self, n: usize) {
        self.in_flight = n;
    }

    /// Tell this session how many peers can take its header requests, and how
    /// many of those can send uncles with them, which sets the header phases'
    /// budget. See [`HEADER_REQUESTS_PER_PEER`].
    pub fn note_header_peers(&mut self, headers: usize, uncles: usize) {
        self.header_peers = headers;
        self.uncle_peers = uncles;
    }

    /// What may be outstanding at once in the current phase.
    fn budget(&self) -> usize {
        let per_peer = |peers: usize| {
            peers.saturating_mul(HEADER_REQUESTS_PER_PEER).min(MAX_HEADER_REQUESTS)
        };
        let cap = match self.phase {
            Phase::VerifyingHeaders => per_peer(self.header_peers),
            Phase::AscendingHeaders => per_peer(self.uncle_peers),
            _ => 0,
        };
        cap.max(self.config.max_in_flight).max(1)
    }

    /// Moves to a new phase, restarting the clock the progress lines report
    /// against.
    fn set_phase(&mut self, phase: Phase) {
        if self.phase != phase {
            self.phase_started = Instant::now();
            // Report the new phase promptly rather than up to five seconds
            // later: the first line is the one that says what is happening.
            self.last_report = Instant::now() - Duration::from_secs(5);
        }
        self.phase = phase;
    }

    /// Say how the current phase is going, at most every five seconds.
    ///
    /// Every phase that can run for minutes reports. The header walk ran for
    /// about two hours and the state download for three, both in silence,
    /// and silence is indistinguishable from a hang -- which is how #187 was
    /// found, twice, before the same lesson was applied here (#208).
    fn report_progress(&mut self) {
        const EVERY: Duration = Duration::from_secs(5);
        if self.last_report.elapsed() < EVERY {
            return;
        }
        self.last_report = Instant::now();
        let elapsed = self.phase_started.elapsed().as_secs_f64();

        match self.phase {
            Phase::AscendingHeaders => {
                let Some(ascent) = self.ascent.as_ref() else { return };
                let Some(top) = self.checkpoint.as_ref().map(|c| c.number) else { return };
                let at = ascent.frontier();
                if top == 0 {
                    return;
                }
                let done = at as f64 / top as f64;
                let eta = if done > 0.0 { elapsed * (1.0 - done) / done } else { 0.0 };
                info!(
                    target: "rustock::snap",
                    "ascending the header chain: {:.1}% (at #{at} of #{top}), \
                     {:.0}s elapsed, ~{:.0}s left",
                    done * 100.0,
                    elapsed,
                    eta
                );
            }

            Phase::VerifyingHeaders => {
                let Some(walk) = self.walk.as_ref() else { return };
                let top = walk.top_number();
                let at = walk.frontier();
                if top == 0 {
                    return;
                }
                let done = (top - at) as f64 / top as f64;
                let eta = if done > 0.0 { elapsed * (1.0 - done) / done } else { 0.0 };
                info!(
                    target: "rustock::snap",
                    "walking the header chain: {:.1}% (at #{at} of #{top}), {} frozen, \
                     {:.0}s elapsed, ~{:.0}s left",
                    done * 100.0,
                    walk.staged(),
                    elapsed,
                    eta
                );
            }
            Phase::DownloadingState => {
                let Some(download) = self.download.as_ref() else { return };
                let (covered, total) = download.progress();
                let Some(total) = total.filter(|t| *t > 0) else { return };
                let done = covered as f64 / total as f64;
                let eta = if done > 0.0 { elapsed * (1.0 - done) / done } else { 0.0 };
                info!(
                    target: "rustock::snap",
                    "downloading the state: {:.1}% ({}/{} MB), {:.0}s elapsed, ~{:.0}s left",
                    done * 100.0,
                    covered / (1 << 20),
                    total / (1 << 20),
                    elapsed,
                    eta
                );
            }
            Phase::DownloadingBlocks => {
                let floor = self.blocks_floor();
                let from = self.checkpoint.as_ref().map_or(0, |h| h.number);
                if from <= floor {
                    return;
                }
                let done = (from - self.blocks_cursor) as f64 / (from - floor) as f64;
                info!(
                    target: "rustock::snap",
                    "downloading block bodies: {:.1}% (at #{} of #{}..#{}), {:.0}s elapsed",
                    done * 100.0,
                    self.blocks_cursor,
                    floor,
                    from,
                    elapsed
                );
            }
            _ => {}
        }
    }

    pub fn poll(&mut self) -> Vec<Action> {
        self.report_progress();
        // What the budget has room for *after* what is already outstanding.
        //
        // No floor. An earlier version ended this with `.max(1)` on the
        // reasoning that a session should always be able to make progress;
        // that let the budget be exceeded by one on *every* call, which is
        // unbounded growth wearing a smaller number. When the queue is full
        // the right answer is to ask for nothing and wait for an answer.
        let budget = self.budget().saturating_sub(self.in_flight);
        if budget == 0 {
            return Vec::new();
        }
        match self.phase {
            Phase::AwaitingStatus => vec![Action::RequestStatus],

            Phase::SamplingClaim => {
                use crate::sampler::{GateAction, GateOutcome, GateRejection};
                let Some(gate) = self.gate.as_mut() else {
                    let next = self.header_phase();
                    self.set_phase(next);
                    return self.poll();
                };
                let actions = gate.poll();
                match gate.outcome() {
                    GateOutcome::Pending => actions
                        .into_iter()
                        .map(|a| match a {
                            GateAction::RequestSkeleton { start } => {
                                Action::RequestSkeleton { start }
                            }
                            GateAction::RequestHeader { hash, .. } => {
                                Action::RequestHeaders { from: hash, count: 1, point: 0 }
                            }
                        })
                        .collect(),
                    GateOutcome::Passed { ceiling } => {
                        info!(
                            target: "rustock::snap",
                            "the peer's claimed difficulty is within what its chain could \
                             carry (ceiling {ceiling}); verifying its header chain"
                        );
                        self.gate = None;
                        let next = self.header_phase();
                        self.set_phase(next);
                        self.poll()
                    }
                    GateOutcome::Rejected(why) => match why {
                        GateRejection::AboveCeiling { claimed, ceiling }
                        | GateRejection::BelowCheckpoint { claimed, allowed: ceiling } => {
                            self.fail(SnapFailure::OverstatedDifficulty { claimed, ceiling })
                        }
                        GateRejection::Unsubstantiated { missing } => {
                            self.fail(SnapFailure::UnsubstantiatedClaim {
                                why: format!("{missing} sample(s) went unanswered"),
                            })
                        }
                    },
                }
            }

            Phase::AscendingHeaders => {
                let Some(ascent) = self.ascent.as_mut() else { return Vec::new() };
                ascent
                    .wants(budget)
                    .into_iter()
                    .map(|want| match want {
                        super::forward::Want::Skeleton { start } => {
                            Action::RequestSkeleton { start }
                        }
                        // Emitted as a plain header request: the service
                        // upgrades it to `BlockHeadersWithUnclesRequest` for a
                        // peer that negotiated `rsk/63`, which is the only kind
                        // this phase runs against.
                        super::forward::Want::Headers { from, count, point } => {
                            Action::RequestHeaders { from, count, point }
                        }
                    })
                    .collect()
            }

            Phase::VerifyingHeaders => {
                let Some(walk) = self.walk.as_mut() else { return Vec::new() };
                walk.wants(budget)
                    .into_iter()
                    .map(|want| match want {
                        super::headers::Want::Skeleton { start } => {
                            Action::RequestSkeleton { start }
                        }
                        super::headers::Want::Headers { from, count, point } => {
                            Action::RequestHeaders { from, count, point }
                        }
                    })
                    .collect()
            }

            Phase::DownloadingState => {
                let Some(checkpoint) = self.checkpoint.clone() else { return Vec::new() };
                let Some(download) = self.download.as_mut() else { return Vec::new() };

                let mut actions = Vec::new();
                while let Some(request) = download.next_request() {
                    actions.push(Action::RequestChunk {
                        block_number: checkpoint.number,
                        state_root: checkpoint.state_root,
                        from: request.from,
                        budget: request.budget,
                    });
                }
                actions
            }

            Phase::DownloadingBlocks => {
                if self.blocks_in_flight || self.blocks_cursor <= self.blocks_floor() {
                    return Vec::new();
                }
                self.blocks_in_flight = true;
                vec![Action::RequestBlocks { block_number: self.blocks_cursor }]
            }

            Phase::Done | Phase::Failed => Vec::new(),
        }
    }

    /// A peer's offer of a state it can serve.
    ///
    /// The blocks are checked for shape only -- that they form a chain, that
    /// difficulty rises along it. Whether this chain is *the* chain is settled
    /// by the header walk that follows, not here.
    pub fn on_status(
        &mut self,
        blocks: &[Block],
        difficulties: &[U256],
        trie_size: u64,
        grid: u64,
    ) -> Vec<Action> {
        if self.phase != Phase::AwaitingStatus {
            return Vec::new();
        }
        let Some(checkpoint) = blocks.last() else {
            return self.fail(SnapFailure::NoCheckpoint);
        };
        if difficulties.len() != blocks.len() {
            return self.fail(SnapFailure::BadDifficulty);
        }
        if let Err(why) = check_chain_shape(blocks, difficulties) {
            return self.fail(why);
        }

        let header = checkpoint.header.clone();

        // The checkpoint is the one header the walk never visits as a
        // candidate -- it is only ever the child -- so its own rules, proof of
        // work included, are checked here. A peer offering a checkpoint it did
        // not mine gets no further than this.
        if let Err(e) = self.verifier.verify(&header, None) {
            return self.fail(SnapFailure::InvalidHeader {
                number: header.number,
                reason: e.to_string(),
            });
        }

        info!(
            target: "rustock::snap",
            "peer offers state at #{} ({:?}), {} bytes; verifying its header chain first",
            header.number, header.hash(), trie_size
        );

        // The state download is set up now but does not start until the
        // header chain is verified: see the module header.
        self.download = Some(StateDownload::on_grid(
            header.state_root,
            trie_size,
            &self.config,
            grid,
            self.trie.clone(),
        ));
        self.blocks_wanted_to = header.number.saturating_sub(self.config.blocks_required);
        self.blocks_cursor = header.number;

        self.checkpoint_td = *difficulties.last().unwrap_or(&U256::ZERO);
        self.offered = blocks.iter().cloned().zip(difficulties.iter().copied()).collect();

        // Bound the claim before committing to the walk. The walk costs about
        // about two hours on a mainnet chain and rests entirely on this
        // peer's offer; a few hundred sampled headers settle it first.
        //
        // The anchor is this node's own chain where it has one -- its own
        // accumulated work is better evidence than a shipped constant, and
        // more recent. The checkpoint is the fallback for a node with nothing
        // of its own, which is the case snapshot sync runs in.
        // `bound_work` carries the sampling with it: bounding without
        // sampling refutes only a claim made at or below the checkpoint
        // height, which an attacker steps around for free. The two are one
        // switch for that reason.
        //
        // One case skips it. Each sampled height costs a message -- scattered
        // heights cannot be batched -- while the walk carries `HEADER_CHUNK`
        // per message, so over a short enough window sampling spends the same
        // requests to see a fraction of the data and ends with a bound where
        // the walk ends with the exact number. That is only true of a peer
        // that sends the uncles: from an `rsk/62` peer the walk sums header
        // difficulty alone and computes a *lower* bound, which is worse than
        // the gate's upper one. So the capability decides, not the window.
        let defence = self.config.checkpoint_defence;
        if let Some(checkpoint) = self.config.checkpoint.filter(|_| defence.any()) {
            let window = header.number.saturating_sub(checkpoint.number);
            let walk_is_cheaper =
                self.peer_serves_uncles && window < crate::sampler::WALK_INSTEAD_BELOW;
            if walk_is_cheaper {
                info!(
                    target: "rustock::snap",
                    "skipping the sampling gate: {} blocks above the checkpoint is under \
                     the {} where walking costs the same requests, and this peer serves \
                     uncle headers, so the walk establishes the work exactly",
                    window,
                    crate::sampler::WALK_INSTEAD_BELOW
                );
            }
            if header.number > checkpoint.number && !walk_is_cheaper {
                self.gate = Some(crate::sampler::SamplingGate::new(
                    checkpoint,
                    self.checkpoint_td,
                    header.number,
                    self.config.difficulty_divisor,
                    self.config.min_difficulty,
                    super::headers::HEADER_CHUNK * super::headers::SKELETON_POINTS,
                    defence,
                ));
                self.set_phase(Phase::SamplingClaim);
            }
        }

        // The ascent is the alternative shape, and it needs two things the
        // descending walk does not: a peer that sends uncles, because it totals
        // the work exactly rather than bounding it, and ground to stand on.
        // Genesis is that ground for a node with nothing else.
        let ascending = self.config.forward_headers && self.peer_serves_uncles;
        if ascending {
            match self.anchor() {
                Some((number, hash, work)) if number < header.number => {
                    info!(
                        target: "rustock::snap",
                        "ascending the header chain from #{number} to #{}, with uncles",
                        header.number
                    );
                    self.ascent = Some(super::forward::ForwardSync::new(
                        number,
                        hash,
                        work,
                        header.number,
                        header.hash(),
                        self.config.archive_uncles,
                        self.store.clone(),
                        self.verifier.clone(),
                    ));
                }
                _ => {
                    warn!(
                        target: "rustock::snap",
                        "forward headers asked for, but this node has no anchor below \
                         #{}; falling back to the descending walk",
                        header.number
                    );
                }
            }
        }

        self.walk = Some(super::headers::HeaderWalk::new(
            header.clone(),
            self.store.clone(),
            self.verifier.clone(),
        ));

        self.checkpoint = Some(header);
        // The walk is built either way, but the gate — when there is one —
        // decides whether it runs. Only move to the walk if nothing is
        // bounding the claim first.
        if self.phase != Phase::SamplingClaim {
            let next = self.header_phase();
            self.set_phase(next);
        }
        self.poll()
    }

    /// Once the ascent reaches the checkpoint, check the offer against the
    /// chain this node just established for itself, and move to the state.
    ///
    /// This is what replaces the sampling gate and the `OverstatedDifficulty`
    /// ceiling in this shape. Neither is needed: the work is not bounded, it is
    /// counted, and the offered block is either the one at that height on the
    /// chain we proved or it is not.
    fn finish_ascent_or_continue(&mut self) -> Vec<Action> {
        let Some(ascent) = self.ascent.as_ref() else { return Vec::new() };
        if !ascent.done() {
            return self.poll();
        }
        let established = ascent.work();
        let Some(checkpoint) = self.checkpoint.clone() else { return Vec::new() };

        // The ascent wrote every header it proved, so the question is whether
        // the block offered is the one it arrived at.
        if ascent.frontier() != checkpoint.number {
            return self.fail(SnapFailure::NoCommonAncestor);
        }

        if self.checkpoint_td > established {
            return self.fail(SnapFailure::OverstatedDifficulty {
                claimed: self.checkpoint_td,
                ceiling: established,
            });
        }

        info!(
            target: "rustock::snap",
            "header chain established to #{} by ascent: cumulative difficulty {} \
             (exact, uncles proven); downloading state",
            checkpoint.number, established
        );
        self.set_phase(Phase::DownloadingState);
        self.poll()
    }

    /// Whichever header phase this session was configured for.
    ///
    /// Every transition out of `SamplingClaim` goes through here. Hard-coding
    /// `VerifyingHeaders` at those sites would build an ascent in `on_status`
    /// and then silently never run it, falling back to the descending walk
    /// with no sign that anything was ignored.
    #[cfg(test)]
    pub(crate) fn header_phase_for_test(&self) -> Phase {
        self.header_phase()
    }

    fn header_phase(&self) -> Phase {
        if self.ascent.is_some() { Phase::AscendingHeaders } else { Phase::VerifyingHeaders }
    }

    /// The highest block this node already accepts, with the work behind it.
    ///
    /// What the ascent stands on. Everything above it is this peer's word
    /// until the links reach up to it.
    ///
    /// This is the node's *head*, not a common ancestor with the peer. On a
    /// fresh node -- which is the case snapshot sync runs in -- head is genesis
    /// and the distinction does not arise. On a node whose head is already on
    /// another branch the ascent simply never links and the session fails over,
    /// which is honest but blunt; finding the fork point first would be the
    /// improvement.
    fn anchor(&self) -> Option<(u64, B256, U256)> {
        let hash = self.store.head().ok().flatten()?;
        let header = self.store.header(hash).ok().flatten()?;
        let work = self.store.total_difficulty(hash).ok().flatten().unwrap_or(U256::ZERO);
        Some((header.number, hash, work))
    }

    /// Headers walking back from the checkpoint, newest first, as rskj's
    /// `BlockHeadersResponse` delivers them.
    /// Headers delivered with their uncles, so the walk can total the work
    /// exactly rather than bounding it from below.
    /// Whether the uncles sent with a header are the ones it commits to, and
    /// each did the work it claims.
    ///
    /// A header failing either check still goes through as a bare header. Only
    /// its uncle-derived difficulty is withheld, which understates the chain
    /// rather than overstating it -- and understated is the direction that
    /// refuses a liar rather than admitting one.
    fn uncles_are_proven(
        &mut self,
        entry: &rustock_networking::protocol::HeaderWithUncles,
    ) -> bool {
        // The commitment first: it binds the list to the trunk header's proof
        // of work, and every rule after it is about a list the block really
        // chose rather than one the sender assembled.
        if !entry.commitment_matches() {
            warn!(
                target: "rustock::snap",
                "block #{} came with uncles its header does not commit to; \
                 not crediting the difficulty they would have proved",
                entry.header.number
            );
            return false;
        }

        // Then the whole of rskj's uncle rule: list limit, generation limit,
        // no repeats, not an ancestor, nothing an ancestor already used, a
        // parent that is itself an ancestor, and every per-header and
        // parent-relative rule a trunk block faces -- proof of work among
        // them.
        //
        // Commitment and proof of work alone would still let a miner reference
        // one real uncle under several of its own blocks and have the work
        // counted once per reference.
        if let Err(why) = self.uncle_guard.uncles_are_admissible(
            &self.store,
            &self.verifier,
            &entry.header,
            &entry.uncles,
        ) {
            warn!(
                target: "rustock::snap",
                "block #{}: uncles not admissible ({why}); not crediting the \
                 difficulty they would have proved",
                entry.header.number
            );
            return false;
        }

        // Recorded only once admissible, so a rejected list cannot seed the
        // window that later blocks are judged against.
        self.uncle_guard.record(&entry.header, entry.uncles.clone());
        true
    }

    /// Record whether this session's peer serves headers-with-uncles.
    ///
    /// Must be called before the status response is handled, since that is
    /// where the gate is built or skipped.
    pub fn set_peer_serves_uncles(&mut self, yes: bool) {
        self.peer_serves_uncles = yes;
    }

    pub fn on_headers_with_uncles(
        &mut self,
        point: u64,
        entries: &[rustock_networking::protocol::HeaderWithUncles],
    ) -> Vec<Action> {
        if self.phase == Phase::AscendingHeaders {
            let Some(ascent) = self.ascent.as_mut() else { return Vec::new() };
            if let Err(e) = ascent.on_headers_with_uncles(point, entries) {
                // Every one of these means the peer sent something it could
                // not have got from the real chain, so there is nothing to
                // salvage by asking it again.
                return self.fail(SnapFailure::InvalidHeader {
                    number: point,
                    reason: e.to_string(),
                });
            }
            return self.finish_ascent_or_continue();
        }
        // The same two checks the ordinary path makes, and for the same
        // reason: `cumulative_difficulty()` is the sender's arithmetic over
        // the uncles it chose to send, and only `ommers_hash` plus each
        // uncle's own proof of work turn that into a figure this node may
        // believe.
        //
        // It matters more here than there. These values flow into
        // `walked_difficulty`, hence `established_difficulty`, hence the
        // `OverstatedDifficulty` ceiling -- so a peer that fabricates uncles
        // *raises the very ceiling* its claim is checked against. The one
        // guard against an overstated claim could be widened by the peer it
        // was guarding against.
        let mut proven = std::collections::HashMap::with_capacity(entries.len());
        let mut headers: Vec<Header> = Vec::with_capacity(entries.len());
        // Oldest first: the uncle rule judges a block against its ancestors,
        // so the window must be filled in the order the chain was built.
        for e in entries.iter().rev() {
            if self.uncles_are_proven(e) {
                proven.insert(e.header.hash(), e.cumulative_difficulty());
            }
            headers.push(e.header.clone());
        }
        headers.reverse(); // back to newest first, as the walk expects

        // Keep the uncles for the descending walk too. They arrive once and
        // nothing else will hand them to a node that fetches no bodies.
        if self.phase == Phase::VerifyingHeaders {
            let lists: Vec<(u64, Vec<Header>)> = entries
                .iter()
                .map(|e| (e.header.number, e.uncles.clone()))
                .collect();
            if self.config.archive_uncles {
                if let Some(walk) = self.walk.as_mut() {
                    walk.stage_uncles(&lists);
                }
            }
        }
        self.ingest_headers(point, &headers, &proven)
    }

    pub fn on_headers(&mut self, point: u64, headers: &[Header]) -> Vec<Action> {
        self.ingest_headers(point, headers, &std::collections::HashMap::new())
    }

    fn ingest_headers(
        &mut self,
        point: u64,
        headers: &[Header],
        proven: &std::collections::HashMap<B256, U256>,
    ) -> Vec<Action> {
        // While the claim is being bounded, headers are samples rather than
        // chain: each is checked against the identifier it was asked for and
        // its own proof of work, and only its difficulty is kept.
        if self.phase == Phase::SamplingClaim {
            if let Some(gate) = self.gate.as_mut() {
                for header in headers {
                    gate.on_header(header, self.verifier.as_ref());
                }
            }
            return self.poll();
        }
        if self.phase != Phase::VerifyingHeaders {
            return Vec::new();
        }
        let Some(walk) = self.walk.as_mut() else {
            return self.fail(SnapFailure::NoCheckpoint);
        };

        if headers.is_empty() {
            // That peer cannot fill this range; another might. Give up only
            // once several in a row have come back empty.
            //
            // The range is handed back first, which is all the walk does with
            // an empty run. Left marked as asked, it was never asked again,
            // and when it was the frontier nothing could move the walk past it.
            let _ = walk.on_headers(point, headers, proven);
            self.empty_header_replies += 1;
            if self.empty_header_replies >= EMPTY_HEADER_REPLIES_ALLOWED {
                return self.fail(SnapFailure::NoCommonAncestor);
            }
            return self.poll();
        }
        self.empty_header_replies = 0;

        // Every header's own rules and every adjacent pair's, exactly as the
        // serial walk did. What has changed is when the request went out, not
        // what is accepted.
        if let Err(e) = walk.on_headers(point, headers, proven) {
            return self.fail(match e {
                super::headers::WalkError::InvalidHeader { number, reason } => {
                    SnapFailure::InvalidHeader { number, reason }
                }
                super::headers::WalkError::BrokenChunk { .. } => SnapFailure::BrokenChain,
                super::headers::WalkError::ForeignGenesis => SnapFailure::ForeignGenesis,
            });
        }

        self.link_headers()
    }

    /// Block identifiers telling the walk where to ask next. Claims about
    /// where blocks sit, believed only as far as the runs they lead to link.
    pub fn on_skeleton(&mut self, identifiers: &[BlockIdentifier]) -> Vec<Action> {
        if self.phase == Phase::SamplingClaim {
            if let Some(gate) = self.gate.as_mut() {
                let ids: Vec<(u64, B256)> =
                    identifiers.iter().map(|i| (i.number, i.hash)).collect();
                gate.on_skeleton(&ids);
            }
            return self.poll();
        }
        if self.phase == Phase::AscendingHeaders {
            let Some(ascent) = self.ascent.as_mut() else { return Vec::new() };
            ascent.on_skeleton(identifiers);
            return self.poll();
        }
        if self.phase != Phase::VerifyingHeaders {
            return Vec::new();
        }
        let Some(walk) = self.walk.as_mut() else { return Vec::new() };
        walk.on_skeleton(identifiers);
        self.poll()
    }

    /// Follow whatever links now reach, and start the state download if the
    /// chain has come all the way down.
    fn link_headers(&mut self) -> Vec<Action> {
        let Some(walk) = self.walk.as_mut() else { return Vec::new() };
        match walk.advance() {
            Ok(_) => {}
            Err(super::headers::WalkError::ForeignGenesis) => {
                return self.fail(SnapFailure::ForeignGenesis)
            }
            Err(super::headers::WalkError::InvalidHeader { number, reason }) => {
                return self.fail(SnapFailure::InvalidHeader { number, reason })
            }
            Err(super::headers::WalkError::BrokenChunk { .. }) => {
                return self.fail(SnapFailure::BrokenChain)
            }
        }
        if walk.is_done() {
            return self.start_state_download();
        }
        self.poll()
    }

    /// Ask again for a header range nobody answered.
    /// Ask again for headers nobody answered.
    ///
    /// Both header phases, not just the descending walk. An earlier version
    /// released only `walk`, so during an ascent a single dropped response
    /// left its request marked outstanding for ever: `wants` would not reissue
    /// it, nothing else could, and the frontier stopped where it stood. That
    /// is what stalled the first real run at 99.96%.
    pub fn release_header_request(&mut self, point: u64, from: B256, count: u32) {
        if let Some(walk) = self.walk.as_mut() {
            walk.release(&super::headers::Want::Headers { from, count, point });
        }
        if let Some(ascent) = self.ascent.as_mut() {
            ascent.release(&super::forward::Want::Headers { from, count, point });
        }
    }

    /// Ask again for a skeleton nobody answered: in both header phases, and in
    /// the sampling gate before them, which asks for skeletons too and waits
    /// for every one of them before it judges.
    pub fn release_skeleton_request(&mut self, start: u64) {
        if let Some(gate) = self.gate.as_mut() {
            gate.release_skeleton(start);
        }
        if let Some(walk) = self.walk.as_mut() {
            walk.release(&super::headers::Want::Skeleton { start });
        }
        if let Some(ascent) = self.ascent.as_mut() {
            ascent.release(&super::forward::Want::Skeleton { start });
        }
    }

    /// Is this block one this node had already accepted as canonical?
    ///
    /// Asked of the canonical index rather than of "is this header stored",
    /// because the walk itself stores headers by hash as it goes. A check its
    /// own writes could satisfy would be no check at all.
    fn is_ours(&self, number: u64, hash: B256) -> bool {
        self.store.canonical_hash(number).ok().flatten() == Some(hash)
    }

    fn start_state_download(&mut self) -> Vec<Action> {
        let checkpoint = self.checkpoint.clone();

        // The claim is judged before anything is written. Everything after this
        // makes the checkpoint this node's own -- its total difficulty, the
        // canonical index under it, the head -- and the next session's walk
        // stops at the first block it finds there. Written first and refused
        // after, a claim turned down here was taken on the next attempt without
        // a walk: on mainnet the second session "verified" the chain in four
        // seconds, on the strength of the first one's refused total.
        //
        // The walk has read every header from the checkpoint, its first, down
        // to a block this node already trusted, and counted each run as it
        // joined the chain. Uncles it could not count: they travel in bodies,
        // which a header walk never fetches, and rskj peers send none
        // alongside. Taken for a ceiling, with only the checkpoint's own
        // uncles allowed for, that floor refused every honest peer on mainnet:
        // #9381160 carries 6.24e28, and its headers alone 3.54e28.
        //
        // What the walk did see bounds the uncles it did not, and
        // `HeaderWalk::work_ceiling` adds that bound to the floor. With every
        // uncle sent, the ceiling is the exact work.
        //
        // The claim is written as this node's own total difficulty at the
        // checkpoint, so it is worth bounding rather than accepting.
        let judged = self.walk.as_ref().and_then(|walk| {
            Some((
                walk.established_difficulty()?,
                walk.work_ceiling(self.config.min_difficulty)?,
                walk.uncles_omitted(),
            ))
        });
        if let Some((_, ceiling, _)) = judged {
            if self.checkpoint_td > ceiling {
                return self.fail(SnapFailure::OverstatedDifficulty {
                    claimed: self.checkpoint_td,
                    ceiling,
                });
            }
        }

        // The walk reached a block this node already had, so everything above
        // it is anchored to work this node had already accepted. Only now do
        // the headers become part of this chain.
        for (block, td) in std::mem::take(&mut self.offered) {
            let hash = block.header.hash();
            let _ = self.store.put_header_with_hash(hash, &block.header);
            let _ = self.store.put_body(hash, &block.transactions, &block.ommers);
            let _ = self.store.put_total_difficulty(hash, td);
        }
        if let Some(header) = &checkpoint {
            let hash = header.hash();
            let _ = self.store.put_total_difficulty(hash, self.checkpoint_td);

            // Index the window this session will work in, and no more.
            //
            // The walk stored every header it verified, by hash, which for a
            // fresh node is the whole chain. Indexing all of it here would
            // build one write batch of nine million entries -- hundreds of
            // megabytes, in the middle of the sync loop. What the session
            // needs indexed is the range whose bodies it is about to fetch,
            // plus a margin; the rest is a local pass over data already on
            // disk, and belongs in the background. See issue #133.
            let window = self.config.blocks_required + self.config.block_chunk_size + 1;
            match self.store.repair_canonical_lineage(hash, window) {
                Ok(report) => debug!(
                    target: "rustock::snap",
                    "indexed {} blocks down to #{:?} for the checkpoint",
                    report.walked, report.lowest
                ),
                Err(e) => warn!(
                    target: "rustock::snap",
                    "could not index the verified chain: {e}"
                ),
            }
            let _ = self.store.set_head(hash);
        }

        let frontier = self.walk.as_ref().map_or(0, |w| w.frontier());
        let at = checkpoint.as_ref().map_or(0, |h| h.number);
        match judged {
            Some((established, ceiling, uncles)) => info!(
                target: "rustock::snap",
                "header chain verified back to #{frontier}: work {established} counted, at most \
                 {ceiling} with the {uncles} uncles a header walk cannot see, against {} claimed; \
                 downloading state at #{at}",
                self.checkpoint_td
            ),
            None => info!(
                target: "rustock::snap",
                "header chain verified back to #{frontier}; downloading state at #{at}"
            ),
        }
        self.set_phase(Phase::DownloadingState);
        self.poll()
    }

    /// A chunk of state, still unverified.
    ///
    /// `from` is the offset the *client* asked for, carried through the
    /// request's own bookkeeping -- never read off the response.
    pub fn on_chunk(
        &mut self,
        from: u64,
        payload: &ChunkPayload,
        refusal: Refusal,
    ) -> Vec<Action> {
        if self.phase != Phase::DownloadingState {
            return Vec::new();
        }

        // A server that said why it could not answer is believed about that
        // much: it costs it nothing to lie, but the lie only wastes our
        // requests, and the alternative is guessing from an empty payload.
        if refusal != Refusal::None {
            self.chunk_fault = Some(if refusal.worth_asking_again() {
                ChunkFault::Realign
            } else {
                ChunkFault::Declined
            });
            debug!(target: "rustock::snap", "peer refused offset {from}: {refusal:?}");
            return self.fruitless(from);
        }

        let Some(root_hash) = self.checkpoint.as_ref().map(|h| h.state_root) else {
            return Vec::new();
        };

        let arrived = match super::client::chunk_from_payload(payload, root_hash) {
            Ok(arrived) => arrived,
            Err(e) => {
                debug!(target: "rustock::snap", "chunk from offset {from} unusable: {e}");
                self.chunk_fault = Some(match e {
                    ChunkError::LegacyRebuild(_) => ChunkFault::BadRebuild,
                    other => ChunkFault::Misbehaved(other),
                });
                return self.fruitless(from);
            }
        };

        // An rskj chunk proves itself by rebuilding to the root, which has
        // already happened -- there is no way to inspect one without
        // reconstructing it. What is left is to keep the nodes.
        let proof = match arrived {
            super::client::Arrived::Rebuilt(rebuilt) => {
                let Some(download) = self.download.as_mut() else { return Vec::new() };
                let progress = download.accept_rebuilt(from, &rebuilt);
                self.fruitless_chunks = 0;
                return if progress.complete {
                    self.finish_state_download()
                } else {
                    self.poll()
                };
            }
            super::client::Arrived::Proved(proof) => proof,
        };

        if proof.entries.is_empty() {
            // "I cannot serve this." Hand the range back rather than treat an
            // empty answer as the end of the trie -- only the root says where
            // that is. Declining is not misbehaviour: the peer may have pruned
            // the state, or be on another chain.
            self.chunk_fault = Some(ChunkFault::Declined);
            return self.fruitless(from);
        }

        let Some(download) = self.download.as_mut() else { return Vec::new() };
        match download.accept(from, &proof) {
            Ok(progress) => {
                self.fruitless_chunks = 0;
                if progress.complete {
                    return self.finish_state_download();
                }
            }
            Err(e) => {
                debug!(target: "rustock::snap", "chunk from offset {from} refused: {e}");
                self.chunk_fault = Some(ChunkFault::Misbehaved(e));
                return self.fruitless(from);
            }
        }
        self.poll()
    }

    /// An answer that added nothing: put the range back, and count it.
    fn fruitless(&mut self, from: u64) -> Vec<Action> {
        if let Some(download) = self.download.as_mut() {
            download.release(from);
        }
        self.fruitless_chunks += 1;
        if self.fruitless_chunks >= FRUITLESS_CHUNKS_ALLOWED {
            return self.fail(SnapFailure::NoProgress(self.fruitless_chunks));
        }
        self.poll()
    }

    /// Give a range back after a timeout or a disconnect.
    pub fn release_chunk(&mut self, from: u64) {
        if let Some(download) = self.download.as_mut() {
            download.release(from);
        }
    }



    /// Ask for a block range again after a timeout.
    pub fn release_blocks(&mut self) {
        self.blocks_in_flight = false;
    }

    fn finish_state_download(&mut self) -> Vec<Action> {
        let Some(download) = self.download.as_ref() else { return Vec::new() };
        match download.verify_stored() {
            Ok(nodes) => {
                let (covered, _) = download.progress();
                info!(
                    target: "rustock::snap",
                    "state complete: {nodes} nodes, {covered} bytes, root {:?}",
                    download.root_hash()
                );
                self.set_phase(Phase::DownloadingBlocks);
                self.poll()
            }
            // Every chunk verified against the root, so this is not about the
            // peers -- it is this node failing to keep what it was given.
            Err(why) => self.fail(SnapFailure::IncompleteState(why)),
        }
    }

    /// Blocks behind the checkpoint, oldest first.
    pub fn on_blocks(&mut self, blocks: &[Block], difficulties: &[U256]) -> Vec<Action> {
        if self.phase != Phase::DownloadingBlocks {
            return Vec::new();
        }
        self.blocks_in_flight = false;

        if blocks.is_empty() || difficulties.len() != blocks.len() {
            // That peer had nothing to add. Another may; but if none does,
            // stop rather than ask the same question forever.
            self.fruitless_blocks += 1;
            if self.fruitless_blocks >= FRUITLESS_CHUNKS_ALLOWED {
                return self.fail(SnapFailure::NoProgress(self.fruitless_blocks));
            }
            return self.poll();
        }
        self.fruitless_blocks = 0;

        if let Err(why) = check_chain_shape(blocks, difficulties) {
            return self.fail(why);
        }

        let mut oldest = self.blocks_cursor;
        for (block, td) in blocks.iter().zip(difficulties.iter()) {
            let hash = block.header.hash();

            // These blocks are never executed -- they are fetched because
            // contracts can read them -- so nothing downstream would ever
            // check them. Bind each body to the header this node verified for
            // itself during the walk: the right chain, and the right contents
            // for that chain.
            if !self.is_ours(block.header.number, hash) {
                return self.fail(SnapFailure::BrokenChain);
            }
            if let Err(why) = check_body_matches_header(block) {
                return self.fail(why);
            }

            let _ = self.store.put_body(hash, &block.transactions, &block.ommers);
            let _ = self.store.put_total_difficulty(hash, *td);
            oldest = oldest.min(block.header.number);
        }

        self.blocks_cursor = oldest;
        if self.blocks_cursor <= self.blocks_floor() {
            info!(
                target: "rustock::snap",
                "snapshot sync complete: state at #{}, bodies back to #{}",
                self.checkpoint.as_ref().map_or(0, |h| h.number),
                self.blocks_cursor
            );
            self.set_phase(Phase::Done);
            return Vec::new();
        }
        self.poll()
    }
}

/// A body must be the one its header commits to.
///
/// The transaction root's encoding changed at the unitrie fork, and this has
/// no hardfork table to consult, so either encoding is accepted: both are
/// genuine, and matching one of them is what proves the transaction set. The
/// question being answered is "are these the right transactions", not "which
/// era is this".
fn check_body_matches_header(block: &Block) -> Result<(), SnapFailure> {
    use rustock_core::ordered_tx_trie_root;

    let wanted = block.header.transactions_root;
    if ordered_tx_trie_root(&block.transactions, true) != wanted
        && ordered_tx_trie_root(&block.transactions, false) != wanted
    {
        return Err(SnapFailure::BadBody {
            number: block.header.number,
            what: "transactions",
        });
    }
    if rustock_execution::processor::compute_ommers_hash(&block.ommers)
        != block.header.ommers_hash
    {
        return Err(SnapFailure::BadBody { number: block.header.number, what: "uncles" });
    }
    Ok(())
}

/// Blocks must form one chain, oldest first, with cumulative difficulty
/// rising along it.
///
/// This is rskj's `areBlockPairsValid` in miniature. It catches a peer
/// stitching unrelated blocks together cheaply, before any of the expensive
/// checks run -- it is not itself evidence that the chain is the real one.
pub(crate) fn check_chain_shape(blocks: &[Block], difficulties: &[U256]) -> Result<(), SnapFailure> {
    for i in 1..blocks.len() {
        let (parent, child) = (&blocks[i - 1], &blocks[i]);
        if child.header.parent_hash != parent.header.hash() {
            return Err(SnapFailure::BrokenChain);
        }
        if child.header.number != parent.header.number + 1 {
            return Err(SnapFailure::BrokenChain);
        }
        // Cumulative difficulty must grow by exactly this block's own
        // contribution: the pair has to agree with itself.
        //
        // That contribution is the header difficulty *plus every uncle's*,
        // rskj's `Block.getCumulativeDifficulty`. Comparing against the header
        // difficulty alone rejects every honest peer whose totals are right,
        // because an RSK chain absorbs about one uncle per block. The uncles
        // are in hand here: the status response carries whole blocks.
        if difficulties[i] <= difficulties[i - 1] {
            return Err(SnapFailure::BadDifficulty);
        }
        let mut contribution = child.header.difficulty;
        for uncle in &child.ommers {
            contribution = contribution.saturating_add(uncle.difficulty);
        }
        if difficulties[i] - difficulties[i - 1] != contribution {
            return Err(SnapFailure::BadDifficulty);
        }
    }
    Ok(())
}
