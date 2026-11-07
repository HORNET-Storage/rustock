use crate::events::SyncEvent;
use crate::manager::{SyncManager, MAX_SKELETON_CHUNKS};
use crate::progress::SyncProgress;
use crate::unlinked::Verdict;
use crate::state::{InFlightBody, SyncState};
use crate::invariant::{self, Scope, Violation};
use crate::tracker::PeerChunkTracker;
use crate::watchdog::{Escalation, Phi, ProgressWatchdog};
use rustock_core::types::header::Header;
use rustock_core::types::transaction::Transaction;
use rustock_core::Block;
use rustock_execution::BlockProcessor;
use rustock_networking::protocol::{
    BlockHashRequest, BlockIdentifier, BodyRequest, HeaderWithUncles, P2pMessage, RskMessage,
    RskSubMessage,
    SkeletonRequest,
};
use rustock_storage::{BlockStore, Transition, Validated};
use rustock_trie::{TrieNode, TrieStore};
use alloy_primitives::{B256, B512};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Who to tell when a block becomes the executed best block: rskj's
/// `EthereumListener.onBestBlock`, which the miner uses to rebuild its
/// candidate. Registered after the service starts, which is why it is a
/// shared slot and not a builder argument: the miner is built later.
#[derive(Default)]
pub struct BestBlockListeners {
    listeners: std::sync::RwLock<Vec<Arc<dyn Fn(&Header) + Send + Sync>>>,
}

impl BestBlockListeners {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add(&self, listener: Arc<dyn Fn(&Header) + Send + Sync>) {
        self.listeners.write().unwrap_or_else(|e| e.into_inner()).push(listener);
    }

    pub fn notify(&self, header: &Header) {
        let listeners = self.listeners.read().unwrap_or_else(|e| e.into_inner()).clone();
        for listener in listeners {
            listener(header);
        }
    }
}
use tokio::task::JoinHandle;
use tracing::{info, debug, trace, warn, error};

/// Timeout for pending requests before resetting to Idle.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Snapshot sync sessions to try before concluding it will not work here.
///
/// A session that fails on one peer's bad data is that peer's fault, not a
/// reason to abandon the feature -- but trying forever against a hostile
/// network is not better. Each attempt costs a status round trip and whatever
/// of the header walk it got through.
const MAX_SNAP_ATTEMPTS: u32 = 5;

/// How long a coherence violation must persist before it is worth reporting.
///
/// Long enough to cover the ordinary gap between canonicalising a header and
/// executing its body -- which is a second or two, and happens on every tip --
/// and far shorter than any stall the node has ever suffered.
const VIOLATION_GRACE: Duration = Duration::from_secs(45);

/// How long I5 must hold before execution is rolled back onto the canonical
/// chain.
///
/// I5 -- the executed head is not the canonical block at its own height --
/// holds for a moment on every ordinary reorg, between the canonical index
/// switching and the replacement block executing. Acting on the first tick
/// would retreat execution for a sibling that is about to win anyway, and two
/// siblings alternating would make the node thrash.
///
/// Shorter than `VIOLATION_GRACE` because this is a repair, not a report: the
/// 2026-09-24 19:00 stall stood for twelve minutes, and the ordinary case it
/// must not disturb resolves inside a second.
pub(crate) const EXECUTION_OFF_CHAIN_GRACE: Duration = Duration::from_secs(10);

/// Faster reclaim for body requests: a body not back within this window is
/// re-sent to another peer. Shorter than REQUEST_TIMEOUT because idempotent
/// application makes a duplicate harmless, so reclaiming a slot stuck on a
/// slow/dead peer quickly is pure upside.
const BODY_RECLAIM_TIMEOUT: Duration = Duration::from_secs(12);

/// Cap on concurrent body requests to a single peer, so a fast peer can
/// pipeline deeply without the whole window piling onto one slow peer.
/// Extra blocks to re-assert below the executed head when repairing the
/// canonical index, so a repair is not defeated by damage just below the hole.
/// How long a follow-mode gap must persist, with nothing in flight that could
/// fill it, before the missing range is re-fetched.
///
/// Long enough that ordinary out-of-order responses are never disturbed --
/// those land within seconds -- and short enough that a permanent gap costs a
/// minute rather than the twenty hours it cost on mainnet.
const FOLLOW_GAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long execution may stand still, with blocks downloaded and nothing in
/// flight, before the pipeline is restarted.
///
/// Generous enough that a slow batch is never interrupted -- executing a few
/// hundred mainnet blocks takes seconds, not minutes -- and short enough that a
/// stall costs minutes rather than the twenty hours it cost unfixed.
const EXEC_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// How long a follow-mode body request may go unanswered before it is dropped
/// and the block re-requested.
///
/// Comfortably longer than any healthy round trip, and far shorter than
/// forever, which is what it was.
const FOLLOW_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Unexecuted blocks tolerated in follow mode before switching to the body
/// pipeline.
///
/// One or two is ordinary -- a tip has arrived and is about to be executed.
/// More than that means blocks were missed, and follow mode has no way to go
/// back for them.
pub(crate) const FOLLOW_BACKLOG_TOLERANCE: u64 = 2;

/// Whether downloaded-but-unexecuted blocks must be executed before following.
///
/// Follow mode only executes blocks that arrive as fresh announcements; it has
/// no path for a backlog already in the store. Entering it with one leaves those
/// blocks unexecuted forever, and the backlog grows with every new tip.
///
/// Only applies to a node that executes: without a block processor there is no
/// execution to fall behind.
/// The highest canonical height at or above `from` that we hold a linked chain
/// up to.
///
/// Walks up the canonical index while every step is present in the header
/// store and links to the one below. Returns `None` when nothing above `from`
/// qualifies.
///
/// Bounded: a damaged index must not turn a recovery into a full-chain sweep.
/// A [`ChainView`](crate::rollback::ChainView) over this node's stores.
///
/// `trie` is optional because two of the three decisions in `rollback` never
/// ask about state: `fork_point` and `ancestor_at_depth` walk headers only.
/// Only `choose_resume_point` needs the trie, and it is the only caller that
/// passes one.
pub(crate) struct StoreView<'a> {
    pub store: &'a BlockStore,
    pub trie: Option<&'a dyn TrieStore>,
}

impl crate::rollback::ChainView for StoreView<'_> {
    fn header(&self, hash: B256) -> Option<Header> {
        self.store.header(hash).ok().flatten()
    }
    fn canonical_hash(&self, number: u64) -> Option<B256> {
        self.store.canonical_hash(number).ok().flatten()
    }
    fn has_state(&self, root: B256) -> bool {
        self.trie.is_some_and(|t| t.get(root.as_slice()).is_some())
    }
}

pub(crate) fn canonical_top_held(store: &BlockStore, from: u64) -> Option<B256> {
    const MAX_WALK_UP: u64 = 4_096;

    let mut top_hash = store.canonical_hash(from).ok().flatten()?;
    let mut top_number = from;

    for _ in 0..MAX_WALK_UP {
        let next = top_number + 1;
        let Some(hash) = store.canonical_hash(next).ok().flatten() else { break };
        let Some(header) = store.header(hash).ok().flatten() else { break };
        if header.parent_hash != top_hash {
            break;
        }
        top_hash = hash;
        top_number = next;
    }

    Some(top_hash)
}

/// Record execution progress through a transition, so the executed head can
/// never be set to a block whose lineage does not hold.
/// Adopt a block this node has already executed, instead of executing it again.
///
/// Returns its state root node when the block can be fast-forwarded over, and
/// `None` when it has to be executed.
///
/// **Two conditions, and neither implies the other.** `was_executed_locally`
/// says *this node* validated this exact block -- verified by hashing the
/// stored receipts against the header's `receiptsRoot`, not taken on trust.
/// The trie lookup says the state it produced is *still there*. Skipping on the
/// state root alone would be a validation bypass: a header's state root is
/// attacker-chosen, and every root in our own history is public.
///
/// This is what makes a deep retreat cheap. An orphan recovery retreats below
/// the fork and climbs back over blocks it executed minutes ago; only the
/// handful above the fork are new work. Re-running the EVM over the rest
/// reproduces bytes already on disk -- measured at 13-55 ms per block, so
/// 0.3-1.4 s on every reorg.
pub(crate) fn fast_forward_state(
    processor: &rustock_execution::BlockProcessor,
    trie_store: &Arc<dyn TrieStore>,
    header: &Header,
    hash: B256,
) -> Option<TrieNode> {
    if !processor.was_executed_locally(hash) {
        return None;
    }
    let data = trie_store.get(header.state_root.as_slice())?;
    Some(TrieNode::from_message(&data, trie_store.as_ref()))
}

/// Advance the executed-head marker, reporting whether it actually moved.
///
/// **The return value is not decoration.** `Transition::Executed` refuses a
/// block that is not canonical at its height, which happens whenever a reorg
/// lands between executing a block and recording it. A caller that ignores the
/// refusal goes on to claim the block executed and to advance its in-memory
/// state root to a block the node is not on -- which is how #9,267,779 came to
/// be logged as `Executed block` one line after the store refused it, on
/// 2026-09-24 at 14:01:15, and why the coherence check then had to reload the
/// committed root five seconds later.
pub(crate) fn record_execution(store: &BlockStore, hash: B256, state_root: B256) -> bool {
    match Validated::prove(store, hash) {
        Ok(at) => match store.apply(&Transition::Executed { at, state_root }) {
            Ok(_) => true,
            Err(e) => {
                error!(target: "rustock::sync", "Recording execution of {:?} failed: {:?}", hash, e);
                false
            }
        },
        Err(broken) => {
            error!(
                target: "rustock::sync",
                "Executed {:?} but its lineage does not hold ({}); not recording it",
                hash, broken
            );
            false
        }
    }
}

pub(crate) fn backlog_needs_executing(has_processor: bool, downloaded: u64, executed: u64) -> bool {
    has_processor && downloaded > executed
}

const CANONICAL_REPAIR_MARGIN: u64 = 64;

/// How far *below* the executed head the coherence check looks.
///
/// The delta window between the executed head and the validated head is where
/// disagreements were assumed to live, and for I4..I8 that is true. I3 -- the
/// canonical chain links to itself -- is different: a reorg rewrites pointers
/// at and below the fork point, and `ensure_canonical_lineage` stops walking
/// at the first consistent pair, so a pointer left stale underneath that point
/// is never revisited by anything.
///
/// On mainnet 2026-10-04 seven such pointers accumulated. Nothing noticed for
/// 33 hours, because the only thing that looks at a settled height again is
/// REMASC, 4,000 blocks later -- and what it does then is compute a different
/// state root and stop the node for good.
///
/// A reorg cannot move the chain further than `MAX_REORG_DEPTH`, so looking
/// that far below the executed head covers the whole of where the damage can
/// be done. It costs two point lookups per height per sweep.
const COHERENCE_LOOKBACK: u64 = 1_000;

const MAX_BODY_REQUESTS_PER_PEER: usize = 16;

/// Ceiling on body requests outstanding across all peers at once. Bounds memory
/// held for pending responses regardless of how many peers are connected.
const MAX_TOTAL_BODY_REQUESTS: usize = 256;

/// A peer is skipped for new body assignments after this many of its requests
/// time out; reset to zero whenever it answers one. Keeps work off dead peers.
const BODY_PEER_STRIKE_LIMIT: u32 = 8;

/// Per-peer stall timeout during header download: a peer holding chunks
/// that hasn't responded within this window gets its chunks reassigned
/// and is sidelined (rskj punishes TIMEOUT_MESSAGE peers via peer scoring;
/// without this a single dead-but-connected peer wedges every round, since
/// chunks are processed in order).
const PEER_STALL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a stalled peer is excluded from header-chunk assignment.
const PEER_SIDELINE_DURATION: Duration = Duration::from_secs(300);

/// Interval between sync tick checks.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// How often this node re-states its status to every peer.
///
/// rskj's figure, and matching it is the point rather than a coincidence. An
/// rskj peer refreshes a node's liveness **only** when a `STATUS` arrives --
/// `SyncPeerStatus.updateActivity` is called from its constructor and from
/// `setStatus`, and from nowhere else, so block traffic, headers, bodies and
/// announcements all leave the clock untouched. After
/// `sync.expirationTimePeerStatus`, ten minutes, it drops the node from the
/// set it will sync from, while the connection stays up and looks healthy.
///
/// rustock sent its status once, at the handshake. An rskj peer could
/// therefore start a sync round from this node for ten minutes and never
/// again, which was observed: a sync stopped after fourteen minutes at a whole
/// number of skeleton chunks, with one connected peer and nothing wrong.
pub(crate) const STATUS_REFRESH: Duration = Duration::from_secs(10);

/// Maximum block gap for follow mode. Gaps larger than this trigger skeleton
/// sync; smaller gaps are handled by fetching individual headers.
/// Matches RSKj's `longSyncLimit` (default 24).
const LONG_SYNC_LIMIT: u64 = 24;

/// How far below an orphaned head to retreat when the fork point cannot be
/// computed, because the branch that replaced us was never downloaded.
///
/// **One past `LONG_SYNC_LIMIT`, and that is the whole derivation.** This is
/// not a guess at how deep reorgs go; no constant could be. It is the depth at
/// which `check_follow_gap` stops trying to bridge the gap by chasing
/// individual missing parents and switches to skeleton sync, which requests
/// **by height range**. A range request is the only mechanism that re-fetches
/// a height whose block the node already holds -- and holding the wrong block
/// at a contested height is exactly the situation a blind retreat is in.
///
/// Retreating one block instead is what stalled mainnet for twelve minutes on
/// 2026-09-24. It left the node "1 block behind", holding that one block (the
/// losing one), so follow mode had nothing to chase and sat idle while the
/// network moved on. It escaped only when the network's own progress carried
/// it past this same threshold, 12 minutes later, and skeleton sync fixed it
/// in 20 seconds.
///
/// The cost is re-executing up to 25 blocks -- a few seconds -- on a reorg
/// whose replacement branch is not held. That is most of them: a one-block
/// reorg at the tip takes this path too, because the block that replaced us is
/// equally not in the store. Robustness is worth more here than those seconds;
/// three stalls in three days (3 hours, 3 days, 12 minutes) all lived in this
/// decision.
pub(crate) const BLIND_RETREAT_DEPTH: u64 = LONG_SYNC_LIMIT + 1;

fn create_block_hash_request(height: u64) -> P2pMessage {
    let req = BlockHashRequest {
        id: rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF,
        height,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)))
}

fn create_body_request(hash: B256) -> (u64, P2pMessage) {
    // Mask to 63 bits: RSKj uses Java's signed long, so IDs > 2^63 get
    // sign-mangled when echoed back via BigInteger.valueOf(long).
    let id: u64 = rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF;
    let req = BodyRequest { id, hash };
    (id, P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req))))
}

fn create_skeleton_request(start_number: u64) -> P2pMessage {
    let req = SkeletonRequest {
        id: rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF,
        start_number,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)))
}

/// How many times the same executed head may halt before the node stops
/// retrying it.
///
/// Two is a coincidence; three from an unchanged height is a plan that does
/// not work.
const FUTILE_HALTS_BEFORE_GIVING_UP: u32 = 3;

/// Current count of in-flight body requests per connected peer.
fn peer_body_load(
    peers: &[B512],
    in_flight: &HashMap<usize, InFlightBody>,
) -> HashMap<B512, usize> {
    let mut load: HashMap<B512, usize> = peers.iter().map(|p| (*p, 0)).collect();
    for req in in_flight.values() {
        if let Some(c) = load.get_mut(&req.peer) {
            *c += 1;
        }
    }
    load
}

/// Pick the least-loaded peer for a body request, preferring responsive peers
/// (under the strike limit) and never exceeding the per-peer cap. `exclude`
/// (the peer a request just timed out on) is avoided when an alternative
/// exists. Relaxes through fallbacks so a request is still placed while any
/// peer has spare capacity.
fn pick_body_peer(
    load: &HashMap<B512, usize>,
    strikes: &HashMap<B512, u32>,
    exclude: Option<B512>,
) -> Option<B512> {
    let pick = |require_fresh: bool, honor_exclude: bool| -> Option<B512> {
        load.iter()
            .filter(|(p, &c)| {
                c < MAX_BODY_REQUESTS_PER_PEER
                    && (!honor_exclude || Some(**p) != exclude)
                    && (!require_fresh
                        || strikes.get(*p).copied().unwrap_or(0) < BODY_PEER_STRIKE_LIMIT)
            })
            .min_by_key(|(_, &c)| c)
            .map(|(p, _)| *p)
    };
    // 1) responsive and not the excluded peer; 2) responsive (any);
    // 3) any peer under cap.
    pick(true, true)
        .or_else(|| pick(true, false))
        .or_else(|| pick(false, false))
}

/// An external, local source of block bodies — e.g. a synced rskj LevelDB —
/// consulted before requesting bodies from peers. Lets the node reuse an
/// existing on-disk chain instead of re-downloading it over the network.
pub trait ExternalBlockSource: Send + Sync {
    /// Returns `(transactions, ommers)` for the block with this hash, if known.
    fn body_by_hash(&self, hash: B256) -> Option<(Vec<Transaction>, Vec<Header>)>;
}

/// Result of executing one downloaded batch on a blocking thread.
pub(crate) struct ExecOutcome {
    /// `false` when a block failed to execute (or a parent/body was missing);
    /// the sync must not advance past it.
    pub(crate) all_ok: bool,
    /// State root after the last successfully executed block in the batch.
    /// Becomes the starting root for the next batch's execution.
    pub(crate) new_state_root: TrieNode,
    /// Number of `blocks_since_flush` accumulated but not yet flushed when the
    /// batch ended (carried back so flush cadence survives across batches).
    pub(crate) blocks_since_flush: u64,
}

/// A batch currently executing off the async event loop.
struct ExecutionJob {
    handle: JoinHandle<ExecOutcome>,
    /// `peer_best` of the round that produced this batch, used to decide
    /// whether to keep syncing or enter follow mode after it completes.
    peer_best: u64,
}

/// The execution step run on a blocking thread for one downloaded batch.
/// Captures the (cloneable, thread-safe) handles execution needs; production
/// wires this to [`process_downloaded_blocks`]. Boxed so tests can substitute
/// a controllable stand-in and exercise the scheduling logic in isolation.
pub(crate) type ExecFn = Arc<
    dyn Fn(TrieNode, u64, Vec<(B256, Header)>) -> ExecOutcome + Send + Sync + 'static,
>;

/// Skeleton-based forward sync with pipelining, multi-peer downloads,
/// and overlapping skeleton pre-fetch.
pub struct SyncService {
    manager: Arc<SyncManager>,
    /// Per-block counters for the periodic activity report. Shared with the
    /// reporter task, and written from both execution paths so the window
    /// covers everything executed however it arrived.
    chain_activity: Arc<crate::chain_activity::ChainActivity>,
    peer_store: Arc<rustock_networking::peers::PeerStore>,
    event_rx: mpsc::UnboundedReceiver<SyncEvent>,
    /// Inbound wire messages waiting to be handled, published for
    /// `debug_wireProtocolQueueSize`.
    ///
    /// Refreshed every time the loop takes an event, so a reader sees the live
    /// backlog rather than a sample taken on some other schedule.
    wire_queue_depth: Arc<std::sync::atomic::AtomicUsize>,
    gas_price: Arc<crate::gas_price::GasPriceTracker>,
    pub(crate) state: SyncState,
    pub(crate) last_progress: Instant,
    /// Per-peer body-request timeout strikes: incremented when a request to a
    /// peer is reclaimed (timed out), reset to zero when the peer answers. A
    /// peer over BODY_PEER_STRIKE_LIMIT is skipped for new assignments so dead
    /// or slow peers stop receiving work.
    pub(crate) body_peer_strikes: HashMap<B512, u32>,
    progress: SyncProgress,
    /// An active snapshot sync, when one has been started.
    ///
    /// Absent by default, and absent is a complete answer: with no driver the
    /// snap events are dropped and this service behaves exactly as it did
    /// before snapshot sync existed.
    snap: Option<crate::snap::driver::SnapDriver>,
    /// What it would take to start another session, kept so a session that
    /// fails on one peer's bad data can be retried against a different one.
    snap_restart: Option<(
        crate::snap::SnapConfig,
        Arc<rustock_core::validation::HeaderVerifier>,
    )>,
    /// Sessions started so far, including the one running.
    snap_attempts: u32,
    /// Peers not worth asking, carried between sessions.
    snap_avoid: std::collections::HashSet<B512>,
    block_processor: Option<Arc<BlockProcessor>>,
    trie_store: Option<Arc<dyn TrieStore>>,
    pub(crate) current_state_root: Option<TrieNode>,
    /// One-batch-ahead execution pipeline: the batch currently executing on a
    /// blocking thread, if any. While set, downloads may run for the next
    /// batch but no further batch may begin executing — enforcing a strict
    /// "one executing, at most one downloading" depth.
    executing: Option<ExecutionJob>,
    /// A fully-downloaded batch parked because execution of the previous batch
    /// is still in flight. Holds `(pending_headers, peer_best)`. Execution
    /// starts (and N+2 download resumes) only once `executing` completes.
    pending_exec: Option<(Vec<(B256, Header)>, u64)>,
    /// Closure run on a blocking thread to execute a batch. Set when a block
    /// processor is attached; tests may override it to control timing/outcome.
    exec_fn: Option<ExecFn>,
    pub(crate) last_body_height: u64,
    /// The executed head that last halted, and how many times in a row.
    ///
    /// A halt normally clears: the node retries from the executed head and
    /// makes progress. A halt that repeats at the *same* height is a plan
    /// that cannot work, and retrying it costs thousands of body requests a
    /// round (#192).
    futile_exec_halts: (u64, u32),
    /// Executed height at the last check, with when it was last seen to move.
    ///
    /// Every other trigger in this service measures the *downloaded* head, which
    /// sits at the tip whether or not a single block is being executed. Nothing
    /// watched execution itself, so it could stop and no mechanism would notice.
    pub(crate) last_exec_height: u64,
    pub(crate) last_exec_progress: std::time::Instant,
    /// Generic liveness net: tracks Φ and escalates when it fails to improve.
    ///
    /// Every watchdog that existed before this one measured the *downloaded*
    /// head, which is the frontier that sits at the tip whether or not the node
    /// is making progress. This one is anchored to the executed head, which is
    /// the only frontier that cannot lie about progress.
    pub(crate) watchdog: ProgressWatchdog,
    /// Set by the watchdog's second escalation: distrust the cheap
    /// connection-point shortcut and binary-search for it instead.
    ///
    /// Without this, the second rung of the ladder would do exactly what the
    /// first one did -- which is the kind of escalation that looks like it
    /// works because it never runs alone.
    pub(crate) force_connection_search: bool,
    /// When a coherence violation was last logged, so a persistent one reports
    /// steadily rather than once per tick.
    pub(crate) last_violation_log: Option<std::time::Instant>,
    /// The violation currently outstanding, and when it was first seen.
    ///
    /// Several relations are transiently false in normal operation: a header
    /// is canonicalised as soon as it links, and the head only advances once
    /// the body is executed, so I6 is briefly true on essentially every new
    /// tip. Reporting those would put a warning in the log every few seconds
    /// and teach whoever reads it to skip the line -- which is the exact
    /// failure this subsystem already had, where a stall printed 450 times and
    /// was treated as nothing.
    pub(crate) violation_since: Option<(String, std::time::Instant)>,
    /// When the follow buffer was first seen blocked behind a missing block.
    ///
    /// A block arriving before its predecessor is normal -- a gap-pull fires
    /// several body requests and the responses land out of order -- so a gap is
    /// only treated as permanent once it has outlived any plausible in-flight
    /// response.
    pub(crate) follow_gap_since: Option<std::time::Instant>,
    /// Follow-mode body requests awaiting a response, with when each was sent.
    ///
    /// The timestamp is the point. Entries used to be removed only when a
    /// matching response arrived, so a request a peer never answered -- it
    /// disconnected, or the response was dropped -- stayed here forever. The
    /// block was never re-requested, every later block piled up behind the hole
    /// it left, and execution stopped for good. Worse, two separate recovery
    /// paths check this map for in-flight work and stand down when it is
    /// non-empty, so a single stuck entry disabled both of them.
    ///
    /// Carries the peer each request was sent to, so the answer can be
    /// matched against it.
    pub(crate) pending_follow_bodies: HashMap<u64, (B256, Header, Instant, B512)>,
    /// Blocks whose body was derived from the header rather than requested.
    /// Counted so the saving can be checked against an offline prediction.
    pub(crate) derived_bodies: u64,
    /// Headers a derivation attempt has already refused. Without this a
    /// header that cannot be derived would be re-tested on every pass over
    /// the queue, paying the predicate repeatedly to learn the same thing.
    pub(crate) underivable: std::collections::HashSet<B256>,
    /// Follow-mode blocks whose bodies have arrived, keyed by block number so
    /// they execute in strict order. Body responses for the several headers a
    /// gap-pull requests can land out of order; executing them as they arrive
    /// would run a block against the wrong parent state. Buffer here and drain
    /// only consecutive, parent-linked blocks from the executed head.
    pub(crate) follow_buffer: BTreeMap<u64, (B256, Header, Vec<Transaction>, Vec<Header>)>,
    tx_pool: Option<Arc<crate::TransactionPool>>,
    /// Told of every block this service executes as best.
    best_block_listeners: Arc<BestBlockListeners>,
    blocks_since_flush: u64,
    /// Blocks executed per durability point while catching up. See
    /// `execution_commit`.
    trie_flush_every: u64,
    /// Peers excluded from header-chunk assignment (stalled mid-round),
    /// mapped to the instant their sideline expires.
    pub(crate) sidelined: HashMap<B512, Instant>,
    /// Chain events for `eth_subscribe`, when the node was built with a
    /// WebSocket server.
    ///
    /// Published from the **follow** path only. During bulk sync a subscriber
    /// would receive thousands of heads it did not ask to be caught up on,
    /// and would simply trip the lag disconnect; subscriptions are a tip
    /// feature and the tip is where they are fed.
    pub(crate) events: Option<rustock_core::events::EventSender>,
    /// Who supplied the body of each block we have accepted but not yet
    /// executed, keyed by block number.
    ///
    /// Provenance has to outlive receipt to credit a peer for a block that
    /// *executes*, and by execution time the block has been through a store
    /// and a buffer with no peer attached. One map, drained in one place,
    /// rather than threading a peer id through the follow buffer -- that is
    /// the code responsible for three mainnet stalls on 2026-09-24, and this
    /// does not need to touch it. See #114.
    pub(crate) body_providers: HashMap<u64, B512>,
    /// Ordinary sync is standing down while a snapshot session runs.
    ///
    /// Set when a session opens and cleared only by `resume_ordinary_sync`,
    /// rather than inferred from `self.snap.is_some()`. The two differ at
    /// exactly the moment that matters: `finish_snap_sync` takes the driver
    /// out before deciding whether to start another, so an inferred flag would
    /// let the ordinary sync start a round in that gap and then be interrupted
    /// by the next session. Making the handover explicit means one place
    /// decides, and it decides after the outcome is known. See #185.
    suspended_for_snap: bool,
    /// Whether to catch up with the chain at all.
    ///
    /// `false` makes this node a server and nothing else: it answers requests
    /// from what it holds and never syncs, executes or follows. A server that
    /// drifts forward is not the same fixture twice, which is what a timed
    /// comparison against it needs it to be.
    pub(crate) follow_up: bool,
    /// Exit once the chain is synced, reporting how long it took.
    pub(crate) exit_when_synced: bool,
    /// When this node started syncing, for that report.
    started_at: Instant,
    /// When this node last re-stated its status. See [`STATUS_REFRESH`].
    last_status_sent: Instant,
    /// Highest block this node speaks for, under `--simulate-height`.
    ///
    /// The refreshed status has to agree with what the handshake said, or a
    /// peer would be told two different things about where the chain ends.
    serve_ceiling: Option<u64>,
    /// Whether the block pruner may run, readable from outside the service.
    ///
    /// **Starts false, and is only ever turned on once this service has
    /// determined what the node is doing.** A snapshot sync downloads the
    /// blocks below its checkpoint as its last phase, so a sweep during one
    /// would delete the very history the sync is fetching.
    ///
    /// Default-deny rather than default-allow, because the two are not
    /// symmetric. Asking "is a snapshot sync running?" at startup answers
    /// "no" during the window before one has begun -- the node is still
    /// finding peers, and no session exists yet to report itself. A sweep in
    /// that window deletes history that only a resync restores. Waiting a few
    /// seconds longer than necessary costs nothing.
    prune_allowed: Arc<std::sync::atomic::AtomicBool>,
    /// Peer scoring, when the node was built with it.
    ///
    /// The sidelining below **feeds** this rather than being replaced by it.
    /// The two answer different questions: sidelining says "do not assign this
    /// peer work in the current round", which has to be immediate and
    /// round-local; scoring says "this peer has a history", which outlives the
    /// round and the process. A peer sidelined once is not banned; a peer
    /// sidelined every round accumulates a record an operator can see.
    pub(crate) scoring: Option<Arc<rustock_networking::scoring::ScoringService>>,
    /// Start height of the last skeleton pre-fetch request, so the request
    /// is sent once per round instead of on every incoming event.
    last_prefetch_start: Option<u64>,
    /// Optional local block source (e.g. rskj's LevelDB) tried before peers.
    block_source: Option<Arc<dyn ExternalBlockSource>>,
}

impl SyncService {
    pub fn new(
        manager: Arc<SyncManager>,
        peer_store: Arc<rustock_networking::peers::PeerStore>,
        event_rx: mpsc::UnboundedReceiver<SyncEvent>,
    ) -> Self {
        Self {
            manager,
            chain_activity: Arc::new(crate::chain_activity::ChainActivity::new()),
            peer_store,
            event_rx,
            wire_queue_depth: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            gas_price: Arc::new(crate::gas_price::GasPriceTracker::default()),
            state: SyncState::Idle,
            last_progress: Instant::now(),
            body_peer_strikes: HashMap::new(),
            progress: SyncProgress::new(),
            block_processor: None,
            snap: None,
            snap_restart: None,
            snap_attempts: 0,
            snap_avoid: std::collections::HashSet::new(),
            trie_store: None,
            current_state_root: None,
            executing: None,
            pending_exec: None,
            exec_fn: None,
            last_body_height: 0,
            futile_exec_halts: (0, 0),
            last_exec_height: 0,
            last_exec_progress: Instant::now(),
            watchdog: ProgressWatchdog::default(),
            force_connection_search: false,
            last_violation_log: None,
            violation_since: None,
            follow_gap_since: None,
            pending_follow_bodies: HashMap::new(),
            derived_bodies: 0,
            underivable: std::collections::HashSet::new(),
            follow_buffer: BTreeMap::new(),
            tx_pool: None,
            best_block_listeners: BestBlockListeners::new(),
            blocks_since_flush: 0,
            trie_flush_every: crate::execution_commit::DEFAULT_FLUSH_EVERY,
            sidelined: HashMap::new(),
            events: None,
            body_providers: HashMap::new(),
            suspended_for_snap: false,
            follow_up: true,
            exit_when_synced: false,
            started_at: Instant::now(),
            last_status_sent: Instant::now(),
            serve_ceiling: None,
            prune_allowed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            scoring: None,
            last_prefetch_start: None,
            block_source: None,
        }
    }

    /// Attach a local block source (e.g. rskj's LevelDB) consulted for bodies
    /// before requesting them from peers.
    pub fn with_block_source(mut self, source: Arc<dyn ExternalBlockSource>) -> Self {
        self.block_source = Some(source);
        self
    }

    /// Fill a missing body from the local block source, if available. Returns
    /// true when the body was found and stored (so no peer request is needed).
    fn try_fill_body_locally(&self, hash: B256) -> bool {
        let Some(source) = &self.block_source else {
            return false;
        };
        match source.body_by_hash(hash) {
            Some((txs, ommers)) => self.manager.store.put_body(hash, &txs, &ommers).is_ok(),
            None => false,
        }
    }

    /// Attach the chain-event channel that feeds `eth_subscribe`.
    pub fn with_events(mut self, events: Option<rustock_core::events::EventSender>) -> Self {
        self.events = events;
        self
    }

    /// Attach peer scoring. Without it the service behaves exactly as before.
    pub fn with_scoring(
        mut self,
        scoring: Option<Arc<rustock_networking::scoring::ScoringService>>,
    ) -> Self {
        self.scoring = scoring;
        self
    }

    /// Attach a transaction pool for removing mined txs during block processing.
    /// Share the best-block listeners, so a component built after the
    /// service starts (the miner) can still register.
    pub fn with_best_block_listeners(mut self, listeners: Arc<BestBlockListeners>) -> Self {
        self.best_block_listeners = listeners;
        self
    }

    pub fn with_tx_pool(mut self, pool: Arc<crate::TransactionPool>) -> Self {
        self.tx_pool = Some(pool);
        self
    }

    /// A live view of the inbound wire-message backlog, for
    /// `debug_wireProtocolQueueSize`.
    ///
    /// rskj answers that method with `messageHandler.getMessageQueueSize()` --
    /// messages received from peers and not yet handled. This is the same
    /// quantity for this node: the `SyncEvent` channel is where inbound wire
    /// work waits, and its depth is what "the peer loop is falling behind"
    /// looks like here.
    pub fn wire_queue_depth(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        self.wire_queue_depth.clone()
    }

    /// Attach a block processor for full block validation and execution.
    pub fn with_block_processor(
        mut self,
        processor: BlockProcessor,
        trie_store: Arc<dyn TrieStore>,
        initial_state_root: TrieNode,
    ) -> Self {
        let processor = Arc::new(processor);
        self.block_processor = Some(processor.clone());
        self.trie_store = Some(trie_store.clone());
        self.current_state_root = Some(initial_state_root);

        // Wire the execution step to the real block processor. Cloned handles
        // (Arc<BlockProcessor>, Arc<dyn TrieStore>, Arc<BlockStore>, Arc<pool>)
        // are all Send + Sync, so the closure runs safely on a blocking thread.
        let store = self.manager.store.clone();
        let tx_pool = self.tx_pool.clone();
        let activity = self.chain_activity.clone();
        let gas_price = self.gas_price.clone();
        let flush_every = self.trie_flush_every;
        self.exec_fn = Some(Arc::new(move |state_root, blocks_since_flush, pending| {
            process_downloaded_blocks(
                &processor,
                trie_store.clone(),
                state_root,
                &store,
                tx_pool.as_deref(),
                blocks_since_flush,
                flush_every,
                &pending,
                &activity,
                &gas_price,
            )
        }));
        self
    }

    /// The per-block counters, for the periodic activity report. Taken before
    /// the service is moved into its task.
    pub fn chain_activity(&self) -> Arc<crate::chain_activity::ChainActivity> {
        self.chain_activity.clone()
    }

    /// Stop, having caught up, and say how long it took.
    ///
    /// "Caught up" means **executed**, not downloaded. A node holding every
    /// header to the tip but still running the blocks has not finished the
    /// work being measured, and exiting there would report a time for
    /// something nobody asked about.
    ///
    /// Exits the process rather than returning, because the point is an
    /// unambiguous end time. A log line invites an argument about which line
    /// counts; a process exit does not.
    async fn exit_if_synced(&mut self) {
        let Some((_, meta)) = self.peer_store.best_peer().await else { return };
        if meta.best_number == 0 {
            return; // nobody has told us where the chain ends yet
        }

        let store = &self.manager.store;
        let executed = store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0);

        if executed < meta.best_number {
            return;
        }

        let elapsed = self.started_at.elapsed();
        info!(
            target: "rustock::sync",
            "Synced to #{} in {:.1}s ({:.1} blocks/s); exiting as instructed",
            executed,
            elapsed.as_secs_f64(),
            executed as f64 / elapsed.as_secs_f64().max(f64::EPSILON),
        );
        // Flush whatever the logger is holding before the process goes.
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::process::exit(0);
    }

    /// Re-state this node's status to every peer.
    ///
    /// Sent on a timer whether or not anything changed, and whether or not
    /// this node is following. The figure is not the point: an rskj peer
    /// treats the arrival of a `STATUS` as the only evidence that a node is
    /// still worth syncing from, so a node whose status never changes still
    /// has to keep saying it. A `--follow-up false` server is exactly that
    /// case, and is the one most likely to be sat on by a peer for hours.
    async fn refresh_status_to_peers(&self) {
        let peers = self.peer_store.peers().await;
        if peers.is_empty() {
            return;
        }
        let Some(status) = self.current_status() else { return };
        let msg = rustock_networking::protocol::P2pMessage::RskMessage(
            rustock_networking::protocol::RskMessage::new(
                rustock_networking::protocol::RskSubMessage::Status(status),
            ),
        );
        for peer in peers {
            self.peer_store.send_to_peer(&peer, msg.clone()).await;
        }
    }

    /// This node's status as it stands now.
    ///
    /// Built from the store each time rather than captured at startup,
    /// because on a following node the head moves and a stale figure is worse
    /// than none: it would have a peer believe this node had stopped.
    fn current_status(&self) -> Option<rustock_networking::protocol::RskStatus> {
        let store = &self.manager.store;
        // The simulated head when there is one, so a refresh cannot contradict
        // what the handshake said.
        let hash = match self.serve_ceiling {
            Some(c) => store.canonical_hash(c).ok().flatten()?,
            None => store.head().ok().flatten()?,
        };
        let header = store.header(hash).ok().flatten()?;
        Some(rustock_networking::protocol::RskStatus {
            best_block_number: header.number,
            best_block_hash: hash,
            best_block_parent_hash: Some(header.parent_hash),
            total_difficulty: store.total_difficulty(hash).ok().flatten(),
            earliest_block: Some(
                store.prune_floor().ok().flatten().map(|f| f.number).unwrap_or(0),
            ),
        })
    }

    #[cfg(test)]
    pub(crate) fn current_status_for_test(
        &self,
    ) -> Option<rustock_networking::protocol::RskStatus> {
        self.current_status()
    }

    /// Highest block to speak for, under `--simulate-height`.
    pub fn with_serve_ceiling(mut self, ceiling: Option<u64>) -> Self {
        self.serve_ceiling = ceiling;
        self
    }

    /// Whether to catch up at all. `false` serves only.
    /// Blocks executed per durability point while catching up.
    ///
    /// Trie nodes are derivable, so the store may flush less often than
    /// the node executes; what it may not do is advance the executed head
    /// past what a crash would keep. The cost of raising this is that many
    /// blocks of re-execution after an unclean stop. Follow mode is
    /// unaffected: it makes every block durable.
    pub fn with_trie_flush_every(mut self, every: u64) -> Self {
        self.trie_flush_every = every.max(1);
        self
    }

    pub fn with_follow_up(mut self, follow_up: bool) -> Self {
        self.follow_up = follow_up;
        self
    }

    /// Exit once synced, reporting the elapsed time.
    pub fn with_exit_when_synced(mut self, exit: bool) -> Self {
        self.exit_when_synced = exit;
        self
    }

    /// Whether the block pruner may run. See [`Self::prune_allowed`].
    pub fn prune_gate(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.prune_allowed.clone()
    }

    /// Share a gas-price tracker with the transaction pool, which needs the
    /// same one: the limiter's low-gas-price factor and `eth_gasPrice` must
    /// not disagree about the market.
    pub fn with_gas_price_tracker(
        mut self,
        tracker: Arc<crate::gas_price::GasPriceTracker>,
    ) -> Self {
        self.gas_price = tracker;
        self
    }

    /// The gas-price tracker, fed by every block this node executes.
    ///
    /// rskj feeds its tracker from an `EthereumListener` on the same events;
    /// here the execution paths call it directly, which keeps "a block was
    /// executed" and "the tracker saw it" in one place rather than two.
    pub fn gas_price_tracker(&self) -> Arc<crate::gas_price::GasPriceTracker> {
        self.gas_price.clone()
    }

    /// Test seam: install a controllable execution step and a starting state
    /// root, standing in for a real block processor. Lets scheduling tests
    /// drive batch execution timing/outcome without a full EVM/trie setup.
    #[cfg(test)]
    pub(crate) fn set_test_exec(&mut self, exec_fn: ExecFn) {
        self.exec_fn = Some(exec_fn);
        if self.current_state_root.is_none() {
            self.current_state_root = Some(TrieNode::empty());
        }
    }

    #[cfg(test)]
    pub(crate) fn is_executing_for_test(&self) -> bool {
        self.executing.is_some()
    }

    /// Wait until the in-flight execution job can actually be reaped.
    ///
    /// The test controller signals completion from *inside* the execution
    /// closure, so it fires before the closure returns and before the
    /// JoinHandle is marked finished. `poll_execution` skips a job whose
    /// handle is not finished yet, so a test that ticks immediately after the
    /// controller's signal reaps nothing and sees none of the reap's effects.
    ///
    /// Production never notices: it ticks on a timer and reaps on whichever
    /// tick comes after the handle settles. A test that asserts on the reap
    /// has to wait for it instead of assuming one tick is enough.
    #[cfg(test)]
    pub(crate) async fn await_reapable_execution_for_test(&self) {
        let Some(job) = &self.executing else { return };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !job.handle.is_finished() {
            assert!(
                Instant::now() < deadline,
                "execution job never finished: it is blocked, not merely unreaped"
            );
            tokio::task::yield_now().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn has_parked_batch_for_test(&self) -> bool {
        self.pending_exec.is_some()
    }

    /// Park an empty batch so tests can exercise the paths that must stand
    /// down while a background execution owns the trie state.
    #[cfg(test)]
    pub(crate) fn park_empty_batch_for_test(&mut self) {
        self.pending_exec = Some((Vec::new(), 0));
    }

    #[cfg(test)]
    pub(crate) fn last_body_height_for_test(&self) -> u64 {
        self.last_body_height
    }

    #[cfg(test)]
    pub(crate) fn peer_store_for_test(&self) -> Arc<rustock_networking::peers::PeerStore> {
        self.peer_store.clone()
    }

    pub async fn start(mut self) {
        info!(
            target: "rustock::sync",
            "Sync service started (pipelined multi-peer skeleton sync)"
        );

        // The node's state is now determined: either a snapshot session is
        // open, or none is coming. Only in the second case may the pruner run,
        // and this is the earliest point at which that is knowable -- which is
        // why the gate starts closed rather than being inferred later from the
        // absence of a session.
        if self.snap.is_none() && self.snap_restart.is_none() {
            self.prune_allowed.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        let mut timer = tokio::time::interval(TICK_INTERVAL);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    self.on_tick().await;
                }
                event = self.event_rx.recv() => {
                    self.wire_queue_depth
                        .store(self.event_rx.len(), std::sync::atomic::Ordering::Relaxed);
                    match event {
                        Some(e) => {
                            let is_progress = matches!(
                                &e,
                                SyncEvent::HeadersResponse { .. }
                                | SyncEvent::HeadersWithUnclesResponse { .. }
                                | SyncEvent::BodyResponse { .. }
                                | SyncEvent::SkeletonResponse { .. }
                                | SyncEvent::BlockHashResponse { .. }
                            );
                            if is_progress {
                                self.last_progress = Instant::now();
                            }
                            self.handle_event(e).await;
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// Attach a trie store without a block processor, for tests that exercise
    /// snapshot sync in isolation.
    #[cfg(test)]
    pub fn with_trie_store_for_test(mut self, trie_store: Arc<dyn TrieStore>) -> Self {
        self.trie_store = Some(trie_store);
        self
    }

    /// Start a snapshot sync instead of replaying the chain from genesis.
    ///
    /// Takes effect on the next tick. Does nothing if a session is already
    /// running, so calling it twice is harmless.
    pub fn start_snap_sync(
        &mut self,
        config: crate::snap::SnapConfig,
        verifier: Arc<rustock_core::validation::HeaderVerifier>,
    ) {
        if self.snap.is_some() {
            return;
        }
        let Some(trie_store) = self.trie_store.clone() else {
            warn!(target: "rustock::snap", "snapshot sync needs a trie store; not starting");
            return;
        };

        // Only for a node that has never executed anything. A node that is
        // merely behind should catch up the ordinary way: executing the
        // blocks it is missing is cheaper than downloading a state, and
        // downloading one would throw away the state it already has.
        let executed = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.manager.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0);
        if executed > 0 {
            info!(
                target: "rustock::snap",
                "not starting snapshot sync: this node has already executed to #{executed}, \
                 so ordinary sync is the shorter path"
            );
            return;
        }
        info!(
            target: "rustock::snap",
            "starting snapshot sync (chunk {} bytes, {} in flight)",
            config.chunk_bytes, config.max_in_flight
        );
        self.snap_restart = Some((config.clone(), verifier.clone()));
        self.snap_attempts = 0;
        self.open_snap_session(config, verifier, trie_store);
    }

    fn open_snap_session(
        &mut self,
        config: crate::snap::SnapConfig,
        verifier: Arc<rustock_core::validation::HeaderVerifier>,
        trie_store: Arc<dyn TrieStore>,
    ) {
        self.snap_attempts += 1;
        self.suspend_ordinary_sync();
        let session = crate::snap::session::SnapSession::new(
            config,
            self.manager.store.clone(),
            trie_store,
            verifier,
        );
        self.snap = Some(
            crate::snap::driver::SnapDriver::new(session).avoiding(self.snap_avoid.clone()),
        );
    }

    /// Whether a snapshot sync is running.
    pub fn snap_phase(&self) -> Option<crate::snap::session::Phase> {
        self.snap.as_ref().map(|d| d.phase())
    }

    /// The id of any outstanding snap request, for tests that need to answer
    /// one without a network.
    #[cfg(test)]
    pub(crate) fn snap_request_id_for_test(&self) -> Option<u64> {
        self.snap.as_ref()?.outstanding_ids().first().copied()
    }

    /// Whether ordinary sync is standing down for a snapshot session.
    #[cfg(test)]
    #[cfg(test)]
    pub(crate) fn suspend_ordinary_sync_for_test(&mut self) {
        self.suspend_ordinary_sync();
    }

    #[cfg(test)]
    pub(crate) fn resume_ordinary_sync_for_test(&mut self) {
        self.resume_ordinary_sync();
    }

    #[allow(dead_code)] // no caller; see the dead-code issue before deleting
    pub(crate) fn is_suspended_for_snap_for_test(&self) -> bool {
        self.suspended_for_snap
    }

    /// Drop the session as though it had failed, for testing the handover.
    #[cfg(test)]
    pub(crate) fn fail_snap_for_test(&mut self) {
        self.snap = None;
        self.snap_restart = None;
    }

    /// Sessions started so far.
    #[cfg(test)]
    pub(crate) fn snap_attempts_for_test(&self) -> u32 {
        self.snap_attempts
    }

    /// Runs one step of the snap driver and sends whatever it asks for.
    ///
    /// The driver decides what to ask; this supplies the peers and the wire.
    async fn drive_snap<F>(&mut self, step: F)
    where
        F: FnOnce(
            &mut crate::snap::driver::SnapDriver,
            &[B512],
        ) -> Vec<crate::snap::driver::Outbound>,
    {
        // Only peers that announced `snap`. Sending one of the six snapshot
        // messages to a peer that did not is not a wasted request -- rskj
        // throws out of `MessageType.valueOfType` on an unknown id and closes
        // the connection, so an unfiltered round robin sheds every
        // non-snap-capable peer, which on mainnet is most of them.
        let peers: Vec<B512> = self.peer_store.peers_serving_snapshots().await;
        if peers.is_empty() {
            // Say so rather than falling back to every peer: a snapshot sync
            // with nobody to ask should stall visibly and let the ordinary
            // sync take over, not quietly disconnect the peer set.
            debug!(
                target: "rustock::snap",
                "no peer has announced the snap capability; nothing to drive"
            );
            return;
        }
        let Some(driver) = self.snap.as_mut() else { return };

        let outbound = step(driver, &peers);

        // Charge whatever the step turned up before anything else: a peer that
        // misbehaved should pay for it even if the session went on to finish
        // or fail for some other reason.
        let blame = driver.take_blame();
        for fault in &blame {
            if let Some(scoring) = &self.scoring {
                scoring.record_peer(fault.peer, fault.event);
            }
            warn!(
                target: "rustock::snap",
                "peer {:?} charged {:?}: {}",
                &fault.peer.0[..4], fault.event, fault.why
            );
        }

        for out in outbound {
            // The walk is where a snapshot's checkpoint is converted into
            // verified work, and in RSK that work includes the uncles. The
            // driver builds its requests synchronously and cannot look up a
            // capability, so the upgrade happens here, where the peer is
            // known: an `rsk/63` peer is asked for the uncles alongside, and
            // everyone else still gets the plain request.
            let message = match out.message {
                P2pMessage::RskMessage(RskMessage {
                    sub_message: RskSubMessage::BlockHeadersRequest(ref r),
                    ..
                }) if self
                    .peer_store
                    .capabilities(&out.peer)
                    .await
                    .is_some_and(|c| c.understands_header_uncles()) =>
                {
                    P2pMessage::RskMessage(RskMessage::new(
                        RskSubMessage::BlockHeadersWithUnclesRequest(
                            rustock_networking::protocol::BlockHeadersWithUnclesRequest {
                                id: r.id,
                                query: r.query.clone(),
                            },
                        ),
                    ))
                }
                other => other,
            };
            self.peer_store.send_to_peer(&out.peer, message).await;
        }

        if let Some(driver) = self.snap.as_ref() {
            if driver.is_finished() {
                self.finish_snap_sync().await;
            }
        }
    }

    /// Stand the ordinary sync down for the duration of a snapshot session.
    ///
    /// **Header sync first, then state — never the reverse.** A snapshot is
    /// only trustworthy because the header walk vouches for the checkpoint it
    /// hangs from, so the walk has to own the peer set until it is done.
    ///
    /// Without this the two compete. On a network with many peers that is
    /// merely wasteful; on one peer it is fatal, and it was measured being
    /// fatal: the ordinary sync's header requests were served, the snapshot
    /// session's queued behind them and timed out 12,094 times, their late
    /// answers arrived at a driver that no longer awaited those ids and were
    /// dropped, and not one state chunk was ever requested. Meanwhile the
    /// ordinary sync ran 2.8M blocks ahead of a state that did not exist,
    /// leaving a node that reported it could not resume. See #185.
    fn suspend_ordinary_sync(&mut self) {
        self.suspended_for_snap = true;
        self.prune_allowed.store(false, std::sync::atomic::Ordering::Relaxed);
        // Abandon whatever round was in flight rather than leaving it parked:
        // its requests are outstanding against the same peers the snapshot
        // session is about to need, and its answers would be matched against a
        // state machine that is no longer driving.
        if !matches!(self.state, SyncState::Idle) {
            debug!(
                target: "rustock::snap",
                "standing ordinary sync down (was {:?}) for the duration of the snapshot session",
                std::mem::discriminant(&self.state)
            );
            self.state = SyncState::Idle;
        }
        self.follow_buffer.clear();
        self.pending_follow_bodies.clear();
    }

    /// Give the peer set back to the ordinary sync.
    ///
    /// Called from exactly one place -- the end of `finish_snap_sync`, after
    /// the outcome is known and after any replacement session has been opened.
    /// A replacement re-suspends, so the flag ends up true again and the gap
    /// never opens.
    fn resume_ordinary_sync(&mut self) {
        // Outside the `if`: this is also the path taken when a snapshot sync
        // gives up without ever having suspended anything, and pruning must
        // still be released then or a node that tried and failed to snapshot
        // sync would never prune at all.
        self.prune_allowed.store(true, std::sync::atomic::Ordering::Relaxed);
        if self.suspended_for_snap {
            self.suspended_for_snap = false;
            debug!(target: "rustock::snap", "ordinary sync resumed");
        }
    }

    /// Hand a completed snapshot over to ordinary sync, or report the failure.
    async fn finish_snap_sync(&mut self) {
        let Some(driver) = self.snap.take() else { return };
        match driver.phase() {
            crate::snap::session::Phase::Done => {
                if let Some(checkpoint) = driver.checkpoint() {
                    let hash = checkpoint.hash();
                    info!(
                        target: "rustock::snap",
                        "snapshot sync finished at #{} ({hash:?}); handing over to forward sync",
                        checkpoint.number
                    );
                    // The state is on disk and proved against this header, so
                    // execution can begin from here rather than from genesis.
                    if let Err(e) = self.manager.store.set_exec_head(hash, checkpoint.state_root) {
                        error!(target: "rustock::snap", "could not record the snapshot head: {e}");
                    }

                    // The headers are all on disk; only the index below the
                    // checkpoint window is missing. Filling it is an hour of
                    // background disk that the node does not have to wait for,
                    // so it runs behind the sync rather than in front of it.
                    if self.snap_restart.as_ref().is_some_and(|(c, _)| c.index_history) {
                        let store = self.manager.store.clone();
                        tokio::spawn(crate::snap::indexer::fill_canonical_index(store, hash));
                    }
                }
                self.snap_restart = None;
                // The state is on disk and the executed head points at it, so
                // ordinary sync can take over from the checkpoint rather than
                // from genesis.
                self.resume_ordinary_sync();
            }
            _ => {
                // One peer's bad data must not end snapshot sync. The peer has
                // already been charged for it; what is left is to ask someone
                // else, which is the whole reason peers are plural.
                let why = driver
                    .session()
                    .failure()
                    .map_or("unknown".to_string(), |f| f.to_string());
                self.snap_avoid.extend(driver.unhelpful().iter().copied());

                let Some((config, verifier)) = self.snap_restart.clone() else {
                    warn!(target: "rustock::snap", "snapshot sync gave up: {why}");
                    self.resume_ordinary_sync();
                    return;
                };
                if self.snap_attempts >= MAX_SNAP_ATTEMPTS {
                    warn!(
                        target: "rustock::snap",
                        "snapshot sync gave up after {} attempts: {why}", self.snap_attempts
                    );
                    self.snap_restart = None;
                    self.resume_ordinary_sync();
                    return;
                }
                let Some(trie_store) = self.trie_store.clone() else {
                    self.resume_ordinary_sync();
                    return;
                };
                warn!(
                    target: "rustock::snap",
                    "snapshot sync attempt {} failed ({why}); starting another",
                    self.snap_attempts
                );
                self.open_snap_session(config, verifier, trie_store);
            }
        }
    }

    pub(crate) async fn on_tick(&mut self) {
        // Gauges are sampled here rather than written wherever they change.
        // A gauge is a level, not an event: a scrape wants its value now, and
        // the tick is the one place that reliably has all three without
        // adding a write to a hot path.
        {
            use rustock_core::metrics;
            metrics::PEERS.set(self.peer_store.peers().await.len() as u64);
            if let Ok(Some(hash)) = self.manager.store.head() {
                if let Ok(Some(header)) = self.manager.store.header(hash) {
                    metrics::SYNC_HEIGHT.set(header.number);
                }
            }
            if let Some((_, meta)) = self.peer_store.best_peer().await {
                metrics::SYNC_TARGET.set(meta.best_number);
            }
        }

        // Reap a finished background execution before driving the state machine
        // so a parked next batch can start executing and downloads can resume.
        self.poll_execution().await;

        if self.exit_when_synced {
            self.exit_if_synced().await;
        }

        if self.last_status_sent.elapsed() >= STATUS_REFRESH {
            self.last_status_sent = Instant::now();
            self.refresh_status_to_peers().await;
        }

        if self.snap.is_some() {
            let now = Instant::now();
            if let Some(driver) = self.snap.as_mut() {
                driver.expire(now);
            }
            self.drive_snap(|driver, peers| driver.poll(peers)).await;
        }

        // Suspended with no session to wait for is a bug, and the shape of the
        // bug is a node that never syncs again -- the worst failure available
        // here, and a silent one. `finish_snap_sync` resumes on every path it
        // owns; this catches a path it does not, complains, and recovers.
        if self.suspended_for_snap && self.snap.is_none() {
            warn!(
                target: "rustock::snap",
                "ordinary sync was suspended with no snapshot session running; resuming"
            );
            self.resume_ordinary_sync();
        }

        // Header sync first, then state. While a snapshot session holds the
        // peer set, the ordinary state machine does not run at all -- not its
        // rounds, not its watchdogs, not its coherence repair. Every one of
        // those reaches for the same peers or the same executed head, and the
        // session is mid-way through establishing what that head should be.
        if self.suspended_for_snap {
            return;
        }

        self.expire_stale_follow_bodies();
        self.check_execution_progress();
        self.resync_state_root_with_exec_head();
        self.verify_coherence();
        self.check_phi_progress().await;

        match &self.state {
            SyncState::Idle => {
                // Don't kick off a fresh sync round while a batch is executing
                // (or a downloaded batch is parked waiting to execute): that
                // would let a second batch begin downloading ahead of the cap.
                if self.executing.is_none() && self.pending_exec.is_none() {
                    self.try_start_sync().await;
                }
            }
            SyncState::Following => {
                // A tip reorg can orphan the block we last executed, and follow
                // mode has no path that notices: `drain_follow_buffer` sees the
                // next tip fail to link and returns, while the reconcile that
                // rolls the executed head back is reachable only from
                // `try_start_sync`, which runs in `Idle`. The node therefore
                // stands still until the backlog check or the execution
                // watchdog forces it out -- ninety seconds at best. Observed on
                // mainnet: twenty orphaned executions in three hours, each
                // costing that wait, holding the node fifteen to twenty-five
                // blocks behind the tip.
                //
                // Reconcile here, and leave follow mode when it rolls back:
                // follow mode only executes blocks as they are announced and
                // cannot re-fetch the canonical ones we now need -- only the
                // body pipeline can.
                let before = self.manager.store.exec_head().ok().flatten().map(|(h, _)| h);
                self.reconcile_exec_head_with_canonical().await;
                let after = self.manager.store.exec_head().ok().flatten().map(|(h, _)| h);
                if before != after {
                    self.state = SyncState::Idle;
                } else {
                    self.fill_follow_body_gap().await;
                    // Canonical blocks whose bodies we already hold but never
                    // executed. See `refill_follow_buffer_from_store`.
                    self.refill_follow_buffer_from_store();
                    self.drain_follow_buffer().await;
                    self.check_follow_gap().await;
                    self.leave_follow_if_backlog().await;
                }
            }
            SyncState::DownloadingBodies { .. } => {
                // Nothing in flight means nothing will call back, because a
                // body response is the only thing that advances this state.
                // Either the request loop stopped early -- no peer would take
                // one -- so top it up, or it consumed the batch locally, so
                // finish it. See `finish_body_batch_if_complete`.
                if self.body_requests_idle() {
                    self.send_body_requests().await;
                    self.finish_body_batch_if_complete().await;
                }
                // Per-request timeout: re-send only the individually-stalled
                // requests (older than REQUEST_TIMEOUT), each to a rotated
                // peer — never re-blast the whole in-flight window.
                self.retry_stale_body_requests().await;
                self.log_progress().await;
            }
            _ => {
                if self.last_progress.elapsed() > REQUEST_TIMEOUT {
                    warn!(
                        target: "rustock::sync",
                        "Sync request timed out in state {:?}, resetting",
                        std::mem::discriminant(&self.state)
                    );
                    self.state = SyncState::Idle;
                } else {
                    self.check_disconnected_peers().await;
                    self.log_progress().await;
                }
            }
        }
    }

    /// Detect peers that disconnected or stalled while holding in-flight
    /// chunks and reassign those chunks so the round can make progress.
    /// Stalled peers are additionally sidelined from future assignment.
    async fn check_disconnected_peers(&mut self) {
        if let SyncState::DownloadingHeaders { tracker, .. } = &mut self.state {
            let tracked_peers: Vec<B512> = tracker.in_flight.keys().cloned().collect();
            let mut any_removed = false;
            for peer in tracked_peers {
                if !self.peer_store.is_connected(&peer).await {
                    let count = tracker.in_flight.get(&peer).map_or(0, |q| q.len());
                    if count > 0 {
                        debug!(
                            target: "rustock::sync",
                            "Peer {:?} disconnected with {} in-flight chunks, reassigning",
                            &peer.0[..4], count
                        );
                        tracker.handle_peer_disconnect(&peer);
                        any_removed = true;
                    }
                }
            }
            for peer in tracker.stalled_peers(PEER_STALL_TIMEOUT) {
                warn!(
                    target: "rustock::sync",
                    "Peer {:?} stalled with in-flight header chunks, sidelining and reassigning",
                    &peer.0[..4]
                );
                tracker.handle_peer_disconnect(&peer);
                self.sidelined.insert(peer, Instant::now() + PEER_SIDELINE_DURATION);
                if let Some(scoring) = &self.scoring {
                    scoring.record_peer(
                        peer,
                        rustock_networking::scoring::EventType::TimeoutMessage,
                    );
                }
                any_removed = true;
            }
            if any_removed {
                self.last_progress = Instant::now();
            }
        }
        if let SyncState::DownloadingHeaders { .. } = &self.state {
            self.fill_pipeline().await;
        }
    }

    /// If we're behind the best peer, initiate sync.
    /// Small gaps (<= LONG_SYNC_LIMIT) enter Following mode;
    /// large gaps use skeleton sync.
    /// If the executed head was orphaned by a tip reorg, roll it back one block
    /// so the next round re-downloads and re-executes the canonical chain from
    /// there instead of wedging on a lineage mismatch.
    ///
    /// Detection can't use `canonical_hash(exec_head.number)`: skeleton sync
    /// starts *forward* from the executed head and never re-fetches the block
    /// at its own height, so that pointer keeps naming the orphan. The reliable
    /// signal is the canonical child at N+1 — if it exists and its parent isn't
    /// our executed head, our head is on an abandoned fork. Rolling back one
    /// block (then re-syncing, which re-fetches block N and lets the heavier
    /// canonical header win the fork choice) converges to the common ancestor;
    /// a deeper reorg simply trips this again on the next round.
    pub(crate) async fn reconcile_exec_head_with_canonical(&mut self) {
        if self.block_processor.is_none() {
            return;
        }
        let store = &self.manager.store;
        let exec_hash = match store.exec_head().ok().flatten() {
            Some((h, _)) => h,
            None => return,
        };
        let header = match store.header(exec_hash).ok().flatten() {
            Some(h) => h,
            None => return,
        };
        // Is there a canonical child, and does it build on our executed head?
        let child_hash = match store.canonical_hash(header.number + 1).ok().flatten() {
            Some(h) => h,
            None => {
                // No pointer at the next height. That means one of two very
                // different things, and treating them alike wedges the node:
                // either we are at the tip and there is genuinely nothing to
                // reconcile, or the canonical index has a hole and the block
                // we need is unreachable by number.
                //
                // The best downloaded head tells them apart. If it sits above
                // the missing height, this is a hole -- repair the lineage
                // downward from the head, which fills it and corrects anything
                // else the damaged walk left behind.
                let head_number = store
                    .head()
                    .ok()
                    .flatten()
                    .and_then(|h| store.header(h).ok().flatten())
                    .map(|h| h.number);
                match head_number {
                    Some(head_number) if head_number > header.number + 1 => {
                        warn!(
                            target: "rustock::sync",
                            "Canonical index has no entry for #{} while the head is #{}; \
                             repairing lineage",
                            header.number + 1, head_number
                        );
                        self.repair_canonical_gap(head_number, header.number);
                        return;
                    }
                    _ => {}
                }

                // Neither signal above can describe a fork this node never
                // adopted. Both read the canonical index, and a branch we did
                // not follow never got a pointer -- so `canonical_hash(N+1)`
                // is None *and* the head never rose above N+1, because the head
                // tracks the canonical chain too. That is not an edge case: it
                // wedged mainnet for three days at #9,251,058, with the network
                // 7,000 blocks ahead on a sibling branch whose headers this
                // node had already downloaded.
                //
                // The height index does describe it -- that is what it is for.
                // If blocks are stored at N+1 and *none* of them builds on our
                // executed head, then nothing extends us and we are on a branch
                // the network left behind. Adopting the stored lineage gives
                // N+1 a canonical pointer; when it cannot be adopted the
                // retreat goes straight to the fork point rather than one
                // block per round (see `orphan_retreat_target` -- one block per
                // round does not converge, because after the first step a
                // stored child of the losing head satisfies `extends_us` and
                // the condition stops being detected at all).
                let stored_next = store.hashes_at_height(header.number + 1).unwrap_or_default();
                if stored_next.is_empty() {
                    return; // genuinely at the tip: nothing to reconcile
                }
                let extends_us = stored_next.iter().any(|h| {
                    store
                        .header(*h)
                        .ok()
                        .flatten()
                        .is_some_and(|c| c.parent_hash == exec_hash)
                });
                if extends_us {
                    return; // a successor builds on us; the index just lacks a pointer
                }
                // Prefer a successor that is itself extended: with several
                // siblings the one carrying descendants is the branch that kept
                // going. Ties break on the hash so two nodes reach the same
                // answer. Picking wrong is survivable -- the next round
                // re-evaluates -- but picking arbitrarily is not reproducible.
                let mut candidates = stored_next.clone();
                candidates.sort();
                let successor = candidates
                    .iter()
                    .find(|h| {
                        store
                            .header(**h)
                            .ok()
                            .flatten()
                            .and_then(|c| store.hashes_at_height(c.number + 1).ok())
                            .is_some_and(|next| !next.is_empty())
                    })
                    .copied()
                    .unwrap_or(candidates[0]);
                warn!(
                    target: "rustock::sync",
                    "Executed head #{} ({:?}) has no descendant among the {} block(s) stored \
                     at #{}; treating it as orphaned and adopting {:?}",
                    header.number, exec_hash, stored_next.len(), header.number + 1, successor
                );
                // One transition: the lineage and the head move together, or
                // neither does. Writing canonical entries and leaving KEY_HEAD
                // behind is what wedged mainnet for three hours on
                // 2026-09-22, and `Transition` has no way to express it.
                match Validated::prove(store, successor) {
                    Ok(head) => {
                        if let Err(e) = store.apply(&Transition::Adopt { head }) {
                            warn!(
                                target: "rustock::sync",
                                "Orphan recovery: adopting {:?} failed: {:?}", successor, e
                            );
                        }
                    }
                    Err(broken) => {
                        // The only successor we know of hangs off a block we
                        // never downloaded, so there is nothing to adopt.
                        //
                        // Retreat *here*, rather than doing nothing. The code
                        // this replaced wrote the unprovable pointer anyway and
                        // relied on a later round to notice it was broken and
                        // recover -- a deliberate detour through an incoherent
                        // store. Refusing to write it is right; refusing and
                        // then standing still is a wedge, so the retreat that
                        // the later round used to perform happens now.
                        warn!(
                            target: "rustock::sync",
                            "Orphan recovery: cannot adopt {:?} ({}); retreating below the fork \
                             so the range is downloaded again",
                            successor, broken
                        );
                        self.retreat_below_orphaned_head(&header, successor);
                    }
                }
                return;
            }
        };
        let child = match store.header(child_hash).ok().flatten() {
            Some(h) => h,
            None => return,
        };
        if child.parent_hash == exec_hash {
            return; // executed head is on the canonical chain
        }
        // The canonical child names a different block at our head's height
        // (`child.parent_hash`) as its parent. A reorg whose canonical walk was
        // truncated by a late-arriving header can leave that pointer stale
        // (still naming our orphan); repair the lineage so the next round
        // downloads and executes the true canonical block at this height.
        //
        // That repair only works if we HOLD the true canonical block.
        // This used to call a repair that walked down and stopped at the first
        // header the store did not have -- so when the replacement block was
        // never downloaded it wrote nothing, returned success, and left the
        // canonical pointer naming the orphan. `Validated::prove` makes that a
        // located error instead.
        //
        // When the block is absent there is nothing to repair the lineage TO,
        // so retreat instead: drop the canonical entry at this height and move
        // the head pointer down to the orphan's parent, which both branches
        // agree on. The connection-point search then re-runs from a block that
        // really is on the chain, and this height is downloaded again.
        // Either the true canonical block at this height can be proved -- held,
        // and linked all the way down -- in which case adopt it; or it cannot,
        // in which case retreat so the height is downloaded again.
        //
        // The proof is what decides. The old code asked only whether the header
        // existed, then called a repair that silently wrote nothing when the
        // lineage was broken further down, returned `Ok`, and left the pointer
        // naming an orphan. Mainnet #9,258,222 sat in that loop for 15 minutes.
        match Validated::prove(store, child.parent_hash) {
            Ok(head) => {
                if let Err(e) = store.apply(&Transition::Adopt { head }) {
                    warn!(target: "rustock::sync", "Reorg: adopting the canonical block failed: {:?}", e);
                }
            }
            Err(broken) => {
                warn!(
                    target: "rustock::sync",
                    "Reorg: canonical block {:?} at #{} cannot be proved ({}); retreating below \
                     the fork so the range is downloaded again",
                    child.parent_hash, header.number, broken
                );
                // The fork point, not our parent -- same rule, and same
                // reason, as the other orphan path. See
                // `orphan_retreat_target`.
                let target = self.orphan_retreat_target(&header, child_hash);
                match Validated::prove(store, target.hash) {
                    Ok(to) => {
                        if let Err(e) = store.apply(&Transition::Retreat { to }) {
                            warn!(target: "rustock::sync", "Reorg: retreat failed: {:?}", e);
                        }
                    }
                    Err(b) => warn!(
                        target: "rustock::sync",
                        "Reorg: cannot retreat to {} either ({}); the chain below is broken",
                        target, b
                    ),
                }
            }
        }
        // Orphaned: roll execution back onto the canonical chain.
        warn!(
            target: "rustock::sync",
            "Reorg: executed head #{} ({:?}) orphaned (canonical child #{} builds on {:?})",
            header.number, exec_hash, child.number, child.parent_hash
        );
        self.roll_execution_back(rustock_storage::BlockRef::new(header.number, exec_hash));
    }

    /// Drop follow-mode body requests a peer never answered.
    ///
    /// Without this the entry lives forever: the block is never re-requested,
    /// and the two recovery paths that treat a non-empty map as "work in
    /// flight" never act. Expiring lets the next tip re-request the body and
    /// lets those recoveries see an idle pipeline.
    fn expire_stale_follow_bodies(&mut self) {
        let before = self.pending_follow_bodies.len();
        self.pending_follow_bodies
            .retain(|_, (_, _, sent, _)| sent.elapsed() < FOLLOW_BODY_TIMEOUT);
        let expired = before - self.pending_follow_bodies.len();
        if expired > 0 {
            warn!(
                target: "rustock::sync",
                "Expired {expired} follow-mode body request(s) with no response; \
                 the blocks will be re-requested"
            );
        }
    }

    /// Request bodies for canonical blocks above the executed head that we
    /// hold a header for and no body.
    ///
    /// **The hole this fills.** Follow mode is reactive: `request_follow_bodies`
    /// asks only for the bodies of headers that just arrived. If one of those
    /// requests is never answered, `expire_stale_follow_bodies` drops it and
    /// nothing re-issues it -- the comment there says "the next tip will
    /// re-request the body", but the next tip brings *its own* header, not the
    /// one that was lost. The block stays header-only for good.
    ///
    /// Every other guard measures a difference that is **zero** in that state:
    ///
    /// * `leave_follow_if_backlog` compares the downloaded head to the
    ///   executed head. Both sat at #9,267,974 on 2026-09-24 while the missing
    ///   blocks were *above* the head, so it returned on its first check.
    /// * `check_execution_progress` watches execution stop while blocks wait.
    ///   None were waiting by its measure.
    /// * `check_follow_gap` is the only check that compares against peers, and
    ///   it is gated at `LONG_SYNC_LIMIT`.
    ///
    /// So the node idled 13m40s, 12 to 22 blocks behind, with nothing in
    /// flight -- and escaped only when the network's own progress carried it
    /// past 25 and skeleton sync took over, which then fetched all 25 bodies in
    /// 385 ms. The Φ watchdog saw it and escalated four times; each escalation
    /// restarted the round, `try_start_sync` found the gap under the limit, and
    /// put the node straight back into follow mode. Escalation and "Near tip
    /// (N blocks behind), entering follow mode" share a timestamp in the log,
    /// every time.
    ///
    /// **Why the condition is safe to run every tick.** A canonical block with
    /// no body is the ordinary state for the moment between a header arriving
    /// and its body answering -- but during that moment the request is in
    /// `pending_follow_bodies`. Requiring that to be empty makes the pair
    /// "canonical, body-less, and nothing outstanding" mean the request was
    /// lost rather than merely young.
    pub(crate) async fn fill_follow_body_gap(&mut self) {
        if !self.pending_follow_bodies.is_empty() {
            return; // a request is already outstanding; do not pile on
        }
        let Some(executed) = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(h, _)| self.manager.store.header(h).ok().flatten())
            .map(|h| h.number)
        else {
            return;
        };

        // Bounded by the follow/skeleton boundary: past that `check_follow_gap`
        // switches to the pipeline, which is the better tool for a long range.
        let mut missing: Vec<Header> = Vec::new();
        for number in executed + 1..=executed + LONG_SYNC_LIMIT {
            let Ok(Some(hash)) = self.manager.store.canonical_hash(number) else {
                break; // the canonical chain we hold ends here
            };
            let Ok(Some(header)) = self.manager.store.header(hash) else {
                break;
            };
            if self.manager.store.body(hash).ok().flatten().is_none() {
                missing.push(header);
            }
        }

        if missing.is_empty() {
            return;
        }
        warn!(
            target: "rustock::sync",
            "Follow mode holds {} canonical block(s) above #{} with no body and nothing \
             in flight; re-requesting them",
            missing.len(), executed
        );
        self.request_follow_bodies(&missing).await;
    }

    /// Leave follow mode when a backlog has built up behind the tip.
    ///
    /// Follow mode executes blocks as they are announced and has no way to fetch
    /// ones it missed. When the chain moves faster than announcements are
    /// processed, the blocks in between are never requested and execution falls
    /// behind for good.
    ///
    /// The execution watchdog does eventually notice, but only after two minutes
    /// of standing still, so the node spent most of its time stalled and
    /// recovering rather than following. This catches it within a tick.
    ///
    /// The tolerance matters: a single unexecuted block is the ordinary state
    /// between a tip arriving and being executed, and reacting to that would
    /// fight follow mode rather than help it.
    async fn leave_follow_if_backlog(&mut self) {
        if self.block_processor.is_none() || self.executing.is_some() || self.pending_exec.is_some()
        {
            return;
        }
        let executed = match self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(h, _)| self.manager.store.header(h).ok().flatten())
        {
            Some(h) => h.number,
            None => return,
        };
        let downloaded = self.our_head_number();
        if downloaded <= executed + FOLLOW_BACKLOG_TOLERANCE {
            return;
        }
        info!(
            target: "rustock::sync",
            "Follow mode is {} blocks behind execution (#{} executed, #{} downloaded); \
             switching to the body pipeline",
            downloaded - executed, executed, downloaded
        );
        self.follow_buffer.clear();
        self.follow_gap_since = None;
        self.last_body_height = executed;
        self.state = SyncState::Idle;
    }

    /// Restart the pipeline if execution has stopped while blocks are waiting.
    ///
    /// This is a watchdog over the one thing nothing else measures. Header
    /// download, the "fell behind" check and the resync trigger all compare the
    /// *downloaded* head against peers; when execution stops, that head keeps
    /// climbing and every trigger reports health. A node in that state logs a
    /// new tip every thirty seconds and executes nothing -- twenty hours of it
    /// went unnoticed on mainnet, and the only symptom was a log line that never
    /// appeared.
    ///
    /// Recovery is the same as after an execution failure: rewind the body
    /// cursor to the executed head and leave whatever state we are in, so a
    /// fresh round re-queues the blocks between there and the tip.
    fn check_execution_progress(&mut self) {
        let exec_height = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.manager.store.header(hash).ok().flatten())
            .map(|h| h.number);
        let Some(exec_height) = exec_height else { return };

        if exec_height != self.last_exec_height {
            self.last_exec_height = exec_height;
            self.last_exec_progress = Instant::now();
            return;
        }

        // Standing still is only a fault if there is something to execute.
        let downloaded = self.our_head_number();
        if downloaded <= exec_height {
            self.last_exec_progress = Instant::now();
            return;
        }

        // Executing a batch, or holding one ready, is progress in flight.
        //
        // Report rather than silently reset: a batch that never finishes looks
        // exactly like one making progress, and treating it as healthy is how a
        // watchdog ends up never firing. If this line repeats, execution is
        // wedged inside the pipeline rather than starved of work.
        if self.executing.is_some() || self.pending_exec.is_some() {
            if self.last_exec_progress.elapsed() >= EXEC_STALL_TIMEOUT {
                warn!(
                    target: "rustock::sync",
                    "Execution stuck at #{exec_height} for {}s with #{downloaded} downloaded, \
                     but a batch is {} -- watchdog deferring",
                    self.last_exec_progress.elapsed().as_secs(),
                    if self.executing.is_some() { "in flight" } else { "parked" }
                );
            }
            return;
        }

        if self.last_exec_progress.elapsed() < EXEC_STALL_TIMEOUT {
            return;
        }

        warn!(
            target: "rustock::sync",
            "Execution has not advanced past #{exec_height} for {}s while #{downloaded} is \
             downloaded (state {:?}, body cursor #{}); restarting the block pipeline",
            self.last_exec_progress.elapsed().as_secs(),
            std::mem::discriminant(&self.state),
            self.last_body_height
        );
        self.follow_buffer.clear();
        self.follow_gap_since = None;
        self.last_body_height = exec_height;
        self.pending_exec = None;
        self.state = SyncState::Idle;
        self.last_exec_progress = Instant::now();
    }

    /// Keep the in-memory state root equal to the one the executed head
    /// committed.
    ///
    /// These are two representations of the same fact and they can come apart:
    /// `Transition::Retreat` rolls the *committed* executed head back on its
    /// own when a reorg moves the ground under it, and the service's in-memory
    /// root does not hear about it. Follow mode already refused to execute in
    /// that state -- correctly -- but refusing is not recovering, and the body
    /// pipeline had no such guard at all, so it executed against the stale root
    /// and produced `NonceTooLow`: the state one transaction ahead of where the
    /// marker said it was.
    ///
    /// Mainnet 2026-09-23 17:21, and it is the same shape as every other
    /// failure this subsystem has had -- two notions of one fact, and a code
    /// path reading the wrong one. The committed root is the authority; this
    /// reloads from it.
    pub(crate) fn resync_state_root_with_exec_head(&mut self) {
        // Not while execution is in flight. The job commits the executed head
        // block by block as it goes, but `current_state_root` is only replaced
        // when the job finishes, so the two are legitimately apart for the
        // whole of a batch. Checking here reported a disagreement on almost
        // every tick -- 11 a minute in follow mode -- reloaded a root that was
        // not wrong, and threw away the follow buffer and any pending
        // execution each time (#194).
        //
        // The condition this guard exists for is a reorg moving the committed
        // head under a *settled* in-memory root. That is still caught: the
        // check runs on the next tick after the job lands.
        if self.executing.is_some() {
            return;
        }

        let Some(trie_store) = self.trie_store.clone() else { return };
        let Ok(Some((_, committed))) = self.manager.store.exec_head() else { return };

        let in_memory = self
            .current_state_root
            .as_ref()
            .map(|r| r.compute_hash(trie_store.as_ref()));
        if in_memory == Some(committed) {
            return;
        }

        match trie_store.get(committed.as_slice()) {
            Some(data) => {
                warn!(
                    target: "rustock::sync",
                    "In-memory state root {:?} disagrees with the executed head's committed \
                     root {:?}; reloading from the committed one",
                    in_memory, committed
                );
                self.current_state_root = Some(TrieNode::from_message(&data, trie_store.as_ref()));
                // Anything queued was queued against the old root.
                self.follow_buffer.clear();
                self.pending_exec = None;
            }
            None => warn!(
                target: "rustock::sync",
                "The executed head's committed state root {:?} is not in the trie store; \
                 execution cannot resume from it", committed
            ),
        }
    }

    /// Re-queue canonical blocks this node already holds but has not executed.
    ///
    /// `drain_follow_buffer` is reachable from exactly one place:
    /// `on_body_response`. Follow mode therefore only ever executes a block as
    /// its body *arrives*. That is sound while every unexecuted block is still
    /// waiting on a body, and it stops being true the moment something empties
    /// the buffer for a block whose body has already come and gone.
    /// `resync_state_root_with_exec_head` does exactly that, and rightly so --
    /// what it discards was queued against a root that no longer exists.
    ///
    /// Nothing re-queues it. The rest of the `Following` arm declines: the
    /// reconcile finds no rollback to make, `fill_follow_body_gap` only
    /// re-requests blocks with *no* body, and `leave_follow_if_backlog` wants
    /// a backlog over `FOLLOW_BACKLOG_TOLERANCE`. So a canonical block one
    /// ahead of the executed head, whose body is already stored, is dropped on
    /// the floor until the execution watchdog restarts the pipeline 120s
    /// later. Mainnet 2026-10-23 18:17:33: a tip reorg, the reload, then
    /// nothing at all for 125 seconds, then `Processed 1 blocks` the instant
    /// the watchdog kicked it.
    ///
    /// The fix is to read the work back out of the store rather than wait for
    /// a message that has already been delivered. Bounded by the backlog
    /// follow mode is willing to carry anyway: past `FOLLOW_BACKLOG_TOLERANCE`
    /// it is `leave_follow_if_backlog`'s job to hand over to the body
    /// pipeline, which fetches on its own initiative.
    ///
    /// Safe to run every tick. `drain_follow_buffer` refuses to execute while
    /// a batch is running or parked, and parent-links each block against the
    /// executed head before running it, so a block queued here is subject to
    /// exactly the checks a block queued by a body response is.
    pub(crate) fn refill_follow_buffer_from_store(&mut self) {
        if self.executing.is_some() || self.pending_exec.is_some() {
            return;
        }
        let Ok(Some((exec_hash, _))) = self.manager.store.exec_head() else { return };
        let Ok(Some(exec_header)) = self.manager.store.header(exec_hash) else { return };

        for number in
            (exec_header.number + 1)..=(exec_header.number + FOLLOW_BACKLOG_TOLERANCE)
        {
            if self.follow_buffer.contains_key(&number) {
                continue;
            }
            let Ok(Some(hash)) = self.manager.store.canonical_hash(number) else { break };
            let Ok(Some(header)) = self.manager.store.header(hash) else { break };
            // No body yet: `fill_follow_body_gap` is the path for that one.
            let Ok(Some((txs, uncles))) = self.manager.store.body(hash) else { break };
            self.follow_buffer.insert(number, (hash, header, txs, uncles));
        }
    }

    /// Check the coherence invariant over the heights this node just touched.
    ///
    /// Cheap: a handful of point reads. It runs on every tick rather than only
    /// after a commit because a violation can also be written by the storage
    /// layer's own fork choice, which sync does not drive.
    ///
    /// A violation does not halt the node. It is reported loudly, with the
    /// relation and the height, and left to the watchdog to act on -- halting a
    /// live node on a relation that has never been checked before would turn a
    /// diagnostic into an outage. The point of stage 2 is that the node stops
    /// being silent, not that it stops.
    pub(crate) fn verify_coherence(&mut self) {
        let store = &self.manager.store;
        let cursor = match invariant::derive_cursor(store) {
            Ok(Some(c)) => c,
            Ok(None) => {
                self.clear_violation();
                return;
            }
            Err(v) => {
                self.report_violation(&v);
                return;
            }
        };

        // Delta scope: the window between what we have executed and what we
        // consider downloaded, which is where every disagreement so far has
        // lived. The I4..I7 relations are checked whatever the scope.
        let scope = Scope::Delta {
            from: cursor.executed.number.saturating_sub(COHERENCE_LOOKBACK),
            to: cursor.validated_head.number,
        };
        let trie = self.trie_store.as_deref();
        match invariant::check_with_cursor(store, trie, scope, &cursor) {
            Err(v) => {
                self.report_violation(&v);
                // I6 and I8 have a well-defined, safe repair: re-seat the head
                // onto the canonical chain and walk it up as far as we hold
                // linked blocks. Do it here rather than leaving it to the
                // watchdog.
                //
                // Waiting for the watchdog meant three minutes of standing
                // still every time an orphaned tip was adopted -- which is
                // routine, several times an hour -- so the node sawtoothed
                // between the tip and three minutes behind it. A liveness net
                // is the wrong thing to make progress depend on: it exists for
                // the failures nothing else understands, and a failure we can
                // name and repair is not one of them.
                match v {
                    Violation::CanonicalAboveHead { .. } | Violation::HeadNotCanonical { .. } => {
                        self.reverify_head_lineage(0);
                    }
                    // I5: the executed head is not the canonical block at
                    // its own height, so this node has executed the losing
                    // side of a fork. Every *other* guard in the service
                    // measures a difference of block numbers -- downloaded
                    // head versus executed head, our height versus peers' --
                    // and that difference is **zero** when the fork is one
                    // block deep at the tip. So nothing moved.
                    //
                    // Mainnet 2026-09-24 18:57: two siblings at #9,268,363
                    // with the same parent; the canonical index switched to
                    // one, execution stayed on the other, and the node stood
                    // still for twelve minutes. I5 reported it correctly every
                    // thirty-five seconds and nothing consumed the report --
                    // the invariant checker was a reporter, not an actuator.
                    //
                    // `choose_resume_point` walks the executed head's own
                    // ancestry to the first block that is both canonical and
                    // still has state, which for a one-deep sibling fork is
                    // the shared parent: one block re-executed.
                    // I3: the canonical chain does not link to itself. One
                    // height names a block that is not the parent of the block
                    // above it, so every consumer walking the index gets a
                    // chain that was never mined.
                    //
                    // Repaired rather than only reported, because nothing else
                    // will: `ensure_canonical_lineage` stops at the first
                    // consistent pair and so never descends to it, and the
                    // only existing repair trigger fires on a *missing* entry.
                    // A stale one is not missing.
                    //
                    // Left alone it is silent until REMASC settles that height
                    // 4,000 blocks later, computes a different state root from
                    // the rest of the network and wedges the node permanently.
                    // That is mainnet 2026-10-04, and it cost 33 hours before
                    // anything said a word.
                    Violation::ParentMismatch { at, .. } => {
                        warn!(
                            target: "rustock::sync",
                            "Canonical index does not link at #{at}; repairing lineage"
                        );
                        self.repair_canonical_gap(cursor.validated_head.number, at.saturating_sub(1));
                    }
                    Violation::ExecutedOffChain { at, hash, canonical } => {
                        if self.violation_held_for(&v, EXECUTION_OFF_CHAIN_GRACE) {
                            warn!(
                                target: "rustock::sync",
                                "Executed head #{at} ({hash}) is not canonical at its height \
                                 ({canonical:?}); rolling execution back onto the canonical \
                                 chain"
                            );
                            self.roll_execution_back(cursor.executed);
                        }
                    }
                    // I7: the executed head names a state root the trie store
                    // does not have, so the node cannot execute another block
                    // from it -- and nothing else notices, because the executed
                    // head is perfectly canonical.
                    //
                    // Mainnet 2026-09-23: a rollback left execution on an
                    // abandoned branch; by the time that branch became canonical
                    // again its state had been collected. I5 cleared itself, I7
                    // did not, and the node sat in a retry loop failing every
                    // block with `NonceTooHigh { state: 0 }` -- an account read
                    // back empty, which is what a missing trie node looks like.
                    //
                    // Rolling back to a height whose state we still hold costs
                    // re-executing a few blocks. Not rolling back costs the node.
                    Violation::StateRootMissing { at, .. } => {
                        // Say whether the collector took it. A node at or below
                        // the collection floor is gone deliberately and will
                        // not come back; one above it means the store is
                        // damaged, which is a different problem with a
                        // different fix. Reporting "no state" for both sends
                        // whoever reads this down the wrong path.
                        let why = match self.trie_store.as_ref().and_then(|t| t.collected_below()) {
                            Some(w) if at <= w => format!(
                                "the trie collector has swept blocks up to #{w}, so this \
                                 state was collected and is not recoverable here"
                            ),
                            Some(w) => format!(
                                "the trie collector has only swept up to #{w}, so this state \
                                 should still be present: the store is damaged"
                            ),
                            None => "this store never collects, so the state should be \
                                     present: the store is damaged"
                                .to_string(),
                        };
                        warn!(
                            target: "rustock::sync",
                            "Executed head #{at} has no state in the trie store ({why}); \
                             resuming from the highest ancestor that does"
                        );
                        self.roll_execution_back(cursor.executed);
                    }
                    // I1, I2, I3: the chain between the executed head and
                    // the head is not contiguous. Reported correctly and acted
                    // on never, so the node stood still -- execution asks for
                    // blocks across the break, fails, and retries from the
                    // same place.
                    // `ParentMismatch` here is unreachable: #263 added an arm
                    // above that claims it. Left in place deliberately -- see
                    // issue #280, which asks whether that is correct.
                    #[allow(unreachable_patterns)]
                    Violation::NoCanonicalEntry { at }
                    | Violation::CanonicalHeaderMissing { at, .. }
                    | Violation::ParentMismatch { at, .. } => {
                        self.reseat_head_above_executed(at);
                    }
                    _ => {}
                }
            }
            Ok(()) => self.clear_violation(),
        }
    }

    /// Report a broken relation once it has *persisted*, then at most once
    /// every thirty seconds.
    ///
    /// The grace period is what separates the pipeline from a stall. A
    /// canonical entry above the head clears within a second or two on every
    /// ordinary tip; the one that wedged mainnet on 2026-09-22 stood for three
    /// hours. Only the second kind is worth a line in the log.
    fn report_violation(&mut self, v: &Violation) {
        let now = Instant::now();
        let identity = Self::violation_identity(v);

        let first_seen = match &self.violation_since {
            Some((seen, at)) if *seen == identity => *at,
            _ => {
                // A different violation (or the first): start its clock and say
                // nothing yet.
                self.violation_since = Some((identity, now));
                self.last_violation_log = None;
                return;
            }
        };

        if now.saturating_duration_since(first_seen) < VIOLATION_GRACE {
            return;
        }

        let due = self
            .last_violation_log
            .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(30));
        if !due {
            return;
        }
        self.last_violation_log = Some(now);
        warn!(
            target: "rustock::sync",
            "Coherence violation {} unresolved for {}s: {}",
            v.relation(),
            now.saturating_duration_since(first_seen).as_secs(),
            v
        );
    }

    /// How a violation is identified across ticks: the relation and the
    /// height it was found at. Two different heights are two different
    /// violations, each with its own clock.
    fn violation_identity(v: &Violation) -> String {
        format!("{}@{:?}", v.relation(), v.at())
    }

    /// Has *this* violation been held continuously for at least `grace`?
    ///
    /// The identity is checked rather than assumed. `report_violation` runs
    /// first and would have reset the clock for a different relation, but a
    /// repair that fires on the strength of some other relation's age would be
    /// a subtle and rare bug, and checking costs a string compare.
    fn violation_held_for(&self, v: &Violation, grace: Duration) -> bool {
        let identity = Self::violation_identity(v);
        self.violation_since.as_ref().is_some_and(|(seen, first_seen)| {
            *seen == identity && Instant::now().saturating_duration_since(*first_seen) >= grace
        })
    }

    /// The store is coherent again: forget whatever was outstanding.
    fn clear_violation(&mut self) {
        if let Some((relation, first_seen)) = self.violation_since.take() {
            // Only worth a line if it had been reported.
            if self.last_violation_log.is_some() {
                info!(
                    target: "rustock::sync",
                    "Coherence restored after {}s ({} cleared)",
                    Instant::now().saturating_duration_since(first_seen).as_secs(),
                    relation
                );
            }
        }
        self.last_violation_log = None;
    }

    /// Outstanding network requests and the age of the oldest, across whichever
    /// phase the node is in. The second and third components of Φ.
    fn outstanding_requests(&self) -> (usize, Option<Duration>) {
        let now = Instant::now();
        let mut count = 0usize;
        let mut oldest: Option<Duration> = None;
        let mut note = |since: Instant| {
            let age = now.saturating_duration_since(since);
            oldest = Some(oldest.map_or(age, |o: Duration| o.max(age)));
        };

        match &self.state {
            SyncState::DownloadingHeaders { tracker, .. } => {
                count += tracker.in_flight.values().map(|q| q.len()).sum::<usize>();
                for since in tracker.waiting_since.values() {
                    note(*since);
                }
            }
            SyncState::DownloadingBodies { in_flight, .. } => {
                count += in_flight.len();
                for body in in_flight.values() {
                    note(body.sent);
                }
            }
            _ => {}
        }

        // Follow-mode body requests are outstanding work in any state.
        count += self.pending_follow_bodies.len();
        for (_, _, sent, _) in self.pending_follow_bodies.values() {
            note(*sent);
        }

        (count, oldest)
    }

    /// The Φ watchdog. Runs every tick; escalates when Φ has failed to improve.
    pub(crate) async fn check_phi_progress(&mut self) {
        let Some((_, metadata)) = self.peer_store.best_peer().await else {
            // With no peer there is no target, so there is nothing to be
            // behind. Do not accumulate a stall against a disconnected node.
            self.watchdog.reset(Instant::now());
            return;
        };

        let executed = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.manager.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0);

        let (outstanding, oldest) = self.outstanding_requests();
        let phi = Phi::new(metadata.best_number, executed, outstanding, oldest);
        let now = Instant::now();
        // Read before `observe`, which opens a new window when it escalates.
        let stalled_for = self.watchdog.stalled_for(now);
        let Some(escalation) = self.watchdog.observe(phi, now) else {
            return;
        };

        warn!(
            target: "rustock::sync",
            "No progress for {}s: Φ = (behind {}, outstanding {}, oldest {}s), \
             best this window {:?}, escalation {} -> {:?}",
            stalled_for.as_secs(),
            phi.behind,
            phi.outstanding,
            -phi.neg_age_secs,
            self.watchdog.best(),
            self.watchdog.level(),
            escalation,
        );

        match escalation {
            Escalation::RetreatAndReverify { blocks }
            | Escalation::WidenRetreat { blocks } => {
                self.reverify_head_lineage(blocks);
                self.restart_round();
            }
            Escalation::ResearchConnectionPoint => {
                // Drop the assumption about where we join the peer's chain and
                // make `try_start_sync` search for it again from scratch.
                self.force_connection_search = true;
                self.reverify_head_lineage(0);
                self.restart_round();
            }
            Escalation::Exhausted { blocks } => {
                error!(
                    target: "rustock::sync",
                    "Retreating {blocks} blocks has not restored progress. This is not a \
                     stall the watchdog can clear; the node needs attention."
                );
            }
        }
    }
    /// Tell subscribers a block joined or left the canonical chain.
    ///
    /// Receipts are read back from the store rather than carried from
    /// execution, because a removal has no execution to carry them from and
    /// both cases must produce the same event. One point read at the tip.
    ///
    /// Silent when nobody is subscribed: `broadcast::send` returns an error
    /// with no receivers, and that is the ordinary state of a node whose
    /// WebSocket server is off.
    pub(crate) fn publish_block(
        &self,
        hash: B256,
        header: &Header,
        transactions: &[rustock_core::Transaction],
        removed: bool,
    ) {
        let Some(events) = &self.events else { return };
        if events.receiver_count() == 0 {
            return;
        }
        let receipts = self.manager.store.receipts(hash).ok().flatten().unwrap_or_default();
        let _ = events.send(rustock_core::events::ChainEvent::Block(std::sync::Arc::new(
            rustock_core::events::BlockEvent {
                hash,
                header: header.clone(),
                transactions: transactions.to_vec(),
                receipts,
                removed,
            },
        )));
    }

    /// Retract every block between `from` (exclusive of the resume point) and
    /// `to`, walking the abandoned branch's own ancestry.
    ///
    /// This is rskj's `BlockchainBranchComparator.calculateFork` reduced to
    /// the half rustock needs: the old branch. The new branch announces
    /// itself as it executes.
    fn publish_removals(&self, from: rustock_storage::BlockRef, to: rustock_storage::BlockRef) {
        let Some(events) = &self.events else { return };
        if events.receiver_count() == 0 {
            return;
        }
        let store = &self.manager.store;
        let mut hash = from.hash;
        // Bounded by the rollback depth the caller already accepted.
        for _ in 0..crate::rollback::MAX_ROLLBACK {
            if hash == to.hash {
                break;
            }
            let Ok(Some(header)) = store.header(hash) else { break };
            if header.number <= to.number {
                break;
            }
            let transactions = store
                .body(hash)
                .ok()
                .flatten()
                .map(|(txs, _)| txs)
                .unwrap_or_default();
            self.publish_block(hash, &header, &transactions, true);
            hash = header.parent_hash;
        }
    }

    /// Move execution to the highest block on the executed head's own ancestry
    /// that is canonical and whose state we still hold.
    ///
    /// The decision itself is [`crate::rollback::choose_resume_point`], which
    /// is pure and simulated over thousands of generated chains. This method
    /// only applies it. Three bugs in one day lived in this decision when it
    /// was written inline; the module docs list them.
    ///
    /// Returns false when nothing usable was found, and says so loudly: a node
    /// that cannot resume needs a resync, not another retry.
    pub(crate) fn roll_execution_back(&mut self, from: rustock_storage::BlockRef) -> bool {
        let Some(trie_store) = self.trie_store.clone() else { return false };

        let target = {
            let view = StoreView {
                store: &self.manager.store,
                trie: Some(trie_store.as_ref()),
            };
            match crate::rollback::choose_resume_point(&view, from) {
                Ok(t) => t,
                Err(why) => {
                    error!(
                        target: "rustock::sync",
                        "No block on the ancestry of {from} is canonical with state in the \
                         trie store ({why:?}); execution cannot resume and the node needs a \
                         resync from a state that exists."
                    );
                    return false;
                }
            }
        };

        if target == from {
            return true; // already usable; nothing to do
        }

        let store = &self.manager.store;
        let Some(header) = store.header(target.hash).ok().flatten() else { return false };
        let Some(data) = trie_store.get(header.state_root.as_slice()) else { return false };

        let at = match Validated::prove(store, target.hash) {
            Ok(v) => v,
            Err(broken) => {
                error!(
                    target: "rustock::sync",
                    "Resume point {target} cannot be proved ({broken}); execution not moved"
                );
                return false;
            }
        };
        if let Err(e) = store.apply(&Transition::Executed { at, state_root: header.state_root }) {
            error!(target: "rustock::sync", "Recording the resume point {target} failed: {e:?}");
            return false;
        }

        // Retract the abandoned branch before moving execution, so a
        // subscriber sees `removed: true` for those blocks before it sees the
        // replacements arrive. rskj's logs emitter emits the old branch first
        // for the same reason.
        self.publish_removals(from, target);

        self.current_state_root = Some(TrieNode::from_message(&data, trie_store.as_ref()));
        self.last_body_height = header.number;
        self.follow_buffer.clear();
        self.pending_exec = None;
        warn!(
            target: "rustock::sync",
            "Execution resumed at {target} (was {from}); {} block(s) will be re-executed",
            from.number.saturating_sub(target.number)
        );
        true
    }

    /// Where to retreat to when our head has been orphaned by `replaced_by`:
    /// **below the fork, not one block down.**
    ///
    /// Retreating to the orphaned head's own parent is correct only when the
    /// reorg is exactly one block deep. Any deeper and that parent is on the
    /// abandoned branch too, so the retreat re-canonicalises a losing block
    /// and the node then waits for a child no peer will ever produce. Mainnet
    /// sat in exactly that state for twelve minutes on 2026-09-24
    /// (#9,266,649-#9,266,652, a three-deep reorg), and escaped only when the
    /// network's own progress carried it 25 blocks ahead -- which switched it
    /// to skeleton sync, whose bulk path noticed in one round.
    ///
    /// It would be better to retreat to the fork point exactly. That is not
    /// available here, and the reason is worth stating because it is not
    /// obvious: we only reach this function when `Validated::prove` on the
    /// replacement failed, and it fails for one reason only -- a header
    /// missing while walking that branch down. Locating the fork means walking
    /// the same segment, from the same tip toward the same meeting point, so
    /// it runs into the same gap. The two succeed and fail together. When the
    /// replacement branch *is* held, `prove` succeeds and the caller adopts it
    /// rather than retreating at all.
    ///
    /// So the retreat covers distance rather than locating the fork, and the
    /// distance is [`BLIND_RETREAT_DEPTH`] -- chosen to cross the follow /
    /// skeleton boundary, because a height-range request is the only mechanism
    /// that re-fetches a height whose block the node already holds.
    ///
    /// The exact fork point is then reached one round later, for free: the
    /// re-download puts the replacement branch in the store, `prove` succeeds,
    /// adoption un-canonicalises our losing blocks, and `choose_resume_point`
    /// walks execution back to precisely the last block both chains share.
    fn orphan_retreat_target(
        &self,
        header: &Header,
        replaced_by: B256,
    ) -> rustock_storage::BlockRef {
        let store = &self.manager.store;
        let view = StoreView { store, trie: self.trie_store.as_deref() };
        let ours = header.hash();
        let parent = rustock_storage::BlockRef::new(
            header.number.saturating_sub(1),
            header.parent_hash,
        );

        let _ = replaced_by;
        // Blind, and it has to be: the fork point is NOT computable here.
        //
        // We only reach this function because `Validated::prove` on the
        // replacement failed, and it fails for exactly one reason -- a header
        // missing while walking that branch down. A fork-point search walks
        // the *same* segment, from the same tip toward the same meeting point,
        // so it hits the same gap and fails whenever `prove` does. The two are
        // not independent: when the replacement branch is held, `prove`
        // succeeds and we adopt it instead of ever coming here.
        // `rollback::fork_point` states that relationship and the property
        // test `a_blind_retreat_never_stops_above_the_fork` checks this
        // function against it.
        //
        // So the retreat goes below the fork by covering distance instead of
        // by locating it, and the exact fork point is reached one round later,
        // for free: once the range is re-downloaded the replacement branch is
        // in the store, `prove` succeeds, adoption un-canonicalises our losing
        // blocks, and `choose_resume_point` walks execution back to precisely
        // the last block both chains share.
        let blind = crate::rollback::deepest_resumable_within(
            &view,
            ours,
            BLIND_RETREAT_DEPTH,
        )
        .unwrap_or(parent);
        warn!(
            target: "rustock::sync",
            "Orphan recovery: retreating {} block(s) to {}, below the orphaned head #{}, \
             so the range is downloaded again",
            header.number.saturating_sub(blind.number), blind, header.number
        );
        blind
    }

    /// Retreat the head below an orphaned executed head, and roll execution
    /// back with it.
    ///
    /// Both orphan paths use this, so they cannot drift apart: one finds a
    /// canonical child that does not build on us, the other finds no canonical
    /// child at all, and the recovery is the same in both cases.
    ///
    /// Execution comes back with the head. Retreating one without the other is
    /// how I4 gets broken by the act of recovering -- which is what the
    /// watchdog's first deployment did to mainnet within fifteen seconds.
    fn retreat_below_orphaned_head(&mut self, header: &Header, replaced_by: B256) {
        let target = self.orphan_retreat_target(header, replaced_by);
        let store = &self.manager.store;

        let to = match Validated::prove(store, target.hash) {
            Ok(v) => v,
            Err(broken) => {
                warn!(
                    target: "rustock::sync",
                    "Orphan recovery: cannot retreat to {} ({}); the chain below is broken",
                    target, broken
                );
                return;
            }
        };
        let dest = to.block();
        if let Err(e) = store.apply(&Transition::Retreat { to }) {
            warn!(target: "rustock::sync", "Orphan recovery: retreat failed: {:?}", e);
            return;
        }

        // Execution follows the head onto the canonical chain. Targeting the
        // orphan's own parent here was the 2026-09-23 bug: that parent is on
        // the branch being abandoned, so recording execution at it is refused
        // and execution stays stranded. See `roll_execution_back`.
        let executed = match store.cursor() {
            Ok(Some(c)) => c.executed,
            _ => return,
        };
        if self.roll_execution_back(executed) {
            warn!(
                target: "rustock::sync",
                "Orphan recovery: head and execution retreated to {}", dest
            );
        }
    }

    /// Re-establish that the head is the top of the contiguous canonical chain
    /// we actually hold.
    ///
    /// Two moves, in this order:
    ///
    /// 1. **Adopt** the highest canonical block we hold a linked chain up to.
    ///    This re-seats a head that has drifted off the canonical chain and
    ///    picks up blocks stranded above it -- the shape that wedged mainnet
    ///    for three hours.
    /// 2. **Retreat**, if there is nothing above and the caller asked for it,
    ///    so the range is downloaded again.
    ///
    /// Both go through `Transition`, so neither can leave the three position
    /// keys disagreeing.
    ///
    /// The retreat **may** go below the executed head, and takes execution
    /// with it when it does. Refusing to was the bug: head and executed are
    /// equal on a caught-up node, so a floor at the executed height made the
    /// whole step a no-op for precisely the node that needs it.
    /// Re-seat the head onto the highest block that is contiguously held
    /// above the executed head.
    ///
    /// The repair for a broken chain *below* the head: a missing canonical
    /// entry, a canonical entry whose header is absent, or a link that does
    /// not join. All three mean the same thing — the head is not reachable
    /// from the executed head — and a head that cannot be walked back to is
    /// not a usable head. Execution will keep asking for the blocks in
    /// between, keep failing, and the node stands still while reporting the
    /// problem correctly.
    ///
    /// `reverify_head_lineage` does not cover this: it walks *up* from the
    /// head looking for something better, and there is nothing above a head
    /// whose problem is underneath it.
    ///
    /// The executed head is the one block known to be sound, so the walk
    /// starts there. Whatever is contiguous above it is reachable by
    /// construction, and the head never moves below what has already been
    /// executed.
    fn reseat_head_above_executed(&mut self, at: u64) {
        let store = &self.manager.store;
        let Ok(Some(cursor)) = store.cursor() else { return };
        let head = cursor.validated_head;
        let executed = cursor.executed;

        let Some(top) = canonical_top_held(store, executed.number) else {
            warn!(
                target: "rustock::sync",
                "Chain broken at #{at} and nothing is contiguous above the executed head \
                 #{}; cannot re-seat", executed.number
            );
            return;
        };
        if top == head.hash {
            return; // already where it should be
        }

        match Validated::prove(store, top) {
            Ok(proved) => {
                let to = proved.block();
                match store.apply(&Transition::Adopt { head: proved }) {
                    Ok(_) => {
                        warn!(
                            target: "rustock::sync",
                            "Chain broken at #{at}: re-seated the head to {} (was {}), which \
                             is the highest block reachable from the executed head #{}",
                            to, head, executed.number
                        );
                        // Anything downloaded above the new head was counted
                        // against a head that no longer exists.
                        self.last_body_height = self.last_body_height.min(to.number);
                        self.state = SyncState::Idle;
                    }
                    Err(e) => warn!(
                        target: "rustock::sync",
                        "Chain broken at #{at}: could not re-seat the head to {to}: {e:?}"
                    ),
                }
            }
            Err(broken) => warn!(
                target: "rustock::sync",
                "Chain broken at #{at}: the block above the executed head does not prove \
                 either: {broken:?}"
            ),
        }
    }

    pub(crate) fn reverify_head_lineage(&mut self, retreat: u64) {
        let store = &self.manager.store;
        let Ok(Some(cursor)) = store.cursor() else { return };
        let head = cursor.validated_head;

        // 1. Adopt the top of what we hold.
        if let Some(top) = canonical_top_held(store, head.number) {
            if top != head.hash {
                match Validated::prove(store, top) {
                    Ok(proved) => {
                        let to = proved.block();
                        match store.apply(&Transition::Adopt { head: proved }) {
                            Ok(_) => {
                                warn!(
                                    target: "rustock::sync",
                                    "Head re-verification: adopted {} (was {})", to, head
                                );
                                self.last_body_height = self.last_body_height.min(head.number);
                                return;
                            }
                            Err(e) => warn!(
                                target: "rustock::sync",
                                "Head re-verification: adopting {} failed: {:?}", to, e
                            ),
                        }
                    }
                    Err(broken) => warn!(
                        target: "rustock::sync",
                        "Head re-verification: {:?} is canonical but cannot be proved ({})",
                        top, broken
                    ),
                }
            }
        }

        if retreat == 0 {
            return;
        }

        // 2. Nothing above: retreat, and take execution down with us.
        //
        // **This used to floor the retreat at the executed head's number**:
        //
        // ```
        // let floor = head.number.min(cursor.executed.number);
        // let depth = retreat.min(head.number.saturating_sub(floor));
        // ```
        //
        // which is zero whenever the node is caught up -- and a caught-up node
        // in follow mode is exactly the one that gets stuck. So the watchdog's
        // first escalation was a no-op in the commonest stall shape. Mainnet
        // 2026-09-24 19:00:48 logged `escalation 1 -> RetreatAndReverify
        // { blocks: 1 }` against head == executed == #9,268,363 and moved
        // nothing; three minutes later escalation 2 did the same.
        //
        // The old comment defended the floor as "a head under execution is not
        // a recovery, it is a second incoherence". That is right about the end
        // state and wrong about the method: `Transition::Retreat` pulls
        // execution down with the head through `stage_execution_after_reorg`
        // whenever the retreat orphans it, and `roll_execution_back` below
        // settles execution onto a height whose state we still hold. The pair
        // is what the orphan-recovery path already does; there is no moment at
        // which the head sits under execution.
        let depth = retreat.min(head.number);
        if depth == 0 {
            debug!(
                target: "rustock::sync",
                "Head re-verification: nothing above the head and nothing to retreat to \
                 (head {}, executed {})", head, cursor.executed
            );
            return;
        }

        let mut target = head.hash;
        for _ in 0..depth {
            let Ok(Some(h)) = store.header(target) else { return };
            if h.number == 0 {
                break;
            }
            target = h.parent_hash;
        }
        if target == head.hash {
            return;
        }

        match Validated::prove(store, target) {
            Ok(to) => {
                let dest = to.block();
                match store.apply(&Transition::Retreat { to }) {
                    Ok(_) => {
                        warn!(
                            target: "rustock::sync",
                            "Head re-verification: retreated from {} to {} so the range is \
                             downloaded again", head, dest
                        );
                        self.last_body_height = self.last_body_height.min(dest.number);
                        // Execution follows the head, exactly as it does in
                        // orphan recovery. Reading the cursor again rather
                        // than reusing `cursor.executed` matters: the retreat
                        // may already have moved execution, and rolling back
                        // from a stale reference would walk the ancestry of a
                        // block that is no longer the executed head.
                        if let Ok(Some(after)) = self.manager.store.cursor() {
                            self.roll_execution_back(after.executed);
                        }
                    }
                    Err(e) => warn!(target: "rustock::sync", "Head re-verification: retreat failed: {:?}", e),
                }
            }
            Err(broken) => warn!(
                target: "rustock::sync",
                "Head re-verification: cannot retreat to {:?} ({})", target, broken
            ),
        }
    }


    /// Abandon whatever round is in flight so the next tick starts a fresh one.
    fn restart_round(&mut self) {
        self.follow_buffer.clear();
        self.follow_gap_since = None;
        self.pending_exec = None;
        self.state = SyncState::Idle;
        self.last_progress = Instant::now();
    }

    /// Rebuild the canonical pointers from the best downloaded head down past
    /// `exec_number`, so execution has a contiguous chain to follow again.
    ///
    /// Walks a little below the executed head as well: the damage that hides a
    /// height is rarely confined to one pointer, and re-asserting a few blocks
    /// that were already correct costs nothing.
    fn repair_canonical_gap(&self, head_number: u64, exec_number: u64) {
        let store = &self.manager.store;
        let head_hash = match store.head().ok().flatten() {
            Some(h) => h,
            None => return,
        };
        let depth = head_number.saturating_sub(exec_number) + CANONICAL_REPAIR_MARGIN;
        match store.repair_canonical_lineage(head_hash, depth) {
            Ok(r) => {
                if r.corrected > 0 || r.filled > 0 {
                    warn!(
                        target: "rustock::sync",
                        "Canonical repair: {} pointers rewritten, {} holes filled \
                         over {} blocks down to #{:?}",
                        r.corrected, r.filled, r.walked, r.lowest
                    );
                } else {
                    warn!(
                        target: "rustock::sync",
                        "Canonical repair found nothing to fix over {} blocks; \
                         the missing height is not recoverable from stored headers",
                        r.walked
                    );
                }
            }
            Err(e) => {
                error!(target: "rustock::sync", "Canonical repair failed: {:?}", e);
            }
        }
    }

    pub(crate) async fn try_start_sync(&mut self) {
        if !self.follow_up {
            // A server, by instruction. It answers what it is asked and
            // adopts nothing.
            return;
        }

        let best_peer = self.peer_store.best_peer().await;
        let (peer_id, metadata) = match best_peer {
            Some(p) => p,
            None => return,
        };

        // A tip reorg can orphan the block we last executed: the storage
        // layer's fork choice has already moved the canonical pointers to the
        // heavier chain, but exec_head still points at the abandoned block.
        // Reconcile before downloading so the round resumes from a canonical
        // ancestor instead of wedging on a lineage mismatch.
        self.reconcile_exec_head_with_canonical().await;

        // A full node syncs from its EXECUTED head: blocks past it are
        // downloaded but have no state, so execution must resume there.
        // Without a block processor (no execution), fall back to the
        // download head.
        let head_hash = if self.block_processor.is_some() {
            match self.manager.store.exec_head().ok().flatten() {
                Some((h, _)) => h,
                None => match self.manager.store.canonical_hash(0).ok().flatten() {
                    Some(h) => h,
                    None => return,
                },
            }
        } else {
            match self.manager.store.head().ok().flatten() {
                Some(h) => h,
                None => return,
            }
        };
        let head = match self.manager.store.header(head_hash).ok().flatten() {
            Some(h) => h,
            None => return,
        };

        // Keep the body/execution cursor aligned with the sync head: a
        // stale (or zero, after restart) cursor would queue blocks below
        // or above the executed head.
        if self.block_processor.is_some() {
            self.last_body_height = head.number;
        }

        // Blocks may already be downloaded but not yet executed. Follow mode
        // only executes blocks that arrive as fresh announcements -- it has no
        // path for a backlog already sitting in the store -- so entering it here
        // leaves those blocks unexecuted forever, and the backlog grows with
        // every new tip.
        //
        // This is what made the stall self-sustaining. Both recovery paths
        // rewound the cursor to the executed head and dropped to Idle, and the
        // very next tick came back through here, saw a small gap, and returned
        // to follow mode without executing anything.
        let downloaded = self.our_head_number();
        if backlog_needs_executing(self.block_processor.is_some(), downloaded, head.number) {
            // A backlog that has already failed from this exact height will
            // fail the same way again: nothing the decision depends on has
            // changed. Retrying is not free -- each pass issues a body request
            // per block in the range, thousands of them, to real peers (#192).
            //
            // The case this was found in: a snapshot sync that failed before
            // committing its checkpoint leaves headers to #9265000, an
            // executed head at genesis, and no bodies in between. Ordinary
            // execution cannot bridge that, however often it tries.
            if self.futile_exec_halts.0 == head.number
                && self.futile_exec_halts.1 >= FUTILE_HALTS_BEFORE_GIVING_UP
            {
                if self.futile_exec_halts.1 == FUTILE_HALTS_BEFORE_GIVING_UP {
                    error!(
                        target: "rustock::sync",
                        "Executing #{} -> #{} has failed {} times from the same head and \
                         cannot succeed by retrying: this node holds headers it has no way \
                         to execute, which is what a snapshot sync that did not finish \
                         leaves behind. Not retrying. Re-run with --snap-sync to resume \
                         from the state it already verified, or start from an empty data \
                         directory.",
                        head.number, downloaded, FUTILE_HALTS_BEFORE_GIVING_UP
                    );
                    // Past the limit, so the message is said once.
                    self.futile_exec_halts.1 += 1;
                }
                return;
            }
            info!(
                target: "rustock::sync",
                "{} block(s) downloaded but not executed (#{} -> #{}); executing before following",
                downloaded - head.number, head.number, downloaded
            );
            self.start_body_downloads(metadata.best_number).await;
            return;
        }

        // Read before the near-tip shortcut, not after it.
        //
        // The watchdog sets this when a round has stopped making progress, and
        // follow mode is the round it most often stops in: `outstanding 0`
        // means nothing is in flight, so no timeout will fire and nothing will
        // restart the flow. The escalation drops to `Idle` expecting a search
        // to follow.
        //
        // Consulting the flag below the shortcut made that escalation a
        // no-op. A node a few hundred blocks behind takes the near-tip branch,
        // returns to the state it was stuck in, and never reaches the search
        // it was told to run -- so the flag is still set, the stall is still
        // there, and the watchdog fires again on the next tick, forever.
        // Observed twice: three hours on the mainnet node, and two hours forty
        // on a test node that had a peer 358 blocks ahead the whole time.
        //
        // The near-tip branch is an assumption that this node is where it
        // thinks it is. That assumption is exactly what the flag withdraws.
        let forced = std::mem::take(&mut self.force_connection_search);

        if head.number >= metadata.best_number {
            // Nothing above us on this peer, so there is no search to run:
            // it would converge on our own head.
            self.state = SyncState::Following;
            return;
        }

        let gap = metadata.best_number - head.number;

        if gap <= LONG_SYNC_LIMIT && !forced {
            info!(
                target: "rustock::sync",
                "Near tip ({} blocks behind), entering follow mode", gap
            );
            self.state = SyncState::Following;
            return;
        }

        if forced && gap <= LONG_SYNC_LIMIT {
            info!(
                target: "rustock::sync",
                "Near tip ({gap} blocks behind) but progress had stopped; searching for \
                 the connection point rather than following again"
            );
        }

        info!(
            target: "rustock::sync",
            "Starting sync: our head #{}, peer best #{} ({} blocks behind)",
            head.number, metadata.best_number, gap
        );

        self.progress.reset(head.number);

        // If the peer's best hash matches our chain, use our head as connection point.
        // Otherwise, use binary search to find where our chain diverges from the peer.
        let peer_hash_known =
            !forced && self.manager.store.has_block(metadata.best_hash).unwrap_or(false);

        if peer_hash_known || head.number == 0 {
            let cp = head.number;
            debug!(target: "rustock::sync", "Connection point: #{} (head)", cp);
            self.state = SyncState::DownloadingSkeleton {
                peer: peer_id,
                peer_best: metadata.best_number,
                connection_point: cp,
            };
            self.last_progress = Instant::now();
            self.send_skeleton_request_to(&peer_id, cp).await;
        } else {
            debug!(
                target: "rustock::sync",
                "Peer best hash unknown, searching for connection point below #{}",
                head.number
            );
            self.state = SyncState::FindingConnectionPoint {
                peer: peer_id,
                peer_best: metadata.best_number,
                start: 0,
                end: head.number,
                gallop: Some(1),
            };
            self.last_progress = Instant::now();
            self.send_connection_point_probe().await;
        }
    }

    async fn send_connection_point_probe(&self) {
        if let SyncState::FindingConnectionPoint { peer, start, end, gallop, .. } = &self.state {
            let height = connection_point_probe_height(*start, *end, *gallop);
            match gallop {
                Some(step) => debug!(
                    target: "rustock::sync",
                    "Probing connection point at #{} (galloping down from #{}, step {})",
                    height, end, step
                ),
                None => debug!(
                    target: "rustock::sync",
                    "Probing connection point at #{} (bisecting {}..{})",
                    height, start, end
                ),
            }
            let msg = create_block_hash_request(height);
            self.peer_store.send_to_peer(peer, msg).await;
        }
    }

    async fn send_skeleton_request_to(&self, peer: &B512, start: u64) {
        debug!(target: "rustock::sync", "Requesting skeleton from #{}", start);
        let msg = create_skeleton_request(start);
        self.peer_store.send_to_peer(peer, msg).await;
    }

    /// Sends a chunk request for `chunk_idx` in the skeleton to `peer`.
    async fn send_chunk_to_peer(
        &self,
        peer: &B512,
        skeleton: &[BlockIdentifier],
        connection_point: u64,
        chunk_idx: usize,
    ) {
        if chunk_idx == 0 || chunk_idx >= skeleton.len() {
            return;
        }

        let hash = skeleton[chunk_idx].hash;
        let height = skeleton[chunk_idx].number;
        let prev_height = skeleton[chunk_idx - 1].number;
        let prev_known = std::cmp::max(prev_height, connection_point);

        // Skip chunks already covered by the connection point
        if prev_known >= height {
            return;
        }

        let count = (height - prev_known) as u32;

        trace!(
            target: "rustock::sync",
            "Requesting {} headers from #{} (chunk {}/{}) -> peer {:?}",
            count, height, chunk_idx, skeleton.len() - 1,
            &peer.as_slice()[..4]
        );

        self.request_headers_from(peer, hash, count).await;
    }

    /// Fill the pipeline for all available peers.
    async fn fill_pipeline(&mut self) {
        if let SyncState::DownloadingHeaders {
            skeleton,
            connection_point,
            tracker,
            ..
        } = &mut self.state
        {
            let mut peers = self.peer_store.peers().await;
            if peers.is_empty() {
                return;
            }

            // A peer whose history starts above this skeleton cannot answer
            // any chunk in it. Asking anyway costs a round trip and a timeout
            // each, which is what the served range exists to avoid -- and
            // silence still means "ask me anything", so this narrows nothing
            // on a network of peers that do not state a range.
            let lowest_needed = *connection_point;
            let serving = self.peer_store.peers_serving(&peers, lowest_needed).await;
            if !serving.is_empty() {
                peers = serving;
            }

            // Exclude sidelined (stalled) peers; if every peer is sidelined,
            // forgive them all rather than stalling the round.
            let now = Instant::now();
            self.sidelined.retain(|_, until| *until > now);
            if peers.iter().any(|p| !self.sidelined.contains_key(p)) {
                peers.retain(|p| !self.sidelined.contains_key(p));
            } else {
                self.sidelined.clear();
            }

            // Collect assignments first, then send (to avoid borrow issues)
            let mut assignments: Vec<(B512, usize)> = Vec::new();
            for peer in &peers {
                let capacity = tracker.peer_capacity(peer);
                for _ in 0..capacity {
                    if let Some(idx) = tracker.next_assignment() {
                        tracker.record_sent(*peer, idx);
                        assignments.push((*peer, idx));
                    } else {
                        break;
                    }
                }
            }

            // Clone what we need for sending
            let skeleton_clone = skeleton.clone();
            let cp = *connection_point;

            for (peer, idx) in assignments {
                self.send_chunk_to_peer(&peer, &skeleton_clone, cp, idx).await;
            }
        }
    }

    /// Try to pre-fetch the next skeleton when we've sent the last chunk.
    async fn maybe_prefetch_skeleton(&mut self) {
        if let SyncState::DownloadingHeaders {
            tracker,
            skeleton,
            pending_next_skeleton,
            ..
        } = &self.state
        {
            // Pre-fetch when all chunks have been assigned but not all processed,
            // and we haven't already pre-fetched.
            if tracker.next_to_assign >= tracker.total_chunks
                && !tracker.is_complete()
                && pending_next_skeleton.is_none()
            {
                let last_height = skeleton.last().map(|b| b.number).unwrap_or(0);
                if self.last_prefetch_start == Some(last_height) {
                    return; // already requested; re-sending on every event spams peers
                }
                let peers = self.peer_store.peers().await;
                let peer = peers
                    .iter()
                    .find(|p| !self.sidelined.contains_key(*p))
                    .or_else(|| peers.first());
                if let Some(peer) = peer {
                    debug!(
                        target: "rustock::sync",
                        "Pre-fetching next skeleton from #{}",
                        last_height
                    );
                    let msg = create_skeleton_request(last_height);
                    self.peer_store.send_to_peer(peer, msg).await;
                    self.last_prefetch_start = Some(last_height);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Event handlers
    // -----------------------------------------------------------------------

    pub(crate) async fn handle_event(&mut self, event: SyncEvent) {
        // `--follow-up false` is an instruction not to catch up, and catching
        // up is more than starting a sync round: a header response, a body, an
        // announcement of a new tip all write chain data on arrival. Gating
        // only `try_start_sync` would leave a node that does not *begin* a
        // sync but still adopts whatever a peer pushes at it.
        //
        // `--read-only` is the defence behind this rather than the same
        // measure twice: if some path is missed here, the database refuses the
        // write rather than taking it. One is the instruction, the other is
        // what makes a mistake in carrying it out harmless.
        if !self.follow_up {
            match &event {
                SyncEvent::HeadersResponse { .. }
                | SyncEvent::HeadersWithUnclesResponse { .. }
                | SyncEvent::BodyResponse { .. }
                | SyncEvent::SkeletonResponse { .. }
                | SyncEvent::BlockHashResponse { .. }
                | SyncEvent::NewBlockHashes { .. }
                | SyncEvent::SnapStatusResponse { .. }
                | SyncEvent::SnapChunkResponse { .. }
                | SyncEvent::SnapBlocksResponse { .. } => {
                    trace!(
                        target: "rustock::sync",
                        "serving only (--follow-up false); dropping an inbound chain-data \
                         message"
                    );
                    return;
                }
            }
        }

        match event {
            SyncEvent::BlockHashResponse { hash, .. } => {
                self.on_block_hash_response(hash).await;
            }
            SyncEvent::SkeletonResponse { peer, id, identifiers } => {
                // A snap session's parallel walk shares the ordinary skeleton
                // message, so it is claimed by request id before the normal
                // path sees it.
                if self.snap.as_ref().is_some_and(|d| d.awaits_skeleton(id)) {
                    self.drive_snap(|driver, ps| driver.on_skeleton(id, peer, &identifiers, ps))
                        .await;
                    return;
                }
                self.on_skeleton_response(identifiers).await;
            }
            SyncEvent::HeadersResponse { peer, id, headers } => {
                // A snap session's header walk shares the ordinary headers
                // message, so it is claimed by request id before the normal
                // path sees it.
                if self.snap.as_ref().is_some_and(|d| d.awaits_headers(id)) {
                    self.drive_snap(|driver, ps| driver.on_headers(id, peer, &headers, ps))
                        .await;
                    return;
                }
                self.on_headers_response(peer, headers).await;
            }
            SyncEvent::HeadersWithUnclesResponse { peer, id, entries } => {
                // The snap walk's requests are upgraded to this message too,
                // so it is claimed by request id first, exactly as the plain
                // headers response is.
                if self.snap.as_ref().is_some_and(|d| d.awaits_headers(id)) {
                    self.drive_snap(|driver, ps| driver.on_headers_with_uncles(id, peer, &entries, ps))
                        .await;
                    return;
                }
                self.on_headers_with_uncles_response(peer, entries).await;
            }
            SyncEvent::BodyResponse { peer, id, transactions, uncles } => {
                self.on_body_response(peer, id, transactions, uncles).await;
            }
            SyncEvent::SnapStatusResponse {
                peer,
                id,
                blocks,
                difficulties,
                trie_size,
                chunk_grid,
            } => {
                // Resolved here rather than in the driver, which builds its
                // requests synchronously and cannot await a capability lookup.
                // The session needs it before `on_status`, which is where the
                // sampling gate is built or skipped.
                let serves_uncles = self
                    .peer_store
                    .capabilities(&peer)
                    .await
                    .is_some_and(|c| c.understands_header_uncles());
                if let Some(driver) = self.snap.as_mut() {
                    driver.set_peer_serves_uncles(serves_uncles);
                }
                self.drive_snap(|driver, ps| {
                    driver.on_status(id, peer, &blocks, &difficulties, trie_size, chunk_grid, ps)
                })
                .await;
            }
            SyncEvent::SnapChunkResponse { peer, id, payload, refusal, .. } => {
                self.drive_snap(|driver, ps| driver.on_chunk(id, peer, &payload, refusal, ps))
                    .await;
            }
            SyncEvent::SnapBlocksResponse { peer, id, blocks, difficulties } => {
                self.drive_snap(|driver, ps| driver.on_blocks(id, peer, &blocks, &difficulties, ps))
                    .await;
            }
            SyncEvent::NewBlockHashes { peer, identifiers } => {
                self.on_new_block_hashes(peer, identifiers).await;
            }
        }
    }

    pub(crate) async fn on_block_hash_response(&mut self, hash: B256) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::FindingConnectionPoint {
                peer, peer_best, start, end, gallop,
            } => {
                let probed = connection_point_probe_height(start, end, gallop);
                let known = match self.manager.store.has_block(hash) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            target: "rustock::sync",
                            "Storage error during connection-point search: {:?}", e
                        );
                        self.state = SyncState::Idle;
                        return;
                    }
                };

                match advance_connection_point(start, end, gallop, probed, known) {
                    Probe::NoCommonAncestor => {
                        // The gallop reached the bottom and even the peer's
                        // lowest block is not ours. This peer is following a
                        // different network's chain, and no amount of further
                        // searching will produce an ancestor.
                        warn!(
                            target: "rustock::sync",
                            "No common ancestor with peer {:?}: its chain shares \
                             nothing with ours",
                            &peer.0[..4]
                        );
                        if let Some(scoring) = &self.scoring {
                            scoring.record_peer(
                                peer,
                                rustock_networking::scoring::EventType::InvalidMessage,
                            );
                        }
                        self.state = SyncState::Idle;
                    }
                    Probe::Gallop { step } => {
                        self.state = SyncState::FindingConnectionPoint {
                            peer, peer_best, start, end, gallop: Some(step),
                        };
                        self.send_connection_point_probe().await;
                    }
                    Probe::Bisect { start: new_start, end: new_end }
                        if new_end.saturating_sub(new_start) <= 1 =>
                    {
                        let cp = new_start;
                        debug!(target: "rustock::sync", "Connection point found at #{}", cp);
                        self.state = SyncState::DownloadingSkeleton {
                            peer,
                            peer_best,
                            connection_point: cp,
                        };
                        self.send_skeleton_request_to(&peer, cp).await;
                    }
                    Probe::Bisect { start: new_start, end: new_end } => {
                        self.state = SyncState::FindingConnectionPoint {
                            peer, peer_best,
                            start: new_start,
                            end: new_end,
                            gallop: None,
                        };
                        self.send_connection_point_probe().await;
                    }
                }
            }
            other => {
                self.state = other;
            }
        }
    }

    pub(crate) async fn on_skeleton_response(&mut self, identifiers: Vec<BlockIdentifier>) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingSkeleton {
                peer: _, peer_best, connection_point,
            } => {
                if identifiers.len() < 2 {
                    debug!(
                        target: "rustock::sync",
                        "Skeleton too small ({} entries), entering follow mode",
                        identifiers.len()
                    );
                    self.state = SyncState::Following;
                    return;
                }

                debug!(
                    target: "rustock::sync",
                    "Received skeleton with {} points (#{} -> #{})",
                    identifiers.len(),
                    identifiers.first().map(|b| b.number).unwrap_or(0),
                    identifiers.last().map(|b| b.number).unwrap_or(0)
                );

                let chunks = std::cmp::min(identifiers.len(), MAX_SKELETON_CHUNKS + 1);
                let tracker = PeerChunkTracker::new(chunks);

                self.state = SyncState::DownloadingHeaders {
                    peer_best,
                    skeleton: identifiers,
                    connection_point,
                    tracker,
                    pending_next_skeleton: None,
                };
                self.fill_pipeline().await;
            }
            // If we're in DownloadingHeaders and receive a skeleton, it's the pre-fetch
            SyncState::DownloadingHeaders {
                peer_best, skeleton, connection_point, tracker,
                pending_next_skeleton: _,
            } => {
                debug!(
                    target: "rustock::sync",
                    "Received pre-fetched skeleton ({} points)",
                    identifiers.len()
                );
                self.state = SyncState::DownloadingHeaders {
                    peer_best,
                    skeleton,
                    connection_point,
                    tracker,
                    pending_next_skeleton: Some(identifiers),
                };
            }
            other => {
                self.state = other;
            }
        }
    }

    /// Ask `peer` for headers, with their uncles when it can supply them.
    ///
    /// Uncle difficulty counts toward total difficulty and lives only in
    /// bodies, so headers from an `rsk/62` peer -- every rskj node today --
    /// leave this node computing a lower bound. A peer at `rsk/63` sends the
    /// uncles alongside, making it exact. Asking an `rsk/62` peer for the new
    /// message would drop the connection, so the capability decides.
    async fn request_headers_from(&self, peer: &B512, hash: B256, count: u32) {
        let with_uncles = self
            .peer_store
            .capabilities(peer)
            .await
            .is_some_and(|c| c.understands_header_uncles());
        let msg = if with_uncles {
            self.manager.create_headers_with_uncles_request(hash, count)
        } else {
            self.manager.create_headers_request(hash, count)
        };
        self.peer_store.send_to_peer(peer, msg).await;
    }

    /// Headers that came with their uncles (`rsk/63`).
    ///
    /// The uncles are not stored -- they are not blocks of this chain -- but
    /// the cumulative difficulty they prove is recorded, so the ordinary
    /// header path computes a total difficulty that matches what rskj computes
    /// from bodies. Everything after that is the plain header flow.
    pub(crate) async fn on_headers_with_uncles_response(
        &mut self,
        peer: B512,
        entries: Vec<HeaderWithUncles>,
    ) {
        let headers = self.manager.note_proven_difficulties(entries);
        self.on_headers_response(peer, headers).await;
    }

    pub(crate) async fn on_headers_response(&mut self, peer: B512, headers: Vec<Header>) {
        rustock_core::metrics::HEADERS_RECEIVED.add(headers.len() as u64);
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingHeaders {
                peer_best,
                skeleton,
                connection_point,
                mut tracker,
                pending_next_skeleton,
            } => {
                // Match the response to a skeleton chunk by content, not FIFO order.
                // Peers may return responses out of order, so FIFO identification
                // would swap chunks and break the TD chain.
                // The highest block number in the response should match a skeleton entry.
                let chunk_idx = identify_chunk_by_content(&headers, &skeleton);

                // A chunk is only taken from a peer that was actually asked
                // for one. Content matching alone identifies *which* chunk a
                // response belongs to, not *who* was entitled to answer: any
                // connected peer can compute where the skeleton boundaries
                // fall and send headers ending on one.
                let solicited = tracker.has_outstanding(&peer);
                // Consume the FIFO entry for this peer regardless (keeps queue aligned)
                let _ = tracker.identify_response(&peer);

                match chunk_idx {
                    Some(idx) if idx < tracker.total_chunks && solicited => {
                        if !tracker.buffer_response(peer, idx, headers) {
                            debug!(
                                target: "rustock::sync",
                                "Chunk {} already answered; ignoring the copy from {:?}",
                                idx, &peer.0[..4]
                            );
                        }
                    }
                    Some(_) if !solicited => {
                        debug!(
                            target: "rustock::sync",
                            "Headers from {:?}, which has no chunk request outstanding; ignoring",
                            &peer.0[..4]
                        );
                    }
                    _ => {
                        // Response doesn't match any skeleton entry. This happens when
                        // stale responses from previous skeleton rounds arrive during a
                        // new round. Drop them — processing unordered headers with
                        // potentially-corrupted store TDs can set the head to an
                        // erroneously high TD, preventing legitimate chunks from advancing.
                        warn!(
                            target: "rustock::sync",
                            "Dropped unmatched headers response ({} headers, blocks #{}-#{})",
                            headers.len(),
                            headers.iter().map(|h| h.number).min().unwrap_or(0),
                            headers.iter().map(|h| h.number).max().unwrap_or(0),
                        );
                        self.state = SyncState::DownloadingHeaders {
                            peer_best, skeleton, connection_point, tracker,
                            pending_next_skeleton,
                        };
                        return;
                    }
                }

                // Process all consecutive ready chunks
                let ready = tracker.drain_ready();
                for (_idx, chunk_peer, chunk_headers) in &ready {
                    // A chunk that does not connect is a failure, not
                    // something to carry on past. Chunks are released in
                    // skeleton order, so the first header's parent is the last
                    // header of the chunk before it and must already be held.
                    // When it is not, the rest of the chunk has nothing to
                    // verify against and is refused — and continuing would
                    // leave a hole in the canonical index that halts execution
                    // when it is reached. Storing it unverified instead is the
                    // hole this change exists to close, so the answer is to
                    // stop and resync, charging the peer that served it.
                    let outcome =
                        self.manager.handle_headers_response(chunk_headers.clone(), *chunk_peer);

                    // A chunk that does not connect stops the round, but does
                    // not condemn the peer that served it.
                    //
                    // The two are separate judgements and were previously the
                    // same one. Stopping is right: continuing past a chunk
                    // whose tail has nothing to verify against leaves a hole
                    // in the canonical index that halts execution when it is
                    // reached. Condemning is not, because this node cannot
                    // tell the difference between a peer serving junk and its
                    // own head having moved under a request already in
                    // flight -- a reorg mid-round, or a late answer from a
                    // previous skeleton, produce exactly this observation and
                    // are nobody's fault.
                    //
                    // So it is treated the way a stalled peer is: sidelined
                    // from assignment for the sideline window, and recorded
                    // against a counter that does not gate `has_good_score`.
                    // A peer that does this once is skipped; one that does it
                    // every round is sidelined every round, never gets work,
                    // and leaves a record an operator can see. What it is no
                    // longer is permanently unusable after a single event
                    // whose cause may have been local.
                    if let Ok(o) = &outcome {
                        if o.unlinked > 0 {
                            warn!(
                                target: "rustock::sync",
                                "Chunk from peer {:?} did not connect: {} of {} headers had \
                                 no parent held. Dropping the round and resyncing; the peer \
                                 is sidelined, not charged -- this node cannot tell its \
                                 fault from a reorg under an in-flight request.",
                                &chunk_peer.0[..4], o.unlinked, chunk_headers.len()
                            );
                            self.sidelined
                                .insert(*chunk_peer, Instant::now() + PEER_SIDELINE_DURATION);
                            if let Some(scoring) = &self.scoring {
                                scoring.record_peer(
                                    *chunk_peer,
                                    rustock_networking::scoring::EventType::UnexpectedMessage,
                                );
                            }
                            self.state = SyncState::Idle;
                            return;
                        }
                        if o.rejected > 0 {
                            // Distinct, and unambiguous: these headers had a
                            // parent this node holds and failed verification
                            // against it. That is the peer's doing.
                            warn!(
                                target: "rustock::sync",
                                "Peer {:?} served {} header(s) that failed verification \
                                 against a parent this node holds",
                                &chunk_peer.0[..4], o.rejected
                            );
                        }
                    }

                    if let Err(e) = outcome.map_err(|e| format!("{e:?}")) {
                        error!(
                            target: "rustock::sync",
                            "Failed to process headers chunk: {}", e
                        );
                        // INVALID_HEADER is one of the three counters that
                        // cost reputation in rskj, so this is a punishing
                        // event -- which is right: a chunk that fails to
                        // validate came from a peer serving a chain we
                        // cannot use.
                        // `chunk_peer`, not `peer`: chunks are processed in
                        // skeleton order, so the response that triggered this
                        // drain is usually not the one carrying the bad chunk.
                        if let Some(scoring) = &self.scoring {
                            scoring.record_peer(
                                *chunk_peer,
                                rustock_networking::scoring::EventType::InvalidHeader,
                            );
                        }
                        self.state = SyncState::Idle;
                        return;
                    }
                }

                if tracker.is_complete() {
                    self.start_body_downloads(peer_best).await;
                } else {
                    // More chunks to go — restore state and refill pipeline
                    self.state = SyncState::DownloadingHeaders {
                        peer_best, skeleton, connection_point, tracker,
                        pending_next_skeleton,
                    };
                    self.fill_pipeline().await;
                    self.maybe_prefetch_skeleton().await;
                }
            }
            other => {
                let is_following = matches!(other, SyncState::Following);
                self.state = other;
                let before_height = self.our_head_number();
                let before_hash = self.manager.store.head().ok().flatten();
                let _ = self.manager.handle_headers_response(headers.clone(), peer);
                if is_following {
                    let after_height = self.our_head_number();
                    let after_hash = self.manager.store.head().ok().flatten();
                    if after_hash != before_hash {
                        if after_height > before_height {
                            info!(
                                target: "rustock::sync",
                                "New tip: #{}", after_height
                            );
                        } else {
                            info!(
                                target: "rustock::sync",
                                "Reorg: #{} -> #{} (new head {:?})",
                                before_height, after_height,
                                after_hash
                            );
                        }
                        self.request_follow_bodies(&headers).await;
                    }
                }

                // Headers we could not link are evidence that this peer has a
                // chain we cannot connect to. When enough of it has settled,
                // go and find where the two diverge.
                //
                // This is the half that makes refusing an unverifiable header
                // safe. Refusing without it leaves a node on a minority chain
                // with no way back: it asks only for blocks above its own
                // head, so the other chain's fork block is never requested and
                // nothing ever links. That is what stalled a node for an hour.
                self.maybe_search_for_fork(peer).await;
            }
        }
    }

    /// Starts a connection-point search if this peer's unlinked headers have
    /// settled into enough evidence to justify one.
    ///
    /// Only from `Following`. A search already under way, or a skeleton
    /// download in progress, is doing this work already, and interrupting it
    /// would let a peer that sends junk derail a sync that was going fine.
    async fn maybe_search_for_fork(&mut self, peer: B512) {
        if !matches!(self.state, SyncState::Following) {
            return;
        }

        // A peer still sending headers we cannot link after a search already
        // settled where its chain diverges is not serving the chain it agreed
        // on. That is the signal worth charging for: it survived the search
        // precisely because the search succeeded.
        if self.manager.unlinked_persisted_after_search(&peer) {
            warn!(
                target: "rustock::sync",
                "Peer {:?} keeps sending headers we cannot link after its chain was \
                 already resolved",
                &peer.0[..4]
            );
            if let Some(scoring) = &self.scoring {
                scoring.record_peer(
                    peer,
                    rustock_networking::scoring::EventType::InvalidMessage,
                );
            }
            self.manager.forget_peer(&peer);
            return;
        }

        let Verdict::SearchForFork { from } = self.manager.consider_fork_search(&peer) else {
            return;
        };

        let head = self.our_head_number();
        let peer_best = self
            .peer_store
            .metadata(&peer)
            .await
            .map(|m| m.best_number)
            .unwrap_or(head);

        info!(
            target: "rustock::sync",
            "Peer {:?} is on a chain we cannot connect to (lowest unlinked #{}); \
             searching for the fork point below our head #{}",
            &peer.0[..4], from, head
        );

        self.state = SyncState::FindingConnectionPoint {
            peer,
            peer_best,
            start: 0,
            end: head,
            gallop: Some(1),
        };
        self.last_progress = Instant::now();
        self.send_connection_point_probe().await;
    }

    /// Handle NewBlockHashes: fetch announced headers we don't have yet,
    /// and detect potential reorgs (different hash at a height we already have).
    /// Only active in Following state; ignored during skeleton sync.
    pub(crate) async fn on_new_block_hashes(&mut self, peer: B512, identifiers: Vec<BlockIdentifier>) {
        if !matches!(self.state, SyncState::Following) {
            trace!(
                target: "rustock::sync",
                "Ignoring NewBlockHashes ({} entries) — sync in progress",
                identifiers.len()
            );
            return;
        }

        let our_height = self.our_head_number();

        for id in &identifiers {
            if id.number > our_height {
                // New block ahead of our tip — request it
                let metadata = rustock_networking::peers::PeerMetadata {
                    best_number: id.number,
                    best_hash: id.hash,
                    total_difficulty: alloy_primitives::U256::ZERO,
                    client_id: String::new(),
                    address: None,
                earliest_block: None,
                };
                self.peer_store.update_metadata(&peer, metadata).await;

                let count = (id.number - our_height) as u32;
                trace!(
                    target: "rustock::sync",
                    "NewBlockHashes: requesting {} headers up to #{} from peer {:?}",
                    count, id.number, &peer.as_slice()[..4]
                );
                self.request_headers_from(&peer, id.hash, count).await;
            } else {
                // Block at or below our height — check for reorg candidate
                let canonical = self.manager.store
                    .canonical_hash(id.number)
                    .ok()
                    .flatten();

                if canonical == Some(id.hash) {
                    continue; // same block, nothing to do
                }

                // Different hash at a height we already have — potential reorg.
                // Request enough headers to cover a shallow fork.
                let count = std::cmp::min(LONG_SYNC_LIMIT, id.number) as u32;
                debug!(
                    target: "rustock::sync",
                    "NewBlockHashes: reorg candidate at #{} (canonical {:?}, announced {:?}), requesting {} headers",
                    id.number,
                    canonical.map(|h| format!("{:?}", h)).unwrap_or_else(|| "none".into()),
                    id.hash,
                    count
                );
                self.request_headers_from(&peer, id.hash, count).await;
            }
        }
    }

    /// In Following state, periodically check if we've fallen too far behind
    /// and need to switch back to skeleton sync.
    pub(crate) async fn check_follow_gap(&mut self) {
        let best_peer = self.peer_store.best_peer().await;
        let (peer_id, metadata) = match best_peer {
            Some(p) => p,
            None => return,
        };

        let our_height = self.our_head_number();
        if our_height == 0 {
            return;
        }

        if metadata.best_number > our_height + LONG_SYNC_LIMIT {
            // Don't open a fresh round while a batch is parked waiting to
            // execute (that would put a batch beyond the one-ahead cap in
            // flight). A batch merely executing is fine — that's the point of
            // pipelining, and finish_batch parks rather than over-fetches.
            if self.pending_exec.is_some() {
                return;
            }
            info!(
                target: "rustock::sync",
                "Fell behind by {} blocks, switching to skeleton sync",
                metadata.best_number - our_height
            );
            self.state = SyncState::Idle;
            self.try_start_sync().await;
        } else if metadata.best_number > our_height {
            // Small gap: a peer's tip is ahead but not far enough for skeleton
            // sync. Peers may only advertise their tip via STATUS (updating
            // best_number) without pushing a NewBlockHashes, so pull the
            // missing headers proactively instead of waiting for an
            // announcement — otherwise the node stalls forever in follow mode.
            // Re-issued each tick; harmless (idempotent store) and doubles as a
            // retry if a response is dropped.
            let count = (metadata.best_number - our_height) as u32;
            debug!(
                target: "rustock::sync",
                "Follow gap of {} blocks, requesting headers up to #{}",
                count, metadata.best_number
            );
            self.request_headers_from(&peer_id, metadata.best_hash, count).await;
        }
    }

    /// Return our current head block number (0 if unknown).
    fn our_head_number(&self) -> u64 {
        self.manager
            .store
            .head()
            .ok()
            .flatten()
            .and_then(|h| self.manager.store.header(h).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0)
    }

    /// After all headers in a skeleton round are downloaded, transition to
    /// body downloading. ALL blocks past the cursor are queued so they are
    /// executed in order; bodies already in the store are not re-requested.
    pub(crate) async fn start_body_downloads(&mut self, peer_best: u64) {
        let our_height = self.our_head_number();
        let start = self.last_body_height + 1;

        let mut pending = Vec::new();
        let mut missing_bodies = 0usize;
        for num in start..=our_height {
            if let Ok(Some(hash)) = self.manager.store.canonical_hash(num) {
                if let Ok(Some(header)) = self.manager.store.header(hash) {
                    if matches!(self.manager.store.body(hash), Ok(None))
                        && !self.try_fill_body_locally(hash)
                    {
                        missing_bodies += 1;
                    }
                    pending.push((hash, header));
                }
            }
        }

        if pending.is_empty() {
            debug!(
                target: "rustock::sync",
                "No blocks pending past #{}", self.last_body_height
            );
            self.last_body_height = our_height;
            self.continue_after_bodies(peer_best).await;
            return;
        }

        if missing_bodies == 0 {
            debug!(
                target: "rustock::sync",
                "All {} bodies already stored, executing", pending.len()
            );
            self.finish_batch(&pending, peer_best).await;
            return;
        }

        info!(
            target: "rustock::sync",
            "Starting body download for {} blocks (#{} to #{}, {} bodies to fetch)",
            pending.len(),
            pending.first().map(|(_, h)| h.number).unwrap_or(0),
            pending.last().map(|(_, h)| h.number).unwrap_or(0),
            missing_bodies,
        );

        self.state = SyncState::DownloadingBodies {
            peer_best,
            pending_headers: pending,
            next_request: 0,
            in_flight: HashMap::new(),
            id_index: HashMap::new(),
        };
        self.last_progress = Instant::now();
        self.send_body_requests().await;
    }

    /// A batch (N) finished downloading. Advance the *download* cursor and,
    /// respecting the one-batch-ahead cap, either kick off N's execution on a
    /// blocking thread (freeing the event loop to download N+1) or — if a
    /// previous batch is still executing — park this batch until it completes.
    pub(crate) async fn finish_batch(&mut self, pending: &[(B256, Header)], peer_best: u64) {
        // The download succeeded: advance the download cursor so the next
        // skeleton round queues the blocks that follow this batch. Execution
        // (the exec_head cursor) advances independently when the spawned job
        // completes.
        self.last_body_height = pending
            .last()
            .map(|(_, h)| h.number)
            .unwrap_or(self.last_body_height);

        // No execution configured (header/body-only sync): keep the original
        // straight-through behaviour.
        if self.exec_fn.is_none() {
            self.continue_after_bodies(peer_best).await;
            return;
        }

        if self.executing.is_some() {
            // A previous batch is still executing. Cap depth at one: park this
            // batch and stop downloading (no N+2). It will be executed — and
            // downloads resumed — when the running job is reaped in on_tick.
            // The "at most one parked batch" invariant holds because we never
            // download a further batch while pending_exec is set.
            debug!(
                target: "rustock::sync",
                "Batch downloaded (up to #{}) while previous batch still executing; parking",
                self.last_body_height
            );
            self.pending_exec = Some((pending.to_vec(), peer_best));
            self.state = SyncState::Idle;
        } else {
            // Nothing executing: start this batch on a blocking thread and
            // immediately continue downloading the next batch concurrently.
            self.spawn_execution(pending.to_vec(), peer_best);
            self.continue_after_bodies(peer_best).await;
        }
    }

    /// Move execution of `pending` off the async event loop onto a blocking
    /// thread and track it as `self.executing`. Execution owns the trie state;
    /// concurrent downloading only writes headers/bodies (an independent key
    /// space) and touches network state, so the two cannot race.
    fn spawn_execution(&mut self, pending: Vec<(B256, Header)>, peer_best: u64) {
        let (Some(exec_fn), Some(ambient)) =
            (self.exec_fn.clone(), self.current_state_root.clone())
        else {
            // No processor configured — should not reach here (finish_batch
            // guards on it), but stay safe and just advance.
            return;
        };
        // Execute against the state this batch's first block builds on, not
        // against wherever execution happens to be standing.
        let state_root = self.state_for_batch(&pending).unwrap_or(ambient);
        let blocks_since_flush = self.blocks_since_flush;
        let handle = tokio::task::spawn_blocking(move || {
            exec_fn(state_root, blocks_since_flush, pending)
        });
        self.executing = Some(ExecutionJob { handle, peer_best });
    }

    /// The state a batch must be executed against: the one its first block's
    /// parent committed.
    ///
    /// Returns `None` when the ambient root is already correct, or when the
    /// parent's state cannot be resolved — the caller then falls back to
    /// `current_state_root`, which is the behaviour this replaces.
    ///
    /// Executing a block is a function of two things, the block and the state
    /// it is applied to. The block is fixed; the state was not. The body
    /// pipeline passed `self.current_state_root` — a field, mutated by every
    /// other execution path — when the answer is fully determined by the block
    /// itself. Follow mode has refused to execute against a root that is not
    /// its parent's since #326; this path had no such check, and that
    /// asymmetry is the bug.
    ///
    /// Mainnet 2026-10-23, #9,350,770. Follow mode executed it correctly and
    /// produced the header's root. A reorg then retreated the committed
    /// `exec_head` to #9,350,769 without telling the in-memory root, which
    /// still held "after #9,350,770". Twenty-four seconds later this path
    /// re-executed #9,350,770 against that root — applying the block on top of
    /// itself — and computed a different state. The tick-level guard,
    /// `resync_state_root_with_exec_head`, fired 0.1s afterwards: it runs on a
    /// timer and the bug is a race, which is why no amount of tightening the
    /// timer fixes it.
    ///
    /// rskj cannot reach this state at all, because it executes against
    /// `parent.getHeader()` rather than a head pointer -- see
    /// `docs/follow-mode-rskj-vs-rustock.md` §7. Adopting that rule here needs
    /// no equivalent of its `stateRootHandler`: rustock verifies the computed
    /// root against the header on every block, so the parent header's
    /// `state_root` *is* the state the child must build on, already stored.
    ///
    /// Note what this does to a duplicated batch rather than a wrong one.
    /// Re-executing a block the node has already executed is now harmless: it
    /// is applied to its parent's state again and recomputes the same result.
    /// The failure above becomes a redundant execution instead of a halt.
    pub(crate) fn state_for_batch(&self, pending: &[(B256, Header)]) -> Option<TrieNode> {
        let trie_store = self.trie_store.as_ref()?;
        let (_, first) = pending.first()?;
        let parent = self.manager.store.header(first.parent_hash).ok().flatten()?;

        // Already standing on the right state: the overwhelmingly common case,
        // and it costs one memoised hash.
        let ambient = self.current_state_root.as_ref()?;
        if ambient.compute_hash(trie_store.as_ref()) == parent.state_root {
            return None;
        }

        // The parent's state must actually be there. A node that has pruned
        // it, or has not yet executed that far, falls back rather than
        // refusing -- this change is meant to remove a way of being wrong, not
        // to add a way of stopping.
        let data = trie_store.get(parent.state_root.as_slice())?;
        let node = TrieNode::from_message(&data, trie_store.as_ref());
        // The store can hold bytes under a hash they do not hash to; executing
        // against those is the consensus error this exists to prevent.
        if node.compute_hash(trie_store.as_ref()) != parent.state_root {
            warn!(
                target: "rustock::sync",
                "Not using the parent state for #{}: the trie store's entry for {:?} \
                 does not hash to it",
                first.number, parent.state_root
            );
            return None;
        }
        info!(
            target: "rustock::sync",
            "Executing #{} against its parent's committed state {:?}, not the in-memory \
             root {:?} that execution was standing on",
            first.number,
            parent.state_root,
            ambient.compute_hash(trie_store.as_ref())
        );
        Some(node)
    }

    /// If a background execution job has finished, reap it and apply the
    /// outcome (advance the execution cursor or halt). On success, start any
    /// parked next batch and resume downloading; on failure, halt the sync.
    async fn poll_execution(&mut self) {
        let Some(job) = &mut self.executing else { return };
        if !job.handle.is_finished() {
            return;
        }
        let job = self.executing.take().unwrap();
        let outcome = match job.handle.await {
            Ok(o) => o,
            Err(e) => {
                error!(target: "rustock::sync", "Block execution task panicked: {e}");
                self.halt_after_exec_failure();
                return;
            }
        };
        self.blocks_since_flush = outcome.blocks_since_flush;
        self.current_state_root = Some(outcome.new_state_root);

        if !outcome.all_ok {
            self.halt_after_exec_failure();
            return;
        }

        // The batch executed cleanly, so every body in it was a real block.
        // Credited here rather than inside the executor: that runs on its own
        // thread over a range, and reaping it on the main loop is where the
        // outcome and the scoring table are both in hand.
        if let Ok(Some((hash, _))) = self.manager.store.exec_head() {
            if let Ok(Some(header)) = self.manager.store.header(hash) {
                self.credit_executed_bodies(header.number);
            }
        }

        // The batch executed cleanly. If a next batch was parked, execute it
        // now (and only now may downloading resume past the cap). Otherwise
        // continue the normal download flow if we weren't already mid-round.
        if let Some((pending, peer_best)) = self.pending_exec.take() {
            self.spawn_execution(pending, job.peer_best);
            // Resume downloading the batch after the one we just started.
            if matches!(self.state, SyncState::Idle) {
                self.continue_after_bodies(peer_best).await;
            }
        }
    }

    /// A block failed to execute (or its body/parent was missing). Do not
    /// advance past it: reset the download cursor to the executed head so the
    /// retry re-downloads and re-executes from there, drop any parked batch
    /// (it must not execute on the wrong parent state — its already-stored
    /// bodies are kept and reused), and go Idle. Mirrors rskj treating such a
    /// block as invalid and stopping there.
    fn halt_after_exec_failure(&mut self) {
        let exec_number = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.manager.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0);
        self.last_body_height = exec_number;
        self.pending_exec = None;
        if self.futile_exec_halts.0 == exec_number {
            self.futile_exec_halts.1 += 1;
        } else {
            self.futile_exec_halts = (exec_number, 1);
        }
        error!(
            target: "rustock::sync",
            "Sync halted: block execution failed; will retry from executed head #{exec_number}"
        );
        self.state = SyncState::Idle;
    }

    /// After body downloads (or when no bodies needed), decide whether to
    /// continue syncing headers or enter follow mode.
    async fn continue_after_bodies(&mut self, peer_best: u64) {
        let our_height = self.our_head_number();
        if our_height < peer_best {
            debug!(
                target: "rustock::sync",
                "Skeleton round complete (head #{}, peer #{}), requesting next skeleton",
                our_height, peer_best
            );
            let next_peer = self.peer_store.best_peer().await
                .map(|(id, _)| id)
                .unwrap_or(B512::ZERO);
            self.state = SyncState::DownloadingSkeleton {
                peer: next_peer,
                peer_best,
                connection_point: our_height,
            };
            self.send_skeleton_request_to(&next_peer, our_height).await;
        } else {
            info!(
                target: "rustock::sync",
                "Sync complete! Head at #{}, entering follow mode", our_height
            );
            self.state = SyncState::Following;
        }
    }

    /// In Following mode, request bodies for newly received block headers.
    async fn request_follow_bodies(&mut self, headers: &[Header]) {
        let peers = self.peer_store.peers().await;
        if peers.is_empty() {
            return;
        }
        for header in headers {
            let hash = header.hash();
            if self.manager.store.body(hash).ok().flatten().is_none() {
                let (req_id, msg) = create_body_request(hash);
                let peer = &peers[0];
                self.peer_store.send_to_peer(peer, msg).await;
                self.pending_follow_bodies
                    .insert(req_id, (hash, header.clone(), Instant::now(), *peer));
            }
        }
    }

    /// Send body requests for pending headers up to a bounded window, assigning
    /// each to the least-loaded responsive peer. RSK is one body per request,
    /// so throughput comes from pipelining many in flight — concentrated on the
    /// peers that actually answer rather than spread evenly onto slow ones.
    pub(crate) async fn send_body_requests(&mut self) {
        // Not an early return on an empty peer set. Two of the arms below need
        // no peer at all -- a body already in the store, and one derivable
        // from its header -- and returning here left a batch that needed
        // nothing from the network waiting on a peer to arrive before it could
        // be recognised as finished. The request path is still guarded: with
        // no peers `pick_body_peer` yields None and the loop breaks at the
        // first body that genuinely has to be asked for.
        let peers = self.peer_store.peers().await;
        if peers.is_empty() {
            debug!(target: "rustock::sync", "No connected peers for body requests");
        }
        let SyncService {
            state,
            body_peer_strikes,
            peer_store,
            manager,
            derived_bodies,
            underivable,
            ..
        } = self;
        let SyncState::DownloadingBodies {
            pending_headers,
            next_request,
            in_flight,
            id_index,
            ..
        } = state
        else {
            return;
        };

        // The global in-flight window should be the sum of what each peer will
        // accept, not half of it. `peers.len() * 8` with a ceiling of 96 left
        // most of the allowed concurrency unused: at 13 peers the per-peer limit
        // permits 208 outstanding requests but this clamped to 96.
        //
        // BodyRequest carries a single hash (protocol-fixed), so the number of
        // requests in flight *is* the download throughput -- there is no batching
        // to trade against it. Each peer is still independently bounded by
        // MAX_BODY_REQUESTS_PER_PEER in pick_body_peer, so raising the global
        // ceiling cannot make us impolite to any individual peer.
        let max_in_flight =
            (peers.len() * MAX_BODY_REQUESTS_PER_PEER).clamp(8, MAX_TOTAL_BODY_REQUESTS);
        let mut load = peer_body_load(&peers, in_flight);
        let mut sent = 0u32;
        while in_flight.len() < max_in_flight && *next_request < pending_headers.len() {
            let idx = *next_request;
            let (hash, _header) = &pending_headers[idx];
            // Bodies already in the store don't need a request.
            if matches!(manager.store.body(*hash), Ok(Some(_))) {
                *next_request += 1;
                continue;
            }

            // Nor does one the header already determines. The protocol
            // carries a single body per request, so each one skipped is a
            // whole round trip saved, and around a fifth of mainnet
            // qualifies. Storing it here is all that is needed: this loop
            // and the completion check both key off the store, so a derived
            // body advances the batch exactly as a delivered one does.
            if !underivable.contains(hash) {
                match crate::body_check::derivable_body(_header) {
                    Some(transactions) => {
                        match manager.store.put_body(*hash, &transactions, &[]) {
                            Ok(()) => {
                                *derived_bodies += 1;
                                rustock_core::metrics::BODIES_DERIVED.inc();
                                trace!(
                                    target: "rustock::sync",
                                    "Derived body for #{} instead of requesting it",
                                    _header.number
                                );
                                *next_request += 1;
                                continue;
                            }
                            // Storing failed, so ask for it the ordinary way
                            // rather than lose the block. Not marked
                            // underivable: the header was fine, the store
                            // was not.
                            Err(e) => warn!(
                                target: "rustock::sync",
                                "Could not store derived body for #{}: {e:?}; requesting it",
                                _header.number
                            ),
                        }
                    }
                    // Remembered so the predicate is paid once per header.
                    // No peer is charged, because no peer sent anything.
                    None => {
                        underivable.insert(*hash);
                    }
                }
            }
            let Some(peer) = pick_body_peer(&load, body_peer_strikes, None) else {
                // Every peer is at its per-peer cap; stop topping up and let
                // responses free slots before sending more.
                break;
            };
            let (req_id, msg) = create_body_request(*hash);
            if !peer_store.send_to_peer(&peer, msg).await {
                debug!(
                    target: "rustock::sync",
                    "Failed to send body request to peer {:?}, leaving for retry",
                    &peer.0[..4]
                );
            } else {
                sent += 1;
            }
            // Track the request even if the send failed (peer may have just
            // disconnected): the reclaim timeout re-sends it. Dropping it here
            // would orphan the block and the batch could never finish.
            in_flight.insert(idx, InFlightBody { req_id, sent: Instant::now(), peer });
            id_index.insert(req_id, (idx, peer));
            // Counted here rather than on a successful send, because the
            // request is tracked here either way: a send that failed is
            // still outstanding and still waiting on the reclaim timeout.
            rustock_core::metrics::BODIES_REQUESTED.inc();
            rustock_core::metrics::BODY_REQUESTS_IN_FLIGHT.set(in_flight.len() as u64);
            *load.entry(peer).or_default() += 1;
            *next_request += 1;
        }
        if sent > 0 {
            debug!(
                target: "rustock::sync",
                "Sent {sent} body requests ({} in-flight, {} pending)",
                in_flight.len(),
                pending_headers.len().saturating_sub(*next_request)
            );
        }
    }

    /// Is the body pipeline waiting on nobody?
    fn body_requests_idle(&self) -> bool {
        matches!(
            &self.state,
            SyncState::DownloadingBodies { in_flight, .. } if in_flight.is_empty()
        )
    }

    /// Hand a body batch to execution when it completed without a response.
    ///
    /// Returns true if the batch was handed over.
    ///
    /// `DownloadingBodies` is driven entirely by `on_body_response`, which
    /// holds the only check that the batch is complete. That is sound only if
    /// every header in the batch is waiting on a peer, and two of them need
    /// not be: `send_body_requests` skips a header whose body is already in
    /// the store, and derives and stores one the header itself determines.
    /// Both are a `continue` that sends nothing. When they absorb the last
    /// outstanding header, `in_flight` empties with no request outstanding and
    /// no response will ever arrive to run the completion check.
    ///
    /// `start_body_downloads` means to catch this with its `missing_bodies ==
    /// 0` early-out, but it counts a header as missing from `store.body` and
    /// `try_fill_body_locally` alone -- it does not consult `derivable_body`.
    /// So a batch that needs no network at all still enters the state, and
    /// then cannot leave it.
    ///
    /// Nothing else rescues it. `retry_stale_body_requests` returns early on
    /// an empty `in_flight`, and `DownloadingBodies` has its own `on_tick`
    /// arm, so it never reaches the `REQUEST_TIMEOUT` reset in the fallback
    /// arm. The node sits on a fully downloaded batch until the execution
    /// watchdog restarts the pipeline 120s later -- 1.9 times an hour on
    /// mainnet, and the whole of what was left of #323 once the follow-mode
    /// refusal was removed.
    async fn finish_body_batch_if_complete(&mut self) -> bool {
        let SyncState::DownloadingBodies { pending_headers, in_flight, .. } = &self.state
        else {
            return false;
        };
        if !in_flight.is_empty() {
            return false;
        }
        // Completeness is every body being in the store, not the request
        // cursor reaching the end. The cursor is the wrong question twice
        // over: it does not move when the loop breaks for want of a peer, and
        // it moves past a header whose derived body failed to store. Execution
        // is what pays for the difference, so ask the store.
        if !pending_headers
            .iter()
            .all(|(hash, _)| matches!(self.manager.store.body(*hash), Ok(Some(_))))
        {
            return false;
        }

        let SyncState::DownloadingBodies { pending_headers, peer_best, .. } =
            std::mem::take(&mut self.state)
        else {
            return false;
        };
        info!(
            target: "rustock::sync",
            "All {} block bodies present with no request outstanding \
             ({} derived from their headers so far)",
            pending_headers.len(),
            self.derived_bodies
        );
        self.finish_batch(&pending_headers, peer_best).await;
        true
    }

    /// Reclaim body requests outstanding past `BODY_RECLAIM_TIMEOUT`: re-send
    /// each to a different, responsive peer with a fresh id (the old id stays
    /// mapped in `id_index`, so a late response still applies). The peer a
    /// request timed out on takes a strike, so dead peers stop receiving work.
    pub(crate) async fn retry_stale_body_requests(&mut self) {
        // Find timed-out requests first (cheap, no await) and bail if none.
        let stale: Vec<usize> = match &self.state {
            SyncState::DownloadingBodies { in_flight, .. } => in_flight
                .iter()
                .filter(|(_, req)| req.sent.elapsed() > BODY_RECLAIM_TIMEOUT)
                .map(|(idx, _)| *idx)
                .collect(),
            _ => return,
        };
        if stale.is_empty() {
            return;
        }

        let peers = self.peer_store.peers().await;
        if peers.is_empty() {
            warn!(target: "rustock::sync", "No peers for body retry");
            return;
        }

        let SyncService { state, body_peer_strikes, peer_store, scoring, .. } = self;
        let SyncState::DownloadingBodies { pending_headers, in_flight, id_index, .. } = state
        else {
            return;
        };

        let mut load = peer_body_load(&peers, in_flight);
        let count = stale.len();
        for idx in stale {
            // Free the timed-out peer's slot and give it a strike.
            let old_peer = in_flight.get(&idx).map(|r| r.peer);
            if let Some(p) = old_peer {
                *body_peer_strikes.entry(p).or_default() += 1;
                if let Some(scoring) = scoring.as_ref() {
                    // The strike is round-local and forgotten on the next
                    // successful body; the scoring counter is not.
                    scoring.record_peer(
                        p,
                        rustock_networking::scoring::EventType::TimeoutMessage,
                    );
                }
                if let Some(c) = load.get_mut(&p) {
                    *c = c.saturating_sub(1);
                }
            }
            let Some(peer) = pick_body_peer(&load, body_peer_strikes, old_peer) else {
                break;
            };
            let (hash, header) = &pending_headers[idx];
            debug!(
                target: "rustock::sync",
                "Stalled body request: block #{} hash {:?}",
                header.number, hash
            );
            let (req_id, msg) = create_body_request(*hash);
            let _ = peer_store.send_to_peer(&peer, msg).await;
            // Point this block at the new request, but keep the old id in
            // `id_index` so a late response to it still lands.
            in_flight.insert(idx, InFlightBody { req_id, sent: Instant::now(), peer });
            id_index.insert(req_id, (idx, peer));
            *load.entry(peer).or_default() += 1;
        }
        info!(
            target: "rustock::sync",
            "Retried {count} stalled body requests across {} peers",
            peers.len()
        );
    }

    /// A peer sent a body that is not the one its header commits to.
    ///
    /// Charged to whoever *sent* it rather than whoever was asked: a body is
    /// good whatever its route, so blame has to follow the sender for a
    /// request to be safely retried elsewhere. The body is not stored and the
    /// request is left outstanding, so the ordinary retry path asks somebody
    /// else.
    fn charge_bad_body(&self, peer: B512, number: u64, what: &str) {
        warn!(
            target: "rustock::sync",
            "Peer {peer:?} sent a body for #{number} whose {what} do not match the \
             header; not storing it"
        );
        if let Some(scoring) = &self.scoring {
            scoring.record_peer(peer, rustock_networking::scoring::EventType::InvalidBlock);
        }
    }

    /// Credit every peer whose body has now executed, up to and including
    /// `through`.
    ///
    /// Called from both execution paths, because "the block executed to the
    /// state root its header claims" is the only evidence that is worth a
    /// credit -- a body that merely matched its header proves the peer copied
    /// correctly, not that it gave us a real block.
    pub(crate) fn credit_executed_bodies(&mut self, through: u64) {
        let done: Vec<u64> = self
            .body_providers
            .keys()
            .copied()
            .filter(|n| *n <= through)
            .collect();
        for number in done {
            let Some(peer) = self.body_providers.remove(&number) else { continue };
            if let Some(scoring) = &self.scoring {
                scoring.record_peer(peer, rustock_networking::scoring::EventType::ValidBlock);
            }
        }
        // A halt can leave entries above the executed head that will never be
        // credited, so the map cannot be allowed to grow on its own. It is
        // naturally the size of the download window; well past that, the
        // oldest are stale by definition.
        const MAX_TRACKED: usize = 20_000;
        if self.body_providers.len() > MAX_TRACKED {
            let mut numbers: Vec<u64> = self.body_providers.keys().copied().collect();
            numbers.sort_unstable();
            for number in numbers.iter().take(self.body_providers.len() - MAX_TRACKED) {
                self.body_providers.remove(number);
            }
        }
    }

    pub(crate) async fn on_body_response(
        &mut self,
        peer: B512,
        request_id: u64,
        transactions: Vec<Transaction>,
        uncles: Vec<Header>,
    ) {
        rustock_core::metrics::BODIES_RECEIVED.inc();
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingBodies {
                peer_best,
                pending_headers,
                next_request,
                mut in_flight,
                mut id_index,
            } => {
                // Route via id_index, which keeps superseded request ids mapped
                // so a late response to a retried request still applies.
                // A body is taken only from the peer the request was sent to.
                // The id is unguessable, so this is belt-and-braces -- but it
                // is the check that keeps the binding true if the id ever
                // stops being random.
                let idx = match id_index.get(&request_id) {
                    Some((i, asked)) if *asked == peer => {
                        let i = *i;
                        id_index.remove(&request_id);
                        i
                    }
                    Some(_) => {
                        debug!(
                            target: "rustock::sync",
                            "Body for request {} came from {:?}, which was not asked; ignoring",
                            request_id, &peer.0[..4]
                        );
                        self.state = SyncState::DownloadingBodies {
                            peer_best,
                            pending_headers,
                            next_request,
                            in_flight,
                            id_index,
                        };
                        return;
                    }
                    None => {
                        debug!(
                            target: "rustock::sync",
                            "Body response for unknown request {} (already received or foreign); ignoring",
                            request_id
                        );
                        self.state = SyncState::DownloadingBodies {
                            peer_best,
                            pending_headers,
                            next_request,
                            in_flight,
                            id_index,
                        };
                        return;
                    }
                };

                // First body to arrive for this block (still outstanding) → store
                // it. Otherwise it's a duplicate of an already-stored block (an
                // earlier retry already landed) → drop silently, no re-fetch.
                if let Some(req) = in_flight.remove(&idx) {
                    // The peer that answered is responsive, so its strikes go.
                    // Crediting the peer the request was sent to would clear
                    // strikes it has not earned.
                    self.body_peer_strikes.remove(&peer);
                    let (hash, header) = &pending_headers[idx];

                    // Does this body belong to that header? Receipt is the one
                    // moment the sender is unambiguous, and two hashes settle
                    // it. A mismatch is not stored and the request goes back
                    // in flight, so the stall path asks somebody else.
                    if let Some(what) =
                        crate::body_check::body_mismatch(header, &transactions, &uncles)
                    {
                        self.charge_bad_body(peer, header.number, what);
                        in_flight.insert(idx, req);
                        id_index.insert(request_id, (idx, peer));
                        self.state = SyncState::DownloadingBodies {
                            peer_best,
                            pending_headers,
                            next_request,
                            in_flight,
                            id_index,
                        };
                        return;
                    }
                    self.body_providers.insert(header.number, peer);

                    if let Err(e) = self.manager.store.put_body(*hash, &transactions, &uncles) {
                        error!(
                            target: "rustock::sync",
                            "Failed to store body for {:?}: {:?}", hash, e
                        );
                    }
                    trace!(
                        target: "rustock::sync",
                        "Stored body for block {:?} ({} txs, {} uncles)",
                        hash, transactions.len(), uncles.len()
                    );
                } else {
                    trace!(
                        target: "rustock::sync",
                        "Duplicate body for already-stored block (req {}); ignoring",
                        request_id
                    );
                }

                // Advance past entries whose bodies are already stored, then
                // check whether the whole batch is downloaded.
                let mut next_request = next_request;
                while next_request < pending_headers.len()
                    && matches!(
                        self.manager.store.body(pending_headers[next_request].0),
                        Ok(Some(_))
                    )
                {
                    next_request += 1;
                }
                let all_done = next_request >= pending_headers.len() && in_flight.is_empty();
                if all_done {
                    info!(
                        target: "rustock::sync",
                        "All {} block bodies downloaded ({} derived from their headers so far)",
                        pending_headers.len(),
                        self.derived_bodies
                    );
                    self.finish_batch(&pending_headers, peer_best).await;
                } else {
                    self.state = SyncState::DownloadingBodies {
                        peer_best,
                        pending_headers,
                        next_request,
                        in_flight,
                        id_index,
                    };
                    self.send_body_requests().await;
                }
            }
            SyncState::Following => {
                self.state = SyncState::Following;
                let asked = self.pending_follow_bodies.get(&request_id).map(|e| e.3);
                if asked.is_some_and(|a| a != peer) {
                    debug!(
                        target: "rustock::sync",
                        "Follow body for request {} came from {:?}, which was not asked; ignoring",
                        request_id, &peer.0[..4]
                    );
                    return;
                }
                if let Some((hash, header, sent, _asked)) =
                    self.pending_follow_bodies.remove(&request_id)
                {
                    // Same check as the batch path, same reason.
                    if let Some(what) =
                        crate::body_check::body_mismatch(&header, &transactions, &uncles)
                    {
                        self.charge_bad_body(peer, header.number, what);
                        // Put it back so the follow-mode retry re-requests it;
                        // dropping the entry would strand the block instead.
                        self.pending_follow_bodies
                            .insert(request_id, (hash, header, sent, peer));
                        return;
                    }
                    self.body_providers.insert(header.number, peer);

                    if let Err(e) = self.manager.store.put_body(hash, &transactions, &uncles) {
                        error!(
                            target: "rustock::sync",
                            "Failed to store follow-mode body for {:?}: {:?}", hash, e
                        );
                        return;
                    }
                    debug!(
                        target: "rustock::sync",
                        "Stored body for block #{} ({} txs) in follow mode",
                        header.number, transactions.len()
                    );
                    // Buffer by number and execute only consecutive,
                    // parent-linked blocks: bodies for a multi-block gap can
                    // arrive out of order, and running one against the wrong
                    // parent state forks our trie from the network.
                    self.follow_buffer
                        .insert(header.number, (hash, header, transactions, uncles));
                    self.drain_follow_buffer().await;
                }
            }
            other => {
                self.state = other;
            }
        }
    }

    /// Execute buffered follow-mode blocks in strict block-number order,
    /// starting from the executed head. Stops at the first gap (a buffered
    /// block whose parent isn't our current head — its predecessor hasn't
    /// arrived yet) or the first execution failure.
    pub(crate) async fn drain_follow_buffer(&mut self) {
        // Never execute a follow-mode block while a batch is executing in the
        // background or parked waiting to run.
        //
        // The batch thread commits each block as it goes, so `exec_head` in the
        // store advances while `self.current_state_root` -- the in-memory trie
        // root this path executes against -- still holds the pre-batch state
        // until `poll_execution` reaps the job on a later tick. In that window
        // the parent-link check below passes against the freshly committed head
        // while execution would start from an older state, and the block fails
        // with a state root mismatch.
        //
        // Observed on mainnet at #9238768: the batch for #9238765-#9238767
        // committed at 09:16:24, the body for #9238768 arrived 3.4s later and
        // executed against the state after #9238764, computing
        // 0x2c5ab80b... against a header root of 0x8b2b2497.... Re-executed
        // from the pipeline two minutes later it produced the header's root, so
        // the block was fine -- the state it ran against was not.
        //
        // Staying buffered costs nothing: the next drain runs after
        // `poll_execution` has installed the batch's root.
        if self.executing.is_some() || self.pending_exec.is_some() {
            return;
        }
        loop {
            let head_hash = match self.manager.store.exec_head().ok().flatten() {
                Some((hash, _)) => hash,
                None => return,
            };
            let next_num = match self.follow_buffer.keys().next().copied() {
                Some(n) => n,
                None => return,
            };
            // Only execute the lowest buffered block if it builds directly on
            // our executed head; otherwise a lower block is still missing.
            let links = self
                .follow_buffer
                .get(&next_num)
                .is_some_and(|(_, header, _, _)| header.parent_hash == head_hash);
            if !links {
                // The lowest buffered block does not build on what we executed.
                // Two quite different situations produce that, and only one of
                // them resolves on its own.
                let exec_number = self
                    .manager
                    .store
                    .header(head_hash)
                    .ok()
                    .flatten()
                    .map(|h| h.number)
                    .unwrap_or(0);

                // Wait while responses that could fill the gap are still in
                // flight; out-of-order arrival is ordinary and the buffer exists
                // precisely to hold those blocks.
                if !self.pending_follow_bodies.is_empty() {
                    return;
                }

                let waited = match self.follow_gap_since {
                    Some(t) => t.elapsed(),
                    None => {
                        self.follow_gap_since = Some(std::time::Instant::now());
                        return;
                    }
                };
                if waited < FOLLOW_GAP_TIMEOUT {
                    return;
                }

                if next_num > exec_number + 1 {
                    // A gap: the block right after our executed head was never
                    // buffered -- missed while the node was busy or restarting,
                    // or simply never announced. Nothing in the follow path ever
                    // fetches it, so every later block piles up behind a hole
                    // and execution stops for good. Observed on mainnet: a node
                    // executed nothing for twenty hours while downloading tips
                    // the whole time, with no error logged.
                    //
                    // The sync trigger cannot notice, because it compares the
                    // *downloaded* head against peers and that is at the tip.
                    // Recover the way an execution failure does: rewind the body
                    // cursor to the executed head and let the normal sync round
                    // re-fetch and re-execute the missing range.
                    warn!(
                        target: "rustock::sync",
                        "Follow buffer starts at #{next_num} but the executed head is \
                         #{exec_number}; blocks #{}..#{} are missing. Rewinding to \
                         re-fetch them.",
                        exec_number + 1,
                        next_num - 1
                    );
                    self.follow_buffer.clear();
                    self.last_body_height = exec_number;
                    self.pending_exec = None;
                    self.follow_gap_since = None;
                    self.state = SyncState::Idle;
                }
                // Otherwise `next_num` is the very next block and simply does
                // not extend our head -- a reorg at that height, which the
                // reconcile path handles by rolling the executed head back.
                return;
            }
            self.follow_gap_since = None;
            let (hash, header, txs, uncles) = self.follow_buffer.remove(&next_num).unwrap();
            if !self.process_single_block(hash, &header, txs, uncles).await {
                // Real divergence: head didn't advance, so looping would spin.
                return;
            }
        }
    }

    /// Process a single block received in follow mode. Returns `true` if it
    /// executed and committed (advancing the executed head), `false` otherwise.
    async fn process_single_block(
        &mut self,
        hash: B256,
        header: &Header,
        transactions: Vec<Transaction>,
        ommers: Vec<Header>,
    ) -> bool {
        if let Some(pool) = &self.tx_pool {
            pool.remove_mined(&transactions);
            pool.evict_outdated(header.number);
        }

        let (trie_store, mut state_root) = match (&self.trie_store, &self.current_state_root) {
            (Some(ts), Some(sr)) => (ts.clone(), sr.clone()),
            _ => return false,
        };

        // The in-memory root must be the state the executed head committed.
        // Executing against anything else silently computes a wrong state root
        // for a perfectly valid block -- the failure looks like a bad block and
        // is not. The cost of being wrong here is a consensus error, so this
        // stays a hard gate.
        //
        // What changed is what happens when it trips. It used to refuse and
        // return, which is safe and is not recovery: a reorg at the tip leaves
        // the in-memory root holding the state of the block that just stopped
        // being canonical, and the tick-level reconcile then reloads the right
        // root *and clears the follow buffer* -- discarding this very block.
        // The backlog that leaves is one block, which
        // `leave_follow_if_backlog` tolerates as "a tip about to be executed",
        // so nothing moved until the 120-second progress watchdog escalated.
        // Measured on mainnet: 38 `Sync halted` cycles and 69 watchdog
        // escalations in under seven hours.
        //
        // Nothing about that wait was necessary. The committed root is the
        // authority and it is on disk; this block is in hand and builds on the
        // committed head. So reload and carry on, and the reorg costs a trie
        // read rather than two minutes.
        if let Ok(Some((committed_hash, committed_root))) = self.manager.store.exec_head() {
            if state_root.compute_hash(trie_store.as_ref()) != committed_root {
                // Only when this block extends the committed head. A block
                // that does not is a different disagreement and the tick-level
                // reconcile is the right place for it.
                if header.parent_hash != committed_hash {
                    warn!(
                        target: "rustock::sync",
                        "Refusing to execute #{} in follow mode: it builds on {:?}, not on \
                         the executed head {:?}",
                        header.number, header.parent_hash, committed_hash
                    );
                    return false;
                }
                match trie_store.get(committed_root.as_slice()) {
                    Some(data) => {
                        let reloaded = TrieNode::from_message(&data, trie_store.as_ref());
                        // The store can hold bytes under a hash they do not
                        // hash to. Executing against those would be the
                        // consensus error this gate exists to prevent.
                        if reloaded.compute_hash(trie_store.as_ref()) != committed_root {
                            warn!(
                                target: "rustock::sync",
                                "Refusing to execute #{}: the trie store's entry for the \
                                 committed root {:?} does not hash to it",
                                header.number, committed_root
                            );
                            return false;
                        }
                        debug!(
                            target: "rustock::sync",
                            "Reloaded the in-memory state root from the committed one \
                             before executing #{}",
                            header.number
                        );
                        self.current_state_root = Some(reloaded.clone());
                        state_root = reloaded;
                    }
                    None => {
                        warn!(
                            target: "rustock::sync",
                            "Refusing to execute #{} in follow mode: the executed head's \
                             committed root {:?} is not in the trie store",
                            header.number, committed_root
                        );
                        return false;
                    }
                }
            }
        }

        let processor = match &self.block_processor {
            Some(p) => p,
            None => return false,
        };

        let block = Block {
            header: header.clone(),
            transactions,
            ommers,
        };

        // rskj validates a block's body against the consensus rules when it
        // arrives (`BlockValidatorImpl`), separately from executing it
        // (`BlockExecutor`). These are the rules that REJECT a block --
        // transaction gas-price bounds, the REMASC transaction, uncles,
        // extraData, fork-detection data -- none of which changes what a valid
        // block executes to.
        if let Err(e) = processor.validate_block(&block) {
            warn!(
                target: "rustock::sync",
                "Block #{} ({:?}) failed consensus validation: {e}",
                block.header.number, hash
            );
            return false;
        }

        // Already executed by this node? Adopt the result instead of redoing it.
        if let Some(node) = fast_forward_state(processor, &trie_store, header, hash) {
            record_execution(&self.manager.store, hash, header.state_root);
            self.credit_executed_bodies(header.number);
            self.current_state_root = Some(node);
            info!(
                target: "rustock::sync",
                "Re-adopted block #{} without re-executing it (already executed locally, \
                 state root {:?} still held)",
                header.number, header.state_root
            );
            return true;
        }

        let cpu_start = crate::chain_activity::thread_cpu_time();
        let wall_start = Instant::now();
        match processor.process_and_commit(&block, &state_root, trie_store.clone()) {
            Ok(result) => {
                self.chain_activity.record_block(
                    header.number,
                    block.transactions.len(),
                    result.gas_used,
                    header.gas_limit.try_into().unwrap_or(u64::MAX),
                    crate::chain_activity::thread_cpu_time().saturating_sub(cpu_start),
                    wall_start.elapsed(),
                );
                let advanced = crate::execution_commit::ExecutionCommitter::new(1)
                    .after_block(trie_store.as_ref(), true, || {
                        record_execution(&self.manager.store, hash, result.state_root_hash)
                    })
                    .unwrap_or(false);
                if !advanced {
                    // The work is done and the state is in the trie, but the
                    // marker did not move -- so neither does the in-memory
                    // root, which must keep matching the committed one. This
                    // method's contract is "true means the executed head
                    // advanced"; it did not.
                    warn!(
                        target: "rustock::sync",
                        "Executed #{} ({:?}) but could not record it; the executed head \
                         stays at its previous block and this one will be re-executed \
                         once the canonical chain settles",
                        header.number, hash
                    );
                    return false;
                }
                info!(
                    target: "rustock::sync",
                    "Executed block #{}, state root: {:?}",
                    header.number, result.state_root_hash
                );
                // It executed to the root its header claims, which is the only
                // evidence worth a credit.
                self.credit_executed_bodies(header.number);
                self.gas_price.on_block(header, &block.transactions);
                self.gas_price.on_best_block(header);
                self.best_block_listeners.notify(header);
                self.publish_block(hash, header, &block.transactions, false);
                self.current_state_root = Some(result.new_state_root);
                true
            }
            Err(e) => {
                warn!(
                    target: "rustock::sync",
                    "Block #{} execution failed: {}", header.number, e
                );
                false
            }
        }
    }

    /// Log sync progress: percentage, speed, ETA, peers.
    async fn log_progress(&mut self) {
        let downloaded = self.our_head_number();
        let executed = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.manager.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(downloaded);
        let peers = self.peer_store.peers().await.len();
        self.progress.log(&self.state, executed, downloaded, peers);
    }
}

/// Identifies which skeleton chunk a headers response belongs to by examining
/// the block numbers in the response.  The highest block number should match
/// one of the skeleton entries, giving us the chunk index.
pub(crate) fn identify_chunk_by_content(
    headers: &[Header],
    skeleton: &[BlockIdentifier],
) -> Option<usize> {
    if headers.is_empty() || skeleton.is_empty() {
        return None;
    }

    // The newest header must *be* a skeleton entry, by hash and not merely by
    // height: a chunk is the answer to a specific question, and matching on
    // the number alone does not establish that it is.
    let newest = headers.iter().max_by_key(|h| h.number)?;
    let idx = skeleton
        .iter()
        .position(|entry| entry.number == newest.number && entry.hash == newest.hash())?;

    // A chunk covers a contiguous run ending at that entry. Anything else is
    // not the answer to the question that was asked.
    let oldest = headers.iter().map(|h| h.number).min()?;
    if newest.number.checked_sub(oldest)? + 1 != headers.len() as u64 {
        return None;
    }

    Some(idx)
}

/// Execute a downloaded batch (headers + bodies) in order, applying state
/// changes to the trie. Runs on a blocking thread (off the async event loop)
/// so body downloads for the next batch proceed concurrently.
///
/// `all_ok` is `false` when a block failed to execute (or a parent/body was
/// missing); the sync must not advance past it (rskj treats such a block as
/// invalid and stops there). The returned state root and flush counter are
/// carried back into the service for the next batch.
fn process_downloaded_blocks(
    processor: &BlockProcessor,
    trie_store: Arc<dyn TrieStore>,
    state_root: TrieNode,
    store: &BlockStore,
    tx_pool: Option<&crate::TransactionPool>,
    blocks_since_flush: u64,
    flush_every: u64,
    pending_headers: &[(B256, Header)],
    activity: &crate::chain_activity::ChainActivity,
    gas_price: &crate::gas_price::GasPriceTracker,
) -> ExecOutcome {
    // Executed state becomes durable here and the head advances only
    // through this, which is what keeps "flush before you claim it" from
    // being a convention each call site has to remember.
    let mut committer =
        crate::execution_commit::ExecutionCommitter::resuming(flush_every, blocks_since_flush);
    let mut current_root = state_root;
    let mut processed = 0u64;
    // Of `processed`, how many were adopted without re-running the EVM.
    let mut fast_forwarded = 0u64;
    let mut all_ok = true;
    let mut last_executed: Option<(B256, B256)> = None;

    // Lineage guard: the first block must extend the executed head and
    // each block its predecessor; executing out of order would apply
    // transactions to the wrong parent state.
    let mut expected_parent = store
        .exec_head()
        .ok()
        .flatten()
        .map(|(hash, _)| hash)
        .or_else(|| store.canonical_hash(0).ok().flatten());

    for (hash, header) in pending_headers {
        if let Some(parent) = expected_parent {
            if header.parent_hash != parent {
                error!(
                    target: "rustock::sync",
                    "Block #{} does not extend the executed head (parent {:?}, expected {:?}); halting sync",
                    header.number, header.parent_hash, parent
                );
                all_ok = false;
                break;
            }
        }
        expected_parent = Some(*hash);

        let (transactions, ommers) = match store.body(*hash) {
            Ok(Some(body)) => body,
            Ok(None) => {
                // Executing past a missing body would apply the next block
                // to the wrong parent state — halt here instead.
                warn!(
                    target: "rustock::sync",
                    "Body not found for block #{} ({:?}); halting sync at this block",
                    header.number, hash
                );
                all_ok = false;
                break;
            }
            Err(e) => {
                error!(
                    target: "rustock::sync",
                    "Failed to read body for block #{}: {:?}", header.number, e
                );
                all_ok = false;
                break;
            }
        };

        if let Some(pool) = tx_pool {
            pool.remove_mined(&transactions);
        }

        let block = Block {
            header: header.clone(),
            transactions,
            ommers,
        };

        // Same consensus gate as the single-block path above.
        if let Err(e) = processor.validate_block(&block) {
            warn!(
                target: "rustock::sync",
                "Block #{} ({:?}) failed consensus validation: {e}",
                block.header.number, hash
            );
            break;
        }

        // Already executed by this node? Adopt the result instead of redoing it.
        if let Some(node) = fast_forward_state(processor, &trie_store, header, *hash) {
            current_root = node;
            last_executed = Some((*hash, header.state_root));
            processed += 1;
            fast_forwarded += 1;
            continue;
        }

        // Both clocks, because the difference between them is the diagnostic:
        // CPU time rising is execution getting slower, wall time rising alone
        // is the node waiting on the trie database rather than working.
        let cpu_start = crate::chain_activity::thread_cpu_time();
        let wall_start = Instant::now();
        match processor.process_and_commit(&block, &current_root, trie_store.clone()) {
            Ok(result) => {
                activity.record_block(
                    header.number,
                    block.transactions.len(),
                    result.gas_used,
                    header.gas_limit.try_into().unwrap_or(u64::MAX),
                    crate::chain_activity::thread_cpu_time().saturating_sub(cpu_start),
                    wall_start.elapsed(),
                );
                gas_price.on_block(header, &block.transactions);
                current_root = result.new_state_root;
                last_executed = Some((*hash, result.state_root_hash));
                processed += 1;
                if let Some(false) = committer.after_block(
                    trie_store.as_ref(),
                    false,
                    || record_execution(store, *hash, result.state_root_hash),
                ) {
                    // Not canonical any more: executing further blocks on top
                    // of it would build on a branch the node is not on.
                    all_ok = false;
                    break;
                }
                if processed.is_multiple_of(100) {
                    debug!(
                        target: "rustock::sync",
                        "Processed {} blocks (latest #{}, state root {:?})",
                        processed, header.number, result.state_root_hash
                    );
                }
                if processed.is_multiple_of(1000) {
                    info!(
                        target: "rustock::sync",
                        "Executing batch: #{} ({}/{} blocks)",
                        header.number, processed, pending_headers.len()
                    );
                }
            }
            Err(e) => {
                error!(
                    target: "rustock::sync",
                    "Block #{} execution failed: {}; halting sync at this block",
                    header.number, e
                );
                all_ok = false;
                break;
            }
        }
    }

    if processed > 0 {
        if let Some((hash, root_hash)) = last_executed {
            if let Some(false) = committer.finish(
                trie_store.as_ref(),
                || record_execution(store, hash, root_hash),
            ) {
                // `halt_after_exec_failure` then reconciles the head, which is
                // the only thing that can make this block canonical or replace
                // it. Reporting the batch as clean would leave the executed
                // head behind the blocks just written, with nothing to notice.
                all_ok = false;
            }
        }
        if fast_forwarded > 0 {
            info!(
                target: "rustock::sync",
                "Processed {} blocks ({} re-adopted without re-executing), state root: {:?}",
                processed, fast_forwarded, current_root.compute_hash(trie_store.as_ref())
            );
        } else {
            info!(
                target: "rustock::sync",
                "Processed {} blocks, state root: {:?}",
                processed, current_root.compute_hash(trie_store.as_ref())
            );
        }
    }

    ExecOutcome {
        all_ok,
        new_state_root: current_root,
        blocks_since_flush: committer.pending(),
    }
}


/// The outcome of one connection-point probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// Keep walking down from the head with a larger step.
    Gallop { step: u64 },
    /// Bisect this bracket: `start` is shared, `end` is not.
    Bisect { start: u64, end: u64 },
    /// The peer shares no block with us at all.
    NoCommonAncestor,
}

/// Largest downward step the gallop takes before giving up and bisecting.
///
/// Doubling alone is `2·log2(depth)` probes: excellent for a shallow fork, but
/// for a divergence at genesis it spends ~23 steps reaching the bottom and
/// ~21 more bisecting, against 23 for a plain bisection of `0..head`.
///
/// Capping it bounds that loss. Past this step the gallop has already
/// established that the fork is deep, which is the one case bisection handles
/// better, so it hands over: at most 9 probes spent before a bisection that is
/// itself no worse than the one this replaces. Forks up to 512 deep — which in
/// practice is all of them — still resolve within the gallop.
pub(crate) const MAX_GALLOP_STEP: u64 = 512;

/// Gallop step meaning "probe the lowest height and settle the question".
///
/// The bisection starts at `start = 0` and treats it as shared, but nothing
/// ever checked that. For a peer on another network it is false, and the
/// search then reports a connection point at genesis and syncs against a chain
/// with which we have nothing in common. Reaching that terminal state asks
/// instead, and `saturating_sub` turns this step into a probe of height 0.
pub(crate) const CONFIRM_LOWEST: u64 = u64::MAX;

/// What one probe result means for the search.
///
/// Pure, and the only place the transition is written, so that a test can
/// drive the real search rather than a restatement of it that could be wrong
/// in the same way.
pub(crate) fn advance_connection_point(
    start: u64,
    end: u64,
    gallop: Option<u64>,
    probed: u64,
    known: bool,
) -> Probe {
    let next = match (gallop, known) {
        // Galloping, and this height is not shared: step twice as far down.
        // `end` stays the origin, so the next probe is measured from the head
        // rather than from here — doubling the distance, not the decrement.
        (Some(_), false) if probed == 0 => Probe::NoCommonAncestor,
        // The gallop has gone as far as it usefully can. Everything below
        // `probed` is still a candidate, and bisection searches that better
        // than more doubling would.
        (Some(step), false) if step >= MAX_GALLOP_STEP => Probe::Bisect { start, end: probed },
        (Some(step), false) => Probe::Gallop { step: step.saturating_mul(2) },
        // A shared block. The fork is between here and the last height the
        // gallop rejected, which sits one step back up — or the origin, if
        // this was the very first probe.
        (Some(step), true) => Probe::Bisect {
            start: probed,
            end: end.saturating_sub(step / 2),
        },
        (None, true) => Probe::Bisect { start: probed, end },
        (None, false) => Probe::Bisect { start, end: probed },
    };

    // Never finish on an assumption. If the search has narrowed to height 0
    // and no probe ever confirmed that we share it, ask before believing it.
    match next {
        // ...unless this very probe is what confirmed it.
        Probe::Bisect { start: 0, end }
            if end <= 1 && !(known && probed == 0) && gallop != Some(CONFIRM_LOWEST) =>
        {
            Probe::Gallop { step: CONFIRM_LOWEST }
        }
        other => other,
    }
}

/// Which height the next connection-point probe asks about.
///
/// While galloping, `end` is the origin the search started from and the probe
/// walks down from it by `step`, so a one-block fork is found in one request
/// rather than the 23 a bisection of `0..head` would spend. Once bisecting,
/// `start` is the highest shared height known and `end` the lowest unshared
/// one, and the probe splits them.
pub(crate) fn connection_point_probe_height(start: u64, end: u64, gallop: Option<u64>) -> u64 {
    match gallop {
        Some(step) => end.saturating_sub(step),
        None => start + (end - start) / 2,
    }
}

#[cfg(test)]
mod connection_point_search_tests {
    use super::{advance_connection_point, connection_point_probe_height, Probe, MAX_GALLOP_STEP};

    /// Runs the real search against a chain whose highest shared height is
    /// `fork`, driving the same transition the service does.
    ///
    /// Returns the connection point it settles on and how many probes it
    /// spent, or `None` for "no common ancestor".
    fn search(head: u64, fork: u64) -> (Option<u64>, usize) {
        let (mut start, mut end, mut gallop) = (0u64, head, Some(1u64));
        let mut probes = 0usize;

        loop {
            let probed = connection_point_probe_height(start, end, gallop);
            probes += 1;
            assert!(probes < 200, "search did not converge (head {head}, fork {fork})");

            // The peer holds every height; we share the ones at or below the
            // fork. `known` is therefore monotone decreasing in height, which
            // is the property both phases rely on.
            let known = probed <= fork;

            match advance_connection_point(start, end, gallop, probed, known) {
                Probe::NoCommonAncestor => return (None, probes),
                Probe::Gallop { step } => gallop = Some(step),
                Probe::Bisect { start: s, end: e } => {
                    if e.saturating_sub(s) <= 1 {
                        return (Some(s), probes);
                    }
                    start = s;
                    end = e;
                    gallop = None;
                }
            }
        }
    }

    /// Probes a plain bisection of `0..head` would spend, for comparison.
    fn bisect_probes(head: u64, fork: u64) -> usize {
        let (mut start, mut end, mut probes) = (0u64, head, 0usize);
        while end - start > 1 {
            let mid = start + (end - start) / 2;
            probes += 1;
            if mid <= fork { start = mid } else { end = mid }
        }
        probes
    }

    /// The property that matters: it finds the right block. Every fork depth
    /// from the head down, exhaustively — not a sampled few.
    #[test]
    fn it_finds_the_exact_fork_at_every_depth() {
        let head = 4096u64;
        for fork in 0..head {
            let (found, _) = search(head, fork);
            assert_eq!(
                found,
                Some(fork),
                "head {head}, fork {fork}: search must land on the fork itself"
            );
        }
    }

    /// And at a realistic chain height, where an off-by-one in the gallop's
    /// bracket would be invisible against a small `head`.
    #[test]
    fn it_finds_the_exact_fork_on_a_mainnet_sized_chain() {
        let head = 9_280_000u64;
        // Shallow forks, the common case.
        for depth in 1..=512u64 {
            let fork = head - depth;
            assert_eq!(search(head, fork).0, Some(fork), "depth {depth}");
        }
        // Powers of two and their neighbours, where the step lands exactly on
        // or beside a boundary.
        for shift in 0..23u32 {
            for delta in [-1i64, 0, 1] {
                let depth = (1u64 << shift).saturating_add_signed(delta).max(1);
                if depth >= head { continue }
                let fork = head - depth;
                assert_eq!(search(head, fork).0, Some(fork), "depth {depth}");
            }
        }
        // And a genuinely ancient divergence.
        for fork in [0u64, 1, 2, 1000, head / 2, head - 1] {
            assert_eq!(search(head, fork).0, Some(fork), "fork {fork}");
        }
    }

    /// The point of the gallop. A one-block fork cost 23 round trips.
    #[test]
    fn a_shallow_fork_costs_a_handful_of_probes() {
        let head = 9_280_000u64;
        assert_eq!(search(head, head - 1).1, 1, "a one-block fork: one request");
        assert!(search(head, head - 2).1 <= 2);
        for depth in 1..=MAX_GALLOP_STEP {
            let probes = search(head, head - depth).1;
            assert!(
                probes <= 2 * (MAX_GALLOP_STEP.ilog2() as usize + 1),
                "depth {depth} took {probes} probes; bisection takes {}",
                bisect_probes(head, head - depth)
            );
        }
    }

    /// The other end of open question 0: an ancient divergence must not cost
    /// materially more than the bisection this replaces.
    #[test]
    fn a_deep_fork_does_not_lose_to_bisection() {
        let head = 9_280_000u64;
        for fork in [0u64, 1, 1000, 100_000, head / 4, head / 2, head - head / 8] {
            let (found, probes) = search(head, fork);
            assert_eq!(found, Some(fork));
            let bisect = bisect_probes(head, fork);
            // The cap costs at most the doublings spent before it fires.
            let overhead = MAX_GALLOP_STEP.ilog2() as usize + 2;
            assert!(
                probes <= bisect + overhead,
                "fork {fork}: gallop {probes} probes vs bisection {bisect} \
                 (allowed overhead {overhead})"
            );
        }
    }

    /// Doubling must stay O(log n) — never a linear walk down the chain.
    #[test]
    fn the_search_is_logarithmic_everywhere() {
        let head = 9_280_000u64;
        let mut worst = 0usize;
        for fork in (0..head).step_by(9_973) {
            worst = worst.max(search(head, fork).1);
        }
        assert!(worst <= 48, "worst case {worst} probes is not logarithmic");
    }

    /// A peer sharing nothing is not searched forever; it is identified.
    #[test]
    fn a_peer_sharing_nothing_is_identified_not_searched_forever() {
        // Nothing at all is shared, not even height 0.
        let head = 9_280_000u64;
        let (mut start, mut end, mut gallop) = (0u64, head, Some(1u64));
        let mut probes = 0;
        loop {
            let probed = connection_point_probe_height(start, end, gallop);
            probes += 1;
            assert!(probes < 100, "gave up too slowly");
            match advance_connection_point(start, end, gallop, probed, false) {
                Probe::NoCommonAncestor => break,
                Probe::Gallop { step } => gallop = Some(step),
                Probe::Bisect { start: s, end: e } => {
                    start = s;
                    end = e;
                    gallop = None;
                }
            }
        }
        // The cost is the gallop to its cap, a bisection of what remains, and
        // one probe of height 0 to settle it — bounded, and paid once per peer
        // before that peer is charged and stops being asked.
        let bound = (MAX_GALLOP_STEP.ilog2() as usize + 1) + bisect_probes(head, 0) + 1;
        assert!(
            probes <= bound,
            "{probes} probes to conclude nothing is shared, expected at most {bound}"
        );
    }

    /// A node at genesis has nothing to search.
    #[test]
    fn a_tiny_chain_does_not_underflow() {
        for head in 0..4u64 {
            for fork in 0..=head {
                let (found, _) = search(head, fork);
                assert!(
                    found.is_some(),
                    "head {head}, fork {fork}: must terminate with an answer"
                );
            }
        }
    }
}
