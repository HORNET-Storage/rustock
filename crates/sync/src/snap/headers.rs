//! Walking the header chain down from the checkpoint, in parallel.
//!
//! # Why the obvious way is slow
//!
//! To ask for headers you need a hash, and the only hash you have is the one
//! the last answer gave you. So the natural walk -- ask for 192 headers, take
//! the oldest one's parent, ask again -- is strictly serial. For a node
//! starting from nothing that is about 48,000 round trips, one at a time,
//! before a single byte of state is requested. rskj's client walks this way.
//!
//! # Breaking the dependency
//!
//! A *skeleton* request answers with block identifiers at fixed heights --
//! twenty of them, 192 apart -- and it is addressed by height, not by hash. So
//! skeletons can all be asked for at once, and each identifier they return is
//! the starting hash for a header request that can also be asked for at once.
//!
//! What that buys is not fewer messages. It is that the messages no longer
//! have to wait for each other.
//!
//! # What it must not cost
//!
//! A skeleton identifier is a peer's claim about which block sits at a height.
//! Believing one would hand a peer the chain. It is never believed: it says
//! only *where to ask*, and what makes the answer trustworthy is that the
//! chunks **link**.
//!
//! Chunk boundaries are arithmetic rather than a search, because a request
//! from the hash at height `p` returns `p` down to `p-191`. So the chunk
//! below `p` starts at `p-192`, and:
//!
//! ```text
//! chunk(p).oldest.parent_hash == chunk(p-192).newest.hash()
//! ```
//!
//! A wrong identifier produces a chunk that fails that test, and the range is
//! asked of somebody else. The chain is trusted exactly when an unbroken run
//! of these links reaches from the checkpoint down to a block already in this
//! node's canonical index -- the same anchor the serial walk used, and for the
//! same reason: the canonical index is the one thing the walk cannot write.
//!
//! Every header is checked under the full consensus rules, merged-mining proof
//! of work included, exactly as before. Pipelining changes when the questions
//! are asked, not which answers are accepted.

use alloy_primitives::{B256, U256};
use rustock_core::validation::HeaderVerifier;
use rustock_core::Header;
use rustock_networking::protocol::BlockIdentifier;
use rustock_storage::BlockStore;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Headers per request, and so the spacing of skeleton points. rskj serves at
/// most this many and so does rustock.
pub const HEADER_CHUNK: u64 = 192;

/// Identifiers one skeleton answer carries.
pub const SKELETON_POINTS: u64 = 20;

/// What the walk wants asked next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// Block identifiers from this height upward.
    Skeleton { start: u64 },
    /// `count` headers walking back from this hash.
    Headers { from: B256, count: u32, point: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalkError {
    #[error("header #{number} failed validation: {reason}")]
    InvalidHeader { number: u64, reason: String },
    #[error("the headers for point {point} do not form a chain")]
    BrokenChunk { point: u64 },
    #[error("the chain leads back to a genesis this node has never seen")]
    ForeignGenesis,
}

/// The steepest step the retarget rule has ever allowed, as a divisor: a
/// block's difficulty is its parent's, plus or minus at most this fraction of
/// it, or the floor (rskj `DifficultyCalculator`, whose `difficultyBoundDivisor`
/// was 50 until RSKIP156 raised it to 400). Bounding an uncle by its parent
/// takes the largest step any height could.
const STEEPEST_RETARGET: u64 = 50;

/// How far below the block that includes it an uncle's parent may sit (rskj
/// `uncleGenerationLimit`): an uncle of the block at height `h` hangs from the
/// trunk somewhere in `h-7 ..= h-2` (`BlockUnclesValidationRule
/// .validateParentNumber`).
const UNCLE_GENERATIONS: usize = 7;

/// Uncles whose possible parents have not all been walked yet: how many, the
/// highest trunk difficulty seen among those parents so far, and how many
/// trunk headers below are still to be seen.
#[derive(Debug, Clone)]
struct Reaching {
    count: u64,
    highest: U256,
    below: usize,
}

/// A verified run of headers, remembered by its ends and by what it is worth.
///
/// The headers themselves go to the store as they are checked; only the two
/// ends are kept, which is what makes walking nine million of them affordable.
/// What the run is worth counts only once the run joins the chain: see
/// [`HeaderWalk::advance`].
#[derive(Debug, Clone)]
struct Run {
    newest: B256,
    oldest_number: u64,
    /// The parent of the oldest header: what the run below must produce.
    oldest_parent: B256,
    /// Each header's difficulty, or its exact contribution where the peer
    /// sent its uncles.
    work: U256,
    /// Uncles the work leaves out, because the peer sent none.
    uncles_omitted: u64,
    /// Of those, the ones whose possible parents are all in this run: for each
    /// block, its uncle count times the highest difficulty among them.
    uncle_weight: U256,
    /// The ones whose possible parents reach below the run.
    reaching: Vec<Reaching>,
    /// The difficulties of the run's newest headers, newest first: as many as
    /// the uncles of the run above can hang from.
    newest_difficulties: Vec<U256>,
}

pub struct HeaderWalk {
    store: Arc<BlockStore>,
    verifier: Arc<HeaderVerifier>,

    /// The block being walked down from.
    top: Header,

    /// Skeleton starts not yet asked for, and those outstanding.
    skeleton_todo: Vec<u64>,
    skeleton_sent: HashSet<u64>,
    /// Hashes learned from skeletons, by height. Claims, not facts.
    points: BTreeMap<u64, B256>,

    /// Points whose headers are outstanding, and those already verified.
    headers_sent: HashSet<u64>,
    runs: BTreeMap<u64, Run>,

    /// The header the linked chain still needs: its height, and the hash its
    /// child already named for it.
    ///
    /// This is the whole of the walk's state. A run satisfies it when the run
    /// is keyed at that height *and* its newest header is that hash; consuming
    /// it moves the need to the run's own oldest parent. Nothing else can move
    /// it, which is why a wrong skeleton identifier cannot mislead the walk --
    /// it produces a run that simply never fits.
    need_number: u64,
    need_hash: B256,
    done: bool,

    /// Difficulty summed over the headers of every run that has joined the
    /// chain, each counted once.
    ///
    /// The checkpoint's total difficulty arrives as a claim and is written to
    /// the store as this node's own, so it is worth establishing against the
    /// chain actually walked. The walk reads every header anyway; adding them
    /// up costs nothing and makes the claim checkable. Where a peer sent no
    /// uncles it is a floor, which [`Self::work_ceiling`] bounds from above.
    walked_difficulty: U256,
    /// Uncles in those runs whose difficulty could not be added, because a
    /// header walk never carries bodies. Non-zero means `walked_difficulty`
    /// understates the chain and the totals derived from it need `--repair
    /// total-difficulty` once bodies are present.
    uncles_omitted: u64,
    /// For each block with such uncles whose possible parents have all been
    /// walked, its uncle count times the highest difficulty among them,
    /// summed. See [`Self::work_ceiling`].
    uncle_weight: U256,
    /// The uncles whose possible parents have not all been walked yet.
    reaching: Vec<Reaching>,

    /// Total difficulty this node had already established at the block the
    /// walk anchored on.
    ///
    /// The walk stops at the first block this node already holds, which is
    /// usually but not always genesis. `walked_difficulty` is therefore the
    /// work of the walked *segment*, while the claim it is checked against is
    /// cumulative from genesis. Without this the two are different quantities,
    /// and comparing them refuses an honest peer by whatever the node already
    /// had below the anchor.
    anchor_difficulty: Option<U256>,

    /// Blocks strictly below this may be frozen: `top - FREEZE_DEPTH`.
    freeze_horizon: u64,
    /// The blocks under this height have their uncles staged beside the
    /// headers: see [`Self::with_bodies_from`].
    uncles_below: u64,
    /// Headers written against a checkpoint that is still only a peer's claim.
    ///
    /// `None` when there is no freezer, or when it already holds something --
    /// promotion renames files into place, which replaces rather than merges,
    /// so a populated freezer is left to the background fill instead.
    staging: Option<rustock_storage::freezer::Freezer>,
}

impl HeaderWalk {
    /// Walk down from `top`, stopping at the first block this node has
    /// already accepted as canonical.
    ///
    /// There is no floor to pass in. The queue is drained from the top down
    /// and the walk stops the moment it anchors, so a node that already has
    /// most of the chain never reaches the requests for the part it has --
    /// the anchor is the floor.
    pub fn new(
        top: Header,
        store: Arc<BlockStore>,
        verifier: Arc<HeaderVerifier>,
    ) -> Self {
        let number = top.number;
        let parent = top.parent_hash;
        let top_hash = top.hash();

        // The top of the grid: the highest multiple of the chunk size at or
        // below the checkpoint. Everything above it is one bespoke request,
        // everything below is on the grid.
        let grid_top = (number / HEADER_CHUNK) * HEADER_CHUNK;

        let mut skeleton_todo = Vec::new();
        let span = HEADER_CHUNK * SKELETON_POINTS;
        let mut start = 0u64;
        while start <= grid_top {
            skeleton_todo.push(start);
            start += span;
        }
        // Popped from the back, so the highest start is asked for first: the
        // walk finishes at the bottom, but it is the top that unblocks it.
        //
        // Left ascending for that reason. The ascent reverses its queue
        // because it wants the low end first; reversed here as well, the walk
        // asked from genesis up, and its frontier sat at the checkpoint until
        // all nine million mainnet headers had arrived -- 0.0% for the whole
        // two hours, with nothing to tell that from a hang.

        // A walk feeds the freezer only when there is nothing to lose by
        // doing so: an empty freezer, on a node syncing from scratch. On a
        // node that already froze headers, promotion would replace them.
        let staging = match store.freezer() {
            Some(f) if f.is_empty() => {
                rustock_storage::freezer::Freezer::open_staging(f.dir(), number, top_hash).ok()
            }
            _ => None,
        };

        let _ = parent;
        Self {
            store,
            verifier,
            top,
            skeleton_todo,
            skeleton_sent: HashSet::new(),
            points: BTreeMap::new(),
            headers_sent: HashSet::new(),
            runs: BTreeMap::new(),
            need_number: number,
            need_hash: top_hash,
            done: false,
            walked_difficulty: U256::ZERO,
            uncles_omitted: 0,
            uncle_weight: U256::ZERO,
            reaching: Vec::new(),
            anchor_difficulty: None,
            freeze_horizon: number.saturating_sub(rustock_storage::freezer::FREEZE_DEPTH),
            uncles_below: number.saturating_sub(rustock_storage::freezer::FREEZE_DEPTH),
            staging,
        }
    }

    /// The lowest block whose body the sync goes on to fetch. The uncles sent
    /// beside every header under it are staged with the headers: they are the
    /// only copy this node will get.
    ///
    /// Without this they were staged only under the freeze horizon, 20,000
    /// blocks below the top, on the reasoning that every block above it is
    /// inside the body window. The window is 6,000 blocks (rskj's
    /// `BLOCKS_REQUIRED`), so the blocks between got neither, and their uncles
    /// were lost (#270).
    pub fn with_bodies_from(mut self, lowest: u64) -> Self {
        self.uncles_below = lowest;
        self
    }

    /// Difficulty summed across the headers of every run that has joined the
    /// chain.
    ///
    /// Once the walk is done this is the work of the whole chain from the
    /// checkpoint down to the anchor, the checkpoint included -- but of the
    /// headers only, unless the peers sent the uncles: see
    /// [`Self::work_ceiling`].
    pub fn walked_difficulty(&self) -> U256 {
        self.walked_difficulty
    }

    /// How many uncles the walk could not account for. See `uncles_omitted`.
    pub fn uncles_omitted(&self) -> u64 {
        self.uncles_omitted
    }

    /// The cumulative difficulty the walked chain implies at the checkpoint,
    /// once the walk has anchored: what this node already had at the anchor,
    /// plus every header the walk verified above it.
    ///
    /// `None` until the walk anchors, because until then the chain below is
    /// still the peer's word and nothing has been established.
    pub fn established_difficulty(&self) -> Option<U256> {
        self.anchor_difficulty
            .map(|anchor| anchor.saturating_add(self.walked_difficulty))
    }

    /// The most cumulative difficulty the walked chain can carry at the
    /// checkpoint, once the walk has anchored: the work established, plus the
    /// most that the uncles it did not see can add. Exact when every uncle
    /// came with its header.
    ///
    /// Uncles travel in bodies, which a header walk never fetches, and an rskj
    /// peer (`rsk/62`) sends none alongside, so on mainnet the headers carry a
    /// little over half of the work. What the walk does see bounds the rest.
    /// A header's uncle count is inside what its proof of work commits to, and
    /// an uncle hangs from the trunk two to seven blocks down, with a
    /// difficulty the retarget rule ties to its parent's: at most a fiftieth
    /// more, or the floor. So each uncle unseen is worth at most the highest
    /// trunk difficulty in that stretch and a fiftieth, or `min_difficulty`;
    /// this adds both, which is never less.
    pub fn work_ceiling(&self, min_difficulty: U256) -> Option<U256> {
        let established = self.established_difficulty()?;
        let rise = self.uncle_weight / U256::from(STEEPEST_RETARGET);
        let floor = min_difficulty.saturating_mul(U256::from(self.uncles_omitted));
        Some(
            established
                .saturating_add(self.uncle_weight)
                .saturating_add(rise)
                .saturating_add(floor),
        )
    }

    /// The height the walk started from.
    ///
    /// With `frontier`, this is how far it has descended -- the walk runs for
    /// about two hours on a mainnet chain, so whatever drives it needs
    /// something exact to report.
    pub fn top_number(&self) -> u64 {
        self.top.number
    }

    /// Headers written to the staging freezer so far, if there is one.
    pub fn staged(&self) -> u64 {
        self.staging.as_ref().map(|f| f.end_number()).unwrap_or(0)
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The lowest height the linked chain reaches.
    pub fn frontier(&self) -> u64 {
        self.need_number
    }

    /// Whether this node already accepted this block as canonical.
    ///
    /// Asked of the canonical index, never of "is this header stored": the
    /// walk stores headers as it goes, and a check its own writes could
    /// satisfy would be no check at all.
    fn is_ours(&self, number: u64, hash: B256) -> bool {
        self.store.canonical_hash(number).ok().flatten() == Some(hash)
    }

    /// Up to `budget` things to ask for, none of them already outstanding.
    pub fn wants(&mut self, budget: usize) -> Vec<Want> {
        let mut out = Vec::new();
        if self.done || budget == 0 || self.need_number == 0 {
            return out;
        }
        let need = self.need_number;

        // The frontier first, asked for from the hash the linked chain names
        // for it. That hash is this node's own finding, not a peer's claim,
        // so the request needs no skeleton: it is the serial walk, running
        // beneath the parallel one. It is also the only way back to the
        // frontier once its point is gone -- a run there that does not link
        // takes the point with it, and a short answer leaves the need between
        // grid points, where no point sits -- and either used to stop the
        // walk for good.
        //
        // It reaches down to the grid point below, so that the run under it
        // can link: all 192 from a point on the grid, the remainder from the
        // checkpoint or from wherever a short answer stopped.
        if !self.headers_sent.contains(&need) && !self.runs.contains_key(&need) {
            let floor = ((need - 1) / HEADER_CHUNK) * HEADER_CHUNK;
            self.headers_sent.insert(need);
            out.push(Want::Headers {
                from: self.need_hash,
                count: (need - floor) as u32,
                point: need,
            });
            if out.len() >= budget {
                return out;
            }
        }

        // Then the points below the frontier, highest first: a skeleton is
        // only useful once its points are being turned into headers. Only
        // below, because a point at or above the frontier is linked already,
        // and asking for it again would fetch that stretch twice.
        let points: Vec<(u64, B256)> = self
            .points
            .range(..need)
            .rev()
            .filter(|(p, _)| !self.headers_sent.contains(*p) && !self.runs.contains_key(*p))
            .take(budget - out.len())
            .map(|(p, hash)| (*p, *hash))
            .collect();
        for (point, hash) in points {
            self.headers_sent.insert(point);
            out.push(Want::Headers { from: hash, count: HEADER_CHUNK as u32, point });
        }

        // Skeletons with whatever is left, the highest first. One that starts
        // at or above the frontier could name only linked points, and the
        // frontier never rises, so it is dropped rather than asked.
        while out.len() < budget {
            let Some(start) = self.skeleton_todo.pop() else { break };
            if start >= need {
                continue;
            }
            if self.skeleton_sent.insert(start) {
                out.push(Want::Skeleton { start });
            }
        }
        out
    }

    /// Give up on an outstanding request so it can be asked of someone else.
    pub fn release(&mut self, want: &Want) {
        match want {
            Want::Skeleton { start } => {
                if self.skeleton_sent.remove(start) {
                    self.skeleton_todo.push(*start);
                }
            }
            Want::Headers { point, .. } => {
                self.headers_sent.remove(point);
            }
        }
    }

    /// Skeleton identifiers: where to ask, and nothing more.
    pub fn on_skeleton(&mut self, identifiers: &[BlockIdentifier]) {
        for id in identifiers {
            // Only a grid point below the frontier can lead anywhere. Above
            // it the chain is linked already. Off the grid no run can link,
            // and one identifier usually is: rskj ends every skeleton with
            // its best block, wherever that sits.
            if id.number == 0 || id.number >= self.need_number || id.number % HEADER_CHUNK != 0 {
                continue;
            }
            // A point already answered for is not replaced: the run that
            // linked is the truth, whatever a later peer says.
            if self.runs.contains_key(&id.number) {
                continue;
            }
            self.points.insert(id.number, id.hash);
        }
    }

    /// A run of headers, newest first, as the protocol delivers them.
    ///
    /// Verified on its own terms here -- every header's rules, every adjacent
    /// pair, the internal chain -- and stored. Whether it belongs to *our*
    /// chain is settled by whether it links, which [`Self::advance`] decides.
    pub fn on_headers(
        &mut self,
        point: u64,
        headers: &[Header],
        proven: &std::collections::HashMap<B256, U256>,
    ) -> Result<(), WalkError> {
        self.headers_sent.remove(&point);
        if headers.is_empty() {
            return Ok(());
        }

        // Newest first, and contiguous.
        let newest = &headers[0];
        for pair in headers.windows(2) {
            let (child, parent) = (&pair[0], &pair[1]);
            if child.parent_hash != parent.hash() {
                return Err(WalkError::BrokenChunk { point });
            }
            self.verifier.verify(parent, None).map_err(|e| WalkError::InvalidHeader {
                number: parent.number,
                reason: e.to_string(),
            })?;
            self.verifier.verify_against_parent(child, parent).map_err(|e| {
                WalkError::InvalidHeader { number: child.number, reason: e.to_string() }
            })?;
        }
        // The newest header of a run is never anyone's child here, so its own
        // rules are checked directly.
        self.verifier.verify(newest, None).map_err(|e| WalkError::InvalidHeader {
            number: newest.number,
            reason: e.to_string(),
        })?;

        // What the run is worth, which counts once it joins the chain.
        //
        // Uncle difficulty counts toward the chain's work, and uncle headers
        // travel only in the body, which a backward header walk never fetches.
        // A peer at `rsk/63` sends them alongside and the figure is exact.
        // From anyone else -- every rskj node -- they are left out, and what
        // the run does hold bounds them: see `Self::work_ceiling`.
        let mut work = U256::ZERO;
        let mut uncles_omitted = 0u64;
        let mut uncle_weight = U256::ZERO;
        let mut reaching = Vec::new();
        for (i, header) in headers.iter().enumerate() {
            let hash = header.hash();
            match proven.get(&hash) {
                Some(exact) => work = work.saturating_add(*exact),
                None => {
                    work = work.saturating_add(header.difficulty);
                    if header.uncle_count > 0 {
                        uncles_omitted += header.uncle_count;
                        // Its uncles hang from the headers two to seven below
                        // it: those this run holds, and for the rest, the
                        // newest of the runs below.
                        let end = (i + UNCLE_GENERATIONS + 1).min(headers.len());
                        let highest = headers
                            .get(i + 2..end)
                            .unwrap_or_default()
                            .iter()
                            .map(|parent| parent.difficulty)
                            .max()
                            .unwrap_or(U256::ZERO);
                        let below = (i + UNCLE_GENERATIONS + 1).saturating_sub(headers.len());
                        if below == 0 {
                            uncle_weight = uncle_weight.saturating_add(
                                U256::from(header.uncle_count).saturating_mul(highest),
                            );
                        } else {
                            reaching.push(Reaching {
                                count: header.uncle_count,
                                highest,
                                below,
                            });
                        }
                    }
                }
            }
            let _ = self.store.put_header_with_hash(hash, header);
        }

        // The headers are in hand and verified against each other; writing
        // them to the freezer now saves reading all of them back out of
        // RocksDB in a separate pass afterwards.
        //
        // They are provisional until the walk reaches ground this node
        // already accepted, because until then the whole chain rests on a
        // checkpoint a peer offered. `Freezer::mark_provisional` is what makes
        // that safe: a walk that never finishes leaves a marker, and the next
        // open discards everything behind it.
        self.freeze_provisionally(headers);

        let oldest = headers.last().expect("non-empty");
        self.runs.insert(
            point,
            Run {
                newest: newest.hash(),
                oldest_number: oldest.number,
                oldest_parent: oldest.parent_hash,
                work,
                uncles_omitted,
                uncle_weight,
                reaching,
                newest_difficulties: headers
                    .iter()
                    .take(UNCLE_GENERATIONS)
                    .map(|header| header.difficulty)
                    .collect(),
            },
        );
        Ok(())
    }

    /// Stage the uncles a run of headers referenced, beside the headers: those
    /// of the blocks below the ones whose bodies the sync fetches
    /// ([`Self::with_bodies_from`]), which bring their own.
    ///
    /// Same provisional footing as the headers: the chain is a peer's word
    /// until the walk reaches ground, so these go to the staging freezer and
    /// are promoted with everything else or discarded with it.
    ///
    /// Without this a descending-synced node ends up with every trunk header
    /// and none of the uncles, which is a node that can neither sum its own
    /// chain's work nor serve `rsk/63` -- the sync it just performed.
    pub fn stage_uncles(&mut self, uncles: &[(u64, Vec<rustock_core::Header>)]) {
        let Some(staging) = self.staging.as_ref() else { return };
        let below = self.uncles_below;
        if below == 0 {
            return;
        }
        for (number, list) in uncles {
            if *number < below {
                let _ = staging.put_uncles(*number, list);
            }
        }
    }

    /// Writes a verified run to the staging freezer.
    ///
    /// Only blocks below the freeze horizon: anything younger can still be
    /// replaced by a reorg, and a file addressed by height has no way to say
    /// "this height means something else now".
    fn freeze_provisionally(&mut self, headers: &[rustock_core::Header]) {
        let Some(staging) = self.staging.as_ref() else { return };
        let horizon = self.freeze_horizon;
        if horizon == 0 {
            return;
        }
        for header in headers {
            if header.number < horizon {
                let _ = staging.put(header.number, header);
            }
        }
    }

    /// Renames the staging files into the real freezer.
    ///
    /// Called once the walk has reached ground this node already accepted,
    /// which is the point at which the chain stops resting on a peer's word.
    pub fn commit_freezer(&mut self) {
        let Some(staging) = self.staging.take() else { return };
        match staging.promote() {
            Ok(()) => info!(
                target: "rustock::snap",
                "froze {} header(s) during the walk", staging.end_number()
            ),
            Err(e) => warn!(
                target: "rustock::snap",
                "could not promote the staged headers: {e:#}; \
                 they will be refilled from the block database"
            ),
        }
    }

    /// Follow the links as far down as they now reach.
    ///
    /// Returns how many blocks the chain grew by.
    pub fn advance(&mut self) -> Result<u64, WalkError> {
        let started_at = self.need_number;

        loop {
            // Reached ground this node already accepted: everything above is
            // now anchored to work it had already taken.
            if self.is_ours(self.need_number, self.need_hash) {
                // Record what this node had already established here, so the
                // walked work can be compared against a claim measured from
                // genesis rather than from wherever the walk happened to stop.
                self.anchor_difficulty = Some(
                    self.store
                        .total_difficulty(self.need_hash)
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                );
                self.settle_on_own_chain();
                self.done = true;
                self.commit_freezer();
                break;
            }
            if self.need_number == 0 {
                // A chain of well-formed headers back to a genesis this node
                // has never seen is another network's, or an invented one.
                return Err(WalkError::ForeignGenesis);
            }

            // A run is keyed by the height of its newest header, so the one
            // that could satisfy the need is at exactly that height.
            let Some(run) = self.runs.get(&self.need_number).cloned() else { break };
            if run.newest != self.need_hash {
                // Keyed right, wrong chain: whoever pointed us here was on a
                // fork. Drop it and let the range be asked again.
                debug!(
                    target: "rustock::snap",
                    "run at {} is not on our chain; discarding", self.need_number
                );
                self.runs.remove(&self.need_number);
                self.points.remove(&self.need_number);
                break;
            }

            self.runs.remove(&self.need_number);
            self.points.remove(&self.need_number);
            // The run covered down to its oldest header, so what is needed
            // next is that header's parent: one lower, and named by it.
            self.need_number = run.oldest_number.saturating_sub(1);
            self.need_hash = run.oldest_parent;
            // Only now is the run part of the chain, so only now does it
            // count. Counted as answers arrived, a run that never linked -- an
            // answer from another chain, a range answered twice, a late answer
            // to a request asked again -- raised the work established, and
            // with it the ceiling a claim is checked against.
            self.count(run);
        }

        Ok(started_at.saturating_sub(self.need_number))
    }

    /// Add a run that has just joined the chain to the work established.
    fn count(&mut self, run: Run) {
        // Its newest headers are the trunk that the lowest uncles of the run
        // above may hang from.
        self.absorb(&run.newest_difficulties);
        self.walked_difficulty = self.walked_difficulty.saturating_add(run.work);
        self.uncles_omitted += run.uncles_omitted;
        self.uncle_weight = self.uncle_weight.saturating_add(run.uncle_weight);
        self.reaching.extend(run.reaching);
    }

    /// Show the uncles still waiting for their possible parents the next trunk
    /// headers down, newest first, and settle those that have seen them all.
    fn absorb(&mut self, difficulties: &[U256]) {
        let mut settled = U256::ZERO;
        self.reaching.retain_mut(|uncles| {
            let seen = uncles.below.min(difficulties.len());
            for difficulty in &difficulties[..seen] {
                uncles.highest = uncles.highest.max(*difficulty);
            }
            uncles.below -= seen;
            if uncles.below > 0 {
                return true;
            }
            settled =
                settled.saturating_add(U256::from(uncles.count).saturating_mul(uncles.highest));
            false
        });
        self.uncle_weight = self.uncle_weight.saturating_add(settled);
    }

    /// Settle the uncles whose possible parents reach below the walk, on this
    /// node's own chain under the anchor, which the store holds.
    fn settle_on_own_chain(&mut self) {
        let wanted = self
            .reaching
            .iter()
            .map(|uncles| uncles.below)
            .max()
            .unwrap_or(0);
        let mut difficulties = Vec::with_capacity(wanted);
        let mut hash = self.need_hash;
        let mut whole = true;
        while difficulties.len() < wanted {
            let Ok(Some(header)) = self.store.header(hash) else {
                whole = false;
                break;
            };
            difficulties.push(header.difficulty);
            // Nothing hangs from below genesis.
            if header.number == 0 {
                break;
            }
            hash = header.parent_hash;
        }
        self.absorb(&difficulties);
        if self.reaching.is_empty() {
            return;
        }
        if whole {
            // The chain ended at genesis before their stretches did: what they
            // have seen is all there is.
            let settled = self.reaching.drain(..).fold(U256::ZERO, |sum, uncles| {
                sum.saturating_add(U256::from(uncles.count).saturating_mul(uncles.highest))
            });
            self.uncle_weight = self.uncle_weight.saturating_add(settled);
        } else {
            warn!(
                target: "rustock::snap",
                "a header under the anchor is missing, so the uncles above it cannot be bounded"
            );
            self.reaching.clear();
            self.uncle_weight = U256::MAX;
        }
    }
}
