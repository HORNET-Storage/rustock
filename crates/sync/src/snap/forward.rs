//! Walking the header chain *up* from ground this node already trusts.
//!
//! The counterpart to [`super::headers`], which descends from a checkpoint a
//! peer offered. Both fetch the same descending 192-header chunks -- the wire
//! has no forward request, `BlockHeadersQuery` being `{ hash, count }` with no
//! direction -- and both link those chunks by hash. What differs is which end
//! is trusted, and therefore which way confidence flows.
//!
//! # Why bother, when the other one works
//!
//! A descending walk is one bet on one peer's offer. Nothing it fetches is
//! worth anything until an unbroken run of links reaches ground, so a walk that
//! dies at ninety percent has established nothing, and how far to fan out is a
//! question about how much conditional work one is willing to throw away.
//!
//! Ascending from an anchor, a chunk is permanently valuable the moment it
//! links to the prefix below it. A peer that answers wrongly costs its own
//! chunk and nothing else. That is what makes wide fan-out across many peers
//! cheap to attempt, and it is the whole practical argument for this shape.
//!
//! See `docs/header-first-sync.md` for the design note this implements.
//!
//! # What it establishes
//!
//! The chain's **exact** cumulative difficulty, which in RSK is
//! `trunk.difficulty + sum(uncle.difficulty)` and is therefore not computable
//! from trunk headers alone. This walk takes `BlockHeadersWithUncles`
//! (RSKIP-698) and proves the uncle work rather than assuming or bounding it:
//!
//! 1. `ommers_hash` is inside what the trunk header's proof of work commits to,
//!    so a list matching it cannot have been added to, dropped from or altered.
//!    [`HeaderWithUncles::commitment_matches`] is that check.
//! 2. Each uncle header carries its **own** merged-mining proof of work. A
//!    matching commitment only proves the miner chose this list; verifying each
//!    uncle's proof is what makes its difficulty work rather than a number the
//!    miner wrote down.
//! 3. An uncle hash already counted under another trunk header is refused.
//!    Consensus forbids reuse (`validateIfUncleWasNeverUsed`); without the
//!    check the same uncle's difficulty counts many times over.
//!
//! All three are needed. Any one alone leaves the total an assertion, and no
//! header field substitutes for them -- work is proven by exhibiting it.

use alloy_primitives::{B256, U256};
use rustock_core::validation::HeaderVerifier;
use rustock_core::Header;
use rustock_networking::protocol::{BlockIdentifier, HeaderWithUncles};
use rustock_core::validation::uncles::UNCLE_GENERATION_LIMIT;
use rustock_storage::BlockStore;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Headers per request, matching [`super::headers::HEADER_CHUNK`].
pub use super::headers::{HEADER_CHUNK, SKELETON_POINTS};

/// What the ascent wants asked next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// Block identifiers from this height upward.
    Skeleton { start: u64 },
    /// `count` headers, with their uncles, walking back from this hash.
    Headers { from: B256, count: u32, point: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AscentError {
    #[error("header #{number} failed validation: {reason}")]
    InvalidHeader { number: u64, reason: String },
    #[error("the headers for point {point} do not form a chain")]
    BrokenChunk { point: u64 },
    #[error("block #{number} sent uncles its header does not commit to")]
    UncleCommitment { number: u64 },
    #[error("uncle {hash} of block #{number} has no valid proof of work: {reason}")]
    UncleProofOfWork { number: u64, hash: B256, reason: String },
    #[error("uncle {hash} was already counted under another block")]
    UncleReused { hash: B256 },
    #[error("a peer answered without the uncles this walk needs to total the work")]
    UnclesMissing,
}

/// A verified run, remembered by its ends and what it is worth.
#[derive(Debug, Clone)]
struct Run {
    newest: B256,
    newest_number: u64,
    oldest_number: u64,
    /// The parent of the oldest header: what the prefix below must already be.
    oldest_parent: B256,
    /// Exact cumulative difficulty of the run: trunk plus proven uncles.
    work: U256,
    /// `(including height, uncle hash)` for every uncle this run counted, so
    /// reuse across runs is caught when the run is consumed rather than when it
    /// arrives -- and so the ledger below can be pruned by height.
    uncles: Vec<(u64, B256)>,
    /// The uncle headers each block referenced, oldest block first.
    ///
    /// Carried so they can be written to the freezer when the run is
    /// committed. Bounded by what is in flight -- a few hundred kilobytes --
    /// and the alternative is throwing away the only copy that will ever reach
    /// this node.
    uncle_headers: Vec<(u64, Vec<Header>)>,
    /// `(number, hash)` for every block in the run, oldest first.
    ///
    /// Kept so the canonical index can be written when the run is *consumed*
    /// rather than when it arrives: a run that has not linked yet is still
    /// only a peer's word, and writing it would publish an unproven chain.
    blocks: Vec<(u64, B256)>,
    /// What each of `blocks` adds to the chain's work, in the same order: its
    /// own difficulty and its proven uncles', rskj's
    /// `Block.getCumulativeDifficulty`.
    ///
    /// Kept so that the commit can give every block its own total, as rskj
    /// gives every block it stores one.
    difficulties: Vec<U256>,
}

/// Ascends from an anchor toward a target height, proving the work as it goes.
pub struct ForwardSync {
    store: Arc<BlockStore>,
    verifier: Arc<HeaderVerifier>,

    /// Where the proven prefix currently ends: the walk's whole state.
    ///
    /// A run extends it when the run begins exactly one block above this height
    /// *and* names this hash as its oldest header's parent. Nothing else moves
    /// it, which is why a wrong skeleton identifier cannot mislead the ascent --
    /// it produces a run that simply never fits.
    have_number: u64,
    have_hash: B256,

    /// The height being ascended toward, and its hash.
    ///
    /// The hash matters because the target need not sit on the chunk grid:
    /// skeleton identifiers land on multiples of [`HEADER_CHUNK`], so for a
    /// target that is not one, no identifier will ever name it. The remainder
    /// is asked for from the target's own hash instead.
    target: u64,
    target_hash: B256,

    /// Whether to archive uncle headers; see `SnapConfig::archive_uncles`.
    archive_uncles: bool,

    /// Where skeleton starts are measured from, and how far apart.
    skeleton_base: u64,
    skeleton_span: u64,

    skeleton_todo: Vec<u64>,
    skeleton_sent: HashSet<u64>,
    /// Hashes learned from skeletons, by height. Claims, not facts.
    points: BTreeMap<u64, B256>,

    headers_sent: HashSet<u64>,
    /// Verified runs waiting for the prefix to reach them, keyed by the height
    /// their *oldest* header sits at -- which is what the prefix must reach.
    runs: BTreeMap<u64, Run>,
    /// Points a run is already in hand for, so `wants` does not ask twice.
    ///
    /// Kept beside `runs` rather than derived from it: runs are keyed by their
    /// oldest height and a point is their newest, so deriving this meant
    /// scanning every run for every candidate point.
    satisfied: HashSet<u64>,

    /// Exact cumulative difficulty accumulated over the proven prefix.
    work: U256,
    /// Uncles counted recently, for the reuse rule, as
    /// `(including height, uncle hash)` oldest first.
    ///
    /// A window, not a ledger. Consensus lets a block reference an uncle only
    /// within [`UNCLE_GENERATION_LIMIT`] generations of it, so two references
    /// to the same uncle are at most that far apart and nothing older can ever
    /// collide. Keeping every hash instead would be one `B256` per uncle for
    /// the whole chain -- on mainnet about 8.4 million of them, a few hundred
    /// megabytes, for a rule that needs eight heights.
    counted_uncles: std::collections::VecDeque<(u64, B256)>,
    done: bool,
}

impl ForwardSync {
    /// Starts at `anchor`, which must be a block this node already accepts, and
    /// ascends toward `target`.
    pub fn new(
        anchor_number: u64,
        anchor_hash: B256,
        anchor_work: U256,
        target: u64,
        target_hash: B256,
        archive_uncles: bool,
        store: Arc<BlockStore>,
        verifier: Arc<HeaderVerifier>,
    ) -> Self {
        // Skeleton coverage starts at the anchor, since that is the first
        // height whose chunk the prefix can consume.
        let mut skeleton_todo = Vec::new();
        let span = HEADER_CHUNK * SKELETON_POINTS;
        let mut start = anchor_number;
        while start < target {
            skeleton_todo.push(start);
            start = start.saturating_add(span);
        }
        // Popped from the back, and the low end is what the prefix needs first.
        skeleton_todo.reverse();

        Self {
            store,
            verifier,
            have_number: anchor_number,
            have_hash: anchor_hash,
            target,
            target_hash,
            archive_uncles,
            skeleton_base: anchor_number,
            skeleton_span: span,
            skeleton_todo,
            skeleton_sent: HashSet::new(),
            points: BTreeMap::new(),
            headers_sent: HashSet::new(),
            runs: BTreeMap::new(),
            satisfied: HashSet::new(),
            work: anchor_work,
            counted_uncles: std::collections::VecDeque::new(),
            done: anchor_number >= target,
        }
    }

    pub fn done(&self) -> bool {
        self.done
    }

    /// The highest height the proven prefix reaches.
    pub fn frontier(&self) -> u64 {
        self.have_number
    }

    /// How many uncles the reuse window currently holds. For tests that assert
    /// it stays bounded.
    #[cfg(test)]
    pub fn counted_uncles_len(&self) -> usize {
        self.counted_uncles.len()
    }

    /// Exact cumulative difficulty of the proven prefix.
    ///
    /// Exact, not a bound: every uncle counted here was committed to by a trunk
    /// header's proof of work and carried its own. Contrast
    /// `super::headers::HeaderWalk::walked_difficulty`, which is a lower bound
    /// whenever a peer answered without uncles.
    pub fn work(&self) -> U256 {
        self.work
    }

    /// Up to `budget` things to ask for, none already outstanding.
    ///
    /// Headers before skeletons, and lowest first: the prefix advances from the
    /// bottom, so a chunk far above it is worth nothing until everything under
    /// it has landed.
    pub fn wants(&mut self, budget: usize) -> Vec<Want> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }

        let points: Vec<u64> = self
            .points
            .iter()
            .filter(|(p, _)| {
                **p > self.have_number
                    && !self.headers_sent.contains(*p)
                    && !self.satisfied.contains(*p)
            })
            .map(|(p, _)| *p)
            .take(budget)
            .collect();
        for point in points {
            let Some(hash) = self.points.get(&point).copied() else { continue };
            // Never ask for more than reaches down to the prefix: a longer run
            // would overlap what is already proven and could not link.
            let count = (point - self.have_number).min(HEADER_CHUNK) as u32;
            self.headers_sent.insert(point);
            out.push(Want::Headers { from: hash, count, point });
            if out.len() >= budget {
                return out;
            }
        }

        // Bridge a gap the skeleton did not cover.
        //
        // The prefix can only absorb a run that begins exactly at
        // `have_number + 1`, which needs a point exactly 192 above it. If that
        // one point is missing -- a skeleton answer that never arrived, or a
        // peer that would not serve it -- then every run above is misaligned:
        // a 192-chunk fetched from the next point along starts 192 blocks too
        // high and can never link. They pile up in `runs`, marked satisfied,
        // and `wants` has nothing left to ask for. The sync stops dead with a
        // peer still connected and no error.
        //
        // That is exactly how the mainnet run of 2026-10-05 stalled at
        // #9,281,664 for three hours, 3,336 blocks short.
        //
        // The way out is the hash every run already carries: its oldest
        // header's parent. Asking from there lands a chunk whose newest block
        // is the one immediately below, closing the gap by up to 192 blocks a
        // time without needing a skeleton at all.
        if out.len() < budget {
            if let Some((_, run)) = self
                .runs
                .iter()
                .find(|(oldest, _)| **oldest > self.have_number + 1)
            {
                let point = run.oldest_number - 1;
                let count = (point - self.have_number).min(HEADER_CHUNK);
                if count > 0 && !self.headers_sent.contains(&point) {
                    debug!(
                        target: "rustock::snap",
                        "forward sync: bridging #{}..#{point} from the run above",
                        self.have_number + 1
                    );
                    self.headers_sent.insert(point);
                    out.push(Want::Headers {
                        from: run.oldest_parent,
                        count: count as u32,
                        point,
                    });
                    if out.len() >= budget {
                        return out;
                    }
                }
            }
        }

        // The stretch above the last grid point, which no skeleton identifier
        // covers. Asked for from the target's own hash, the one hash that is
        // known without a skeleton. Without this the ascent can never satisfy
        // `have_number >= target` for a target off the grid, and stalls at
        // 99.9% having done all the work.
        let grid_top = (self.target / HEADER_CHUNK) * HEADER_CHUNK;
        if self.target > grid_top
            && self.have_number < self.target
            && out.len() < budget
            && !self.headers_sent.contains(&self.target)
            && !self.satisfied.contains(&self.target)
        {
            let count = (self.target - grid_top).min(self.target - self.have_number);
            self.headers_sent.insert(self.target);
            out.push(Want::Headers {
                from: self.target_hash,
                count: count as u32,
                point: self.target,
            });
            if out.len() >= budget {
                return out;
            }
        }

        while out.len() < budget {
            let Some(start) = self.skeleton_todo.pop() else { break };
            if self.skeleton_sent.insert(start) {
                out.push(Want::Skeleton { start });
            }
        }
        out
    }

    /// Write a consumed run to the canonical index with each block's total
    /// difficulty, and move the head with it.
    ///
    /// `below` is the total of the block the run builds on. Each block's total
    /// is its parent's plus what it adds, as rskj's
    /// `BlockChainImpl.internalTryToConnect` gives every block it connects one
    /// (`parentTotalDifficulty.add(block.getCumulativeDifficulty())`). The
    /// BlockHeader contract's `getCumulativeWork` reads it for any of the last
    /// 4,000 blocks, and stops the node at a block whose total is missing:
    /// writing the newest block's alone left every other block without one.
    ///
    /// The head is what `SnapSession::anchor` reads on the next start, so this
    /// is the whole of resuming. The newest block's total is the figure the
    /// ascent would otherwise have to re-derive by walking from genesis again.
    fn commit(&self, run: &Run, below: U256) {
        let mut total = below;
        for ((number, hash), difficulty) in run.blocks.iter().zip(&run.difficulties) {
            total = total.saturating_add(*difficulty);
            if let Err(e) = self
                .store
                .put_canonical_hash(*number, *hash)
                .and_then(|()| self.store.put_total_difficulty(*hash, total))
            {
                warn!(
                    target: "rustock::snap",
                    "forward sync: could not index #{number}: {e}"
                );
                return;
            }
        }
        // Keep the uncles, do not just count them.
        //
        // They arrive once, over the wire, and nothing else will ever hand
        // them to this node: uncle headers live in block bodies, and a header
        // sync has no bodies. Dropping them leaves a node that cannot sum its
        // own chain's work and cannot serve `rsk/63` to anyone else -- which
        // is to say, cannot serve the sync it just performed.
        //
        // Only below the freeze horizon. Nearer the target the chain can still
        // move, and the freezer is for settled history; those blocks are
        // inside the body window the sync fetches anyway, so their uncles
        // arrive with the bodies.
        if self.archive_uncles {
          if let Some(freezer) = self.store.freezer() {
            let horizon = self.target.saturating_sub(rustock_storage::freezer::FREEZE_DEPTH);
            for (number, uncles) in &run.uncle_headers {
                if *number < horizon {
                    if let Err(e) = freezer.put_uncles(*number, uncles) {
                        warn!(
                            target: "rustock::snap",
                            "forward sync: could not store the uncles of #{number}: {e}"
                        );
                        break;
                    }
                }
            }
          }
        }

        if let Err(e) = self.store.set_head(run.newest) {
            warn!(target: "rustock::snap", "forward sync: could not move the head: {e}");
        }
    }

    /// The skeleton request whose answer would name a point at `number`.
    fn skeleton_start_covering(&self, number: u64) -> u64 {
        let span = self.skeleton_span.max(1);
        self.skeleton_base + ((number.saturating_sub(self.skeleton_base)) / span) * span
    }

    /// Forget a point and everything derived from it, so it can be learned
    /// again -- from another peer if there is one.
    ///
    /// A height the ascent has given up on is otherwise unreachable: the point
    /// is gone, so `wants` will not ask, and nothing re-queues the skeleton
    /// that would name it again. With one peer that is a permanent stall.
    fn forget_point(&mut self, point: u64) {
        self.points.remove(&point);
        self.satisfied.remove(&point);
        self.headers_sent.remove(&point);
        let start = self.skeleton_start_covering(point);
        if self.skeleton_sent.remove(&start) {
            self.skeleton_todo.push(start);
        }
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
            if id.number <= self.have_number || id.number > self.target {
                continue;
            }
            if self.runs.values().any(|r| r.newest_number == id.number) {
                continue;
            }
            self.points.insert(id.number, id.hash);
        }
    }

    /// A run of headers with their uncles, newest first, as the wire delivers.
    pub fn on_headers_with_uncles(
        &mut self,
        point: u64,
        entries: &[HeaderWithUncles],
    ) -> Result<(), AscentError> {
        self.headers_sent.remove(&point);
        if entries.is_empty() {
            return Ok(());
        }

        let headers: Vec<Header> = entries.iter().map(|e| e.header.clone()).collect();
        self.check_chain(point, &headers)?;

        // Uncles: committed, proven, and not already counted. All three, in
        // that order -- the commitment makes the list the block's own, the
        // proof of work makes each difficulty real, and the reuse check stops
        // one uncle's work being counted under several blocks.
        let mut work = U256::ZERO;
        let mut uncles = Vec::new();
        let mut seen = HashSet::new();
        for entry in entries {
            if !entry.commitment_matches() {
                return Err(AscentError::UncleCommitment { number: entry.header.number });
            }
            for uncle in &entry.uncles {
                let hash = uncle.hash();
                // An uncle's own rules, which are not a trunk header's; its
                // parent is not held here, so only the rules that need none.
                self.verifier.verify_uncle(uncle).map_err(|e| {
                    AscentError::UncleProofOfWork {
                        number: entry.header.number,
                        hash,
                        reason: e.to_string(),
                    }
                })?;
                if self.counted_uncles.iter().any(|(_, h)| *h == hash) || !seen.insert(hash) {
                    return Err(AscentError::UncleReused { hash });
                }
                uncles.push((entry.header.number, hash));
            }
            work = work.saturating_add(entry.cumulative_difficulty());
        }

        // Entries arrive newest first; the ledger is pruned from its oldest
        // end, so what goes into it has to be the other way round.
        uncles.reverse();

        let newest = &headers[0];
        let oldest = headers.last().expect("non-empty");
        let mut blocks: Vec<(u64, B256)> =
            headers.iter().map(|h| (h.number, h.hash())).collect();
        blocks.reverse(); // oldest first, the order the index wants
        let mut uncle_headers: Vec<(u64, Vec<Header>)> =
            entries.iter().map(|e| (e.header.number, e.uncles.clone())).collect();
        uncle_headers.reverse();
        let mut difficulties: Vec<U256> = entries
            .iter()
            .map(HeaderWithUncles::cumulative_difficulty)
            .collect();
        difficulties.reverse();
        self.satisfied.insert(point);
        self.runs.insert(
            oldest.number,
            Run {
                newest: newest.hash(),
                newest_number: newest.number,
                oldest_number: oldest.number,
                oldest_parent: oldest.parent_hash,
                work,
                uncles,
                blocks,
                difficulties,
                uncle_headers,
            },
        );

        for header in &headers {
            let _ = self.store.put_header_with_hash(header.hash(), header);
        }

        self.advance();
        Ok(())
    }

    /// Verifies a run against itself: internal linkage and every rule that does
    /// not need a body. Identical in substance to the descending walk's check,
    /// because the direction a chunk arrives in does not change what makes it
    /// valid.
    fn check_chain(&self, point: u64, headers: &[Header]) -> Result<(), AscentError> {
        let newest = &headers[0];
        for pair in headers.windows(2) {
            let (child, parent) = (&pair[0], &pair[1]);
            if child.parent_hash != parent.hash() {
                return Err(AscentError::BrokenChunk { point });
            }
            self.verifier.verify(parent, None).map_err(|e| AscentError::InvalidHeader {
                number: parent.number,
                reason: e.to_string(),
            })?;
            self.verifier.verify_against_parent(child, parent).map_err(|e| {
                AscentError::InvalidHeader { number: child.number, reason: e.to_string() }
            })?;
        }
        self.verifier.verify(newest, None).map_err(|e| AscentError::InvalidHeader {
            number: newest.number,
            reason: e.to_string(),
        })?;
        Ok(())
    }

    /// Consume every run the prefix can now absorb.
    ///
    /// A run fits when it begins one block above the frontier and names the
    /// frontier's hash as its oldest header's parent. Both conditions, not
    /// either: the height alone would let a run from another chain through.
    fn advance(&mut self) {
        // Runs wholly below the prefix can no longer contribute; a later run
        // overtook them. Dropping them keeps the map from growing and stops a
        // stale entry masking a point that still needs asking for.
        let frontier = self.have_number;
        let stale: Vec<u64> = self
            .runs
            .iter()
            .filter(|(_, r)| r.newest_number <= frontier)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            if let Some(run) = self.runs.remove(&key) {
                self.satisfied.remove(&run.newest_number);
            }
        }

        while let Some(run) = self.runs.get(&(self.have_number + 1)) {
            if run.oldest_parent != self.have_hash {
                // A run at the right height from the wrong chain. Forget the
                // point entirely -- the identifier that produced it was wrong,
                // so asking again with the same hash would return the same
                // run -- and re-queue the skeleton that would name it afresh.
                debug!(
                    target: "rustock::snap",
                    "forward sync: run at #{} does not link to the proven prefix; \
                     re-asking for that height",
                    self.have_number + 1
                );
                let point = run.newest_number;
                self.runs.remove(&(self.have_number + 1));
                self.forget_point(point);
                return;
            }
            let run = self.runs.remove(&(self.have_number + 1)).expect("just read");
            let below = self.work;
            self.work = self.work.saturating_add(run.work);
            self.counted_uncles.extend(run.uncles.iter().copied());
            self.have_number = run.newest_number;
            self.have_hash = run.newest;

            // Drop what is now too old to be referenced again. After the
            // frontier moves, not before: the floor is measured from where the
            // prefix now ends.
            let floor = self.have_number.saturating_sub(UNCLE_GENERATION_LIMIT);
            while self.counted_uncles.front().is_some_and(|(at, _)| *at < floor) {
                self.counted_uncles.pop_front();
            }

            // Commit the run now that it is part of the proven prefix.
            //
            // This is what makes the shape worth its name. A descending walk
            // cannot do it -- nothing it fetches is worth anything until the
            // links reach ground -- so it stages everything and promotes at
            // the end, and a walk that dies has established nothing. Ascending,
            // every run that links is permanently true, and writing it means a
            // sync that is interrupted resumes from where it stopped instead
            // of starting again at genesis.
            self.commit(&run, below);
            self.points.remove(&run.newest_number);
            self.satisfied.remove(&run.newest_number);

            if self.have_number >= self.target {
                self.done = true;
                info!(
                    target: "rustock::snap",
                    "forward header sync complete at #{}: cumulative difficulty {} \
                     with uncle work proven throughout",
                    self.have_number,
                    self.work
                );
                return;
            }
        }
    }
}
