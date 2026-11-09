//! Where execution must resume when the executed head becomes unusable.
//!
//! # The decision, and why it is its own module
//!
//! Three separate bugs in one day (2026-09-23) lived in this decision, each
//! introduced while fixing the previous one:
//!
//! | # | The rule that was broken |
//! |---|---|
//! | 1 | targeted the orphaned head's own parent, which is on the branch being abandoned and so is not canonical either -- the write was refused and the caller gave up |
//! | 2 | nothing responded to a missing state root at all, so the node retried the same impossible block forever |
//! | 3 | searched by **height** rather than by **ancestry**, so it could re-record execution sideways onto a sibling the node had never executed |
//!
//! Bug 3 is the subtle one and it is worth stating plainly. The executed head
//! is a claim: *"I have executed up to this block, and the resulting state is
//! this root."* A sibling at the same height is a different block with a
//! different state. Its root may well be present in the trie -- state roots
//! are shared and forks get executed too -- but recording it makes the claim
//! **false**, and the next block then executes against a state that does not
//! match. On mainnet that surfaced as
//! `NonceTooLow { tx: 177, state: 178 }`: the state was one transaction ahead
//! of where the marker said it was.
//!
//! So the rule, in one sentence:
//!
//! > **Execution may only resume at a block on the executed head's own
//! > ancestry that is also canonical and whose state we still hold.**
//!
//! Ancestry, because those are the only blocks this node has actually
//! executed. Canonical, because [`rustock_storage::Transition::Executed`]
//! refuses anything else -- correctly. State present, because otherwise the
//! node cannot continue and would only discover it on the next block.
//!
//! # Why it is pure
//!
//! The decision takes a [`ChainView`] rather than a store, so it can be driven
//! by a simulator over thousands of generated chains, forks and patterns of
//! missing state. That is a small instance of what stage 6 of
//! `docs/sync-redesign.md` proposes for the whole sync loop, and it exists
//! because all three bugs above were in recovery paths the position-layer
//! simulator structurally could not reach.

use alloy_primitives::B256;
use rustock_core::Header;
use rustock_storage::BlockRef;

/// A rollback deeper than this is not a reorg; it is a broken store, and
/// walking further will not find a resumable state.
pub const MAX_ROLLBACK: u64 = 1_024;

/// Everything the decision needs to know about the chain.
///
/// A trait so the decision can be simulated without a database, and so the
/// three facts it depends on are visible in one place.
pub trait ChainView {
    fn header(&self, hash: B256) -> Option<Header>;
    fn canonical_hash(&self, number: u64) -> Option<B256>;
    /// Is this state root resolvable in the trie store?
    fn has_state(&self, root: B256) -> bool;
}

/// Why no resume point could be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoResumePoint {
    /// The executed head's header is not in the store, so its ancestry cannot
    /// be walked at all.
    HeadHeaderMissing { hash: B256 },
    /// The walk reached genesis without finding a usable block.
    ExhaustedAtGenesis,
    /// The walk hit the depth bound.
    TooDeep { searched: u64 },
    /// An ancestor's header is missing, so the chain cannot be followed lower.
    ChainBroken { at: u64, missing: B256 },
}

/// The block execution must resume from, walking the executed head's own
/// ancestry.
///
/// Returns `Ok(from)` unchanged when the executed head is already usable --
/// callers should treat that as "nothing to do", not as a rollback.
pub fn choose_resume_point<V: ChainView>(
    view: &V,
    from: BlockRef,
) -> Result<BlockRef, NoResumePoint> {
    let mut hash = from.hash;
    let Some(mut header) = view.header(hash) else {
        return Err(NoResumePoint::HeadHeaderMissing { hash });
    };

    for _ in 0..=MAX_ROLLBACK {
        // Canonical AND resumable. Both, or keep walking: a canonical block
        // whose state is gone is no more usable than a fork block.
        let canonical = view.canonical_hash(header.number) == Some(hash);
        if canonical && view.has_state(header.state_root) {
            return Ok(BlockRef::new(header.number, hash));
        }

        if header.number == 0 {
            return Err(NoResumePoint::ExhaustedAtGenesis);
        }

        let parent = header.parent_hash;
        let Some(parent_header) = view.header(parent) else {
            return Err(NoResumePoint::ChainBroken { at: header.number - 1, missing: parent });
        };
        hash = parent;
        header = parent_header;
    }

    Err(NoResumePoint::TooDeep { searched: MAX_ROLLBACK })
}

/// Why the fork point could not be computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoForkPoint {
    /// One of the two branches runs into a header the node does not hold
    /// before the walks meet.
    ///
    /// This is the *ordinary* outcome when a reorg replaces blocks the node
    /// never downloaded: the replacement branch is exactly what is missing.
    /// Callers must have an answer for it, not treat it as an error.
    ChainBroken { missing: B256 },
    /// Neither walk found a shared block within [`MAX_ROLLBACK`].
    TooDeep,
    /// A starting hash has no header.
    HeaderMissing { hash: B256 },
}

/// The deepest block that is on both branches: where they forked.
///
/// `ours` is the head being abandoned, `theirs` the block that replaced it.
///
/// **This is the specification of a correct retreat, not a step in one.** The
/// node cannot call it at the moment it retreats, and the reason is worth
/// stating: the retreat happens only when `Validated::prove` on the
/// replacement failed, and it fails for one reason -- a header missing while
/// walking that branch down. This walks the same segment, from the same tip
/// toward the same meeting point, so it meets the same gap. The two succeed
/// and fail together, and when they succeed the caller adopts the replacement
/// instead of retreating.
///
/// What it is for is checking that the blind retreat which *is* used never
/// stops above the fork -- see `a_blind_retreat_never_stops_above_the_fork`.
/// Here the whole of both branches is known; on the node, half of it is
/// missing by definition.
///
/// Both walks are bounded: a "fork" deeper than [`MAX_ROLLBACK`] is a broken
/// store, not a reorg.
pub fn fork_point<V: ChainView>(
    view: &V,
    ours: B256,
    theirs: B256,
) -> Result<BlockRef, NoForkPoint> {
    use std::collections::HashMap;

    if ours == theirs {
        let header = view.header(ours).ok_or(NoForkPoint::HeaderMissing { hash: ours })?;
        return Ok(BlockRef::new(header.number, ours));
    }

    // Our own ancestry first: it is the one we are sure we hold, because we
    // executed it.
    let mut mine: HashMap<B256, u64> = HashMap::new();
    let mut hash = ours;
    let mut header = view.header(hash).ok_or(NoForkPoint::HeaderMissing { hash: ours })?;
    for _ in 0..=MAX_ROLLBACK {
        mine.insert(hash, header.number);
        if header.number == 0 {
            break;
        }
        let parent = header.parent_hash;
        // A gap on our own side just limits how deep the answer can be; it is
        // not fatal, because the meeting point may be above the gap.
        let Some(parent_header) = view.header(parent) else { break };
        hash = parent;
        header = parent_header;
    }

    // Then walk theirs down until it lands on something of ours.
    let mut hash = theirs;
    let mut header = view.header(hash).ok_or(NoForkPoint::HeaderMissing { hash: theirs })?;
    for _ in 0..=MAX_ROLLBACK {
        if let Some(number) = mine.get(&hash) {
            return Ok(BlockRef::new(*number, hash));
        }
        if header.number == 0 {
            return Err(NoForkPoint::TooDeep);
        }
        let parent = header.parent_hash;
        let Some(parent_header) = view.header(parent) else {
            return Err(NoForkPoint::ChainBroken { missing: parent });
        };
        hash = parent;
        header = parent_header;
    }

    Err(NoForkPoint::TooDeep)
}

/// The deepest ancestor within `depth` blocks of `from` whose state the node
/// still holds.
///
/// Used only when [`fork_point`] cannot answer, to pick a blind retreat
/// target. Two bounds, and both matter:
///
/// * **`depth`**, because a blind retreat is a guess and should not be
///   unbounded.
/// * **state**, because the head is about to retreat here and execution has to
///   resume here. Retreating below the last state the node holds strands
///   execution with nowhere to resume -- `choose_resume_point` would then walk
///   back up looking for a canonical block with state and find none, because
///   the retreat has just un-canonicalised everything above.
///
/// Falls back to the shallowest ancestor walked if none of them has state,
/// which leaves the caller no worse off than the single-step retreat this
/// replaces. Returns `None` only when `from` itself has no header.
pub fn deepest_resumable_within<V: ChainView>(
    view: &V,
    from: B256,
    depth: u64,
) -> Option<BlockRef> {
    let mut hash = from;
    let mut header = view.header(hash)?;
    let mut fallback: Option<BlockRef> = None;
    let mut best: Option<BlockRef> = None;

    for step in 0..=depth {
        // `from` itself is not a candidate: the whole point is to get below it.
        if step > 0 {
            let here = BlockRef::new(header.number, hash);
            fallback.get_or_insert(here);
            if view.has_state(header.state_root) {
                best = Some(here);
            }
        }
        if header.number == 0 {
            break;
        }
        let Some(parent_header) = view.header(header.parent_hash) else { break };
        hash = header.parent_hash;
        header = parent_header;
    }

    best.or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, U256};
    use std::collections::{HashMap, HashSet};

    // ------------------------------------------------------------- model --

    fn header(number: u64, parent: B256, salt: u64) -> Header {
        Header {
            number,
            parent_hash: parent,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::from(U256::from(number * 1_000_003 + salt * 7 + 1)),
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(1),
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: number * 15 + salt,
            extra_data: Bytes::default(),
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

    #[derive(Default)]
    struct World {
        headers: HashMap<B256, Header>,
        canonical: HashMap<u64, B256>,
        state: HashSet<B256>,
    }

    impl ChainView for World {
        fn header(&self, hash: B256) -> Option<Header> {
            self.headers.get(&hash).cloned()
        }
        fn canonical_hash(&self, number: u64) -> Option<B256> {
            self.canonical.get(&number).copied()
        }
        fn has_state(&self, root: B256) -> bool {
            self.state.contains(&root)
        }
    }

    impl World {
        fn add(&mut self, h: &Header) -> B256 {
            let hash = h.hash();
            self.headers.insert(hash, h.clone());
            hash
        }
        fn canonicalise(&mut self, h: &Header) {
            self.canonical.insert(h.number, h.hash());
        }
        fn with_state(&mut self, h: &Header) {
            self.state.insert(h.state_root);
        }
        /// Every ancestor of `hash`, including itself.
        fn ancestry(&self, hash: B256) -> Vec<B256> {
            let mut out = Vec::new();
            let mut cur = hash;
            while let Some(h) = self.headers.get(&cur) {
                out.push(cur);
                if h.number == 0 {
                    break;
                }
                cur = h.parent_hash;
            }
            out
        }
    }

    /// A canonical chain 0..=len, all canonical, all with state.
    fn straight(len: u64) -> (World, Vec<Header>) {
        let mut w = World::default();
        let mut chain = Vec::new();
        let mut parent = B256::ZERO;
        for n in 0..=len {
            let h = header(n, parent, 0);
            parent = w.add(&h);
            w.canonicalise(&h);
            w.with_state(&h);
            chain.push(h);
        }
        (w, chain)
    }

    // ------------------------------------------------- regression fixtures --

    /// Bug 3, mainnet 2026-09-23 14:26. The executed head was a fork block; a
    /// **sibling** at the same height was canonical and had state. Searching by
    /// height re-recorded execution sideways onto a block the node had never
    /// executed, and the next block failed with the state one nonce ahead.
    #[test]
    fn a_sibling_at_the_same_height_is_never_chosen() {
        let (mut w, chain) = straight(10);

        // A fork block at #10, executed but not canonical, state collected.
        let fork = header(10, chain[9].hash(), 99);
        let fork_hash = w.add(&fork);

        let target = choose_resume_point(&w, BlockRef::new(10, fork_hash)).unwrap();

        assert_ne!(target.hash, chain[10].hash(), "chose the canonical SIBLING at #10");
        assert_eq!(target.number, 9, "must step down to the fork point");
        assert_eq!(target.hash, chain[9].hash());
    }

    /// Bug 1, 03:34. The orphan's parent was itself on the abandoned branch.
    /// Walking ancestry keeps going until it rejoins the canonical chain.
    #[test]
    fn a_fork_two_blocks_deep_resumes_at_the_fork_point() {
        let (mut w, chain) = straight(10);

        let f1 = header(9, chain[8].hash(), 77);
        let f1_hash = w.add(&f1);
        let f2 = header(10, f1_hash, 77);
        let f2_hash = w.add(&f2);
        // Both fork blocks have state -- but neither is canonical.
        w.with_state(&f1);
        w.with_state(&f2);

        let target = choose_resume_point(&w, BlockRef::new(10, f2_hash)).unwrap();
        assert_eq!(target.hash, chain[8].hash(), "did not walk back to the fork point");
    }

    /// Bug 2, 14:10. A canonical executed head whose state has been collected
    /// must step down, not be accepted.
    #[test]
    fn a_canonical_head_without_state_steps_down() {
        let (mut w, chain) = straight(10);
        w.state.remove(&chain[10].state_root);
        w.state.remove(&chain[9].state_root);

        let target = choose_resume_point(&w, BlockRef::new(10, chain[10].hash())).unwrap();
        assert_eq!(target.number, 8, "stopped at a height whose state is gone");
    }

    #[test]
    fn a_usable_head_is_returned_unchanged() {
        let (w, chain) = straight(10);
        let target = choose_resume_point(&w, BlockRef::new(10, chain[10].hash())).unwrap();
        assert_eq!(target.hash, chain[10].hash(), "rolled back when nothing was wrong");
    }

    #[test]
    fn a_head_we_do_not_hold_is_reported_not_guessed() {
        let (w, _) = straight(10);
        let err = choose_resume_point(&w, BlockRef::new(10, B256::repeat_byte(0xaa))).unwrap_err();
        assert!(matches!(err, NoResumePoint::HeadHeaderMissing { .. }));
    }

    #[test]
    fn no_state_anywhere_is_reported_not_guessed() {
        let (mut w, chain) = straight(10);
        w.state.clear();
        let err = choose_resume_point(&w, BlockRef::new(10, chain[10].hash())).unwrap_err();
        assert_eq!(err, NoResumePoint::ExhaustedAtGenesis);
    }

    #[test]
    fn a_broken_ancestry_is_reported_not_guessed() {
        let (mut w, chain) = straight(10);
        w.state.clear();
        w.headers.remove(&chain[7].hash());
        let err = choose_resume_point(&w, BlockRef::new(10, chain[10].hash())).unwrap_err();
        assert!(matches!(err, NoResumePoint::ChainBroken { at: 7, .. }), "got {err:?}");
    }

    // ------------------------------------------------------- the simulator --

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed | 1)
        }
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }

    /// Build a world with a canonical chain, forks hanging off it at random
    /// depths, and a random subset of state roots present. Returns the world
    /// and a candidate executed head, which may be on a fork.
    fn generate(seed: u64) -> (World, B256) {
        let mut rng = Rng::new(seed);
        let mut w = World::default();

        let len = 5 + rng.below(40);
        let mut canonical = Vec::new();
        let mut parent = B256::ZERO;
        for n in 0..=len {
            let h = header(n, parent, 0);
            parent = w.add(&h);
            w.canonicalise(&h);
            canonical.push(h);
        }

        // Forks: a run of blocks hanging off a random canonical block.
        let mut fork_tips = Vec::new();
        for f in 0..rng.below(6) {
            let at = rng.below(canonical.len() as u64);
            let mut p = canonical[at as usize].hash();
            let mut n = canonical[at as usize].number;
            for _ in 0..=rng.below(5) {
                n += 1;
                let h = header(n, p, 100 + f);
                p = w.add(&h);
                fork_tips.push(p);
            }
        }

        // A random subset of every header's state root is present.
        let all: Vec<Header> = w.headers.values().cloned().collect();
        for h in all {
            if rng.below(100) < 60 {
                w.with_state(&h);
            }
        }

        // The executed head: usually the canonical tip, sometimes a fork tip.
        let exec = if !fork_tips.is_empty() && rng.below(100) < 50 {
            fork_tips[rng.below(fork_tips.len() as u64) as usize]
        } else {
            canonical[rng.below(canonical.len() as u64) as usize].hash()
        };

        (w, exec)
    }

    /// The specification, asserted over thousands of generated worlds.
    ///
    /// This is the test that did not exist today, and every one of the three
    /// bugs violates one of these four clauses.
    #[test]
    fn the_resume_point_is_always_an_executed_canonical_block_with_state() {
        for seed in 1..=3_000u64 {
            let (w, exec) = generate(seed);
            let exec_header = w.header(exec).expect("generated head");
            let from = BlockRef::new(exec_header.number, exec);
            let ancestry: Vec<B256> = w.ancestry(exec);

            match choose_resume_point(&w, from) {
                Ok(target) => {
                    // 1. On the executed head's own ancestry -- never a sibling.
                    assert!(
                        ancestry.contains(&target.hash),
                        "seed {seed}: resumed at a block this node never executed"
                    );
                    // 2. Canonical, or Transition::Executed will refuse it.
                    assert_eq!(
                        w.canonical_hash(target.number),
                        Some(target.hash),
                        "seed {seed}: resumed at a non-canonical block"
                    );
                    // 3. Its state is actually there.
                    let h = w.header(target.hash).unwrap();
                    assert!(w.has_state(h.state_root), "seed {seed}: resumed with no state");
                    // 4. Never above where we started.
                    assert!(target.number <= from.number, "seed {seed}: resumed forwards");
                }
                Err(_) => {
                    // A refusal must mean no ancestor qualified.
                    for hash in &ancestry {
                        let h = w.header(*hash).unwrap();
                        let ok = w.canonical_hash(h.number) == Some(*hash)
                            && w.has_state(h.state_root);
                        assert!(
                            !ok,
                            "seed {seed}: gave up while #{} was usable",
                            h.number
                        );
                    }
                }
            }
        }
    }

    /// And it must find the *highest* usable ancestor: resuming lower than
    /// necessary re-executes blocks for nothing.
    #[test]
    fn the_resume_point_is_the_highest_usable_ancestor() {
        for seed in 1..=3_000u64 {
            let (w, exec) = generate(seed);
            let exec_header = w.header(exec).expect("generated head");
            let from = BlockRef::new(exec_header.number, exec);

            let Ok(target) = choose_resume_point(&w, from) else { continue };

            for hash in w.ancestry(exec) {
                let h = w.header(hash).unwrap();
                if h.number <= target.number {
                    break;
                }
                let usable = w.canonical_hash(h.number) == Some(hash)
                    && w.has_state(h.state_root);
                assert!(
                    !usable,
                    "seed {seed}: resumed at #{} when #{} was usable",
                    target.number, h.number
                );
            }
        }
    }

    /// A common chain up to `fork_height`, then two branches of `depth` blocks
    /// diverging from it. Returns (fork block, our tip, their tip).
    fn two_branches(w: &mut World, fork_height: u64, depth: u64) -> (B256, B256, B256) {
        let mut parent = B256::ZERO;
        for n in 0..fork_height {
            let h = header(n, parent, 0);
            parent = w.add(&h);
            w.canonicalise(&h);
            w.with_state(&h);
        }
        let fork_block = header(fork_height, parent, 0);
        let fork = w.add(&fork_block);
        w.canonicalise(&fork_block);
        w.with_state(&fork_block);

        let build = |w: &mut World, salt: u64| {
            let mut parent = fork;
            for n in fork_height + 1..=fork_height + depth {
                let h = header(n, parent, salt);
                parent = w.add(&h);
                w.with_state(&h);
            }
            parent
        };
        let ours = build(w, 1);
        let theirs = build(w, 2);
        (fork, ours, theirs)
    }

    impl World {
        /// Drop a header, as a node that never downloaded it would have it.
        fn forget(&mut self, hash: B256) {
            self.headers.remove(&hash);
        }
    }

    mod fork {
        use super::*;

        /// The property the blind retreat must satisfy: **never stop above the
        /// fork.** Stopping above it re-seats the head on a block the network
        /// abandoned, which is the 2026-09-24 stall.
        ///
        /// `fork_point` is the oracle, computed here with both branches fully
        /// known -- which is exactly the knowledge the node does not have when
        /// it retreats.
        #[test]
        fn a_blind_retreat_never_stops_above_the_fork() {
            let limit = crate::service::BLIND_RETREAT_DEPTH;
            for depth in 1..=limit {
                let mut w = World::default();
                let (_, tip_ours, tip_theirs) = two_branches(&mut w, 100, depth);

                let fork = fork_point(&w, tip_ours, tip_theirs).unwrap();
                let target = deepest_resumable_within(&w, tip_ours, limit).unwrap();

                assert!(
                    target.number <= fork.number,
                    "a {depth}-deep reorg retreated to #{} but the branches fork at #{}; \
                     the head would be re-seated on a block the network abandoned",
                    target.number, fork.number
                );
            }
        }

        /// The same property, against the rule this replaces. It fails for
        /// every reorg deeper than one block -- which is the bug, stated as a
        /// test rather than as a paragraph.
        #[test]
        fn retreating_to_the_parent_stops_above_the_fork_whenever_it_is_deeper() {
            for depth in 1..=6u64 {
                let mut w = World::default();
                let (_, tip_ours, tip_theirs) = two_branches(&mut w, 100, depth);

                let fork = fork_point(&w, tip_ours, tip_theirs).unwrap();
                let parent = w.header(tip_ours).unwrap().parent_hash;
                let parent_number = w.header(parent).unwrap().number;

                if depth == 1 {
                    assert_eq!(parent_number, fork.number, "one block deep: the old rule holds");
                } else {
                    assert!(
                        parent_number > fork.number,
                        "a {depth}-deep reorg: the parent (#{parent_number}) is still above \
                         the fork (#{}), i.e. still on the abandoned branch",
                        fork.number
                    );
                }
            }
        }

        /// The shape that stalled mainnet on 2026-09-24: the branches forked three
        /// blocks below the orphaned head. Retreating to the head's own parent --
        /// what this replaces -- lands on a block that is itself on the losing
        /// branch.
        #[test]
        fn fork_point_finds_a_three_deep_divergence() {
            let mut w = World::default();
            let (common, tip_ours, tip_theirs) = two_branches(&mut w, 649, 3);

            let fork = fork_point(&w, tip_ours, tip_theirs).unwrap();
            assert_eq!(fork.number, 649, "the fork is at the last shared block");
            assert_eq!(fork.hash, common);

            // The parent of the orphaned head is NOT the fork point -- it is two
            // blocks above it, on the branch being abandoned.
            let ours_parent = w.header(tip_ours).unwrap().parent_hash;
            assert_ne!(ours_parent, fork.hash, "this is the bug being fixed");
        }

        #[test]
        fn fork_point_of_a_one_deep_reorg_is_the_parent() {
            let mut w = World::default();
            let (common, tip_ours, tip_theirs) = two_branches(&mut w, 100, 1);
            let fork = fork_point(&w, tip_ours, tip_theirs).unwrap();
            assert_eq!(fork.hash, common);
            assert_eq!(fork.hash, w.header(tip_ours).unwrap().parent_hash,
                "for a one-block reorg the old rule and the new one agree");
        }

        #[test]
        fn fork_point_of_a_block_with_itself_is_that_block() {
            let (w, chain) = straight(5);
            let hash = chain[3].hash();
            assert_eq!(fork_point(&w, hash, hash).unwrap().number, 3);
        }

        /// The ordinary case at the tip: the replacement branch was never
        /// downloaded, so there is nothing to walk. The caller must have an answer
        /// for this -- it is not an error condition.
        #[test]
        fn fork_point_reports_a_break_when_the_other_branch_is_not_held() {
            let mut w = World::default();
            let (_, tip_ours, tip_theirs) = two_branches(&mut w, 100, 3);

            // Forget the replacement branch below its tip, as a node that never
            // downloaded it would have it.
            let theirs_parent = w.header(tip_theirs).unwrap().parent_hash;
            w.forget(theirs_parent);

            assert_eq!(
                fork_point(&w, tip_ours, tip_theirs),
                Err(NoForkPoint::ChainBroken { missing: theirs_parent })
            );
        }

        #[test]
        fn fork_point_needs_both_headers() {
            let (w, chain) = straight(3);
            let absent = B256::repeat_byte(0xAB);
            assert_eq!(
                fork_point(&w, absent, chain[1].hash()),
                Err(NoForkPoint::HeaderMissing { hash: absent })
            );
            assert_eq!(
                fork_point(&w, chain[1].hash(), absent),
                Err(NoForkPoint::HeaderMissing { hash: absent })
            );
        }

        /// Two chains that share no ancestor at all are not a reorg.
        #[test]
        fn fork_point_refuses_unrelated_chains() {
            let mut w = World::default();
            let mut a_parent = B256::ZERO;
            let mut b_parent = B256::repeat_byte(0x99);
            let (mut a, mut b) = (B256::ZERO, B256::ZERO);
            for n in 0..4 {
                let ha = header(n, a_parent, 1);
                let hb = header(n, b_parent, 2);
                a = w.add(&ha);
                b = w.add(&hb);
                a_parent = a;
                b_parent = b;
            }
            assert_eq!(fork_point(&w, a, b), Err(NoForkPoint::TooDeep));
        }

        // ---------------------------------------------------- blind retreat --

        #[test]
        fn blind_retreat_goes_the_full_depth_when_state_is_there() {
            let (w, chain) = straight(40);
            let from = chain[40].hash();
            let target = deepest_resumable_within(&w, from, 25).unwrap();
            assert_eq!(target.number, 15, "40 - 25");
        }

        /// The bound that matters: the head is about to retreat here and execution
        /// has to resume here, so the walk must not outrun the state.
        #[test]
        fn blind_retreat_stops_at_the_last_block_with_state() {
            let mut w = World::default();
            let mut chain = Vec::new();
            let mut parent = B256::ZERO;
            for n in 0..=40 {
                let h = header(n, parent, 0);
                parent = w.add(&h);
                w.canonicalise(&h);
                // State only for the newest ten blocks, as a pruned node has it.
                if n >= 31 {
                    w.with_state(&h);
                }
                chain.push(h);
            }
            let target = deepest_resumable_within(&w, chain[40].hash(), 25).unwrap();
            assert_eq!(target.number, 31, "must not retreat past the oldest state held");
        }

        #[test]
        fn blind_retreat_never_returns_the_block_it_started_from() {
            let (w, chain) = straight(10);
            let target = deepest_resumable_within(&w, chain[10].hash(), 25).unwrap();
            assert!(target.number < 10, "the point is to get below the orphan");
            assert_eq!(target.number, 0, "a short chain bottoms out at genesis");
        }
    }

}
