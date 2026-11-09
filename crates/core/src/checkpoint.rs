//! Cumulative-difficulty checkpoints, and an upper bound on the work a chain
//! can carry above one.
//!
//! # The problem
//!
//! A peer advertises a total difficulty and a height. Nothing in the protocol
//! makes that claim cost anything, and a node with no chain of its own has
//! nothing to check it against — so it will follow the claim, download headers
//! for as long as the peer cares to serve them, and only discover the lie at
//! the bottom of the chain, if at all.
//!
//! # Two kinds of checkpoint, and why this is the safe one
//!
//! A **hash** checkpoint asserts identity: *the block at height H is X*. If it
//! is ever wrong — a bad build, a compromised release — the node silently
//! follows a chain nobody else is on, and cannot tell from the inside that
//! anything is amiss.
//!
//! A **cumulative difficulty** checkpoint asserts a bound: *the work from
//! genesis to height H is Y, so nothing may claim more for that height*. If it
//! is wrong, the node can notice: it will find a chain that is valid by every
//! other rule and carries more work than the checkpoint permits. That is a
//! contradiction it can report rather than a capture it cannot see.
//!
//! The failure directions are not symmetric, which is the whole argument:
//!
//! | checkpoint is | hash | cumulative difficulty |
//! |---|---|---|
//! | wrong | silent capture | detectable contradiction |
//! | too generous | no such thing | weak, harmless |
//! | stale | irrelevant or fatal | merely covers less of the chain |
//!
//! So: **err high**. A checkpoint above the true value constrains nothing and
//! harms nothing. One below it is caught by [`CheckpointVerdict::Contradicted`]
//! and is the operator's problem, loudly.
//!
//! # Bounding the window above the checkpoint
//!
//! Below the checkpoint the answer is exact — the work is `Y`. Above it, the
//! chain is bounded by the retarget rule, which changes difficulty by a fixed
//! fraction of the parent's on every block:
//!
//! ```text
//! quotient = parent.difficulty / divisor
//! child    = parent.difficulty ± quotient      (or unchanged)
//! ```
//!
//! Nothing a miner controls changes that magnitude. The timestamp and uncle
//! count pick only the *sign*. So between two headers whose difficulty is known
//! — and whose proof of work has been checked — the work-maximising path is to
//! rise at `(1 + 1/divisor)` for as long as possible and then fall at
//! `(1 - 1/divisor)`, arriving at or below the later header's difficulty.
//!
//! Summing that bound across sampled intervals, and adding `Y`, gives a ceiling
//! on the total difficulty any chain through those samples can carry. A peer
//! claiming more than the ceiling is claiming something no valid chain can
//! provide.

use alloy_primitives::{B256, U256};

/// A point on the chain whose cumulative work is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DifficultyCheckpoint {
    pub number: u64,
    /// The block at `number`. Recorded for diagnostics only: the safety of
    /// this mechanism must not depend on it, because a hash checkpoint has no
    /// safe failure direction. Nothing consults it to decide which chain to
    /// follow.
    pub hash: B256,
    /// Cumulative difficulty from genesis through `number`.
    pub cumulative_difficulty: U256,
    /// The difficulty of the block at `number`, which is where the bound above
    /// the checkpoint starts from.
    pub difficulty: U256,
}

/// Mainnet, block #9,020,000 — 2026-07-05, about three months before this was
/// written.
///
/// Taken from a fully synced node's own chain, and re-verified against that
/// node over RPC on 2026-09-30: all three fields match `eth_getBlockByNumber`
/// for #9,020,000 exactly. The test below checks the limbs against these
/// decimals; only a query against a real chain checks the decimals themselves,
/// and a checkpoint set too low would reject the honest chain.
///
/// A checkpoint should be refreshed
/// each release: the cost of verifying a peer's claim scales with the distance
/// from the newest checkpoint to the tip (see `docs/`), and an old checkpoint
/// is weak rather than wrong.
pub const MAINNET_CHECKPOINT: DifficultyCheckpoint = DifficultyCheckpoint {
    number: 9_020_000,
    hash: B256::new([
        0x27, 0x03, 0x43, 0xb5, 0xb4, 0x3e, 0xca, 0x9c, 0x17, 0x53, 0x8b, 0xda, 0xef, 0xe7, 0xcf,
        0x8f, 0xd3, 0x01, 0x2c, 0xe9, 0xb7, 0xce, 0xfc, 0x9c, 0x7d, 0x4a, 0xc2, 0x32, 0x2b, 0x47,
        0x2c, 0xc5,
    ]),
    // 57604442870340920504421561134 == 0xba2147413df62dc93cc9b32e
    //
    // Written as limbs rather than a literal because `U256` has no const
    // decimal constructor. `checkpoint_value_tests` checks these against the
    // decimal values read off the chain -- an earlier hand-written version of
    // this was wrong in both fields, and the difficulty silently truncated
    // because it does not fit in a u64.
    //
    // Re-read after total difficulty began counting uncle difficulty. The
    // earlier value, 32959497588810990020280199750, was recorded when a block
    // contributed only its header difficulty; the chain carries 1.748x that at
    // this height once uncles are counted. The number and hash did not change,
    // and neither did `difficulty` -- it is the block's own, which uncles
    // never affected.
    cumulative_difficulty: U256::from_limbs([
        0x3df62dc93cc9b32e,
        0x00000000ba214741,
        0x0000000000000000,
        0x0000000000000000,
    ]),
    // 7388898250588046058941
    difficulty: U256::from_limbs([
        0x8d8fe2d95db565bd,
        0x0000000000000190,
        0x0000000000000000,
        0x0000000000000000,
    ]),
};

/// What sampling concluded about a peer's claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// The claim is within what the chain could carry. Not proof it is honest;
    /// only that it is not arithmetically impossible.
    Plausible { ceiling: U256 },
    /// The claim exceeds the ceiling. No valid chain through the sampled
    /// headers can carry this much work, so the peer is lying.
    Impossible { claimed: U256, ceiling: U256 },
    /// This node's *own* chain carries more work at the checkpoint height than
    /// the checkpoint allows.
    ///
    /// The checkpoint is wrong, or this build is not the one it claims to be.
    /// Either way it is not a peer's fault and must not be treated as one: the
    /// right response is to stop and tell the operator, not to pick a side.
    Contradicted { observed: U256, checkpoint: U256 },
}

/// The largest cumulative work the `span` blocks after a block of difficulty
/// `from` can carry, given the next sampled block has difficulty `to`.
///
/// Counts the `span` blocks beginning with the one *after* `from`'s block, so
/// consecutive intervals tile the chain without overlap.
///
/// Each block takes the highest difficulty it may have while still being able
/// to fall to `to` by the end of the span. That is the rise-then-fall shape,
/// but expressed as a per-block maximum rather than a turning point — which
/// matters, because the consensus rule also permits difficulty to stay
/// *unchanged*, and a strict rise-then-fall model cannot express that. A model
/// that cannot produces a "bound" below a flat chain's real work.
///
/// `min_difficulty` clamps the fall, exactly as the consensus rule does. The
/// clamp only ever raises a value, so including it keeps this an upper bound.
pub fn max_work_between(
    from: U256,
    to: U256,
    span: u64,
    divisor: u64,
    min_difficulty: U256,
) -> U256 {
    if span == 0 || divisor < 2 {
        return U256::ZERO;
    }
    let div = U256::from(divisor);

    // Walk forwards, taking the largest difficulty each block may have while
    // still being able to fall to `to` in the blocks that remain.
    //
    // Two limits apply at every step:
    //
    //   * it cannot exceed the previous block's difficulty by more than
    //     `1/divisor`, because that is the whole of the retarget rule;
    //   * it cannot be so high that falling at `1/divisor` for the remaining
    //     blocks still overshoots `to`.
    //
    // The lower of the two is the maximum. Taking the minimum rather than
    // forcing a rise-then-fall shape is what admits `sign == 0` -- a block
    // whose difficulty is unchanged -- which the consensus rule allows and
    // which a rise-then-fall model cannot express. Without it the "bound" came
    // out *below* a flat chain's real work for short spans, and would have
    // rejected honest peers.
    //
    // `ceilings[k]` is the ceiling for the block `k` before the span's last,
    // built backwards from `to`: each step back multiplies by
    // `divisor / (divisor - 1)`, the inverse of a maximal fall. It saturates,
    // which only loosens the bound. Grown back far enough it stops changing
    // -- at `U256::MAX`, or below `divisor - 1`, where the growth rounds away
    // -- and every block before that has the ceiling it stopped at. So only
    // the ceilings that differ are kept, a few thousand at most. The span is
    // the distance to a height a peer names, and a cell for every block let
    // a peer naming a distant one make this node allocate without limit.
    let mut ceilings = vec![to];
    while (ceilings.len() as u64) <= span {
        let last = ceilings[ceilings.len() - 1];
        let grown = last
            .checked_mul(div)
            .map(|v| v / (div - U256::from(1u64)))
            .unwrap_or(U256::MAX);
        if grown == last {
            break;
        }
        ceilings.push(grown);
    }
    let settled = ceilings.len() as u64 - 1;
    // Blocks up to this one all have the settled ceiling.
    let flat_until = span - settled;

    let mut total = U256::ZERO;
    let mut d = from;
    let mut step = 1;
    loop {
        let ceiling = ceilings[(span - step).min(settled) as usize];
        let next = d.saturating_add(d / div).min(ceiling).max(min_difficulty);
        total = total.saturating_add(next);
        if total == U256::MAX {
            // Nothing added after it can take it below the most there is.
            return total;
        }
        // Under the settled ceiling every block is worked out alike, so one
        // whose difficulty is its parent's leaves every block after it
        // there too, up to where the ceilings begin to differ. They are
        // counted at once rather than one by one, which a span a peer names
        // could make last for ever.
        if next == d && step < flat_until {
            total = total.saturating_add(next.saturating_mul(U256::from(flat_until - step)));
            step = flat_until;
        }
        d = next;
        // Stopping at the last block rather than past it: the span can be
        // `u64::MAX`, and there is no step after that.
        if step == span {
            break;
        }
        step += 1;
    }
    total
}

/// Which checkpoint-based defences a node runs.
///
/// Two independent switches, because they cost different things and one of
/// them is a statement about governance rather than about arithmetic.
///
/// | `verify_hash` | `bound_work` | what it gives |
/// |---|---|---|
/// | no | no | no defence |
/// | yes | no | good: a peer must be on the checkpointed chain |
/// | no | yes | good: a peer's claim is bounded, and no fork is declared in code |
/// | yes | yes | strongest |
///
/// The third row is the one worth understanding. Shipping a checkpoint *hash*
/// is a statement about which chain is canonical — it asks whoever ships the
/// build to choose a fork, which is a governance act. Bounding the work does
/// not: it says only that a claim exceeds what any chain could carry. A
/// deployment that wants the bound without the declaration can have it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckpointDefence {
    /// Require a peer to show it is on the checkpointed chain: ask for the
    /// header at the checkpoint height and check its hash.
    ///
    /// Without this, the work below the checkpoint — over 99% of mainnet's
    /// cumulative total — is credited to any peer that asks, including one on
    /// a fork that diverged below it and never did that work.
    pub verify_hash: bool,

    /// Bound a peer's claimed cumulative difficulty against the checkpoint,
    /// **and sample its chain above the checkpoint to do so**.
    ///
    /// These are deliberately one switch and must never be separable. The
    /// bound without the sampling is the "free half": it refutes only a claim
    /// made for a height at or below the checkpoint, which an attacker avoids
    /// for free by claiming a height above it — and which it would claim
    /// anyway, since a sync peer wants to look like the longest chain. An
    /// option to bound without sampling would read as a defence and be none.
    pub bound_work: bool,
}

impl CheckpointDefence {
    /// Neither switch: the node makes no use of a checkpoint.
    pub const NONE: Self = Self { verify_hash: false, bound_work: false };

    /// Both switches.
    pub const FULL: Self = Self { verify_hash: true, bound_work: true };

    /// Whether anything at all is enabled.
    pub fn any(&self) -> bool {
        self.verify_hash || self.bound_work
    }
}

/// Natural log of `3/delta` for the confidence this bound is claimed at, in
/// thousandths. `delta = 1e-9`, so `ln(3e9) = 21.8211...`.
///
/// It appears twice below, and in both places it is the price of the claim
/// being a *bound* rather than an estimate. A looser confidence buys very
/// little -- going to `1e-6` saves about 15% of it -- and the quantity being
/// protected is the decision to adopt a chain, so the confidence is set where
/// a wrong verdict is not something that happens.
pub const LN_3_OVER_DELTA_PER_MILLE: u128 = 21_821;

/// The hard cap on uncles a block may reference, from consensus
/// (`uncleListLimit`).
///
/// This is the bound that applies when nothing has been sampled, and it is
/// also what bounds the range term below. It is sound and it is nearly
/// useless: uncles really add about half a block's difficulty again, so
/// assuming ten is a ceiling an order of magnitude above the chain it bounds.
/// Everything in [`uncle_allowance_per_mille`] exists to do better than this.
pub const UNCLE_LIST_LIMIT: u64 = 10;

/// The per-block uncle allowance implied by the samples, in thousandths of a
/// block's own difficulty.
///
/// Cumulative difficulty counts the trunk block's difficulty **plus every
/// uncle it references**, so a bound computed from header difficulties alone
/// bounds the wrong quantity -- and a smaller one. On mainnet uncles add about
/// half again to the work, so ignoring them leaves the ceiling resting on
/// whatever slack the retarget rule happens to provide.
///
/// The samples carry each block's `uncle_count`, which is inside what its proof
/// of work commits to, so it cannot be overstated for a block we looked at.
/// Applying the sampled rate to the blocks between samples is sound only
/// because sample positions are unpredictable: a peer is committed to its
/// chain before it learns where it will be checked, so what we draw is a
/// uniform sample from a population it has already fixed.
///
/// # What is and is not being claimed
///
/// Not that any particular stretch of the chain is free of uncles. A peer can
/// perfectly well hold a run of ten-uncle blocks between two samples, and no
/// amount of sampling will see it. What the ceiling needs is weaker: it is a
/// bound on the *sum* over every gap, and the allowance multiplies every gap
/// alike, so what has to be bounded is the population mean. A stretch running
/// hot is paid for by the stretches that do not, and it is the mean that
/// concentrates.
///
/// # The bound
///
/// Empirical Bernstein (Maurer & Pontil 2009), which holds with probability
/// `1 - delta` for a sample drawn from a fixed population in `[0, R]`:
///
/// ```text
/// mean <= mean_hat + sqrt(2 * V_hat * L / k) + 3 * R * L / k,  L = ln(3/delta)
/// ```
///
/// It is used rather than Hoeffding because mainnet's uncle counts are tightly
/// clustered -- mean 0.513, standard deviation 0.760 against a range of 10 --
/// and Hoeffding pays for the range in the square-root term where this pays
/// for the *variance* there and relegates the range to a term in `1/k`.
///
/// # What this costs at the sample counts we can reach
///
/// Against the measured mainnet distribution:
///
/// ```text
///  k      allowance   vs. the true 1.513   vs. the 11.0 cap
///  340      3.711           2.45x               0.34x
///  1000     2.327           1.54x               0.21x
///  3400     1.792           1.18x               0.16x
/// ```
///
/// So sampling is worth doing -- at 340 samples it is three times tighter than
/// assuming the cap. But the gain decays slowly, because at these `k` the
/// bound is dominated by the range term (1.925 of the 2.711 at `k = 340`),
/// which does not care what we observed and shrinks only as `1/k`. The number
/// of distinct heights a skeleton walk can ask about over a sampling window
/// caps `k` near 1,250, and so caps this at roughly 1.5x the truth.
///
/// Closing the rest is not a sampling problem. A header that committed to its
/// own cumulative difficulty would make the quantity exact and free; that is
/// the subject of a separate consensus proposal, and it is the right fix.
pub fn uncle_allowance_per_mille(samples: &[Sample]) -> u64 {
    // One block's own difficulty, plus what its uncles may add.
    let cap = 1_000 + UNCLE_LIST_LIMIT * 1_000;

    // Below two samples there is no variance to estimate, and so no bound to
    // make but the consensus one. Note what this is *not*: assuming zero.
    // Having observed nothing, the sound assumption is the worst case, and a
    // ceiling built on "no uncles anywhere" would refuse every honest peer.
    let k = samples.len() as u128;
    if k < 2 {
        return cap;
    }

    // Everything in thousandths, so the arithmetic stays in integers.
    let counts: Vec<u128> = samples.iter().map(|s| s.uncle_count as u128 * 1_000).collect();
    let total: u128 = counts.iter().sum();
    let mean = total / k;

    // Unbiased sample variance, in (thousandths)^2.
    let ss: u128 = counts.iter().map(|&c| { let d = c.abs_diff(mean); d * d }).sum();
    let variance = ss / (k - 1);

    let l = LN_3_OVER_DELTA_PER_MILLE;

    // sqrt(2 * V * L / k). The 1_000 divides out L's own scaling, leaving a
    // square of thousandths under the root.
    let variance_term = (2 * variance * l / (1_000 * k)).isqrt();

    // 3 * R * L / k, with R in thousandths.
    let range_term = 3 * (UNCLE_LIST_LIMIT as u128 * 1_000) * l / (1_000 * k);

    let uncles = mean.saturating_add(variance_term).saturating_add(range_term);
    (1_000u128 + uncles).min(cap as u128) as u64
}

/// One sampled block: where it sits, what it weighs, and how many uncles it
/// carries.
///
/// `uncle_count` comes from the header and is covered by its proof of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub number: u64,
    pub difficulty: U256,
    pub uncle_count: u64,
}

/// The ceiling on total difficulty implied by a checkpoint and a set of samples.
///
/// `samples` are `(height, difficulty)` for blocks above the checkpoint, in
/// ascending order, each already verified — a sample whose proof of work was
/// not checked bounds nothing.
///
/// The work below the checkpoint is exact. Above it, each gap is bounded by
/// [`max_work_between`], including the gap from the last sample to `head`.
/// Every such gap is then scaled by [`uncle_allowance_per_mille`], because the
/// claim being bounded counts uncle difficulty and `max_work_between` does not.
pub fn ceiling_for(
    checkpoint: &DifficultyCheckpoint,
    samples: &[Sample],
    head: u64,
    divisor: u64,
    min_difficulty: U256,
) -> U256 {
    let allowance = uncle_allowance_per_mille(samples);
    let scale = |work: U256| -> U256 {
        work.saturating_mul(U256::from(allowance)) / U256::from(1_000u64)
    };
    let mut total = checkpoint.cumulative_difficulty;
    let mut at = checkpoint.number;
    let mut difficulty = checkpoint.difficulty;

    for s in samples {
        let (number, sampled) = (s.number, s.difficulty);
        if number <= at {
            continue; // out of order or at/below the checkpoint: contributes nothing
        }
        total = total.saturating_add(scale(max_work_between(
            difficulty,
            sampled,
            number - at,
            divisor,
            min_difficulty,
        )));
        at = number;
        difficulty = sampled;
    }

    if head > at {
        // Past the last sample there is no later difficulty to aim for, so the
        // bound is unconstrained growth: this is why the newest sample should
        // sit close to the head.
        total = total.saturating_add(scale(max_work_between(
            difficulty,
            U256::MAX,
            head - at,
            divisor,
            min_difficulty,
        )));
    }
    total
}

/// Judges a peer's advertised total difficulty against the ceiling.
pub fn judge(
    checkpoint: &DifficultyCheckpoint,
    claimed: U256,
    samples: &[Sample],
    head: u64,
    divisor: u64,
    min_difficulty: U256,
) -> CheckpointVerdict {
    let ceiling = ceiling_for(checkpoint, samples, head, divisor, min_difficulty);
    if claimed > ceiling {
        CheckpointVerdict::Impossible { claimed, ceiling }
    } else {
        CheckpointVerdict::Plausible { ceiling }
    }
}

/// Checks this node's own chain against the checkpoint it was shipped with.
///
/// Run when the node has validated its own chain to at least the checkpoint
/// height. A chain that carries *more* work than the checkpoint allows means
/// the checkpoint is wrong — and since a checkpoint arrives with the build,
/// that is a statement about the build, not about the network.
pub fn audit_own_chain(
    checkpoint: &DifficultyCheckpoint,
    observed_cumulative_difficulty: U256,
) -> Option<CheckpointVerdict> {
    if observed_cumulative_difficulty > checkpoint.cumulative_difficulty {
        return Some(CheckpointVerdict::Contradicted {
            observed: observed_cumulative_difficulty,
            checkpoint: checkpoint.cumulative_difficulty,
        });
    }
    None
}

#[cfg(test)]
fn u256_to_f64(v: U256) -> f64 {
    // Enough for locating a turning point; the bound itself never uses this.
    let mut out = 0.0f64;
    for limb in v.as_limbs().iter().rev() {
        out = out * 18_446_744_073_709_551_616.0 + *limb as f64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIV: u64 = 400;
    const MIN: U256 = U256::from_limbs([7_000_000_000_000_000u64, 0, 0, 0]);

    /// The worked example: flat endpoints, 192 blocks, divisor 400. Rising to
    /// a peak near the midpoint and falling back gives about 13% more than a
    /// flat chain would.
    #[test]
    fn a_flat_interval_is_bounded_at_about_thirteen_percent_over() {
        let d = U256::from(1_000_000_000u64) * MIN;
        let bound = max_work_between(d, d, 192, DIV, MIN);
        let flat = d * U256::from(192u64);
        let ratio = u256_to_f64(bound) / u256_to_f64(flat);
        assert!(
            (1.12..1.14).contains(&ratio),
            "expected about 1.13x the flat sum, got {ratio}"
        );
    }

    /// `max_work_between` as it was written first, a cell for every block,
    /// kept to hold the bounded one to the same answers.
    fn max_work_cell_by_cell(from: U256, to: U256, span: u64, divisor: u64, min: U256) -> U256 {
        if span == 0 || divisor < 2 {
            return U256::ZERO;
        }
        let div = U256::from(divisor);
        let mut cap = vec![U256::ZERO; span as usize + 1];
        cap[span as usize] = to;
        for i in (0..span as usize).rev() {
            cap[i] = cap[i + 1]
                .checked_mul(div)
                .map(|v| v / (div - U256::from(1u64)))
                .unwrap_or(U256::MAX);
        }
        let mut total = U256::ZERO;
        let mut d = from;
        for ceiling in &cap[1..] {
            d = d.saturating_add(d / div).min(*ceiling).max(min);
            total = total.saturating_add(d);
        }
        total
    }

    /// Keeping only the ceilings that differ, and counting a settled run at
    /// once, changes no answer.
    #[test]
    fn the_bound_is_the_one_worked_out_block_by_block() {
        let big = U256::from(10u64).pow(U256::from(25u64));
        let froms = [
            U256::ZERO,
            U256::from(1u64),
            U256::from(48u64),
            U256::from(50u64),
            MIN,
            MIN * U256::from(3u64),
            big,
            U256::MAX,
        ];
        let tos = [
            U256::ZERO,
            U256::from(1u64),
            U256::from(49u64),
            MIN,
            MIN * U256::from(2u64),
            big,
            U256::MAX,
        ];
        let mins = [U256::ZERO, U256::from(1u64), MIN];
        for divisor in [2u64, 3, 50, 400] {
            for span in [1u64, 2, 3, 191, 768, 2_500] {
                for &from in &froms {
                    for &to in &tos {
                        for &min in &mins {
                            assert_eq!(
                                max_work_between(from, to, span, divisor, min),
                                max_work_cell_by_cell(from, to, span, divisor, min),
                                "from {from}, to {to}, span {span}, divisor {divisor}, min {min}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// A span no cell-by-cell table could hold is answered, and at once: a
    /// peer names the height it runs to.
    #[test]
    fn a_span_a_peer_names_is_answered_at_once() {
        let started = std::time::Instant::now();
        // Rising without limit, the work passes the most there is.
        assert_eq!(
            max_work_between(MIN, U256::MAX, u64::MAX, 50, MIN),
            U256::MAX
        );
        assert_eq!(max_work_between(MIN, MIN, u64::MAX, 400, MIN), U256::MAX);
        // Held flat, it is the span's blocks at the one difficulty, exactly.
        let span = 1_000_000_000_000_000u64;
        let one = U256::from(1u64);
        assert_eq!(max_work_between(one, one, span, 50, one), U256::from(span));
        assert_eq!(
            max_work_between(one, one, u64::MAX, 2048, one),
            U256::from(u64::MAX)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    }

    /// The bound must never be below what a flat chain actually carries, or it
    /// would reject honest peers.
    #[test]
    fn the_bound_is_never_below_the_flat_truth() {
        let d = U256::from(1_000_000_000u64) * MIN;
        for span in [1u64, 2, 48, 192, 768, 3840] {
            let bound = max_work_between(d, d, span, DIV, MIN);
            assert!(
                bound >= d * U256::from(span),
                "span={span}: bound {bound} is below the flat sum"
            );
        }
    }

    /// A smaller divisor allows faster growth, so it must bound more loosely.
    #[test]
    fn a_smaller_divisor_bounds_more_loosely() {
        let d = U256::from(1_000_000_000u64) * MIN;
        let tight = max_work_between(d, d, 192, 400, MIN);
        let loose = max_work_between(d, d, 192, 50, MIN);
        assert!(loose > tight, "divisor 50 must bound above divisor 400");
    }

    /// Work below the checkpoint is not re-derived; it is the checkpoint.
    #[test]
    fn with_no_window_the_ceiling_is_the_checkpoint() {
        let cp = MAINNET_CHECKPOINT;
        let ceiling = ceiling_for(&cp, &[], cp.number, DIV, MIN);
        assert_eq!(ceiling, cp.cumulative_difficulty);
    }

    /// A claim at or below the ceiling survives; one above it does not.
    #[test]
    fn a_claim_above_the_ceiling_is_refused() {
        let cp = MAINNET_CHECKPOINT;
        let samples = [Sample { number: cp.number + 768, difficulty: cp.difficulty, uncle_count: 0 }];
        let head = cp.number + 768;
        let ceiling = ceiling_for(&cp, &samples, head, DIV, MIN);

        match judge(&cp, ceiling, &samples, head, DIV, MIN) {
            CheckpointVerdict::Plausible { .. } => {}
            other => panic!("a claim exactly at the ceiling must pass: {other:?}"),
        }
        match judge(&cp, ceiling + U256::from(1u64), &samples, head, DIV, MIN) {
            CheckpointVerdict::Impossible { .. } => {}
            other => panic!("a claim above the ceiling must be refused: {other:?}"),
        }
    }

    /// The attack this exists for: a peer claiming a wildly inflated total.
    #[test]
    fn a_wildly_inflated_claim_is_refused() {
        let cp = MAINNET_CHECKPOINT;
        let samples: Vec<Sample> =
            (1..=341).map(|i| Sample { number: cp.number + i * 768, difficulty: cp.difficulty, uncle_count: 0 }).collect();
        let head = cp.number + 341 * 768;
        let absurd = cp.cumulative_difficulty * U256::from(1000u64);
        match judge(&cp, absurd, &samples, head, DIV, MIN) {
            CheckpointVerdict::Impossible { .. } => {}
            other => panic!("a 1000x claim must be refused: {other:?}"),
        }
    }

    /// An honest chain that merely sat at the checkpoint's difficulty for the
    /// whole window must pass, or the gate rejects the network.
    #[test]
    fn an_honest_flat_chain_passes() {
        let cp = MAINNET_CHECKPOINT;
        let n = 341u64;
        let samples: Vec<Sample> =
            (1..=n).map(|i| Sample { number: cp.number + i * 768, difficulty: cp.difficulty, uncle_count: 0 }).collect();
        let head = cp.number + n * 768;
        let honest = cp.cumulative_difficulty + cp.difficulty * U256::from(n * 768);
        match judge(&cp, honest, &samples, head, DIV, MIN) {
            CheckpointVerdict::Plausible { .. } => {}
            other => panic!("an honest flat chain must pass: {other:?}"),
        }
    }

    /// A checkpoint the node's own chain contradicts is the build's problem,
    /// reported as such rather than charged to a peer.
    #[test]
    fn a_contradicted_checkpoint_is_reported() {
        let cp = MAINNET_CHECKPOINT;
        assert_eq!(audit_own_chain(&cp, cp.cumulative_difficulty), None);
        assert_eq!(
            audit_own_chain(&cp, cp.cumulative_difficulty - U256::from(1u64)),
            None,
            "less work than the checkpoint is ordinary: the node is behind"
        );
        match audit_own_chain(&cp, cp.cumulative_difficulty + U256::from(1u64)) {
            Some(CheckpointVerdict::Contradicted { .. }) => {}
            other => panic!("more work than the checkpoint must be reported: {other:?}"),
        }
    }
}

#[cfg(test)]
mod checkpoint_value_tests {
    use super::*;

    /// The shipped constants must be the values read off the chain, not
    /// whatever a hand-written limb array happens to encode.
    ///
    /// Taken from this project's own synced node at block #9,020,000
    /// (2026-07-05). If a checkpoint is ever refreshed, this test is what
    /// catches a transcription error before it ships.
    #[test]
    fn the_mainnet_checkpoint_matches_the_chain() {
        let cp = MAINNET_CHECKPOINT;
        assert_eq!(cp.number, 9_020_000);
        assert_eq!(
            format!("{:?}", cp.hash),
            "0x270343b5b43eca9c17538bdaefe7cf8fd3012ce9b7cefc9c7d4ac2322b472cc5"
        );
        assert_eq!(
            cp.cumulative_difficulty,
            "57604442870340920504421561134".parse::<U256>().unwrap(),
            "cumulative difficulty (0xba2147413df62dc93cc9b32e)"
        );
        assert_eq!(
            cp.difficulty,
            "7388898250588046058941".parse::<U256>().unwrap()
        );
    }
}

#[cfg(test)]
mod real_chain_tests {
    use super::*;

    const DIV: u64 = 400;
    const MIN: U256 = U256::from_limbs([7_000_000_000_000_000u64, 0, 0, 0]);

    /// Samples read from this project's own synced mainnet node on 2026-10-04:
    /// `(height, difficulty, uncle_count)` every 812 blocks from the shipped
    /// checkpoint to #9296080.
    ///
    /// 340 of them, because that is [`RANDOM_SAMPLES`][rs] -- and the count is
    /// not incidental. The uncle allowance is a concentration bound whose
    /// slack falls as `1/k` and `1/sqrt(k)`, so a fixture of forty samples
    /// would exercise a bound an order of magnitude looser than the one that
    /// ships, and would say nothing about it.
    ///
    /// Real difficulty here swings between about 6.5e21 and 8.3e21, and uncle
    /// counts between 0 and 6. A synthetic flat chain cannot exercise either,
    /// and the direction that matters is the one a flat chain never shows: a
    /// bound that sits *below* what the honest chain really carries would
    /// refuse every truthful peer.
    ///
    /// [rs]: ../../rustock_sync/sampler/constant.RANDOM_SAMPLES.html
    const SAMPLES: &[(u64, &str, u64)] = &[
        (9020812, "7729066588500119834490", 2),
        (9021624, "6924154818904372191804", 0),
        (9022436, "6855322435186444531331", 1),
        (9023248, "6719808648751320842103", 0),
        (9024060, "7046834618079955936039", 0),
        (9024872, "7064871151810516565531", 1),
        (9025684, "6408680008163713734285", 0),
        (9026496, "7082887429426324111502", 0),
        (9027308, "6960232400156872224772", 0),
        (9028120, "6960558651590560613839", 1),
        (9028932, "7066041279651925591368", 1),
        (9029744, "6840214362410105688656", 1),
        (9030556, "7674024487010874291175", 1),
        (9031368, "6755518082038566244681", 1),
        (9032180, "6857936319003131647214", 0),
        (9032992, "7120036799551943339524", 0),
        (9033804, "7084768911125095319160", 0),
        (9034616, "6962037787051586366475", 0),
        (9035428, "6858579211236862200758", 0),
        (9036240, "6427131297880908555986", 0),
        (9037052, "6945218618259472291397", 0),
        (9037864, "6928093703544496966762", 1),
        (9038676, "7265392291215258461707", 0),
        (9039488, "7715021638340521470795", 0),
        (9040300, "7930228463431412699756", 0),
        (9041112, "7487382144140852668244", 0),
        (9041924, "7891169344884026192240", 0),
        (9042736, "7413251908465863642520", 0),
        (9043548, "7582272762786326802292", 0),
        (9044360, "7971299019467151779718", 0),
        (9045172, "7194763732276792216214", 1),
        (9045984, "7212773162775537911414", 2),
        (9046796, "7659002490672710230544", 1),
        (9047608, "7395920406328843414581", 0),
        (9048420, "7377591969664387810706", 1),
        (9049232, "8032237193069778853232", 0),
        (9050044, "7267935366545581219758", 0),
        (9050856, "7142120482958883651633", 0),
        (9051668, "7018351979095715616894", 0),
        (9052480, "7178189726153962154403", 0),
        (9053292, "7452716148310790471950", 0),
        (9054104, "7737886786242401601976", 0),
        (9054916, "7622851150929733558836", 0),
        (9055728, "7472071704458894102638", 0),
        (9056540, "6984438857434567862553", 0),
        (9057352, "6829214124813717268033", 0),
        (9058164, "7179558072397821137683", 1),
        (9058976, "6677543482360340857518", 0),
        (9059788, "7020106609100555534152", 1),
        (9060600, "7491641349046607332384", 0),
        (9061412, "7817241541860404664821", 0),
        (9062224, "8426319043876439323886", 0),
        (9063036, "7454952072581676274923", 1),
        (9063848, "7995773084729332362992", 2),
        (9064660, "7511567419032088418721", 1),
        (9065472, "7996172842980917084849", 1),
        (9066284, "7799014292901806116753", 1),
        (9067096, "8469879419152043396976", 0),
        (9067908, "8470223494010187714971", 0),
        (9068720, "8282081664005477903916", 1),
        (9069532, "8344587362146686575073", 0),
        (9070344, "7780659359868310163348", 0),
        (9071156, "7839429770197350551898", 0),
        (9071968, "7703914370213577680959", 2),
        (9072780, "7627425811319311592293", 4),
        (9073592, "7998671836984595282167", 0),
        (9074404, "6833163044363276425087", 0),
        (9075216, "7420946399577463605227", 0),
        (9076028, "6919611129465804976106", 0),
        (9076840, "7274365184879225627708", 0),
        (9077652, "7042012383447758829048", 0),
        (9078464, "6665430130006450215519", 1),
        (9079276, "6989897089711392938804", 1),
        (9080088, "7131258651196674874810", 1),
        (9080900, "7007941169806976119147", 1),
        (9081712, "7114097384971097058573", 1),
        (9082524, "6767159186217853139851", 0),
        (9083336, "6716847099140451672439", 0),
        (9084148, "6835725755414900399341", 0),
        (9084960, "7630787098788200793378", 1),
        (9085772, "7350068755940626356435", 1),
        (9086584, "7517790003052871475205", 2),
        (9087396, "7747007557595407183195", 0),
        (9088208, "7443358708649461099072", 0),
        (9089020, "7963231018713490547894", 0),
        (9089832, "8124378545168123015996", 1),
        (9090644, "7651465790038564585891", 0),
        (9091456, "7519058623641582177922", 0),
        (9092268, "7575853059711972579728", 1),
        (9093080, "7594911342516507155487", 0),
        (9093892, "7576231823558985347056", 2),
        (9094704, "8186896301374157004030", 0),
        (9095516, "7633481946304845622844", 0),
        (9096328, "7595623321935803615863", 1),
        (9097140, "7729958444176061313549", 1),
        (9097952, "6770902983213885610858", 3),
        (9098764, "7262054127126387160361", 1),
        (9099576, "7446057152255199394049", 0),
        (9100388, "8066445607876884620501", 1),
        (9101200, "7390905481205451395265", 1),
        (9102012, "7013242471508942936643", 1),
        (9102824, "7503073837618672413155", 0),
        (9103636, "7281619830276674517523", 0),
        (9104448, "7560101887142440789536", 1),
        (9105260, "7410702566392348698474", 4),
        (9106072, "7014360208262343154787", 2),
        (9106884, "6892762630426539438277", 0),
        (9107696, "6858534773361200866518", 1),
        (9108508, "6363218452263737169674", 3),
        (9109320, "6689656462723234813659", 1),
        (9110132, "5993027231162015108126", 2),
        (9110944, "6053277183042163446558", 1),
        (9111756, "6395593870540545233552", 2),
        (9112568, "6508746120904906328052", 1),
        (9113380, "6657061186520996384738", 2),
        (9114192, "6842927784261371540445", 2),
        (9115004, "6674287781184690435197", 2),
        (9115816, "6946692901967907150596", 0),
        (9116628, "6877636469247282401525", 2),
        (9117440, "6238874832540971953331", 1),
        (9118252, "6724932441335820786814", 0),
        (9119064, "6270460871620725111668", 0),
        (9119876, "6054998660455533338939", 0),
        (9120688, "6477943143532518104271", 1),
        (9121500, "6478044345631225018176", 0),
        (9122312, "6070572417759477822085", 1),
        (9123124, "6642576819478026885651", 1),
        (9123936, "6511105739061011091729", 2),
        (9124748, "6224697351163120577233", 0),
        (9125560, "6543947322275507054620", 3),
        (9126372, "6382515954614771313612", 0),
        (9127184, "6626446551371632982849", 1),
        (9127996, "6272087308765164784355", 2),
        (9128808, "6148025873757733924516", 1),
        (9129620, "6495578866552204672930", 4),
        (9130432, "6383054420688030317462", 2),
        (9131244, "6383273826017536930877", 1),
        (9132056, "6399411975411080352990", 1),
        (9132868, "6778290791683903140816", 1),
        (9133680, "6528811325170868440651", 0),
        (9134492, "6727790803582752036778", 2),
        (9135304, "6578393255609211102975", 0),
        (9136116, "6950362152070326591760", 2),
        (9136928, "6628103168152152519689", 0),
        (9137740, "6711684337473642422592", 1),
        (9138552, "6432413690331060004592", 0),
        (9139364, "6481040772150666426555", 1),
        (9140176, "6211405937826424888523", 0),
        (9140988, "6149812668799507051221", 0),
        (9141800, "6103899643769696074560", 0),
        (9142612, "6258518697479589601022", 1),
        (9143424, "6401091813430267259568", 2),
        (9144236, "6227654404753646589667", 0),
        (9145048, "6196613132590312518864", 3),
        (9145860, "6212318194679290623537", 1),
        (9146672, "6547547051184188479228", 2),
        (9147484, "6613537117293347356815", 0),
        (9148296, "5851326391676573997179", 1),
        (9149108, "6434564677177858125485", 0),
        (9149920, "6075164500960434856259", 3),
        (9150732, "5969922992382289080047", 2),
        (9151544, "5969978945300698146694", 0),
        (9152356, "6516092134897602241920", 2),
        (9153168, "6371236291256970157257", 1),
        (9153980, "6435409171302640304202", 1),
        (9154792, "6614921820889290325580", 3),
        (9155604, "6971614516293506347633", 1),
        (9156416, "6833801905785228781403", 3),
        (9157228, "6356003269790172530039", 1),
        (9158040, "5794516665291954593391", 1),
        (9158852, "6340588756404349331962", 1),
        (9159664, "5867934593744312933044", 1),
        (9160476, "5912294386092714878233", 0),
        (9161288, "6246755532391989349605", 1),
        (9162100, "6649720620218311510233", 2),
        (9162912, "6184715077941411487010", 0),
        (9163724, "6294097076074078544931", 0),
        (9164536, "6405453622875780636600", 1),
        (9165348, "6617381986053342174996", 1),
        (9166160, "6017873729982758847392", 0),
        (9166972, "5973057723528567955477", 1),
        (9167784, "6201300656158725923703", 1),
        (9168596, "6185932704630152032148", 1),
        (9169408, "6438607251187429891813", 0),
        (9170220, "6003523086892071458005", 1),
        (9171032, "6358843970851470084234", 1),
        (9171844, "6343125242852379094762", 2),
        (9172656, "6520267432365083840308", 0),
        (9173468, "6553134764973201639902", 1),
        (9174280, "7081290634675430179591", 1),
        (9175092, "6820701688335430245955", 0),
        (9175904, "6407575553873540230972", 1),
        (9176716, "6855190542489502187927", 4),
        (9177528, "6296673978838744047651", 1),
        (9178340, "6375996085963311172649", 0),
        (9179152, "6456438507732524858144", 3),
        (9179964, "6456579727496921920505", 0),
        (9180776, "6736941641766764960194", 1),
        (9181588, "6203606926254547755200", 1),
        (9182400, "6157446220925079384164", 1),
        (9183212, "6653919144115459566321", 0),
        (9184024, "6266678839092503120363", 0),
        (9184836, "6036180491275151566604", 2),
        (9185648, "6220223744734691090945", 0),
        (9186460, "6036406821555435078077", 0),
        (9187272, "6051705847313273509445", 1),
        (9188084, "6282954087986541504848", 2),
        (9188896, "6490626643006977849821", 1),
        (9189708, "6174170858030381560332", 3),
        (9190520, "6394273312628830232325", 5),
        (9191332, "6556083972830537065089", 0),
        (9192144, "6789589034639669541666", 3),
        (9192956, "6638694715995077534422", 0),
        (9193768, "7209614875319496123210", 3),
        (9194580, "6556370740379329318732", 3),
        (9195392, "6789843579070254822164", 3),
        (9196204, "6638902109939292843660", 0),
        (9197016, "6330925939153270032670", 1),
        (9197828, "6346892074652529798361", 1),
        (9198640, "6589502362250251607967", 2),
        (9199452, "6523874403529916121482", 0),
        (9200264, "6315611682729564357699", 2),
        (9201076, "6206166062088291389272", 0),
        (9201888, "6190824745853086954425", 0),
        (9202700, "6268891782257873715272", 1),
        (9203512, "6023329195514207718317", 1),
        (9204324, "6859647271380993159014", 1),
        (9205136, "6640292089723536412431", 0),
        (9205948, "6269322719424556437243", 4),
        (9206760, "6269616585406017250578", 3),
        (9207572, "6269596976496417282200", 0),
        (9208384, "6191908109373627209468", 1),
        (9209196, "6412642877629771356201", 1),
        (9210008, "6396831141756074043286", 2),
        (9210820, "6493811441378184489297", 3),
        (9211632, "6349411224139184918541", 0),
        (9212444, "6759125147976369212546", 3),
        (9213256, "6861383648248122088463", 2),
        (9214068, "7088219527793833027180", 0),
        (9214880, "6543679621524480041716", 1),
        (9215692, "6930969883228270998945", 3),
        (9216504, "7071183913638294469651", 2),
        (9217316, "6743407226458001282441", 1),
        (9218128, "6382514093038581482970", 2),
        (9218940, "6560715276152994159073", 0),
        (9219752, "6726863971184181571966", 0),
        (9220564, "6351097833850521388442", 2),
        (9221376, "6710256469201370984051", 1),
        (9222188, "6351256580697669412293", 0),
        (9223000, "6431266290039906024522", 0),
        (9223812, "6087344606846472976257", 2),
        (9224624, "6225901528855708938558", 1),
        (9225436, "6415689281908642278743", 0),
        (9226248, "6179748718026915665985", 0),
        (9227060, "7162052951013826274807", 2),
        (9227872, "6594981562164581623844", 0),
        (9228684, "6694965956582320644286", 0),
        (9229496, "6579069719210487474548", 1),
        (9230308, "6612026832389569399229", 2),
        (9231120, "6813542481230872488402", 0),
        (9231932, "7056481939605436449137", 3),
        (9232744, "7253364449452604123303", 0),
        (9233556, "6780004597340779959158", 1),
        (9234368, "6369263846660573615315", 0),
        (9235180, "6449581021350749023884", 2),
        (9235992, "6696200301647563899309", 0),
        (9236804, "6763773130362269966355", 1),
        (9237616, "6482375603093390432598", 2),
        (9238428, "6564242209258292144776", 1),
        (9239240, "6244353344800381753039", 0),
        (9240052, "6815565363024220017489", 1),
        (9240864, "6515927401507430077002", 1),
        (9241676, "6798993830426392977515", 2),
        (9242488, "6060637654489716538148", 1),
        (9243300, "6137024659543626149725", 2),
        (9244112, "6292561466159990943032", 4),
        (9244924, "6355902186649845750085", 1),
        (9245736, "6356080932918943189705", 2),
        (9246548, "6091797175244427398550", 0),
        (9247360, "6484887815586130593603", 2),
        (9248172, "6404411116796798213619", 2),
        (9248984, "6468796851538883971833", 1),
        (9249796, "6501364097711983561421", 2),
        (9250608, "6766796076810570059393", 2),
        (9251420, "6699653599538069167308", 0),
        (9252232, "7404564647937558312811", 2),
        (9253044, "6921423878166642809053", 2),
        (9253856, "6633426048052465186109", 1),
        (9254668, "6583902481631850029913", 1),
        (9255480, "6617214657488601858250", 2),
        (9256292, "7258828666002627908919", 0),
        (9257104, "6939616431689124592908", 0),
        (9257916, "6939898342141581596311", 0),
        (9258728, "6734940236613922684781", 0),
        (9259540, "6803031554569783285239", 2),
        (9260352, "6718900675608754968547", 1),
        (9261164, "6923846627774256511053", 0),
        (9261976, "6439873085663125746608", 2),
        (9262788, "6736392531506631856408", 0),
        (9263600, "6838307111046550929850", 1),
        (9264412, "6172259550692820904757", 0),
        (9265224, "6872927942758428649326", 0),
        (9266036, "6855895576592018876829", 1),
        (9266848, "6959618112324611491873", 0),
        (9267660, "6821957367565513619936", 0),
        (9268472, "6720412428059388568067", 0),
        (9269284, "6620544498587973169447", 2),
        (9270096, "6737423965906853049965", 0),
        (9270908, "6473467759563416455424", 0),
        (9271720, "7226349812180332385249", 0),
        (9272532, "7048216543044140998142", 1),
        (9273344, "7828848632063438372145", 0),
        (9274156, "6908997623150790068190", 1),
        (9274968, "6314445849127863152932", 0),
        (9275780, "7299774263868014561982", 2),
        (9276592, "7031320979996705591484", 0),
        (9277404, "7245660799475474499441", 0),
        (9278216, "6875247668199051108031", 2),
        (9279028, "6589377128180587575807", 0),
        (9279840, "7014531697381095018356", 0),
        (9280652, "6790223680678765267855", 1),
        (9281464, "6426865195880808446564", 1),
        (9282276, "6221427121807792405112", 2),
        (9283088, "6442932325313403400407", 0),
        (9283900, "6927655297606235460893", 2),
        (9284712, "6945039527408125084327", 0),
        (9285524, "7121054669898658240379", 0),
        (9286336, "6980113469427335746354", 1),
        (9287148, "7068089354682746398030", 0),
        (9287960, "6962967773618061208036", 1),
        (9288772, "7193206960219190887342", 0),
        (9289584, "6774242824410121688676", 2),
        (9290396, "6508803462705121169983", 0),
        (9291208, "6963272338539595888256", 1),
        (9292020, "7468330989512305448609", 2),
        (9292832, "7734472158962502140099", 0),
        (9293644, "7229805239254575203414", 1),
        (9294456, "7122456565903328294667", 0),
        (9295268, "7302922523817273656189", 3),
        (9296080, "7303219192979498038343", 0),
    ];

    /// Total difficulty at #9296080, read from the same node, counting uncle
    /// difficulty as consensus does. It and the checkpoint must come from the
    /// same chain, or the base includes uncles while the work above it does
    /// not, and every bound derived from the pair is nonsense. They do: the
    /// node reports exactly [`MAINNET_CHECKPOINT`]'s figure at #9020000.
    const REAL_TD_AT_HEAD: &str = "61136898698724168941501607931";
    const HEAD: u64 = 9296080;

    fn parse(s: &str) -> U256 {
        s.parse().expect("decimal")
    }

    fn samples() -> Vec<Sample> {
        SAMPLES
            .iter()
            .map(|&(number, d, uncle_count)| Sample {
                number,
                difficulty: parse(d),
                uncle_count,
            })
            .collect()
    }

    /// The one that matters. The shipped checkpoint, fed real verified
    /// samples, must not bound the real chain below what it actually carries.
    #[test]
    fn the_shipped_checkpoint_does_not_refuse_the_real_chain() {
        let ceiling = ceiling_for(&MAINNET_CHECKPOINT, &samples(), HEAD, DIV, MIN);
        let real = parse(REAL_TD_AT_HEAD);
        assert!(
            ceiling >= real,
            "the ceiling refuses the honest chain:\n  ceiling {ceiling}\n  real    {real}"
        );
    }

    /// And an honest peer stating exactly the truth is judged plausible, which
    /// is the call the gate actually makes.
    #[test]
    fn an_honest_peer_on_the_real_chain_is_plausible() {
        let verdict = judge(
            &MAINNET_CHECKPOINT, parse(REAL_TD_AT_HEAD), &samples(), HEAD, DIV, MIN,
        );
        assert!(
            matches!(verdict, CheckpointVerdict::Plausible { .. }),
            "an honest peer was refused: {verdict:?}"
        );
    }

    /// A bound that accepts everything is not a bound.
    ///
    /// Measured against the *total* claim, which is what `judge` compares.
    /// At the shipped 340 samples the ceiling sits about 17% above the real
    /// chain, so a peer can overstate its work by a sixth and still be judged
    /// plausible. That is the honest figure and it is not a small one.
    ///
    /// Two things make it up, and only one of them is about spacing:
    ///
    /// * the retarget rule lets difficulty compound by `(1 + 1/400)^gap`
    ///   between samples, and
    /// * the uncle allowance ([`uncle_allowance_per_mille`]) is a
    ///   concentration bound, whose range term `3R*ln(3/delta)/k` contributes
    ///   1.93 of the 4.20 it returns here and does not shrink with anything
    ///   but more samples.
    ///
    /// Together they bound the work above the checkpoint at about 3.9x what
    /// it really is. It stays worth having because that work is only ~6% of
    /// the cumulative total, the rest being exact -- and because the thing it
    /// refuses is the claim an attacker actually needs to make, which is not
    /// 17% high but orders of magnitude high. See `sampling_cost` for the
    /// spacing curve, and the notes on `uncle_allowance_per_mille` for why
    /// closing the rest is a consensus question rather than a sampling one.
    #[test]
    fn the_bound_is_tight_enough_to_be_worth_having() {
        let ceiling = ceiling_for(&MAINNET_CHECKPOINT, &samples(), HEAD, DIV, MIN);
        let real = parse(REAL_TD_AT_HEAD);
        let slack = ceiling - real;
        assert!(
            slack * U256::from(5) <= real,
            "slack {slack} exceeds 20% of the {real} a peer would be claiming"
        );
    }

    /// The property whose absence let the uncle bug ship: the ceiling must sit
    /// above the honest chain's **uncle-inclusive** work at *every* spacing,
    /// not only at the one that happens to be configured.
    ///
    /// Before uncles were counted in the bound, tightening the interval -- the
    /// obvious optimisation -- inverted it: the bound fell *below* the honest
    /// chain's real work, and the node would have judged every truthful peer
    /// impossible and bounded itself out of the network. Thinning the fixture
    /// is the same move in reverse, and it must stay safe in both directions.
    #[test]
    fn the_ceiling_clears_the_real_chain_at_every_spacing() {
        let real = parse(REAL_TD_AT_HEAD);
        for step in [1usize, 2, 4, 8] {
            let samples: Vec<Sample> = SAMPLES
                .iter()
                .enumerate()
                .filter(|(i, _)| (i + 1) % step == 0)
                .map(|(_, &(number, d, uncle_count))| Sample {
                    number,
                    difficulty: parse(d),
                    uncle_count,
                })
                .collect();
            if samples.last().map(|s| s.number) != Some(HEAD) {
                continue;
            }
            let ceiling = ceiling_for(&MAINNET_CHECKPOINT, &samples, HEAD, DIV, MIN);
            assert!(
                ceiling >= real,
                "at {}-block spacing the ceiling refuses the honest chain:\n  \
                 ceiling {ceiling}\n  real    {real}",
                step * 812
            );
        }
    }

    /// The allowance tracks what the samples saw, and beats the consensus cap.
    ///
    /// Assuming `uncleListLimit` everywhere gives 11.0, a ceiling that admits
    /// any liar. 340 real samples bring it to about 4.2 -- still 2.2x the
    /// truth of 1.91, because at this `k` the range term dominates, but a
    /// third of what assuming the cap would cost.
    #[test]
    fn the_uncle_allowance_follows_the_samples() {
        let observed = uncle_allowance_per_mille(&samples());
        assert!(
            (3_900..=4_500).contains(&observed),
            "340 mainnet samples average about 0.91 uncles a block, so the \
             allowance should be near 4.2, got {observed} per mille"
        );

        // Having observed nothing, the sound assumption is the worst case.
        // Returning 1_000 here -- "no uncles anywhere" -- would be a ceiling
        // below the honest chain, which refuses every truthful peer.
        let none: Vec<Sample> = Vec::new();
        assert_eq!(
            uncle_allowance_per_mille(&none),
            1_000 + UNCLE_LIST_LIMIT * 1_000,
            "nothing observed means the worst case assumed"
        );
    }

    /// An inflated claim on the real chain is refused -- but only once the
    /// inflation exceeds the bound's own slack.
    ///
    /// 25%, not the 1% this asserted while the ceiling bounded header
    /// difficulty alone and uncles were assumed away. A peer's lie still has
    /// to be worth telling: claiming the best chain means out-claiming a real
    /// one by enough to win peer selection, and this bounds how far past it a
    /// peer can reach.
    #[test]
    fn an_inflated_claim_on_the_real_chain_is_refused() {
        let real = parse(REAL_TD_AT_HEAD);
        let inflated = real + real / U256::from(4);
        let verdict = judge(&MAINNET_CHECKPOINT, inflated, &samples(), HEAD, DIV, MIN);
        assert!(
            matches!(verdict, CheckpointVerdict::Impossible { .. }),
            "a claim 25% above the real chain passed: {verdict:?}"
        );
    }

    /// The audit that makes shipping a checkpoint safe: this node's own chain
    /// at the checkpoint height must not contradict it.
    #[test]
    fn the_real_chain_does_not_contradict_the_checkpoint() {
        assert_eq!(
            audit_own_chain(&MAINNET_CHECKPOINT, MAINNET_CHECKPOINT.cumulative_difficulty),
            None
        );
    }
}

/// A one-off measurement, not a guard: prints how tight the sampled bound is
/// at each spacing, so the interval is a choice with a number behind it.
/// Run with `cargo test -p rustock-core sampling_cost -- --nocapture --ignored`.
#[cfg(test)]
mod sampling_cost {
    use super::*;

    const DIV: u64 = 400;
    const MIN: U256 = U256::from_limbs([7_000_000_000_000_000u64, 0, 0, 0]);
    const HEAD: u64 = 9049952;
    /// The same figure as `real_chain_tests::REAL_TD_AT_HEAD`, and it must stay
    /// the same: a second copy of a fact is a second thing to forget. This one
    /// was missed when totals began counting uncle difficulty, and the stale
    /// value underflowed `real - checkpoint` into a wrapped U256, which printed
    /// as a ~2^256 "work above the checkpoint" and 0.0% slack at every spacing.
    const REAL_TD: &str = "57930075977936206832660598923";

    /// Every 192nd block from the checkpoint to #9049952, read from this
    /// project's synced mainnet node on 2026-09-30.
    const DENSE: &[(u64, &str, u64)] = &[
        (9020192, "7274662020063509595881", 0),
        (9020384, "7529312041719755308934", 1),
        (9020576, "7468594156406836678092", 1),
        (9020768, "7614994946002703006906", 0),
        (9020960, "7803330447104372329650", 1),
        (9021152, "7663480160924534989023", 0),
        (9021344, "7413993775032742710299", 1),
        (9021536, "6926015941405100741989", 0),
        (9021728, "6921948089376012035085", 2),
        (9021920, "6952602183670272993594", 1),
        (9022112, "7053488264958863725299", 1),
        (9022304, "6772936187870155390801", 0),
        (9022496, "6819895078970878520113", 0),
        (9022688, "6936282700443386191951", 0),
        (9022880, "6627214972769280752906", 2),
        (9023072, "6656522227407884114154", 0),
        (9023264, "6586459083143505604067", 1),
        (9023456, "6834103775244555641868", 2),
        (9023648, "6898819829379759439018", 0),
        (9023840, "6775137721459334918956", 0),
        (9024032, "6977327788118979525601", 1),
        (9024224, "6501795421319416302183", 0),
        (9024416, "6746299003407676099623", 0),
        (9024608, "6776259932436813770316", 0),
        (9024800, "6996060873222112912013", 1),
        (9024992, "6905247331824997846617", 0),
        (9025184, "6370601785561533555901", 0),
        (9025376, "6511677522428858627223", 0),
        (9025568, "6524163432069601985995", 0),
        (9025760, "6552974009861167665088", 0),
        (9025952, "6884949836595639991314", 0),
        (9026144, "6660891948071123261697", 0),
        (9026336, "7139666351085111424922", 0),
        (9026528, "7064517879185484250056", 1),
        (9026720, "6834616282656690312357", 1),
        (9026912, "6847721415863989280455", 1),
        (9027104, "7123041338011178115253", 1),
        (9027296, "6960493414581538909000", 0),
        (9027488, "6904492055398375200063", 0),
        (9027680, "7022235621320739353434", 0),
        (9027872, "7018242847886259687536", 1),
        (9028064, "6996629255155729983289", 0),
        (9028256, "6684872598361605698818", 1),
        (9028448, "6681029889493744529940", 1),
        (9028640, "6984483128871099938457", 1),
        (9028832, "6980337309969418901764", 0),
        (9029024, "7279232658289315491451", 0),
        (9029216, "7024737709657163858379", 2),
        (9029408, "6578827188266924624679", 0),
        (9029600, "6877552397560331364004", 0),
        (9029792, "6942549717222618368994", 1),
        (9029984, "7078638884624765767949", 1),
        (9030176, "6917060994028628683985", 1),
        (9030368, "6691999932601996296327", 0),
        (9030560, "7635654604089318557285", 0),
        (9030752, "7168752604407800972828", 0),
        (9030944, "6815165225296564092140", 1),
        (9031136, "6777233951669377712914", 1),
        (9031328, "6689093699869072319813", 0),
        (9031520, "6888888180060507127356", 0),
        (9031712, "6500109079202782021434", 0),
        (9031904, "6761452877665200488475", 0),
        (9032096, "6893992150703121615467", 2),
        (9032288, "6719913454411387067155", 0),
        (9032480, "6800464542076052863472", 0),
        (9032672, "6830495260151751736727", 0),
        (9032864, "6929609502827035510100", 0),
        (9033056, "6995229955554903144549", 0),
        (9033248, "7367938591136586843040", 0),
        (9033440, "7057236180536581873240", 0),
        (9033632, "7123976153047276846671", 0),
        (9033824, "7137680734000858675462", 1),
        (9034016, "7187213433535620560405", 0),
        (9034208, "7328144346097118442182", 1),
        (9034400, "6931861962861679474287", 1),
        (9034592, "6962559961098692829093", 0),
        (9034784, "6820683410959441794990", 1),
        (9034976, "6582261300490072976970", 0),
        (9035168, "6432013786296933002176", 0),
        (9035360, "6928894867327960362909", 1),
        (9035552, "7082422425854794022897", 1),
        (9035744, "7007832674970455240373", 0),
        (9035936, "6729096546263711519389", 0),
        (9036128, "6526385889766530363753", 0),
        (9036320, "6490143006420026293273", 0),
        (9036512, "6734166304253918252394", 0),
        (9036704, "6646627703401487910669", 0),
        (9036896, "6659413996543502709365", 0),
        (9037088, "6944480725676603142382", 1),
        (9037280, "6685018640507210085863", 0),
        (9037472, "7023683891823346010307", 2),
        (9037664, "6897763219796527259508", 0),
        (9037856, "6910946241321922496058", 0),
        (9038048, "7028843801931139066058", 0),
        (9038240, "7311400245698544997835", 1),
        (9038432, "7288929392396665473224", 0),
        (9038624, "7339557570422188889171", 0),
        (9038816, "7353676871038362321206", 0),
        (9039008, "7479127212327372804966", 0),
        (9039200, "7587748307903181835152", 0),
        (9039392, "7564428126626170266849", 0),
        (9039584, "7751416105938615621659", 0),
        (9039776, "7727496313535944053188", 1),
        (9039968, "7898718949361532018966", 0),
        (9040160, "8033417248360837045821", 0),
        (9040352, "7656226756261853725525", 0),
        (9040544, "7767371363130121987734", 0),
        (9040736, "7821273868193441326820", 0),
        (9040928, "7472819301616357547104", 0),
        (9041120, "7524724760647069942493", 1),
        (9041312, "7925694625732639471015", 0),
        (9041504, "7940891862788093508537", 1),
        (9041696, "7936227944404119464068", 0),
        (9041888, "7833014578250203961900", 0),
        (9042080, "7750519836912523766310", 1),
        (9042272, "7765332648919433244207", 0),
        (9042464, "7664389737127857653380", 1),
        (9042656, "7795189416772961289749", 0),
        (9042848, "7355446472199366191955", 0),
        (9043040, "7387974154434983383639", 1),
        (9043232, "7365221926001376302367", 0),
        (9043424, "7379344476624517921717", 2),
        (9043616, "7430647110369684355669", 0),
        (9043808, "7538564118203866061816", 1),
        (9044000, "7590926234186410077568", 0),
        (9044192, "7605434030518960731207", 0),
        (9044384, "7891391226184679188777", 2),
        (9044576, "7966019766314770267381", 1),
        (9044768, "7981194559523223539395", 0),
        (9044960, "7799063565110005651245", 0),
        (9045152, "7159327069243667133894", 1),
        (9045344, "7391414933915301708664", 0),
        (9045536, "7387073739426127010789", 1),
        (9045728, "7345913473227942771344", 0),
        (9045920, "7304936893057764102022", 0),
        (9046112, "7120392514720170234204", 1),
        (9046304, "7499863609261157070705", 1),
        (9046496, "7347084306013310699966", 0),
        (9046688, "7435106772911396342515", 0),
        (9046880, "7375240768038117586302", 0),
        (9047072, "7501105861392098870565", 0),
        (9047264, "7822202539552976576601", 0),
        (9047456, "7289134188254961309172", 0),
        (9047648, "7469317071875928865358", 2),
        (9047840, "7335407083932573007086", 0),
        (9048032, "7367892196148710591756", 1),
        (9048224, "7568849678173223877691", 0),
        (9048416, "7396128400904648822682", 1),
        (9048608, "7336530388549324614753", 1),
        (9048800, "7536632484838117691620", 0),
        (9048992, "7607953636847295363924", 0),
        (9049184, "8013358517474663685190", 1),
        (9049376, "7988630407208550733056", 1),
        (9049568, "7594556386490896785705", 0),
        (9049760, "7666377772582978423800", 1),
        (9049952, "7108209165328692545538", 2),
    ];

    #[test]
    #[ignore = "measurement, not an assertion"]
    fn how_tight_is_the_bound_at_each_spacing() {
        let real: U256 = REAL_TD.parse().unwrap();
        let above = real - MAINNET_CHECKPOINT.cumulative_difficulty;
        println!("work above the checkpoint: {above}");
        println!("{:>8} {:>8} {:>12}", "spacing", "samples", "slack/above");
        for step in [1usize, 2, 4, 8, 16, 32] {
            let samples: Vec<Sample> = DENSE
                .iter()
                .enumerate()
                .filter(|(i, _)| (i + 1) % step == 0)
                .map(|(_, &(number, d, uncle_count))| Sample {
                    number,
                    difficulty: d.parse().unwrap(),
                    uncle_count,
                })
                .collect();
            if samples.last().map(|s| s.number) != Some(HEAD) {
                continue; // the last sample must sit at the head
            }
            let ceiling = ceiling_for(&MAINNET_CHECKPOINT, &samples, HEAD, DIV, MIN);
            let slack = ceiling - real;
            let pct = (u256_to_f64(slack) / u256_to_f64(above)) * 100.0;
            println!("{:>8} {:>8} {:>11.1}%", step * 192, samples.len(), pct);
        }
    }
}
