//! A miner that mines on a clock, the way rskj's regtest does.
//!
//! rskj's `co.rsk.mine.TimedMinerClient` mines one block per scheduled
//! tick, and the delay to the next tick is drawn from an exponential
//! distribution whose median is `miner.client.medianBlockTime`, floored at
//! 100 ms and scaled by how much the difficulty has moved since the first
//! block it mined. This is a port of that schedule, so a chain this node
//! mines on its own has the block-time distribution a chain rskj's regtest
//! mines has. What a block contains is unchanged: the template is the
//! [`MinerServer`]'s, and the solution goes through the same submit path a
//! pool's would.
//!
//! Each step names the rskj line it mirrors
//! (`rskj-core/src/main/java/co/rsk/mine/TimedMinerClient.java`):
//!
//! - the delay: `scheduleNextMining`, lines 186 to 194. Median scaled by the
//!   difficulty ratio (186), a non-finite or non-positive result falling back
//!   to the base median (187 to 189), mean = median / ln 2 (190), delay =
//!   -mean * ln(1 - u) with u uniform in [0, 1) (191), truncated to whole
//!   milliseconds (191, the `(long)` cast), floor 100 ms (194);
//! - the difficulty ratio: `mineBlock`, lines 115 to 128. The current
//!   difficulty is `MAX / target` of the work just taken (118); the first
//!   difficulty seen is the baseline with scale 1 (120 to 122); afterwards
//!   the scale is current / baseline (124), and 1 again when that is not
//!   finite or not positive (125 to 127);
//! - no proof of work when it is not validated: `mineBlock`, lines 130 to
//!   138. With `skipPowValidation` the Bitcoin block is submitted with nonce
//!   0 (133), and so is any block whose search threw (137);
//! - the first block is scheduled, not mined at once: `start`, line 83;
//! - a block that fails to mine still schedules the next: `mineBlock`,
//!   lines 152 to 158.
//!
//! Two things rskj does are left out. `hasBetterBlockToSync` (lines 100 to
//! 108) pauses the miner while the node is behind a peer; this node has no
//! equivalent handle, and the regtest chain this is for has no peers. And
//! rskj's search for a nonce when proof of work *is* validated is unbounded
//! (`findNonce`); here it is the bounded search of [`dev::mine_one`], which
//! gives up at a real network's difficulty rather than spinning forever.

use alloy_primitives::U256;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::mining::dev::{self, MineError};
use crate::mining::server::{MinerServer, SubmittedBlockInfo};

/// rskj `TimedMinerClient.scheduleNextMining`, line 194: the shortest delay
/// between two blocks.
pub const MIN_DELAY: Duration = Duration::from_millis(100);

/// The delay distribution of rskj's `TimedMinerClient`: exponential with a
/// configurable median, floored, and scaled by the difficulty ratio.
///
/// Pure arithmetic over state the miner updates as it goes; the random draw
/// is passed in so the distribution can be tested without one.
#[derive(Debug, Clone)]
pub struct TimedSchedule {
    /// `baseMedianMillis`: the configured median, before scaling.
    base_median: Duration,
    /// `baselineDifficulty`: the difficulty of the first work taken.
    baseline_difficulty: Option<U256>,
    /// `difficultyScale`: current difficulty over the baseline.
    difficulty_scale: f64,
}

impl TimedSchedule {
    pub fn new(median: Duration) -> Self {
        Self {
            base_median: median,
            baseline_difficulty: None,
            difficulty_scale: 1.0,
        }
    }

    /// The median the next draw uses, after scaling.
    pub fn scaled_median(&self) -> Duration {
        let base = self.base_median.as_secs_f64() * 1000.0;
        let scaled = base * self.difficulty_scale;
        let scaled = if scaled.is_finite() && scaled > 0.0 {
            scaled
        } else {
            base
        };
        Duration::from_secs_f64(scaled / 1000.0)
    }

    /// `TimedMinerClient.mineBlock`, lines 115 to 128: learn the difficulty
    /// of the work just taken from its target, and update the scale.
    pub fn observe_target(&mut self, target: U256) {
        if target.is_zero() {
            return;
        }
        let current = U256::MAX / target;
        match self.baseline_difficulty {
            None => {
                self.baseline_difficulty = Some(current);
                self.difficulty_scale = 1.0;
            }
            Some(baseline) if baseline.is_zero() => {
                self.baseline_difficulty = Some(current);
                self.difficulty_scale = 1.0;
            }
            Some(baseline) => {
                let scale = u256_to_f64(current) / u256_to_f64(baseline);
                self.difficulty_scale = if scale.is_finite() && scale > 0.0 {
                    scale
                } else {
                    1.0
                };
            }
        }
    }

    /// `TimedMinerClient.scheduleNextMining`, lines 186 to 194, with `u` in
    /// place of `random.nextDouble()`: the delay before the next block.
    pub fn delay_from_uniform(&self, u: f64) -> Duration {
        let median_ms = self.scaled_median().as_secs_f64() * 1000.0;
        let mean = median_ms / std::f64::consts::LN_2;
        // Java's `(long)` cast truncates toward zero, as `as u64` does.
        let delay_ms = (-mean * (1.0 - u).ln()) as u64;
        Duration::from_millis(delay_ms).max(MIN_DELAY)
    }

    /// The next delay, drawn from the thread's random generator.
    pub fn next_delay(&self) -> Duration {
        use rand::Rng;
        self.delay_from_uniform(rand::thread_rng().gen::<f64>())
    }
}

/// `BigInteger.doubleValue()` for a 256-bit value: the nearest double, and
/// infinity when it does not fit, which the caller treats as "scale 1".
fn u256_to_f64(value: U256) -> f64 {
    value.as_limbs().iter().rev().fold(0.0_f64, |acc, limb| {
        acc * 18_446_744_073_709_551_616.0 + *limb as f64
    })
}

/// How the miner closes a block: with a nonce search against the target, or
/// with nonce 0 because the chain does not validate proof of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pow {
    /// Search a nonce, giving up after this many per extra-nonce.
    Search { attempts: u32 },
    /// Nonce 0, as rskj with `skipPowValidation`.
    Skip,
}

/// Build work, close it the way `pow` says, submit it, and record its
/// difficulty on `schedule`. The body of rskj's `TimedMinerClient.mineBlock`.
pub fn mine_block(
    server: &MinerServer,
    pow: Pow,
    schedule: &mut TimedSchedule,
) -> Result<SubmittedBlockInfo, MineError> {
    let work = server.build_work().map_err(MineError::Work)?;
    schedule.observe_target(work.target);
    match pow {
        Pow::Skip => dev::submit_unsolved(server, &work),
        Pow::Search { attempts } => dev::solve_and_submit(server, &work, attempts),
    }
}

/// A thread that mines a block per draw of a [`TimedSchedule`].
///
/// A plain OS thread, as the `evm_startMining` miner is: closing a block
/// re-executes it, which is CPU-bound work that should not hold a runtime
/// worker.
pub struct TimedMiner {
    server: Arc<MinerServer>,
    median: Duration,
    pow: Pow,
    running: Arc<AtomicBool>,
    /// Blocks mined so far, for tests and for the stop message.
    mined: Arc<Mutex<u64>>,
}

impl TimedMiner {
    pub fn new(server: Arc<MinerServer>, median: Duration, pow: Pow) -> Self {
        Self {
            server,
            median,
            pow,
            running: Arc::new(AtomicBool::new(false)),
            mined: Arc::new(Mutex::new(0)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn median(&self) -> Duration {
        self.median
    }

    /// Blocks this miner has submitted since it was created.
    pub fn mined(&self) -> u64 {
        *self.mined.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Start the thread, or do nothing if it is running. The first block
    /// comes after a draw, as in rskj (`start`, line 83), not at once.
    pub fn start(&self) {
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let server = self.server.clone();
        let running = self.running.clone();
        let mined = self.mined.clone();
        let pow = self.pow;
        let mut schedule = TimedSchedule::new(self.median);
        std::thread::Builder::new()
            .name("rustock-timed-miner".into())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    let delay = schedule.next_delay();
                    debug!(
                        target: "rustock::mining",
                        "Next block in {} ms (median {} ms)",
                        delay.as_millis(),
                        schedule.scaled_median().as_millis()
                    );
                    // Sleep in slices so a stop is honoured within a tick
                    // rather than after a whole draw, which at a 10 s median
                    // can be half a minute.
                    let mut left = delay;
                    while !left.is_zero() && running.load(Ordering::Relaxed) {
                        let slice = left.min(MIN_DELAY);
                        std::thread::sleep(slice);
                        left -= slice;
                    }
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    match mine_block(&server, pow, &mut schedule) {
                        Ok(info) => {
                            *mined.lock().unwrap_or_else(|e| e.into_inner()) += 1;
                            debug!(
                                target: "rustock::mining",
                                "Timed miner: #{} {}",
                                info.block_included_height,
                                info.block_imported_result.as_str()
                            );
                        }
                        // rskj logs and schedules the next one regardless
                        // (`mineBlock`, lines 152 to 158).
                        Err(e) => warn!(target: "rustock::mining", "Timed miner: {e}"),
                    }
                }
                info!(target: "rustock::mining", "Timed miner stopped");
            })
            .expect("spawning the timed miner thread");
        info!(
            target: "rustock::mining",
            "Timed miner started: median block time {} ms, {}",
            self.median.as_millis(),
            match pow {
                Pow::Skip => "nonce 0 (proof of work not validated)",
                Pow::Search { .. } => "searching nonces",
            }
        );
    }

    /// Stop after the block in flight, if any. Idempotent.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(d: Duration) -> f64 {
        d.as_secs_f64() * 1000.0
    }

    #[test]
    fn the_median_of_the_draw_is_the_configured_median() {
        // At u = 0.5 the exponential's quantile is exactly the median:
        // -mean * ln(0.5) = median / ln 2 * ln 2.
        let s = TimedSchedule::new(Duration::from_secs(10));
        let d = s.delay_from_uniform(0.5);
        assert!((ms(d) - 10_000.0).abs() <= 1.0, "{d:?}");
    }

    #[test]
    fn draws_are_floored_at_100_ms() {
        let s = TimedSchedule::new(Duration::from_secs(10));
        assert_eq!(s.delay_from_uniform(0.0), MIN_DELAY);
        assert_eq!(s.delay_from_uniform(0.001), MIN_DELAY);
        let s = TimedSchedule::new(Duration::from_millis(1));
        assert_eq!(s.delay_from_uniform(0.999), MIN_DELAY);
    }

    #[test]
    fn the_draw_is_exponential() {
        // Quantiles of Exp with median m: q(u) = -m/ln2 * ln(1-u).
        let s = TimedSchedule::new(Duration::from_secs(10));
        for (u, expect_ms) in [(0.25, 4_150.37), (0.75, 20_000.0), (0.9, 33_219.28)] {
            let d = ms(s.delay_from_uniform(u));
            assert!((d - expect_ms).abs() <= 1.0, "u={u}: {d} vs {expect_ms}");
        }
    }

    #[test]
    fn the_empirical_median_is_near_the_configured_one() {
        // Many draws from the real generator: the sample median must sit
        // close to the configured one, and the mean near median / ln 2.
        let s = TimedSchedule::new(Duration::from_millis(1_000));
        let mut draws: Vec<f64> = (0..20_000).map(|_| ms(s.next_delay())).collect();
        draws.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = draws[draws.len() / 2];
        let mean = draws.iter().sum::<f64>() / draws.len() as f64;
        assert!((median - 1_000.0).abs() < 50.0, "median {median}");
        assert!(
            (mean - 1_000.0 / std::f64::consts::LN_2).abs() < 60.0,
            "mean {mean}"
        );
        assert!(draws.iter().all(|d| *d >= 100.0));
    }

    #[test]
    fn the_first_target_sets_the_baseline_and_later_ones_scale_the_median() {
        let mut s = TimedSchedule::new(Duration::from_secs(10));
        let target_for = |difficulty: u64| U256::MAX / U256::from(difficulty);

        s.observe_target(target_for(1 << 28));
        assert_eq!(s.scaled_median(), Duration::from_secs(10));

        // Twice the difficulty, twice the median.
        s.observe_target(target_for(1 << 29));
        assert!((ms(s.scaled_median()) - 20_000.0).abs() < 1.0);
        assert!((ms(s.delay_from_uniform(0.5)) - 20_000.0).abs() <= 1.0);

        // Half the baseline, half the median.
        s.observe_target(target_for(1 << 27));
        assert!((ms(s.scaled_median()) - 5_000.0).abs() < 1.0);

        // A zero target is ignored, as rskj's `signum() > 0` guard does.
        s.observe_target(U256::ZERO);
        assert!((ms(s.scaled_median()) - 5_000.0).abs() < 1.0);
    }

    #[test]
    fn u256_converts_like_big_integer_double_value() {
        assert_eq!(u256_to_f64(U256::from(0)), 0.0);
        assert_eq!(u256_to_f64(U256::from(1u64 << 40)), (1u64 << 40) as f64);
        assert_eq!(u256_to_f64(U256::from(1u128 << 100)), 2f64.powi(100));
        assert!(u256_to_f64(U256::MAX).is_finite());
    }
}
