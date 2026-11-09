//! What the chain did, sampled over a reporting window.
//!
//! The node logs `Processed N blocks` and little else, which says it is alive
//! but nothing about what it is processing. A node keeping up with an idle
//! chain and one keeping up with a saturated one produce the same line.
//!
//! These counters answer the questions that line leaves open: how many
//! transactions per block, how much gas, and how full the blocks are — the
//! last being the same fullness signal rskj's `GasPriceTracker` uses to decide
//! whether the fee market is working (see issue #52).

use std::sync::{PoisonError, RwLock};
use std::time::Duration;

/// CPU time consumed by the calling thread.
///
/// Distinct from wall time on purpose: wall time includes waiting on the trie
/// database, CPU time does not. Tracking both means the two can be compared,
/// and the gap between them is where the node is waiting rather than working.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn thread_cpu_time() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, initialised timespec and CLOCK_THREAD_CPUTIME_ID
    // is available on Linux and on macOS from 10.12. A failure leaves `ts`
    // zeroed, which reports no CPU time rather than a wrong figure.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Windows has no thread CPU clock to read; `GetThreadTimes` gives the
/// thread's kernel and user time instead, in the 100 ns units a FILETIME
/// counts. It advances by scheduler ticks of about 15.6 ms, so a stretch of
/// work shorter than a tick can read as none; the figures it feeds are
/// averages over many blocks.
#[cfg(windows)]
pub fn thread_cpu_time() -> Duration {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThread() -> *mut std::ffi::c_void;
        fn GetThreadTimes(
            thread: *mut std::ffi::c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }
    let (mut creation, mut exit, mut kernel, mut user) = Default::default();
    // SAFETY: GetCurrentThread's pseudo-handle stands for the calling thread
    // and needs no closing, and the four out-pointers are to valid FILETIMEs.
    // A failure, zero, reports no CPU time rather than a wrong figure.
    let ok = unsafe {
        GetThreadTimes(
            GetCurrentThread(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return Duration::ZERO;
    }
    let ticks = |t: FileTime| (u64::from(t.high) << 32) | u64::from(t.low);
    Duration::from_nanos((ticks(kernel) + ticks(user)).saturating_mul(100))
}

/// Every other platform reports zero, so the ratios read as unavailable rather
/// than wrong.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn thread_cpu_time() -> Duration {
    Duration::ZERO
}

#[derive(Default, Debug)]
struct Counters {
    blocks: u64,
    transactions: u64,
    gas_used: u128,
    gas_limit: u128,
    cpu_nanos: u128,
    wall_nanos: u128,
    first_block: Option<u64>,
    last_block: u64,
}

/// Accumulates per-block facts between reports. Shared by both execution
/// paths — the batch pipeline and follow mode — so the window covers
/// everything the node executed, however it arrived.
#[derive(Default, Debug)]
pub struct ChainActivity {
    inner: RwLock<Counters>,
}

impl ChainActivity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one executed block.
    ///
    /// `gas_limit` is carried as well as `gas_used` so the report can state
    /// fullness, which is what distinguishes a quiet chain from a congested
    /// one — the raw gas figure alone cannot.
    pub fn record_block(
        &self,
        number: u64,
        transactions: usize,
        gas_used: u64,
        gas_limit: u64,
        cpu: Duration,
        wall: Duration,
    ) {
        let mut c = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        c.blocks += 1;
        c.transactions += transactions as u64;
        c.gas_used += gas_used as u128;
        c.gas_limit += gas_limit as u128;
        c.cpu_nanos += cpu.as_nanos();
        c.wall_nanos += wall.as_nanos();
        c.first_block.get_or_insert(number);
        c.last_block = number;
    }

    /// The window since the previous call, clearing the counters so each
    /// report covers exactly one window.
    pub fn take(&self) -> ChainActivitySummary {
        let mut c = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let summary = ChainActivitySummary {
            blocks: c.blocks,
            transactions: c.transactions,
            gas_used: c.gas_used,
            gas_limit: c.gas_limit,
            cpu_nanos: c.cpu_nanos,
            wall_nanos: c.wall_nanos,
            first_block: c.first_block,
            last_block: c.last_block,
        };
        *c = Counters::default();
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainActivitySummary {
    pub blocks: u64,
    pub transactions: u64,
    pub gas_used: u128,
    /// Summed block gas limits, for the fullness ratio.
    pub gas_limit: u128,
    /// Thread CPU time spent executing these blocks.
    pub cpu_nanos: u128,
    /// Wall-clock time spent executing them. Exceeds `cpu_nanos` by however
    /// long execution waited on the trie database.
    pub wall_nanos: u128,
    pub first_block: Option<u64>,
    pub last_block: u64,
}

impl ChainActivitySummary {
    /// True when no block was executed, so the reporter can stay quiet. A node
    /// at the tip executes roughly one block every 30 seconds, so an empty
    /// window is itself worth noticing by its absence rather than by a line of
    /// zeroes every five minutes.
    pub fn is_empty(&self) -> bool {
        self.blocks == 0
    }

    pub fn avg_transactions(&self) -> f64 {
        if self.blocks == 0 {
            return 0.0;
        }
        self.transactions as f64 / self.blocks as f64
    }

    pub fn avg_gas_used(&self) -> f64 {
        if self.blocks == 0 {
            return 0.0;
        }
        self.gas_used as f64 / self.blocks as f64
    }

    /// Gas used as a percentage of gas available. rskj calls the fee market
    /// "working" above 90% (`BLOCK_COMPLETION_PERCENT_FOR_FEE_MARKET_WORKING`).
    pub fn fullness_percent(&self) -> f64 {
        if self.gas_limit == 0 {
            return 0.0;
        }
        self.gas_used as f64 / self.gas_limit as f64 * 100.0
    }

    pub fn avg_cpu_ms_per_block(&self) -> f64 {
        if self.blocks == 0 {
            return 0.0;
        }
        self.cpu_nanos as f64 / self.blocks as f64 / 1e6
    }

    pub fn avg_wall_ms_per_block(&self) -> f64 {
        if self.blocks == 0 {
            return 0.0;
        }
        self.wall_nanos as f64 / self.blocks as f64 / 1e6
    }

    /// **CPU nanoseconds per unit of gas — the degradation signal.**
    ///
    /// Gas is a measure of work, so this is the node's cost per unit of work
    /// and should hold roughly steady whatever the chain is doing. Blocks vary
    /// enormously in size and fullness, which makes time-per-block a poor
    /// comparison between two windows; time-per-gas normalises that away.
    ///
    /// A rising figure means each unit of work is costing more than it used
    /// to — the trie is deeper, caches are missing more often, or execution
    /// has regressed.
    pub fn cpu_nanos_per_gas(&self) -> f64 {
        if self.gas_used == 0 {
            return 0.0;
        }
        self.cpu_nanos as f64 / self.gas_used as f64
    }

    /// The same ratio in wall time. Read against `cpu_nanos_per_gas`: the two
    /// rising together is execution getting slower, wall rising alone is the
    /// node spending its time waiting on the database.
    pub fn wall_nanos_per_gas(&self) -> f64 {
        if self.gas_used == 0 {
            return 0.0;
        }
        self.wall_nanos as f64 / self.gas_used as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_until_a_block_is_recorded() {
        let a = ChainActivity::new();
        assert!(a.take().is_empty());

        a.record_block(100, 3, 60_000, 6_800_000, Duration::ZERO, Duration::ZERO);
        assert!(!a.take().is_empty());
    }

    #[test]
    fn averages_and_fullness_are_computed_over_the_window() {
        let a = ChainActivity::new();
        // Three blocks: 2, 4 and 6 transactions; 1M, 2M and 3M gas of 6.8M.
        a.record_block(10, 2, 1_000_000, 6_800_000, Duration::ZERO, Duration::ZERO);
        a.record_block(11, 4, 2_000_000, 6_800_000, Duration::ZERO, Duration::ZERO);
        a.record_block(12, 6, 3_000_000, 6_800_000, Duration::ZERO, Duration::ZERO);

        let s = a.take();
        assert_eq!(s.blocks, 3);
        assert_eq!(s.transactions, 12);
        assert_eq!(s.gas_used, 6_000_000);
        assert_eq!(s.first_block, Some(10));
        assert_eq!(s.last_block, 12);
        assert!((s.avg_transactions() - 4.0).abs() < 1e-9);
        assert!((s.avg_gas_used() - 2_000_000.0).abs() < 1e-9);
        // 6M used of 20.4M available.
        assert!((s.fullness_percent() - 29.411_764_7).abs() < 1e-6, "{}", s.fullness_percent());
    }

    #[test]
    fn taking_the_summary_clears_the_window() {
        let a = ChainActivity::new();
        a.record_block(1, 1, 21_000, 6_800_000, Duration::ZERO, Duration::ZERO);
        assert_eq!(a.take().blocks, 1);
        assert!(a.take().is_empty(), "each report covers exactly one window");
    }

    /// Blocks arrive from two execution paths and may be recorded out of the
    /// order the window started in; the range must still read correctly.
    #[test]
    fn the_block_range_spans_the_window() {
        let a = ChainActivity::new();
        a.record_block(500, 0, 0, 6_800_000, Duration::ZERO, Duration::ZERO);
        a.record_block(501, 0, 0, 6_800_000, Duration::ZERO, Duration::ZERO);
        a.record_block(502, 0, 0, 6_800_000, Duration::ZERO, Duration::ZERO);
        let s = a.take();
        assert_eq!((s.first_block, s.last_block), (Some(500), 502));
    }

    /// An empty block is still a block: it must count, or a quiet chain would
    /// look like a stalled node.
    #[test]
    fn empty_blocks_still_count() {
        let a = ChainActivity::new();
        a.record_block(7, 0, 0, 6_800_000, Duration::ZERO, Duration::ZERO);
        let s = a.take();
        assert_eq!(s.blocks, 1);
        assert_eq!(s.avg_transactions(), 0.0);
        assert_eq!(s.fullness_percent(), 0.0);
        assert!(!s.is_empty(), "a block with no transactions is not 'no activity'");
    }

    /// The degradation signal. Gas measures work, so cost-per-gas should hold
    /// steady whatever the chain is doing; a rise means each unit of work is
    /// costing more than it used to.
    #[test]
    fn cpu_per_gas_is_the_ratio_that_normalises_block_size() {
        // A small block and a large one, both at the same cost per gas.
        let a = ChainActivity::new();
        a.record_block(1, 1, 100_000, 6_800_000,
            Duration::from_millis(5), Duration::from_millis(6));
        a.record_block(2, 50, 1_000_000, 6_800_000,
            Duration::from_millis(50), Duration::from_millis(60));
        let s = a.take();

        // Time per BLOCK differs by 10x between those two blocks...
        assert!((s.avg_cpu_ms_per_block() - 27.5).abs() < 1e-6, "{}", s.avg_cpu_ms_per_block());
        // ...but time per GAS is identical, which is why it is the comparable
        // figure across windows: 55ms over 1.1M gas = 50ns/gas.
        assert!((s.cpu_nanos_per_gas() - 50.0).abs() < 1e-6, "{}", s.cpu_nanos_per_gas());
        assert!((s.wall_nanos_per_gas() - 60.0).abs() < 1e-6, "{}", s.wall_nanos_per_gas());
    }

    /// Wall time exceeds CPU time by however long execution waited on the
    /// database. The gap is the diagnostic: both rising is execution getting
    /// slower, wall rising alone is the node waiting rather than working.
    #[test]
    fn wall_time_exceeds_cpu_time_by_the_io_wait() {
        let a = ChainActivity::new();
        a.record_block(1, 10, 500_000, 6_800_000,
            Duration::from_millis(20), Duration::from_millis(80));
        let s = a.take();
        assert!((s.avg_cpu_ms_per_block() - 20.0).abs() < 1e-6);
        assert!((s.avg_wall_ms_per_block() - 80.0).abs() < 1e-6);
        assert!(
            s.wall_nanos_per_gas() > s.cpu_nanos_per_gas(),
            "60ms of this block was spent waiting, not executing"
        );
    }

    /// A window with blocks but no gas -- all empty blocks -- must report zero
    /// rather than dividing by zero.
    #[test]
    fn cost_per_gas_is_zero_when_no_gas_was_used() {
        let a = ChainActivity::new();
        a.record_block(1, 0, 0, 6_800_000, Duration::from_millis(3), Duration::from_millis(4));
        let s = a.take();
        assert_eq!(s.cpu_nanos_per_gas(), 0.0);
        assert_eq!(s.wall_nanos_per_gas(), 0.0);
        assert!(s.avg_cpu_ms_per_block() > 0.0, "the block still cost time");
    }

    /// `thread_cpu_time` must advance under load, or every ratio it feeds is
    /// silently zero and the degradation signal never fires.
    ///
    /// `black_box` is load-bearing: in release mode the optimiser folds an
    /// ordinary accumulation loop away entirely, and the first version of this
    /// test measured 521ns -- the cost of the two `clock_gettime` calls and
    /// nothing else.
    #[test]
    fn thread_cpu_time_advances_while_working() {
        let start = thread_cpu_time();
        let mut acc = 0u64;
        for i in 0..50_000_000u64 {
            acc = std::hint::black_box(acc.wrapping_add(std::hint::black_box(i)));
        }
        std::hint::black_box(acc);
        let elapsed = thread_cpu_time().saturating_sub(start);
        assert!(
            elapsed > Duration::from_micros(100),
            "thread CPU clock did not advance: {elapsed:?}"
        );
    }

    /// Guards against a divide-by-zero if a chain ever reported a zero gas
    /// limit; the ratio is undefined, not infinite.
    #[test]
    fn a_zero_gas_limit_does_not_divide_by_zero() {
        let a = ChainActivity::new();
        a.record_block(1, 1, 0, 0, Duration::ZERO, Duration::ZERO);
        assert_eq!(a.take().fullness_percent(), 0.0);
    }
}
