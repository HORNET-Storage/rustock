//! The `block connect breakdown best:` line: where the time of connecting a
//! block as best went, in the shape of rskj's debug line of the same name.
//!
//! Two paths write it: the import of an rskj `ExportBlocks` file
//! (`rustock_sync::import`) and the block the node's own miner completes
//! and connects (`mining::server`). Each phase is named after the phase of
//! rskj's `BlockChainImpl.internalTryToConnect` that does the same work,
//! so the lines of the two clients, and of the two paths, read side by
//! side. The clock is only read when measuring is on.

use alloy_primitives::B256;
use std::time::{Duration, Instant};

/// Wall time of each phase of connecting one block, from a monotonic clock.
/// The phases run in this order and `total` covers the whole connect.
#[derive(Debug, Default, Clone)]
pub struct ConnectTimings {
    pub total: Duration,
    /// Finding what the block builds on: that it extends the best block
    /// (import), or the template it completes and the executed-head check
    /// (mining). rskj `preambleMs`.
    pub preamble: Duration,
    /// Header against its parent, body rules, transactions root and ommers
    /// hash; on the mined path the merged-mining rule in place of the
    /// parent check (rskj `initialValidationMs`).
    pub initial_validation: Duration,
    /// `execute_block` (rskj `executeMs`). Includes `trie_save`.
    pub execute: Duration,
    /// The part of `execute` spent writing dirty trie nodes into the trie
    /// store (`TrieNode::save`, one batch). Lookups during execution stay in
    /// `execute`. Zero when the block was not timed. rskj has no such phase:
    /// it writes trie nodes at flush time, inside `onBestBlockMs`.
    pub trie_save: Duration,
    /// Results checked against the header (rskj `postExecuteValidationMs`).
    pub post_execute_validation: Duration,
    /// Header, total difficulty, canonical index and body stored (rskj
    /// `switchChainMs`, which saves the block and makes it best).
    pub switch_chain: Duration,
    /// Receipts and transaction and Bridge-event indexes stored (rskj
    /// `saveReceiptsMs`).
    pub save_receipts: Duration,
    /// Every `flush_every` blocks the trie flushed and the executed head
    /// recorded, zero on other blocks; on the mined path also the pool told
    /// what was mined (rskj `onBestBlockMs`, whose listeners run the flush
    /// every `flushNumberOfBlocks` and `processBest` the pool).
    pub on_best_block: Duration,
}

impl ConnectTimings {
    /// One line in the shape of rskj's `block connect breakdown best:` debug
    /// line, milliseconds with three decimals.
    pub fn breakdown_line(
        &self,
        number: u64,
        hash: B256,
        tx_count: usize,
        gas_used: u64,
    ) -> String {
        let ms = |d: Duration| format!("{:.3}", d.as_secs_f64() * 1000.0);
        format!(
            "block connect breakdown best: block={} hash={} totalMs={} preambleMs={} \
             initialValidationMs={} executeMs={} trieSaveMs={} postExecuteValidationMs={} \
             switchChainMs={} saveReceiptsMs={} onBestBlockMs={} txCount={} gasUsed={}",
            number,
            alloy_primitives::hex::encode(hash),
            ms(self.total),
            ms(self.preamble),
            ms(self.initial_validation),
            ms(self.execute),
            ms(self.trie_save),
            ms(self.post_execute_validation),
            ms(self.switch_chain),
            ms(self.save_receipts),
            ms(self.on_best_block),
            tx_count,
            gas_used,
        )
    }
}

/// Times consecutive phases; reads no clock when disabled.
pub struct Laps {
    start: Option<Instant>,
    last: Option<Instant>,
}

impl Laps {
    pub fn new(enabled: bool) -> Self {
        let now = enabled.then(Instant::now);
        Self {
            start: now,
            last: now,
        }
    }

    pub fn enabled(&self) -> bool {
        self.start.is_some()
    }

    /// Time since the previous lap, zero when disabled.
    pub fn lap(&mut self) -> Duration {
        match self.last {
            Some(last) => {
                let now = Instant::now();
                self.last = Some(now);
                now - last
            }
            None => Duration::ZERO,
        }
    }

    /// Time since the start, zero when disabled.
    pub fn total(&self) -> Duration {
        self.start.map(|s| s.elapsed()).unwrap_or_default()
    }
}

/// Where a path writes its lines. A closure so the execution crate does not
/// choose the file, the buffering or the flush policy.
pub type BreakdownSink = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_breakdown_line_reads_like_rskjs() {
        let t = ConnectTimings {
            total: Duration::from_micros(12_345),
            execute: Duration::from_micros(10_000),
            trie_save: Duration::from_micros(1_500),
            ..Default::default()
        };
        let line = t.breakdown_line(7, B256::repeat_byte(0xab), 21, 24_000_000);
        assert!(line.starts_with(&format!(
            "block connect breakdown best: block=7 hash={} totalMs=12.345 preambleMs=0.000 ",
            "ab".repeat(32)
        )));
        assert!(line.contains(" executeMs=10.000 trieSaveMs=1.500 postExecuteValidationMs=0.000 "));
        // Untimed: the key is there, at zero.
        let zero = ConnectTimings::default().breakdown_line(1, B256::ZERO, 0, 0);
        assert!(zero.contains(" executeMs=0.000 trieSaveMs=0.000 "));
        assert!(line.ends_with(" onBestBlockMs=0.000 txCount=21 gasUsed=24000000"));
    }

    #[test]
    fn disabled_laps_read_no_clock_and_report_zero() {
        let mut laps = Laps::new(false);
        assert!(!laps.enabled());
        assert_eq!(laps.lap(), Duration::ZERO);
        assert_eq!(laps.total(), Duration::ZERO);
        let mut laps = Laps::new(true);
        assert!(laps.enabled());
        std::thread::sleep(Duration::from_millis(2));
        assert!(laps.lap() >= Duration::from_millis(2));
        assert!(laps.total() >= Duration::from_millis(2));
    }
}
