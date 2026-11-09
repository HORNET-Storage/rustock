//! rskj's `GasPriceTracker`: what a transaction should pay to be mined.
//!
//! # Why the node needs it
//!
//! Two things were degraded without it, and one was simply wrong.
//!
//! **`eth_gasPrice` answered with the head block's `minimumGasPrice`.** That
//! is the floor a transaction must clear to be *valid*, not the price it
//! should pay to be *mined*. A wallet trusting it during congestion underpays
//! and its transaction sits.
//!
//! **The rate limiter's low-gas-price factor was disabled.** Five of
//! `VirtualGasCalculator`'s six factors were computed; the sixth needs a
//! market average and so took rskj's `createSkippingGasPriceFactor` branch,
//! pinning it to 1 instead of the 1..4 it ranges over. A transaction priced at
//! the block minimum therefore cost four times less virtual gas than on an
//! rskj node with a working fee market -- and pricing at the floor is exactly
//! the optimal play for someone flooding by broadcast-then-replace, who does
//! not want their transactions mined at all. It is the factor most directly
//! aimed at the abuse the limiter exists for.
//!
//! # The algorithm, and its quirks
//!
//! Two windows, both rskj's sizes:
//!
//! * **512 transactions** for the price percentile, REMASC excluded (it
//!   carries no gas price and would drag the answer to zero).
//! * **50 blocks** for fullness, used only to decide whether the fee market is
//!   "working" -- average fullness at or above 90%.
//!
//! Three details are rskj's and are not what you would write from scratch:
//!
//! * **The answer is the 25th percentile**, not the median:
//!   `values[values.length / 4]` of the sorted window. A suggestion at the
//!   lower quartile, floored by the block minimum times 1.1.
//! * **It is recalculated only every 512 transactions.** rskj caches the
//!   sorted result in `lastVal` and clears it only when the ring wraps
//!   (`// recalculate only 'sometimes'`), so the answer is stale by up to a
//!   full window. Recomputing on every call would be more accurate and would
//!   not match.
//! * **The transaction ring fills backwards**, from index 511 down to 0, and
//!   "is it primed?" is `txWindow[0] == null`. So the calculator returns
//!   nothing at all until it has seen 512 transactions, however many blocks
//!   that took.
//!
//! On a chain with spare capacity rskj itself runs with the low-gas-price
//! factor skipped much of the time, because `isFeeMarketWorking()` is false
//! whenever the 50-block window is not full or average fullness is under 90%.
//! That is a real rskj path, not a degraded one. The difference is that rskj
//! *recovers* the factor when blocks fill up.

use alloy_primitives::U256;
use rustock_core::{Header, Transaction};
use std::sync::{Mutex, PoisonError};

/// Transactions sampled for the price percentile. rskj `TX_WINDOW_SIZE`.
const TX_WINDOW_SIZE: usize = 512;
/// Blocks sampled for fullness. rskj `BLOCK_WINDOW_SIZE`.
const BLOCK_WINDOW_SIZE: usize = 50;

/// How far back priming will walk before giving up on filling the transaction
/// window.
///
/// Without it the walk is bounded only by finding 512 non-REMASC transactions,
/// and a chain with no bodies never does. A node that has synced headers but
/// not bodies -- which is every node part-way through a snapshot sync -- walks
/// to genesis on startup, accumulating every header it passes in memory.
///
/// On mainnet 2026-10-05 that was 9.28M headers and about 3.6 GB, which
/// exhausted RAM and swap on an 8 GB host before the node finished starting.
/// The node logged nothing between opening the trie store and dying, because
/// this runs in between.
///
/// 10,000 blocks is two hundred times `BLOCK_WINDOW_SIZE` and about three days
/// of chain. If the transaction window is not full by then, the estimate is as
/// good as it is going to get and a wider scan would not improve it.
const MAX_PRIME_SCAN: usize = 10_000;
/// Average fullness at which the fee market counts as working. rskj
/// `BLOCK_COMPLETION_PERCENT_FOR_FEE_MARKET_WORKING`.
const FEE_MARKET_FULLNESS: f64 = 0.9;
/// rskj `DEFAULT_GAS_PRICE_MULTIPLIER`, applied to the best block's minimum as
/// a floor. Exact decimal 1.1, so `x * 11 / 10` with truncation matches
/// `BigDecimal.multiply(...).toBigInteger()`.
const MULTIPLIER_NUM: u64 = 11;
const MULTIPLIER_DEN: u64 = 10;
/// rskj's starting `defaultPrice`, until a block replaces it.
const INITIAL_DEFAULT_PRICE: u64 = 20_000_000_000;

struct Inner {
    /// Filled from the back, index 511 down to 0, as rskj does.
    tx_window: [Option<U256>; TX_WINDOW_SIZE],
    tx_idx: i32,
    /// The cached percentile. Cleared only when the ring wraps.
    last_val: Option<U256>,

    block_window: [Option<f64>; BLOCK_WINDOW_SIZE],
    block_idx: usize,

    default_price: U256,
    best_block_price: Option<U256>,
}

/// Tracks recent gas prices and block fullness, as rskj's listener does.
pub struct GasPriceTracker {
    inner: Mutex<Inner>,
}

impl Default for GasPriceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl GasPriceTracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                tx_window: [None; TX_WINDOW_SIZE],
                tx_idx: TX_WINDOW_SIZE as i32 - 1,
                last_val: None,
                block_window: [None; BLOCK_WINDOW_SIZE],
                block_idx: 0,
                default_price: U256::from(INITIAL_DEFAULT_PRICE),
                best_block_price: None,
            }),
        }
    }

    /// rskj `onBlock`: the block's minimum becomes the fallback price, its
    /// fullness enters the block window, and its transactions enter the price
    /// window.
    pub fn on_block(&self, header: &Header, transactions: &[Transaction]) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.default_price = header.minimum_gas_price;

        // rskj `trackBlockCompleteness`: gasUsed / gasLimit.
        let limit = header.gas_limit.saturating_to::<u128>() as f64;
        let completeness = if limit > 0.0 { header.gas_used as f64 / limit } else { 0.0 };
        if inner.block_idx == BLOCK_WINDOW_SIZE {
            inner.block_idx = 0;
        }
        let at = inner.block_idx;
        inner.block_window[at] = Some(completeness);
        inner.block_idx += 1;

        for (index, tx) in transactions.iter().enumerate() {
            if tx.is_remasc(index, transactions.len()) {
                continue;
            }
            if inner.tx_idx == -1 {
                inner.tx_idx = TX_WINDOW_SIZE as i32 - 1;
                // rskj: "recalculate only 'sometimes'".
                inner.last_val = None;
            }
            let at = inner.tx_idx as usize;
            inner.tx_window[at] = Some(tx.gas_price);
            inner.tx_idx -= 1;
        }
    }

    /// rskj `onBestBlock`: only the head's minimum gas price is kept, and only
    /// as the floor applied in `gas_price`.
    pub fn on_best_block(&self, header: &Header) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .best_block_price = Some(header.minimum_gas_price);
    }

    /// rskj `getGasPrice`: the windowed percentile, floored at the best
    /// block's minimum times 1.1; the last seen block minimum until the window
    /// has 512 transactions in it.
    pub fn gas_price(&self) -> U256 {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

        let Some(percentile) = inner.percentile() else {
            return inner.default_price;
        };
        match inner.best_block_price {
            None => percentile,
            Some(best) => {
                let floor = best * U256::from(MULTIPLIER_NUM) / U256::from(MULTIPLIER_DEN);
                percentile.max(floor)
            }
        }
    }

    /// rskj `isFeeMarketWorking`: the 50-block window must be full **and**
    /// average fullness at least 90%.
    ///
    /// The fullness test is what gates the rate limiter's low-gas-price
    /// factor. False is a normal answer on a chain with spare capacity.
    pub fn is_fee_market_working(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        // rskj checks the LAST slot, which is only written once 50 blocks have
        // gone by -- a full ring, not merely a non-empty one.
        if inner.block_window[BLOCK_WINDOW_SIZE - 1].is_none() {
            return false;
        }
        let total: f64 = inner.block_window.iter().map(|c| c.unwrap_or(0.0)).sum();
        total / BLOCK_WINDOW_SIZE as f64 >= FEE_MARKET_FULLNESS
    }

    /// rskj `initializeWindowsFromDB`: fill both windows from stored blocks so
    /// a restarted node is not blind until it has seen 512 fresh transactions.
    ///
    /// Walks back from the head until **both** windows would be satisfied --
    /// 512 non-REMASC transactions and 50 blocks -- then replays them oldest
    /// first, which is the order they were originally connected in.
    ///
    /// **One rskj quirk is reproduced here.** rskj passes `blocks.get(0)` to
    /// `onBestBlock`, and by that point the list has been reversed, so the
    /// "best block" it records is the **oldest** block of the window rather
    /// than the head. The floor that `gas_price` applies is therefore taken
    /// from a block up to 50 heights stale until the next real block arrives
    /// -- about half a minute on mainnet. It is reproduced rather than
    /// corrected because `eth_gasPrice` is observably different in that window
    /// and matching rskj is the point.
    pub fn initialize_from_store(&self, store: &rustock_storage::BlockStore) {
        let Ok(Some(head_hash)) = store.head() else { return };
        let mut blocks: Vec<(Header, Vec<Transaction>)> = Vec::new();
        let mut tx_count = 0usize;
        let mut cursor = Some(head_hash);

        while (tx_count < TX_WINDOW_SIZE || blocks.len() < BLOCK_WINDOW_SIZE)
            && cursor.is_some()
            && blocks.len() < MAX_PRIME_SCAN
        {
            let hash = cursor.take().unwrap();
            let Ok(Some(header)) = store.header(hash) else { break };
            let transactions = store
                .body(hash)
                .ok()
                .flatten()
                .map(|(txs, _)| txs)
                .unwrap_or_default();
            let count = transactions.len();
            tx_count += transactions
                .iter()
                .enumerate()
                .filter(|(index, t)| !t.is_remasc(*index, count))
                .count();
            let parent = header.parent_hash;
            let at_genesis = header.number == 0;
            blocks.push((header, transactions));
            if at_genesis {
                break;
            }
            cursor = Some(parent);
        }

        if blocks.is_empty() {
            return;
        }
        blocks.reverse();

        // rskj's quirk, kept deliberately: the oldest block of the window, not
        // the head.
        self.on_best_block(&blocks[0].0);
        for (header, transactions) in &blocks {
            self.on_block(header, transactions);
        }

        if blocks.len() >= MAX_PRIME_SCAN && tx_count < TX_WINDOW_SIZE {
            tracing::warn!(
                target: "rustock::sync",
                "Gas price tracker gave up priming after {} block(s) with only {} \
                 transaction(s); this chain has headers but no bodies over that \
                 range, so the estimate is thin until blocks arrive",
                blocks.len(), tx_count
            );
        }
        tracing::info!(
            target: "rustock::sync",
            "Gas price tracker primed from {} block(s), {} transaction(s); fee market working: {}",
            blocks.len(), tx_count, self.is_fee_market_working()
        );
    }

    /// How many of the 512 transaction slots are filled. For diagnostics and
    /// tests; rskj has no equivalent.
    pub fn sampled_transactions(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .tx_window
            .iter()
            .filter(|s| s.is_some())
            .count()
    }
}

impl Inner {
    /// rskj `PercentileGasPriceCalculator.getGasPrice`.
    fn percentile(&mut self) -> Option<U256> {
        // Not primed until the ring has been filled all the way to index 0.
        self.tx_window[0]?;
        if self.last_val.is_none() {
            let mut values: Vec<U256> = self.tx_window.iter().filter_map(|v| *v).collect();
            values.sort_unstable();
            // 25th percentile, not the median: rskj's `values[values.length / 4]`.
            self.last_val = values.get(values.len() / 4).copied();
        }
        self.last_val
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, B256};

    fn header(number: u64, gas_used: u64, gas_limit: u64, min_price: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(1),
            number,
            gas_limit: U256::from(gas_limit),
            gas_used,
            timestamp: 1_600_000_000 + number,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(min_price),
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

    fn tx(gas_price: u64) -> Transaction {
        Transaction {
            nonce: 0,
            gas_price: U256::from(gas_price),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x11; 20]),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 27,
            r: U256::from(1),
            s: U256::from(2),
            cached_rlp: None,
        }
    }

    /// The REMASC synthetic transaction: no signature, no gas.
    fn remasc_tx() -> Transaction {
        Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(
                rustock_execution::precompiles::REMASC_ADDR.as_slice(),
            ),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        }
    }

    /// Until 512 transactions have been seen the calculator has no answer, and
    /// rskj falls back to the last block's minimum gas price -- which is what
    /// `eth_gasPrice` used to return unconditionally.
    #[test]
    fn an_unprimed_window_falls_back_to_the_block_minimum() {
        let tracker = GasPriceTracker::new();
        assert_eq!(tracker.gas_price(), U256::from(INITIAL_DEFAULT_PRICE));

        tracker.on_block(&header(1, 0, 6_800_000, 59_240_000), &[tx(100)]);
        assert_eq!(
            tracker.gas_price(),
            U256::from(59_240_000),
            "one block is not 512 transactions"
        );
    }

    /// rskj takes `values[values.length / 4]` of the sorted window -- the
    /// lower quartile, not the median. With prices 1..=512 that is the 129th
    /// smallest, i.e. 129.
    #[test]
    fn the_answer_is_the_twenty_fifth_percentile() {
        let tracker = GasPriceTracker::new();
        let txs: Vec<Transaction> = (1..=TX_WINDOW_SIZE as u64).map(tx).collect();
        tracker.on_block(&header(1, 0, 6_800_000, 1), &txs);

        assert_eq!(tracker.sampled_transactions(), TX_WINDOW_SIZE);
        // best_block_price is unset, so no floor is applied.
        assert_eq!(tracker.gas_price(), U256::from(129));
    }

    /// The floor is the best block's minimum times 1.1, truncated.
    #[test]
    fn the_best_blocks_minimum_times_the_multiplier_is_a_floor() {
        let tracker = GasPriceTracker::new();
        let txs: Vec<Transaction> = (1..=TX_WINDOW_SIZE as u64).map(tx).collect();
        tracker.on_block(&header(1, 0, 6_800_000, 1), &txs);

        // Percentile is 129; a floor above it wins.
        tracker.on_best_block(&header(2, 0, 6_800_000, 1_000));
        assert_eq!(tracker.gas_price(), U256::from(1_100), "1000 * 1.1");

        // A floor below it does not.
        tracker.on_best_block(&header(3, 0, 6_800_000, 10));
        assert_eq!(tracker.gas_price(), U256::from(129));
    }

    /// REMASC carries no gas price; counting it would drag the percentile to
    /// zero, which is why rskj filters it out of both windows.
    #[test]
    fn remasc_is_not_a_price_sample() {
        let tracker = GasPriceTracker::new();
        let mut txs: Vec<Transaction> = (1..=TX_WINDOW_SIZE as u64).map(tx).collect();
        for _ in 0..50 {
            txs.push(remasc_tx());
        }
        tracker.on_block(&header(1, 0, 6_800_000, 1), &txs);

        assert_eq!(
            tracker.sampled_transactions(),
            TX_WINDOW_SIZE,
            "the REMASC transactions must not have entered the window"
        );
        assert_eq!(tracker.gas_price(), U256::from(129), "and must not move the percentile");
    }

    /// rskj caches the sorted result and clears it only when the ring wraps,
    /// so the answer is stale for up to a full window of transactions.
    /// Recomputing per call would be more accurate and would not match rskj.
    ///
    /// The wrap happens on the transaction *after* the ring fills, which is
    /// why the staleness has to be demonstrated between two wraps rather than
    /// straight after the first fill.
    #[test]
    fn the_percentile_is_recalculated_only_when_the_window_wraps() {
        let tracker = GasPriceTracker::new();

        // Fill the ring: prices 1..512, written from index 511 down to 0.
        let txs: Vec<Transaction> = (1..=TX_WINDOW_SIZE as u64).map(tx).collect();
        tracker.on_block(&header(1, 0, 6_800_000, 1), &txs);
        assert_eq!(tracker.gas_price(), U256::from(129), "lower quartile of 1..512");

        // One more transaction wraps the ring, which clears the cache. It
        // lands on index 511, replacing the cheapest sample (price 1), so the
        // recomputed quartile moves by one.
        tracker.on_block(&header(2, 0, 6_800_000, 1), &[tx(9_000)]);
        assert_eq!(tracker.gas_price(), U256::from(130), "recomputed after the wrap");

        // Ten more, no wrap. They replace prices 2..11 with 9000 each, so a
        // fresh calculation would give 140 -- but rskj does not recalculate
        // until the next wrap, and neither does this.
        let more: Vec<Transaction> = (0..10).map(|_| tx(9_000)).collect();
        tracker.on_block(&header(3, 0, 6_800_000, 1), &more);
        assert_eq!(
            tracker.gas_price(),
            U256::from(130),
            "stale between wraps: rskj recalculates 'only sometimes', and the \
             suggestion lags the market by up to a full window"
        );
    }

    /// `isFeeMarketWorking` needs the block window **full**, not merely
    /// non-empty: it tests the last slot, which is written only after 50
    /// blocks.
    #[test]
    fn the_fee_market_needs_a_full_window_and_ninety_percent_fullness() {
        let tracker = GasPriceTracker::new();
        for n in 1..=49u64 {
            tracker.on_block(&header(n, 6_800_000, 6_800_000, 1), &[]);
        }
        assert!(!tracker.is_fee_market_working(), "49 full blocks is not a full window");

        tracker.on_block(&header(50, 6_800_000, 6_800_000, 1), &[]);
        assert!(tracker.is_fee_market_working(), "50 blocks at 100% full");
    }

    #[test]
    fn a_half_empty_chain_is_not_a_working_fee_market() {
        let tracker = GasPriceTracker::new();
        for n in 1..=50u64 {
            tracker.on_block(&header(n, 3_400_000, 6_800_000, 1), &[]);
        }
        assert!(
            !tracker.is_fee_market_working(),
            "50% average fullness is below the 90% threshold"
        );
    }
}
