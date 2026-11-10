//! Per-account transaction rate limiting — a port of rskj's `TxQuotaChecker`.
//!
//! # The abuse this prevents
//!
//! The mempool is a shared, global resource that nobody pays for until a
//! transaction is mined. An account can broadcast a transaction with a large
//! gas limit, have every node on the network store and relay it, and then
//! replace it with a higher-priced one before it is ever included — paying
//! nothing, and doing it again immediately. Repeated, that is free use of
//! every node's memory and bandwidth.
//!
//! rskj answers this with a **virtual gas quota** per account. Virtual gas is
//! not real gas and is never charged: it is a per-node accounting fiction that
//! accumulates while an account is quiet and is spent when it broadcasts. An
//! account that behaves ordinarily never notices. An account that floods runs
//! out and its transactions are refused entry to *this* node's pool, so they
//! are not relayed onward.
//!
//! # The shape of it
//!
//! ```text
//!   quota accumulates with time (while the account is idle)
//!        │
//!        │        ┌─ maxQuota  = maxGasPerSecond × 2000   (ceiling)
//!        │   ─────┴──────────────────────
//!        │  ╱
//!        │ ╱   ← maxGasPerSecond = blockGasLimit × 0.9 per second
//!        │╱
//!        └──────────────────────────────────► time
//!
//!   a transaction costs:  txGasLimit × (product of six penalty factors)
//!
//!   ┌──────────────────┬──────────────────────────────────────────────────┐
//!   │ futureNonce      │ ×2 if the nonce is ahead of the account's        │
//!   │ nonce            │ 1 + 4/(accountNonce+1) — new accounts cost more  │
//!   │ size             │ 1 + size/25000 — big payloads cost more          │
//!   │ lowGasPrice      │ up to ×4 when priced below the market average    │
//!   │ replacement      │ 1 + 1/ratio — cheap replacements cost more       │
//!   │ gasLimit         │ 1 + 4×txGasLimit/blockGasLimit                   │
//!   └──────────────────┴──────────────────────────────────────────────────┘
//! ```
//!
//! Every constant, formula and ordering below is taken from rskj
//! `co.rsk.net.handler.quota.{TxQuotaChecker, TxQuota, TxVirtualGasCalculator}`.
//! Where rustock cannot yet supply an input (see `avg_gas_price`), it takes the
//! same branch rskj takes in that situation rather than inventing one.
//!
//! rskj reads each value it weighs (gas limits, gas prices, nonces) as a Java
//! `long`, the low 64 bits of the whole value (`BigInteger.longValue()`), and
//! computes in `long` and `double`: from 2^63 a value reads negative, from
//! 2^64 it wraps around, and a `long` sum or product can overflow. So does
//! this ([`java_long`]), or the two part once a value passes 2^63, which a
//! minimum gas price raised 1% a block, as fast as `PrevMinGasPriceRule`
//! allows, does in about a day.

use alloy_primitives::{Address, U256};
use rustock_core::Header;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tunables for the rate limiter. Defaults are rskj's values; every one is
/// exposed so a deployment can loosen or tighten the limiter without a rebuild.
#[derive(Debug, Clone)]
pub struct QuotaConfig {
    /// rskj `transaction.accountTxRateLimit.enabled`. When false the limiter
    /// accepts everything and keeps no state at all.
    pub enabled: bool,

    /// rskj `transaction.accountTxRateLimit.cleanerPeriod`, in minutes. Zero or
    /// negative disables the periodic clean. Entries that have accumulated the
    /// full `max_quota` carry no information and are dropped.
    pub cleaner_period_minutes: i64,

    /// rskj `TxQuotaChecker.MAX_QUOTAS_SIZE`. The map is bounded and evicts the
    /// least recently *accessed* entry, so a flood of distinct addresses cannot
    /// grow it without limit.
    pub max_quotas_size: usize,

    /// rskj `TxQuotaChecker.MAX_QUOTA_GAS_MULTIPLIER`. The ceiling on
    /// accumulated virtual gas, as a multiple of `max_gas_per_second` — i.e.
    /// how many seconds of idleness an account may bank.
    pub max_quota_gas_multiplier: u64,

    /// rskj `TxQuotaChecker.MAX_GAS_PER_SECOND_PERCENT`. Virtual gas accrues at
    /// this fraction of the block gas limit per second.
    pub max_gas_per_second_percent: f64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cleaner_period_minutes: 30,
            max_quotas_size: 400_000,
            max_quota_gas_multiplier: 2_000,
            max_gas_per_second_percent: 0.9,
        }
    }
}

impl QuotaConfig {
    /// rskj `getMaxGasPerSecond` (`TxQuotaChecker` L203-205):
    /// `Math.round(blockGasLimit * 0.9)`, of the gas limit as a `long`.
    pub fn max_gas_per_second(&self, block_gas_limit: i64) -> i64 {
        java_round(block_gas_limit as f64 * self.max_gas_per_second_percent)
    }

    /// rskj `getMaxQuota` (L207-209): `maxGasPerSecond *
    /// MAX_QUOTA_GAS_MULTIPLIER`, a `long` product, which wraps.
    pub fn max_quota(&self, max_gas_per_second: i64) -> i64 {
        max_gas_per_second.wrapping_mul(self.max_quota_gas_multiplier as i64)
    }
}

// ---------------------------------------------------------------------------
// Java's arithmetic
// ---------------------------------------------------------------------------

/// `BigInteger.longValue()`, how rskj's checker reads each value it weighs:
/// the low 64 bits of the whole value, as a two's-complement `long`.
pub fn java_long(value: U256) -> i64 {
    value.as_limbs()[0] as i64
}

/// `new BigInteger(1, bytes).longValue()`: the same, of a value held as its
/// big-endian bytes, of any length.
fn java_long_of_bytes(bytes: &[u8]) -> i64 {
    let low = &bytes[bytes.len().saturating_sub(8)..];
    let mut word = [0u8; 8];
    word[8 - low.len()..].copy_from_slice(low);
    i64::from_be_bytes(word)
}

/// Java's `Math.round(double)`, as the JDK computes it: the closest `long`,
/// ties toward positive infinity, so -4.5 is -4 where Rust's `round` gives
/// -5; NaN is 0, and the ends of `long`'s range stand for what lies past
/// them.
fn java_round(a: f64) -> i64 {
    const SIGNIFICAND_WIDTH: i64 = 53;
    const EXP_BIAS: i64 = 1023;
    const EXP_BIT_MASK: i64 = 0x7FF0_0000_0000_0000;
    const SIGNIF_BIT_MASK: i64 = 0x000F_FFFF_FFFF_FFFF;
    let long_bits = a.to_bits() as i64;
    let biased_exp = (long_bits & EXP_BIT_MASK) >> (SIGNIFICAND_WIDTH - 1);
    let shift = (SIGNIFICAND_WIDTH - 2 + EXP_BIAS) - biased_exp;
    if (shift & -64) == 0 {
        // A finite `a` with 2^-64 <= ulp(a) < 1: `r` is a / ulp(a),
        // `r >> shift` is floor(2a), and the rest floor(a + 1/2).
        let mut r = (long_bits & SIGNIF_BIT_MASK) | (SIGNIF_BIT_MASK + 1);
        if long_bits < 0 {
            r = -r;
        }
        ((r >> shift) + 1) >> 1
    } else {
        // Too small to round to anything but zero, already an integer, or
        // not finite: `(long) a`, which `as` is (NaN to 0, saturating).
        a as i64
    }
}

/// Java's `Math.min(double, double)`: NaN if either is (Rust's `min` gives
/// the other), and -0.0 below 0.0.
fn java_min(a: f64, b: f64) -> f64 {
    if a.is_nan() {
        return a;
    }
    if a == 0.0 && b == 0.0 && b.to_bits() == (-0.0f64).to_bits() {
        return b;
    }
    if a <= b {
        a
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// TxVirtualGasCalculator
// ---------------------------------------------------------------------------

/// rskj `TxVirtualGasCalculator`, constant for constant.
///
/// The six `*_FACTOR` values are the per-factor ceilings; they appear only in
/// `MAX_FACTOR`, which is the overflow fallback. The values that shape the
/// result are the three weights and the size divisor.
mod factors {
    pub const FUTURE_NONCE: f64 = 2.0;
    pub const NONCE: f64 = 5.0;
    pub const SIZE: f64 = 5.0;
    pub const LOW_GAS_PRICE: f64 = 4.0;
    pub const REPLACEMENT: f64 = 1.9;
    pub const GAS_LIMIT: f64 = 5.0;

    /// 2 × 5 × 5 × 4 × 1.9 × 5 = 1900.
    pub const MAX: f64 = FUTURE_NONCE * NONCE * SIZE * LOW_GAS_PRICE * REPLACEMENT * GAS_LIMIT;

    pub const GAS_LIMIT_WEIGHT: f64 = 4.0;
    pub const NONCE_WEIGHT: f64 = 4.0;
    pub const LOW_GAS_PRICE_WEIGH: f64 = 3.0;
    pub const SIZE_DIVISOR: f64 = 25_000.0;
}

/// The facts about a transaction the calculator needs, as the transaction
/// holds them: the calculator reads them as rskj does. Grouped so the call
/// sites cannot transpose two arguments, which is the failure mode a
/// six-parameter function invites.
#[derive(Debug, Clone, Copy)]
pub struct TxFacts {
    pub nonce: u64,
    pub gas_limit: U256,
    pub gas_price: U256,
    /// Encoded size in bytes — rskj `Transaction.getSize()`.
    pub size: usize,
}

/// rskj `TxVirtualGasCalculator`, over the `long`s rskj's checker hands it
/// (`TxQuotaChecker.calculateConsumedVirtualGas`, L211-225).
#[derive(Debug, Clone, Copy)]
pub struct VirtualGasCalculator {
    account_nonce: i64,
    block_gas_limit: i64,
    block_min_gas_price: i64,
    /// `None` reproduces rskj `createSkippingGasPriceFactor`, which it uses
    /// whenever `GasPriceTracker.isFeeMarketWorking()` is false.
    avg_gas_price: Option<i64>,
}

impl VirtualGasCalculator {
    /// rskj `createWithAllFactors`.
    pub fn with_all_factors(
        account_nonce: i64,
        block_gas_limit: i64,
        block_min_gas_price: i64,
        avg_gas_price: i64,
    ) -> Self {
        Self { account_nonce, block_gas_limit, block_min_gas_price, avg_gas_price: Some(avg_gas_price) }
    }

    /// rskj `createSkippingGasPriceFactor`.
    pub fn skipping_gas_price_factor(
        account_nonce: i64,
        block_gas_limit: i64,
        block_min_gas_price: i64,
    ) -> Self {
        Self { account_nonce, block_gas_limit, block_min_gas_price, avg_gas_price: None }
    }

    /// rskj `calculate(newTx, replacedTx)` (L81-104).
    pub fn calculate(&self, new_tx: &TxFacts, replaced_tx: Option<&TxFacts>) -> f64 {
        let tx_gas_limit = java_long(new_tx.gas_limit);

        // `newTxNonce == accountNonce ? 1 : 2` — a nonce ahead of the account's
        // is a transaction that cannot execute yet, so it occupies the pool for
        // longer and costs double.
        let new_tx_nonce = new_tx.nonce as i64;
        let future_nonce_factor = if new_tx_nonce == self.account_nonce {
            1.0
        } else {
            2.0
        };

        let low_gas_price_factor = match self.avg_gas_price {
            None => 1.0,
            Some(avg) => self.low_gas_price_factor(new_tx.gas_price, avg),
        };

        // Fresh accounts are cheap to create and so are the natural vehicle for
        // a flood; they pay up to 5x until their nonce climbs. `accountNonce +
        // 1` is a `long` sum, which wraps.
        let nonce_factor = 1.0 + factors::NONCE_WEIGHT / self.account_nonce.wrapping_add(1) as f64;

        let size_factor = 1.0 + new_tx.size as f64 / factors::SIZE_DIVISOR;

        let replacement_factor = Self::replacement_factor(new_tx.gas_price, replaced_tx);

        let gas_limit_factor =
            1.0 + factors::GAS_LIMIT_WEIGHT * tx_gas_limit as f64 / self.block_gas_limit as f64;

        let composite = future_nonce_factor
            * low_gas_price_factor
            * nonce_factor
            * size_factor
            * replacement_factor
            * gas_limit_factor;

        Self::cap_result(tx_gas_limit as f64, composite)
    }

    /// rskj `calculateLowGasPriceFactor` (L106-115). A transaction priced below
    /// the market average is one the sender is in no hurry to have mined, so
    /// it may sit in the pool a long time.
    fn low_gas_price_factor(&self, tx_gas_price: U256, avg_gas_price: i64) -> f64 {
        let tx_gas_price = java_long(tx_gas_price);
        if tx_gas_price >= avg_gas_price {
            return 1.0;
        }
        // `(avg - txPrice) / (avg - (double) blockMin)`: the numerator is a
        // `long` difference, which wraps, and the denominator a `double` one.
        let factor = avg_gas_price.wrapping_sub(tx_gas_price) as f64
            / (avg_gas_price as f64 - self.block_min_gas_price as f64);
        1.0 + factors::LOW_GAS_PRICE_WEIGH * factor
    }

    /// rskj `calculateReplacementFactor`.
    ///
    /// `ratio = newGasPrice / replacedGasPrice`, and the factor is
    /// `1 + 1/ratio` when there was a replacement. A replacement that barely
    /// clears the bump threshold has a ratio near 1 and so costs nearly double;
    /// a large overbid costs less, because it is likelier to be mined and stop
    /// consuming the pool.
    fn replacement_factor(new_gas_price: U256, replaced_tx: Option<&TxFacts>) -> f64 {
        let ratio = match replaced_tx {
            None => 0.0,
            Some(replaced) => {
                let new_gp = u256_to_f64(new_gas_price);
                let old_gp = u256_to_f64(replaced.gas_price);
                new_gp / old_gp // rskj divides as doubles; old_gp == 0 gives inf
            }
        };
        if ratio > 0.0 {
            1.0 + 1.0 / ratio
        } else {
            1.0
        }
    }

    /// rskj `capeResult` (sic). Guards the multiplication overflowing to
    /// infinity, which would otherwise make the quota check meaningless.
    fn cap_result(gas_limit: f64, factor: f64) -> f64 {
        let result = gas_limit * factor;
        if result == f64::INFINITY {
            return gas_limit * factors::MAX;
        }
        result
    }
}

/// rskj reads gas prices as Java `double` via `BigInteger.doubleValue()`,
/// which rounds the whole value to the nearest `double`, ties to even.
fn u256_to_f64(v: U256) -> f64 {
    let bits = v.bit_len();
    if bits <= 64 {
        return v.as_limbs()[0] as f64;
    }
    // The top 64 bits round as the whole value does once any bit below them
    // is folded into their lowest: a `double` keeps 53, so the rounding falls
    // at bit 11 of the 64, and below that only whether anything is set counts.
    let shift = bits - 64;
    let top = v >> shift;
    let mut word = top.as_limbs()[0];
    if top << shift != v {
        word |= 1;
    }
    word as f64 * 2f64.powi(shift as i32)
}

// ---------------------------------------------------------------------------
// TxQuota
// ---------------------------------------------------------------------------

/// rskj `TxQuota` — the accumulated virtual gas of one address.
#[derive(Debug, Clone)]
pub struct TxQuota {
    last_refresh: Instant,
    available_virtual_gas: f64,
}

impl TxQuota {
    /// rskj `TxQuota.createNew`, of a `long` it holds as a `double` (L44-47).
    pub fn create_new(initial_quota: i64, now: Instant) -> Self {
        Self { last_refresh: now, available_virtual_gas: initial_quota as f64 }
    }

    pub fn available_virtual_gas(&self) -> f64 {
        self.available_virtual_gas
    }

    /// rskj `acceptVirtualGasConsumption`: spend if there is enough, otherwise
    /// refuse and spend nothing.
    pub fn accept_virtual_gas_consumption(&mut self, to_consume: f64) -> bool {
        if self.available_virtual_gas < to_consume {
            return false;
        }
        self.available_virtual_gas -= to_consume;
        true
    }

    /// rskj `forceVirtualGasSubtraction`: spend if there is enough, otherwise
    /// drain to zero and report that there was not.
    ///
    /// Used for an account's very first transaction — see
    /// `QuotaChecker::accept_tx` for why that case is special.
    pub fn force_virtual_gas_subtraction(&mut self, to_consume: f64) -> bool {
        if self.accept_virtual_gas_consumption(to_consume) {
            return true;
        }
        self.available_virtual_gas = 0.0;
        false
    }

    /// rskj `refresh` (L126-138): accrue `max_gas_per_second` for every second
    /// since the last refresh, capped at `max_quota`.
    pub fn refresh(&mut self, max_gas_per_second: i64, max_quota: i64, now: Instant) -> f64 {
        let elapsed_seconds = now.saturating_duration_since(self.last_refresh).as_secs_f64();
        let add_to_quota = elapsed_seconds * max_gas_per_second as f64;
        self.last_refresh = now;
        // `Math.min(maxQuota, availableVirtualGas + addToQuota)`, which keeps a
        // NaN where Rust's `min` would drop it.
        self.available_virtual_gas =
            java_min(max_quota as f64, self.available_virtual_gas + add_to_quota);
        self.available_virtual_gas
    }
}

// ---------------------------------------------------------------------------
// The account view the checker needs
// ---------------------------------------------------------------------------

/// What the checker must be able to ask about an address. Kept as a trait so
/// the pool can answer from the trie and tests can answer from a table.
pub trait AccountView {
    /// The account's nonce in the current state.
    fn nonce(&self, address: &Address) -> u64;
    /// rskj `RepositorySnapshot.isContract`.
    fn is_contract(&self, address: &Address) -> bool;
    /// rskj `RepositorySnapshot.isExist`.
    fn exists(&self, address: &Address) -> bool;
}

/// Contextual facts about the moment a transaction is being processed —
/// rskj `TxQuotaChecker.CurrentContext` — as its checker reads them: each a
/// `long`, the low 64 bits of the whole value.
#[derive(Debug, Clone, Copy)]
pub struct QuotaContext {
    /// `bestBlock.getGasLimitAsInteger().longValue()`.
    pub block_gas_limit: i64,
    /// `bestBlock.getMinimumGasPrice().asBigInteger().longValue()`.
    pub block_min_gas_price: i64,
    /// `gasPriceTracker.getGasPrice().asBigInteger().longValue()`, `Some`
    /// only when a fee-market average is available; `None` takes rskj's
    /// `createSkippingGasPriceFactor` branch.
    pub avg_gas_price: Option<i64>,
}

impl QuotaContext {
    /// The context of a transaction arriving over the best block `best`,
    /// `avg_gas_price` the tracker's price when the fee market is working,
    /// read as rskj's checker reads them (`TxQuotaChecker` L77, L178-179,
    /// L212-218): the gas limit's bytes and the minimum gas price whole,
    /// whatever their size, and then their low 64 bits.
    pub fn of(best: &Header, avg_gas_price: Option<U256>) -> Self {
        Self {
            block_gas_limit: best.gas_limit_low_long(),
            block_min_gas_price: java_long_of_bytes(&best.minimum_gas_price_bytes()),
            avg_gas_price: avg_gas_price.map(java_long),
        }
    }
}

// ---------------------------------------------------------------------------
// TxQuotaChecker
// ---------------------------------------------------------------------------

/// rskj `TxQuotaChecker`.
///
/// Holds the available virtual gas for a bounded set of addresses and accepts
/// or rejects a transaction accordingly. The map evicts the least recently
/// accessed entry when full.
pub struct QuotaChecker {
    config: QuotaConfig,
    quotas: HashMap<Address, TxQuota>,
    /// Access order, oldest first — the eviction policy of rskj's
    /// `MaxSizeHashMap(maxSize, accessOrder = true)`.
    access_order: Vec<Address>,
    /// rskj's `lastBlockGasLimit`, a `long`: [`UNKNOWN_LAST_BLOCK_GAS_LIMIT`]
    /// until a transaction has been processed.
    last_block_gas_limit: i64,
}

/// rskj `TxQuotaChecker.UNKNOWN_LAST_BLOCK_GAS_LIMIT`. A gas limit whose low
/// 64 bits read -1 reads as unknown there too, and the clean waits for
/// another.
const UNKNOWN_LAST_BLOCK_GAS_LIMIT: i64 = -1;

impl QuotaChecker {
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            quotas: HashMap::new(),
            access_order: Vec::new(),
            last_block_gas_limit: UNKNOWN_LAST_BLOCK_GAS_LIMIT,
        }
    }

    pub fn config(&self) -> &QuotaConfig {
        &self.config
    }

    /// The virtual gas currently available to `address`, if it is tracked.
    /// Does not count as an access for eviction purposes.
    pub fn quota_of(&self, address: &Address) -> Option<f64> {
        self.quotas.get(address).map(|q| q.available_virtual_gas)
    }

    /// An address's quota as `debug_accountTransactionQuota` reports it:
    /// the available virtual gas and when it was last refreshed, in
    /// milliseconds since the epoch.
    ///
    /// rskj stores that timestamp directly (`TxQuota.timestamp`, set from its
    /// `TimeProvider`). Here `last_refresh` is an `Instant`, which is
    /// monotonic and deliberately has no epoch, so the wall-clock moment is
    /// reconstructed by subtracting its age from now. That is accurate to the
    /// clock's own drift over the quota's lifetime -- at most a few minutes
    /// here -- and avoids carrying a second timestamp that could disagree with
    /// the first.
    pub fn quota_report_of(&self, address: &Address, now: Instant) -> Option<(f64, u64)> {
        let quota = self.quotas.get(address)?;
        let epoch_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let age = now.saturating_duration_since(quota.last_refresh).as_millis() as u64;
        Some((quota.available_virtual_gas, epoch_now.saturating_sub(age)))
    }

    pub fn tracked_accounts(&self) -> usize {
        self.quotas.len()
    }

    /// rskj `TxQuotaChecker.acceptTx`.
    ///
    /// Returns true if the transaction may enter the pool.
    pub fn accept_tx(
        &mut self,
        sender: Address,
        receiver: Option<Address>,
        new_tx: &TxFacts,
        replaced_tx: Option<&TxFacts>,
        ctx: &QuotaContext,
        accounts: &dyn AccountView,
        now: Instant,
    ) -> bool {
        if !self.config.enabled {
            return true;
        }

        // Kept so `clean_max_quotas` has a gas limit to work from; it runs on a
        // timer and has no transaction context of its own.
        self.last_block_gas_limit = ctx.block_gas_limit;

        // Evaluated BEFORE the quota is created, or the map lookup below would
        // always find the entry we are about to insert.
        let is_first_tx_from_sender = self.is_first_tx_from_sender(sender, new_tx, accounts);

        self.update_quota(sender, true, ctx, accounts, now);
        self.update_receiver_quota_if_required(receiver, ctx, accounts, now);

        // `state.getNonce(sender).longValue()` (L212).
        let account_nonce = accounts.nonce(&sender) as i64;
        let calculator = match ctx.avg_gas_price {
            Some(avg) => VirtualGasCalculator::with_all_factors(
                account_nonce,
                ctx.block_gas_limit,
                ctx.block_min_gas_price,
                avg,
            ),
            None => VirtualGasCalculator::skipping_gas_price_factor(
                account_nonce,
                ctx.block_gas_limit,
                ctx.block_min_gas_price,
            ),
        };
        let consumed = calculator.calculate(new_tx, replaced_tx);

        let quota = self
            .quotas
            .get_mut(&sender)
            .expect("update_quota just inserted or refreshed the sender");

        // An account's very first transaction is always accepted, and pays what
        // it can.
        //
        // Without this, a brand-new account's first transaction cannot
        // propagate at all. Consider tx1 from new sender s1 reaching nodes n1
        // then n2:
        //
        //   t1: n1 sees s1 for the first time, grants it the minimum quota,
        //       which is not enough for tx1 → n1 rejects, does not relay
        //   t2: s1 retries; n1 has accumulated since t1 → n1 accepts, relays
        //   t3: n2 sees s1 for the first time → behaves exactly as n1 did at t1
        //
        // and so on for every node in turn. Accepting the first transaction
        // regardless breaks the cycle. It is not a free pass: all available gas
        // is drained, so the account starts from zero for its second.
        if is_first_tx_from_sender {
            quota.force_virtual_gas_subtraction(consumed);
            return true;
        }

        quota.accept_virtual_gas_consumption(consumed)
    }

    /// rskj `isFirstTxFromSender`. The map check matters: without it a resend
    /// or a gas-price bump of the first transaction would also be forced
    /// through, which is exactly the abuse being limited.
    fn is_first_tx_from_sender(
        &self,
        sender: Address,
        new_tx: &TxFacts,
        accounts: &dyn AccountView,
    ) -> bool {
        !self.quotas.contains_key(&sender) && accounts.nonce(&sender) == 0 && new_tx.nonce == 0
    }

    /// rskj `updateReceiverQuotaIfRequired`.
    ///
    /// The receiver is given a quota as soon as we learn it exists, so it starts
    /// accumulating before it ever sends anything. rskj accepts that this also
    /// admits counterfactual contracts — addresses that have received RBTC but
    /// have no code yet — because the map doubles as a cache that saves
    /// repository lookups, and the periodic clean removes them.
    fn update_receiver_quota_if_required(
        &mut self,
        receiver: Option<Address>,
        ctx: &QuotaContext,
        accounts: &dyn AccountView,
        now: Instant,
    ) {
        let Some(receiver) = receiver else { return };
        let is_eoa_or_cf =
            self.quotas.contains_key(&receiver) || !accounts.is_contract(&receiver);
        if is_eoa_or_cf || !accounts.exists(&receiver) {
            self.update_quota(receiver, false, ctx, accounts, now);
        }
    }

    /// rskj `updateQuota`: create with an initial grant, or refresh in place.
    fn update_quota(
        &mut self,
        address: Address,
        is_tx_source: bool,
        ctx: &QuotaContext,
        accounts: &dyn AccountView,
        now: Instant,
    ) {
        let max_gas_per_second = self.config.max_gas_per_second(ctx.block_gas_limit);
        let max_quota = self.config.max_quota(max_gas_per_second);

        if let Some(quota) = self.quotas.get_mut(&address) {
            quota.refresh(max_gas_per_second, max_quota, now);
            self.touch(address);
            return;
        }

        // `state.getNonce(address).longValue()` (L186).
        let account_nonce = accounts.nonce(&address) as i64;
        let initial =
            Self::new_item_quota(account_nonce, is_tx_source, max_gas_per_second, max_quota);
        self.quotas.insert(address, TxQuota::create_new(initial, now));
        self.touch(address);
        self.evict_if_full();
    }

    /// rskj `calculateNewItemQuota`.
    ///
    /// An established sender — one that has transacted before — is trusted with
    /// the full quota immediately. A brand-new account, or any receiver, starts
    /// with one second's worth.
    fn new_item_quota(
        account_nonce: i64,
        is_tx_source: bool,
        max_gas_per_second: i64,
        max_quota: i64,
    ) -> i64 {
        let is_new_account = account_nonce == 0;
        let grant_max_quota = is_tx_source && !is_new_account;
        if grant_max_quota {
            max_quota
        } else {
            max_gas_per_second
        }
    }

    /// Records an access for the LRU ordering.
    fn touch(&mut self, address: Address) {
        if let Some(pos) = self.access_order.iter().position(|a| *a == address) {
            self.access_order.remove(pos);
        }
        self.access_order.push(address);
    }

    fn evict_if_full(&mut self) {
        while self.quotas.len() > self.config.max_quotas_size {
            if self.access_order.is_empty() {
                break;
            }
            let oldest = self.access_order.remove(0);
            self.quotas.remove(&oldest);
        }
    }

    /// rskj `cleanMaxQuotas`.
    ///
    /// Refreshes every entry and drops those that have reached `max_quota`: an
    /// account at the ceiling is indistinguishable from one the node has never
    /// seen, so keeping it costs memory and says nothing. Intended to run on a
    /// timer roughly as often as an account takes to reach the ceiling.
    pub fn clean_max_quotas(&mut self, now: Instant) -> usize {
        if self.last_block_gas_limit == UNKNOWN_LAST_BLOCK_GAS_LIMIT {
            return 0; // no transaction processed yet
        }
        let max_gas_per_second = self.config.max_gas_per_second(self.last_block_gas_limit);
        let max_quota = self.config.max_quota(max_gas_per_second);

        let before = self.quotas.len();
        let mut to_remove = Vec::new();
        for (address, quota) in self.quotas.iter_mut() {
            let accumulated = quota.refresh(max_gas_per_second, max_quota, now);
            // rskj compares `BigDecimal.valueOf` of each (L163), which is
            // this for any ceiling a `double` holds exactly, below 2^53.
            if accumulated == max_quota as f64 {
                to_remove.push(*address);
            }
        }
        for address in &to_remove {
            self.quotas.remove(address);
            if let Some(pos) = self.access_order.iter().position(|a| a == address) {
                self.access_order.remove(pos);
            }
        }
        before - self.quotas.len()
    }

    /// The cleaner interval, or `None` when the clean is disabled (rskj treats
    /// zero and negative alike).
    pub fn cleaner_period(&self) -> Option<Duration> {
        if !self.config.enabled || self.config.cleaner_period_minutes <= 0 {
            return None;
        }
        Some(Duration::from_secs(self.config.cleaner_period_minutes as u64 * 60))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Mainnet-shaped numbers: a 6.8M block gas limit gives 6,120,000 virtual
    /// gas per second and a ceiling of 12,240,000,000.
    const BLOCK_GAS_LIMIT: i64 = 6_800_000;
    const MIN_GAS_PRICE: i64 = 59_240_000;

    fn addr(b: u8) -> Address {
        Address::repeat_byte(b)
    }

    #[derive(Default)]
    struct FakeAccounts {
        nonces: HashMap<Address, u64>,
        contracts: HashSet<Address>,
        existing: HashSet<Address>,
    }

    impl FakeAccounts {
        fn with_nonce(mut self, a: Address, n: u64) -> Self {
            self.nonces.insert(a, n);
            self.existing.insert(a);
            self
        }
        fn contract(mut self, a: Address) -> Self {
            self.contracts.insert(a);
            self.existing.insert(a);
            self
        }
    }

    impl AccountView for FakeAccounts {
        fn nonce(&self, address: &Address) -> u64 {
            self.nonces.get(address).copied().unwrap_or(0)
        }
        fn is_contract(&self, address: &Address) -> bool {
            self.contracts.contains(address)
        }
        fn exists(&self, address: &Address) -> bool {
            self.existing.contains(address)
        }
    }

    fn ctx() -> QuotaContext {
        QuotaContext {
            block_gas_limit: BLOCK_GAS_LIMIT,
            block_min_gas_price: MIN_GAS_PRICE,
            avg_gas_price: None,
        }
    }

    fn tx(nonce: u64, gas_limit: i64, gas_price: i64, size: usize) -> TxFacts {
        TxFacts {
            nonce,
            gas_limit: U256::from(gas_limit as u64),
            gas_price: U256::from(gas_price as u64),
            size,
        }
    }

    // -----------------------------------------------------------------------
    // Configuration constants — rskj ground truth
    // -----------------------------------------------------------------------

    /// rskj `TxQuotaChecker`: MAX_QUOTAS_SIZE 400_000,
    /// MAX_QUOTA_GAS_MULTIPLIER 2000, MAX_GAS_PER_SECOND_PERCENT 0.9; and
    /// `reference.conf`: enabled = true, cleanerPeriod = 30.
    #[test]
    fn defaults_match_rskj() {
        let c = QuotaConfig::default();
        assert!(c.enabled);
        assert_eq!(c.cleaner_period_minutes, 30);
        assert_eq!(c.max_quotas_size, 400_000);
        assert_eq!(c.max_quota_gas_multiplier, 2_000);
        assert_eq!(c.max_gas_per_second_percent, 0.9);

        // getMaxGasPerSecond / getMaxQuota
        assert_eq!(c.max_gas_per_second(BLOCK_GAS_LIMIT), 6_120_000);
        assert_eq!(c.max_quota(6_120_000), 12_240_000_000);
    }

    /// rskj `MAX_FACTOR = 2 * 5 * 5 * 4 * 1.9 * 5`.
    #[test]
    fn max_factor_matches_rskj() {
        assert_eq!(factors::MAX, 1900.0);
    }

    // -----------------------------------------------------------------------
    // TxVirtualGasCalculator
    // -----------------------------------------------------------------------

    /// The baseline: an established account sending a same-nonce, ordinary
    /// transaction still pays more than its gas limit, because the nonce and
    /// gas-limit factors never drop below 1.
    ///
    /// accountNonce 10, txNonce 10, gasLimit 21000, size 110:
    ///   futureNonce = 1
    ///   nonce       = 1 + 4/11          = 1.363636…
    ///   size        = 1 + 110/25000     = 1.0044
    ///   replacement = 1
    ///   gasLimit    = 1 + 4*21000/6.8M  = 1.012352…
    #[test]
    fn calculate_baseline_factors() {
        let calc = VirtualGasCalculator::skipping_gas_price_factor(10, BLOCK_GAS_LIMIT, MIN_GAS_PRICE);
        let got = calc.calculate(&tx(10, 21_000, MIN_GAS_PRICE, 110), None);

        let expected = 21_000.0
            * (1.0 + 4.0 / 11.0)
            * (1.0 + 110.0 / 25_000.0)
            * (1.0 + 4.0 * 21_000.0 / 6_800_000.0);
        assert!((got - expected).abs() < 1e-6, "got {got}, expected {expected}");
    }

    /// rskj: `newTxNonce == accountNonce ? 1 : 2`. A transaction that cannot
    /// execute yet occupies the pool for longer, so it costs double.
    #[test]
    fn future_nonce_doubles_the_cost() {
        let calc = VirtualGasCalculator::skipping_gas_price_factor(5, BLOCK_GAS_LIMIT, MIN_GAS_PRICE);
        let current = calc.calculate(&tx(5, 21_000, MIN_GAS_PRICE, 110), None);
        let future = calc.calculate(&tx(6, 21_000, MIN_GAS_PRICE, 110), None);
        assert!((future / current - 2.0).abs() < 1e-9, "{future} / {current}");
    }

    /// rskj: `nonceFactor = 1 + 4/(accountNonce+1)`. A brand-new account pays
    /// 5x; the factor decays as the account establishes itself. New accounts
    /// are the cheap vehicle for a flood, which is why they are penalised.
    #[test]
    fn nonce_factor_penalises_new_accounts() {
        let cost_at = |account_nonce: i64| {
            VirtualGasCalculator::skipping_gas_price_factor(account_nonce, BLOCK_GAS_LIMIT, MIN_GAS_PRICE)
                .calculate(&tx(account_nonce as u64, 21_000, MIN_GAS_PRICE, 110), None)
        };
        let fresh = cost_at(0);
        let established = cost_at(999);
        // 5.0 vs 1.004 on the nonce factor alone.
        assert!(fresh / established > 4.9, "{fresh} vs {established}");
    }

    /// rskj: `sizeFactor = 1 + size/25000`. A 25 KB payload doubles the cost.
    #[test]
    fn size_factor_matches_rskj_divisor() {
        let calc = VirtualGasCalculator::skipping_gas_price_factor(10, BLOCK_GAS_LIMIT, MIN_GAS_PRICE);
        let small = calc.calculate(&tx(10, 21_000, MIN_GAS_PRICE, 0), None);
        let big = calc.calculate(&tx(10, 21_000, MIN_GAS_PRICE, 25_000), None);
        assert!((big / small - 2.0).abs() < 1e-9, "{big} / {small}");
    }

    /// rskj: `gasLimitFactor = 1 + 4*txGasLimit/blockGasLimit`. A transaction
    /// claiming the whole block pays 5x.
    #[test]
    fn gas_limit_factor_matches_rskj_weight() {
        let calc = VirtualGasCalculator::skipping_gas_price_factor(10, BLOCK_GAS_LIMIT, MIN_GAS_PRICE);
        let whole_block = calc.calculate(&tx(10, BLOCK_GAS_LIMIT, MIN_GAS_PRICE, 0), None);
        let expected = BLOCK_GAS_LIMIT as f64 * (1.0 + 4.0 / 11.0) * 5.0;
        assert!((whole_block - expected).abs() < 1e-3, "{whole_block} vs {expected}");
    }

    /// rskj `calculateReplacementFactor`: `1 + 1/(newGasPrice/oldGasPrice)`.
    ///
    /// This is the heart of the abuse being prevented. A replacement that
    /// barely clears the 40% bump threshold costs nearly double; a large
    /// overbid costs less, because it is likelier to actually be mined.
    #[test]
    fn replacement_factor_punishes_cheap_replacements() {
        let calc = VirtualGasCalculator::skipping_gas_price_factor(10, BLOCK_GAS_LIMIT, MIN_GAS_PRICE);
        let base = tx(10, 21_000, 100, 110);

        let no_replacement = calc.calculate(&base, None);

        // Replacing a 100 with a 100: ratio 1 → factor 2.
        let replaced_equal = tx(10, 21_000, 100, 110);
        let equal = calc.calculate(&base, Some(&replaced_equal));
        assert!((equal / no_replacement - 2.0).abs() < 1e-9);

        // Replacing a 10 with a 100: ratio 10 → factor 1.1.
        let replaced_cheap = tx(10, 21_000, 10, 110);
        let overbid = calc.calculate(&base, Some(&replaced_cheap));
        assert!((overbid / no_replacement - 1.1).abs() < 1e-9);

        // A bigger overbid is cheaper than a marginal one.
        assert!(overbid < equal);
    }

    /// rskj `calculateLowGasPriceFactor`, used only when the fee market is
    /// working: `1 + 3 * (avg - txPrice)/(avg - blockMin)`, and 1 at or above
    /// the average.
    #[test]
    fn low_gas_price_factor_applies_only_below_the_average() {
        let avg = 100i64;
        let calc = VirtualGasCalculator::with_all_factors(10, BLOCK_GAS_LIMIT, 0, avg);

        let at_avg = calc.calculate(&tx(10, 21_000, 100, 0), None);
        let above = calc.calculate(&tx(10, 21_000, 200, 0), None);
        assert!((at_avg - above).abs() < 1e-9, "at or above the average is not penalised");

        // Priced at zero with blockMin zero: factor = 1 + 3*1 = 4.
        let at_zero = calc.calculate(&tx(10, 21_000, 0, 0), None);
        assert!((at_zero / at_avg - 4.0).abs() < 1e-9, "{at_zero} / {at_avg}");
    }

    /// rskj `createSkippingGasPriceFactor` is the branch taken whenever
    /// `isFeeMarketWorking()` is false, and rustock takes it always for now.
    /// It must leave the other five factors untouched.
    #[test]
    fn skipping_gas_price_factor_only_drops_that_factor() {
        let skipping = VirtualGasCalculator::skipping_gas_price_factor(10, BLOCK_GAS_LIMIT, 0);
        let with_avg = VirtualGasCalculator::with_all_factors(10, BLOCK_GAS_LIMIT, 0, 100);
        let cheap = tx(10, 21_000, 100, 110); // at the average → factor 1
        assert!((skipping.calculate(&cheap, None) - with_avg.calculate(&cheap, None)).abs() < 1e-9);
    }

    /// rskj `capeResult` is, in its own words, an "extra security measure":
    /// if the multiplication reaches infinity it falls back to
    /// `gasLimit * MAX_FACTOR`, because an infinite cost would make every
    /// later comparison meaningless (`available < inf` is always true, so the
    /// account would be refused forever).
    ///
    /// Tested directly, because it turns out to be unreachable through
    /// `calculate` with any representable transaction — see the test below.
    /// That is worth knowing rather than assuming.
    #[test]
    fn cap_result_falls_back_to_max_factor_on_overflow() {
        let gas_limit = 21_000f64;
        assert_eq!(
            VirtualGasCalculator::cap_result(gas_limit, f64::MAX),
            gas_limit * factors::MAX,
            "an overflow must fall back, not propagate infinity"
        );
        // An ordinary product passes through untouched.
        assert_eq!(VirtualGasCalculator::cap_result(gas_limit, 3.0), 63_000.0);
    }

    /// The most extreme transaction that can be represented — the largest gas
    /// limit rskj reads (`Long.MAX_VALUE`; from 2^63 it reads negative),
    /// maximum size, smallest possible block gas limit, and a replacement
    /// ratio as close to zero as `U256` allows — still produces a finite
    /// cost. The fallback above is defence in depth, not a live path.
    #[test]
    fn the_most_extreme_transaction_still_produces_a_finite_cost() {
        let calc = VirtualGasCalculator::skipping_gas_price_factor(0, 1, 0);
        let new = TxFacts {
            nonce: 1,
            gas_limit: U256::from(i64::MAX as u64),
            gas_price: U256::from(1u64),
            size: usize::MAX,
        };
        let replaced = TxFacts { gas_price: U256::MAX, ..new };
        let got = calc.calculate(&new, Some(&replaced));
        assert!(got.is_finite(), "got {got}");
        assert!(got > 0.0);
    }

    // -----------------------------------------------------------------------
    // TxQuota
    // -----------------------------------------------------------------------

    /// rskj `acceptVirtualGasConsumption`: spend if there is enough, otherwise
    /// refuse and spend NOTHING. A refused transaction must not drain the
    /// account, or a spammer could grief an honest one by proxy.
    #[test]
    fn accept_spends_only_when_there_is_enough() {
        let now = Instant::now();
        let mut q = TxQuota::create_new(1_000, now);

        assert!(q.accept_virtual_gas_consumption(400.0));
        assert_eq!(q.available_virtual_gas(), 600.0);

        assert!(!q.accept_virtual_gas_consumption(700.0));
        assert_eq!(q.available_virtual_gas(), 600.0, "a refusal must cost nothing");
    }

    /// rskj `forceVirtualGasSubtraction`: accept if possible, otherwise drain
    /// to zero and report false.
    #[test]
    fn force_subtraction_drains_to_zero() {
        let now = Instant::now();
        let mut q = TxQuota::create_new(1_000, now);
        assert!(!q.force_virtual_gas_subtraction(5_000.0));
        assert_eq!(q.available_virtual_gas(), 0.0);

        let mut q2 = TxQuota::create_new(1_000, now);
        assert!(q2.force_virtual_gas_subtraction(400.0));
        assert_eq!(q2.available_virtual_gas(), 600.0);
    }

    /// rskj `refresh`: accrue `maxGasPerSecond` per elapsed second, capped at
    /// `maxQuota`.
    #[test]
    fn refresh_accrues_with_time_and_caps_at_max_quota() {
        let t0 = Instant::now();
        let mut q = TxQuota::create_new(0, t0);

        // Ten seconds at 100/s → 1000.
        let after_10s = q.refresh(100, 1_000_000, t0 + Duration::from_secs(10));
        assert!((after_10s - 1_000.0).abs() < 1e-6, "{after_10s}");

        // A further hour would be 360,000, but the cap is 5,000.
        let capped = q.refresh(100, 5_000, t0 + Duration::from_secs(3610));
        assert_eq!(capped, 5_000.0);
    }

    // -----------------------------------------------------------------------
    // TxQuotaChecker
    // -----------------------------------------------------------------------

    /// Disabled means disabled: accept everything, track nothing.
    #[test]
    fn disabled_limiter_accepts_everything() {
        let cfg = QuotaConfig { enabled: false, ..Default::default() };
        let mut checker = QuotaChecker::new(cfg);
        let accounts = FakeAccounts::default().with_nonce(addr(1), 50);
        let now = Instant::now();

        for _ in 0..1_000 {
            assert!(checker.accept_tx(
                addr(1), None,
                &tx(50, BLOCK_GAS_LIMIT, MIN_GAS_PRICE, 100_000),
                None, &ctx(), &accounts, now,
            ));
        }
        assert_eq!(checker.tracked_accounts(), 0);
    }

    /// rskj's first-transaction exemption. Without it, a new account's first
    /// transaction cannot propagate: every node in turn sees the account for
    /// the first time, grants it one second's quota, finds that insufficient,
    /// and declines to relay.
    ///
    /// It is not a free pass — all available gas is drained, so the account
    /// starts from zero.
    #[test]
    fn first_transaction_from_a_new_account_is_always_accepted() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default(); // nonce 0, does not exist
        let now = Instant::now();

        // Big enough that one second's grant (6.12M) could never cover it.
        let big = tx(0, BLOCK_GAS_LIMIT, MIN_GAS_PRICE, 100_000);
        assert!(checker.accept_tx(addr(1), None, &big, None, &ctx(), &accounts, now));

        assert_eq!(
            checker.quota_of(&addr(1)),
            Some(0.0),
            "the exemption drains the account rather than granting it free capacity"
        );
    }

    /// The exemption must not apply twice. The map check in
    /// `isFirstTxFromSender` is what stops a resend or gas-price bump of the
    /// same first transaction from being forced through repeatedly — which is
    /// precisely the abuse being limited.
    #[test]
    fn the_first_tx_exemption_does_not_repeat() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default();
        let now = Instant::now();
        let big = tx(0, BLOCK_GAS_LIMIT, MIN_GAS_PRICE, 100_000);

        assert!(checker.accept_tx(addr(1), None, &big, None, &ctx(), &accounts, now));
        // Same instant, so nothing has accrued, and the account is now known.
        assert!(
            !checker.accept_tx(addr(1), None, &big, None, &ctx(), &accounts, now),
            "a resend must be subject to the quota"
        );
    }

    /// rskj `calculateNewItemQuota`: an established sender (nonce > 0) not yet
    /// in the map is trusted with the FULL quota immediately, so a node that
    /// has just restarted does not throttle its regular users.
    #[test]
    fn established_sender_is_granted_the_full_quota_on_first_sight() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), 42);
        let now = Instant::now();

        assert!(checker.accept_tx(
            addr(1), None, &tx(42, 21_000, MIN_GAS_PRICE, 110), None, &ctx(), &accounts, now,
        ));

        let cfg = QuotaConfig::default();
        let max_quota = cfg.max_quota(cfg.max_gas_per_second(BLOCK_GAS_LIMIT)) as f64;
        let left = checker.quota_of(&addr(1)).unwrap();
        // Full quota minus one ordinary transaction — still essentially full.
        assert!(left > max_quota * 0.999, "{left} of {max_quota}");
    }

    /// The abuse this exists to stop: broadcast a large transaction, replace
    /// it, repeat. Each replacement is priced by how little it overbids, and
    /// the account runs out.
    #[test]
    fn repeated_cheap_replacements_exhaust_the_quota() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), 7);
        let t0 = Instant::now();

        let mut price = 100i64;
        let mut accepted = 0;
        // No time passes between attempts, so nothing accrues.
        for _ in 0..10_000 {
            let replaced = tx(7, BLOCK_GAS_LIMIT, price, 100_000);
            price = price * 140 / 100; // the 40% bump the pool requires
            let new = tx(7, BLOCK_GAS_LIMIT, price, 100_000);
            if !checker.accept_tx(
                addr(1), None, &new, Some(&replaced), &ctx(), &accounts, t0,
            ) {
                break;
            }
            accepted += 1;
        }

        assert!(accepted > 0, "the first few replacements should succeed");
        assert!(
            accepted < 10_000,
            "an account replacing a full-block transaction forever must eventually be refused"
        );
    }

    /// …and that the limit is a rate, not a ban: waiting restores capacity.
    #[test]
    fn waiting_restores_capacity() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), 7);
        let t0 = Instant::now();
        let heavy = tx(7, BLOCK_GAS_LIMIT, MIN_GAS_PRICE, 100_000);

        while checker.accept_tx(addr(1), None, &heavy, None, &ctx(), &accounts, t0) {}
        assert!(!checker.accept_tx(addr(1), None, &heavy, None, &ctx(), &accounts, t0));

        // One minute of quiet accrues 60 x 6.12M virtual gas.
        let later = t0 + Duration::from_secs(60);
        assert!(
            checker.accept_tx(addr(1), None, &heavy, None, &ctx(), &accounts, later),
            "an exhausted account must recover by being quiet"
        );
    }

    /// rskj `updateReceiverQuotaIfRequired`: an EOA receiver starts
    /// accumulating as soon as we learn of it, so its own first transaction is
    /// not throttled. A contract receiver is not tracked — a contract never
    /// sends.
    #[test]
    fn receiver_quota_is_created_for_eoas_but_not_contracts() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let sender = addr(1);
        let eoa = addr(2);
        let contract = addr(3);
        let accounts = FakeAccounts::default()
            .with_nonce(sender, 9)
            .with_nonce(eoa, 3)
            .contract(contract);
        let now = Instant::now();

        checker.accept_tx(sender, Some(eoa), &tx(9, 21_000, MIN_GAS_PRICE, 110), None, &ctx(), &accounts, now);
        assert!(checker.quota_of(&eoa).is_some(), "an EOA receiver is tracked");

        checker.accept_tx(sender, Some(contract), &tx(10, 21_000, MIN_GAS_PRICE, 110), None, &ctx(), &accounts, now);
        assert!(checker.quota_of(&contract).is_none(), "a contract receiver is not");
    }

    /// A receiver that does not exist yet is tracked too — rskj wants it
    /// accumulating from the moment it is first seen.
    #[test]
    fn receiver_quota_is_created_for_an_unknown_address() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), 9);
        let now = Instant::now();
        checker.accept_tx(
            addr(1), Some(addr(99)), &tx(9, 21_000, MIN_GAS_PRICE, 110), None, &ctx(), &accounts, now,
        );
        assert!(checker.quota_of(&addr(99)).is_some());
    }

    /// A receiver is granted one second's worth, not the full quota — it has
    /// not proved itself as a sender.
    #[test]
    fn receiver_is_granted_only_the_per_second_rate() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), 9).with_nonce(addr(2), 5);
        let now = Instant::now();
        checker.accept_tx(
            addr(1), Some(addr(2)), &tx(9, 21_000, MIN_GAS_PRICE, 110), None, &ctx(), &accounts, now,
        );
        let cfg = QuotaConfig::default();
        assert_eq!(
            checker.quota_of(&addr(2)),
            Some(cfg.max_gas_per_second(BLOCK_GAS_LIMIT) as f64)
        );
    }

    /// rskj `cleanMaxQuotas`: entries at the ceiling carry no information and
    /// are dropped; entries below it are kept.
    #[test]
    fn clean_drops_only_accounts_at_the_ceiling() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), 9).with_nonce(addr(2), 9);
        let t0 = Instant::now();

        // addr(1) spends almost everything; addr(2) spends a little.
        let heavy = tx(9, BLOCK_GAS_LIMIT, MIN_GAS_PRICE, 100_000);
        while checker.accept_tx(addr(1), None, &heavy, None, &ctx(), &accounts, t0) {}
        checker.accept_tx(addr(2), None, &tx(9, 21_000, MIN_GAS_PRICE, 110), None, &ctx(), &accounts, t0);

        assert_eq!(checker.tracked_accounts(), 2);

        // A moment later, addr(2) is back at the ceiling; addr(1) is not.
        let dropped = checker.clean_max_quotas(t0 + Duration::from_secs(1));
        assert_eq!(dropped, 1, "only the account at maxQuota is dropped");
        assert!(checker.quota_of(&addr(1)).is_some());
        assert!(checker.quota_of(&addr(2)).is_none());
    }

    /// rskj returns early from `cleanMaxQuotas` when no transaction has been
    /// processed, because it has no block gas limit to compute the ceiling.
    #[test]
    fn clean_is_a_no_op_before_any_transaction() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        assert_eq!(checker.clean_max_quotas(Instant::now()), 0);
    }

    /// The map is bounded, and evicts by least-recent ACCESS rather than
    /// insertion — rskj's `MaxSizeHashMap(maxSize, accessOrder = true)`. A
    /// flood of fresh addresses must not push out an account that is still
    /// transacting.
    #[test]
    fn the_map_is_bounded_and_evicts_least_recently_used() {
        let cfg = QuotaConfig { max_quotas_size: 3, ..Default::default() };
        let mut checker = QuotaChecker::new(cfg);
        let accounts = FakeAccounts::default();
        let now = Instant::now();
        let t = |n: u64| tx(n, 21_000, MIN_GAS_PRICE, 110);

        for i in 1..=3u8 {
            checker.accept_tx(addr(i), None, &t(0), None, &ctx(), &accounts, now);
        }
        assert_eq!(checker.tracked_accounts(), 3);

        // Touch addr(1) so it is no longer the oldest access.
        checker.accept_tx(addr(1), None, &t(0), None, &ctx(), &accounts, now);
        // A fourth account evicts addr(2), the least recently accessed.
        checker.accept_tx(addr(4), None, &t(0), None, &ctx(), &accounts, now);

        assert_eq!(checker.tracked_accounts(), 3);
        assert!(checker.quota_of(&addr(1)).is_some(), "recently used survives");
        assert!(checker.quota_of(&addr(2)).is_none(), "least recently used evicted");
        assert!(checker.quota_of(&addr(4)).is_some());
    }

    /// rskj treats zero and negative cleaner periods alike: no sweep.
    #[test]
    fn cleaner_period_is_disabled_by_zero_or_negative() {
        let on = QuotaChecker::new(QuotaConfig::default());
        assert_eq!(on.cleaner_period(), Some(Duration::from_secs(30 * 60)));

        for period in [0, -1] {
            let c = QuotaChecker::new(QuotaConfig {
                cleaner_period_minutes: period,
                ..Default::default()
            });
            assert_eq!(c.cleaner_period(), None);
        }

        let disabled = QuotaChecker::new(QuotaConfig { enabled: false, ..Default::default() });
        assert_eq!(disabled.cleaner_period(), None);
    }

    /// The tunables actually tune. Halving the accrual percentage halves the
    /// rate at which an exhausted account recovers.
    #[test]
    fn configuration_changes_the_limits() {
        let strict = QuotaConfig {
            max_gas_per_second_percent: 0.45,
            max_quota_gas_multiplier: 1_000,
            ..Default::default()
        };
        assert_eq!(strict.max_gas_per_second(BLOCK_GAS_LIMIT), 3_060_000);
        assert_eq!(strict.max_quota(3_060_000), 3_060_000_000);

        // A stricter limiter refuses sooner than the default one.
        let count_accepted = |cfg: QuotaConfig| {
            let mut checker = QuotaChecker::new(cfg);
            let accounts = FakeAccounts::default().with_nonce(addr(1), 7);
            let t0 = Instant::now();
            let heavy = tx(7, BLOCK_GAS_LIMIT, MIN_GAS_PRICE, 100_000);
            let mut n = 0;
            while checker.accept_tx(addr(1), None, &heavy, None, &ctx(), &accounts, t0) {
                n += 1;
                if n > 100_000 { break; }
            }
            n
        };
        assert!(count_accepted(strict) < count_accepted(QuotaConfig::default()));
    }

    // -----------------------------------------------------------------------
    // Values as rskj reads them: `long`s
    // -----------------------------------------------------------------------

    /// 2^63 + `n`, which rskj reads as `Long.MIN_VALUE + n`.
    fn past_2_63(n: u64) -> U256 {
        U256::from(1u64 << 63) + U256::from(n)
    }

    /// 2^64 + `n`, of which rskj reads `n`.
    fn past_2_64(n: u64) -> U256 {
        (U256::from(1u64) << 64) + U256::from(n)
    }

    /// The best block's gas limit and minimum gas price, and the tracker's
    /// price, are read as rskj's checker reads them: the low 64 bits of the
    /// whole value, a `long`, whatever its size (`TxQuotaChecker` L77,
    /// L178-179, L212-218).
    #[test]
    fn the_context_reads_each_value_as_its_low_64_bits() {
        let mut best = crate::tests::dummy_header(1, alloy_primitives::B256::ZERO, U256::from(1));
        best.gas_limit = past_2_64(6_800_000);
        best.minimum_gas_price = past_2_63(5);
        let ctx = QuotaContext::of(&best, Some(past_2_64(3_000)));
        assert_eq!(ctx.block_gas_limit, 6_800_000);
        assert_eq!(ctx.block_min_gas_price, i64::MIN + 5);
        assert_eq!(ctx.avg_gas_price, Some(3_000));

        // Past 256 bits the header keeps the bytes, and they are what is read.
        let mut beyond = vec![1u8];
        beyond.extend([0u8; 39]);
        beyond.push(7);
        best.kept = Some(Box::new(rustock_core::types::header::KeptFields {
            gas_limit: Some(beyond.clone().into()),
            minimum_gas_price: Some(beyond.into()),
            ..Default::default()
        }));
        let ctx = QuotaContext::of(&best, None);
        assert_eq!((ctx.block_gas_limit, ctx.block_min_gas_price), (7, 7));
        assert_eq!(ctx.avg_gas_price, None);
    }

    /// rskj reads a price from 2^63 as a negative `long`. Once the average has
    /// passed 2^63 and a transaction's price has not, the transaction is not
    /// below the average (L109) and pays no low-price factor; read unsigned,
    /// it would pay 3.25 times over.
    #[test]
    fn a_price_past_2_63_reads_negative() {
        let min = java_long(U256::from((1u64 << 63) - 1_000));
        let avg = java_long(past_2_63(1_000));
        assert!(min > 0 && avg < 0);
        let with_avg = VirtualGasCalculator::with_all_factors(10, BLOCK_GAS_LIMIT, min, avg);
        let skipping = VirtualGasCalculator::skipping_gas_price_factor(10, BLOCK_GAS_LIMIT, min);
        let below = TxFacts {
            gas_price: U256::from((1u64 << 63) - 500),
            ..tx(10, 21_000, 0, 110)
        };
        assert_eq!(
            with_avg.calculate(&below, None),
            skipping.calculate(&below, None)
        );
    }

    /// From 2^64 a price wraps around: rskj reads its low 64 bits (L107).
    #[test]
    fn a_price_past_2_64_reads_as_its_low_64_bits() {
        let calc = VirtualGasCalculator::with_all_factors(10, BLOCK_GAS_LIMIT, 1_000, 3_000);
        let wrapped = TxFacts {
            gas_price: past_2_64(2_000),
            ..tx(10, 21_000, 0, 110)
        };
        let low = calc.calculate(&tx(10, 21_000, 2_000, 110), None);
        assert_eq!(calc.calculate(&wrapped, None), low);
        // 2,000 halfway from the minimum to the average: 1 + 3 * 1/2.
        let at_avg = calc.calculate(&tx(10, 21_000, 3_000, 110), None);
        assert!((low / at_avg - 2.5).abs() < 1e-9, "{low} / {at_avg}");
    }

    /// A transaction's gas limit too (L82).
    #[test]
    fn a_gas_limit_past_2_64_reads_as_its_low_64_bits() {
        let calc =
            VirtualGasCalculator::skipping_gas_price_factor(10, BLOCK_GAS_LIMIT, MIN_GAS_PRICE);
        let wrapped = TxFacts {
            gas_limit: past_2_64(21_000),
            ..tx(10, 0, MIN_GAS_PRICE, 110)
        };
        assert_eq!(
            calc.calculate(&wrapped, None),
            calc.calculate(&tx(10, 21_000, MIN_GAS_PRICE, 110), None)
        );
    }

    /// `avg - txPrice` is a `long` difference and `avg - (double) blockMin` a
    /// `double` one (L110). Where a `double` can't tell the prices apart, the
    /// numerator is still 2 and the denominator 0: the factor is infinite and
    /// the cost falls back to `gasLimit * MAX_FACTOR`, where a `double`
    /// difference would make it NaN.
    #[test]
    fn the_price_difference_is_a_long_difference() {
        let avg = (1i64 << 62) + 3;
        let calc = VirtualGasCalculator::with_all_factors(10, BLOCK_GAS_LIMIT, 1 << 62, avg);
        let below = tx(10, 21_000, (1 << 62) + 1, 110);
        assert_eq!(calc.calculate(&below, None), 21_000.0 * factors::MAX);
    }

    /// `accountNonce + 1` is a `long` sum (L89). At the largest nonce a `u64`
    /// holds, which rskj reads as -1, it is 0: the nonce factor is infinite,
    /// and the cost falls back to `gasLimit * MAX_FACTOR` (L133-141).
    #[test]
    fn the_nonce_factor_adds_in_long_arithmetic() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), u64::MAX);
        let new = tx(u64::MAX, 21_000, MIN_GAS_PRICE, 110);
        let now = Instant::now();
        assert!(checker.accept_tx(addr(1), None, &new, None, &ctx(), &accounts, now));

        let cfg = QuotaConfig::default();
        let max_quota = cfg.max_quota(cfg.max_gas_per_second(BLOCK_GAS_LIMIT)) as f64;
        assert_eq!(
            checker.quota_of(&addr(1)),
            Some(max_quota - 21_000.0 * factors::MAX)
        );
    }

    /// `Math.round` takes a tie toward positive infinity and Rust's `round`
    /// away from zero: they part on a negative tie, which a gas limit rskj
    /// reads as negative gives (L203-205).
    #[test]
    fn the_rate_rounds_as_java_rounds() {
        let cfg = QuotaConfig::default();
        assert_eq!(cfg.max_gas_per_second(-5), -4, "Math.round(-4.5)");
        assert_eq!(cfg.max_gas_per_second(5), 5, "Math.round(4.5)");
        assert_eq!(java_round(-0.5), 0);
        assert_eq!(java_round(2.5), 3);
        assert_eq!(java_round(0.5 - f64::EPSILON / 4.0), 0);
        assert_eq!(java_round(f64::NAN), 0);
        assert_eq!(java_round(1e300), i64::MAX);
        assert_eq!(java_round(-1e300), i64::MIN);
    }

    /// `maxGasPerSecond * MAX_QUOTA_GAS_MULTIPLIER` is a `long` product,
    /// which wraps rather than saturating (L207-209).
    #[test]
    fn the_ceiling_multiplies_in_long_arithmetic() {
        let cfg = QuotaConfig::default();
        assert_eq!(cfg.max_quota(1 << 62), 0, "2^62 x 2,000 wraps to 0");
        assert_eq!(cfg.max_quota(i64::MAX), i64::MAX.wrapping_mul(2_000));
    }

    /// `Math.min` keeps a NaN where Rust's `min` drops it (TxQuota L132): a
    /// quota a NaN cost spoiled stays spoiled through a refresh, as on rskj.
    #[test]
    fn a_refresh_keeps_a_nan_as_math_min_does() {
        let t0 = Instant::now();
        let mut q = TxQuota::create_new(1_000, t0);
        assert!(q.accept_virtual_gas_consumption(f64::NAN));
        assert!(q.refresh(100, 5_000, t0 + Duration::from_secs(10)).is_nan());
        assert!(java_min(0.0, -0.0).is_sign_negative());
    }

    /// rskj keeps the last gas limit as a `long`, -1 meaning none seen (L44,
    /// L147-150): a gas limit whose low 64 bits read -1 leaves the clean
    /// waiting, as there.
    #[test]
    fn a_gas_limit_read_as_minus_one_leaves_the_clean_waiting() {
        let mut checker = QuotaChecker::new(QuotaConfig::default());
        let accounts = FakeAccounts::default().with_nonce(addr(1), 9);
        let t0 = Instant::now();
        let unknown = QuotaContext {
            block_gas_limit: -1,
            ..ctx()
        };
        let new = tx(9, 21_000, MIN_GAS_PRICE, 110);
        checker.accept_tx(addr(1), None, &new, None, &unknown, &accounts, t0);
        assert_eq!(checker.tracked_accounts(), 1);

        assert_eq!(checker.clean_max_quotas(t0 + Duration::from_secs(3_600)), 0);
        assert_eq!(checker.tracked_accounts(), 1);
    }

    /// rskj weighs a replacement by prices it reads as `double`s through
    /// `BigInteger.doubleValue()`, rounded once (L118-121). Past 2^64,
    /// adding limb by limb rounds twice and can land a `double` away.
    #[test]
    fn a_price_past_2_64_rounds_once_to_a_double() {
        let v = past_2_64((1u64 << 53) + 2_049);
        assert_eq!(u256_to_f64(v), 2f64.powi(64) + 2f64.powi(53) + 4_096.0);
        assert_eq!(u256_to_f64(U256::from(u64::MAX)), u64::MAX as f64);
        assert_eq!(u256_to_f64(U256::MAX), 2f64.powi(256));
    }
}
