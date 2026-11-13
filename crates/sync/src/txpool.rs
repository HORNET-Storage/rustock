use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use rustock_core::{Header, Transaction};
use rustock_storage::BlockStore;
use rustock_trie::{account_key, code_key, AccountState, TrieKeySlice, TrieNode, TrieStore};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Instant;
use tracing::debug;

const TRANSACTION_GAS_CAP: u64 = 1u64 << 60;
const MAX_TX_SIZE: usize = 128 * 1024;
/// rskj `Constants.getMaxInitCodeSize()`: twice the largest contract, the most
/// init code a creation may carry once RSKIP438 is active.
const MAX_INIT_CODE_SIZE: usize = 2 * 0x6000;

/// Ceiling on the total number of transactions held across every account.
///
/// `account_slots` bounds how many transactions a single sender may occupy, but
/// nothing bounded the number of *senders*. Admission does verify balance, so
/// filling the pool costs an attacker real funds — but "expensive" is not the
/// same as "bounded", and geth caps globally for the same reason. At the default
/// 128 KiB per transaction this also bounds worst-case pool memory.
const MAX_POOL_TRANSACTIONS: usize = 8192;

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub account_slots: u64,
    pub gas_price_bump: u64,
    pub outdated_threshold: u64,
    pub outdated_timeout_secs: u64,
    pub max_tx_size: usize,
    /// Maximum transactions held across all accounts, pending and queued.
    pub max_pool_transactions: usize,
    /// Per-account virtual-gas rate limiting (rskj `TxQuotaChecker`).
    pub quota: crate::quota::QuotaConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            account_slots: 16,
            gas_price_bump: 40,
            outdated_threshold: 10,
            outdated_timeout_secs: 650,
            max_tx_size: MAX_TX_SIZE,
            max_pool_transactions: MAX_POOL_TRANSACTIONS,
            quota: crate::quota::QuotaConfig::default(),
        }
    }
}

/// What the pool needs to know about the chain beyond its id: rskj's
/// `TxPendingValidator` reads the activation config, the constants and the
/// free-transaction rule. `None` on the pool keeps the plain checks, which is
/// what a pool built by a tool or a test gets.
#[derive(Debug, Clone)]
pub struct ChainRules {
    pub hardfork_cfg: rustock_execution::hardfork::RskHardforkConfig,
    /// rskj `BridgeUtils.isFreeBridgeTx`: senders whose calls to the Bridge
    /// cost nothing before `areBridgeTxsPaid`.
    pub free_bridge_senders: Vec<Address>,
    /// rskj `Constants.getMinSequentialSetGasLimit()`, for the sublist gas
    /// limits under RSKIP144.
    pub min_sequential_set_gas_limit: u64,
    /// First block RSKIP252 applies at.
    pub rskip252_height: u64,
}

impl ChainRules {
    /// The rules for the chain `hardfork_cfg` describes.
    pub fn for_chain(
        hardfork_cfg: rustock_execution::hardfork::RskHardforkConfig,
        min_sequential_set_gas_limit: u64,
    ) -> Self {
        let constants = rustock_execution::executor::bridge_constants_for(hardfork_cfg.chain_id);
        Self {
            free_bridge_senders: rustock_execution::executor::free_bridge_senders(&constants),
            rskip252_height: hardfork_cfg.rskip252_height(),
            min_sequential_set_gas_limit,
            hardfork_cfg,
        }
    }

    /// The free senders of `constants`, for a chain whose Bridge constants
    /// aren't the ones its id names: rskj's regtest, started from a genesis
    /// file, runs on `BridgeConstants::rskj_regtest`, and the pool must agree
    /// with the block processor on what costs nothing.
    pub fn with_bridge_constants(
        mut self,
        constants: &rustock_execution::bridge::constants::BridgeConstants,
    ) -> Self {
        self.free_bridge_senders = rustock_execution::executor::free_bridge_senders(constants);
        self
    }

    /// rskj `Transaction.transactionCost == 0`: a federator's call to the
    /// Bridge before `areBridgeTxsPaid`.
    fn is_free_tx(&self, tx: &Transaction, sender: &Address, number: u64) -> bool {
        tx.to.len() == 20
            && tx.to.as_ref() == rustock_execution::precompiles::BRIDGE_ADDR.as_slice()
            && !self.hardfork_cfg.has_are_bridge_txs_paid(number)
            && self.free_bridge_senders.contains(sender)
    }

    /// rskj `TxPendingValidator.isValid`: with RSKIP351 and RSKIP144 active
    /// the gas limit a transaction must fit is the larger sublist's
    /// (`BlockUtils.getSublistGasLimit`), not the block's.
    fn gas_limit_bound(&self, header: &Header) -> u64 {
        let block_gas_limit = header.gas_limit.saturating_to::<u64>();
        if self.hardfork_cfg.has_rskip351(header.number) && self.hardfork_cfg.has_rskip144(header.number) {
            let (parallel, sequential) = rustock_execution::mining::partition::sublist_gas_limits(
                block_gas_limit,
                rustock_core::validation::block_rules::TX_EXECUTION_THREADS as u64,
                self.min_sequential_set_gas_limit,
            );
            parallel.max(sequential)
        } else {
            block_gas_limit
        }
    }

    /// rskj `TxValidatorMaximumGasPriceValidator` with
    /// `TxGasPriceCap.FOR_TRANSACTION`: over 80 times the block's minimum is
    /// refused once RSKIP252 is active. No cap at a zero minimum.
    fn gas_price_cap(&self, header: &Header) -> Option<U256> {
        if header.number < self.rskip252_height || header.minimum_gas_price.is_zero() {
            return None;
        }
        Some(header.minimum_gas_price.saturating_mul(U256::from(TX_GAS_PRICE_CAP_MULTIPLIER)))
    }

    /// rskj `Transaction.transactionCost` of a transaction that isn't free,
    /// at block `number`: 21,000, or 53,000 for a creation, plus 4 for every
    /// zero byte of its data and 68 for every other, 16 from RSKIP400; and
    /// from RSKIP438 a creation pays 2 more for every 32 bytes of its init
    /// code, the last ones counted whole (`InitcodeCostCalculator`).
    fn transaction_cost(&self, tx: &Transaction, number: u64) -> u64 {
        let creates = tx.to.is_empty();
        let nonzero = if self.hardfork_cfg.has_reduced_calldata_cost(number) {
            16
        } else {
            68
        };
        let init_code = if creates && self.hardfork_cfg.has_initcode_metering(number) {
            2 * tx.input.len().div_ceil(32) as u64
        } else {
            0
        };
        let data: u64 = tx
            .input
            .iter()
            .map(|byte| if *byte == 0 { 4 } else { nonzero })
            .sum();
        (if creates { 53_000 } else { 21_000 }) + init_code + data
    }
}

/// rskj `TxGasPriceCap.FOR_TRANSACTION`.
pub const TX_GAS_PRICE_CAP_MULTIPLIER: u64 = 80;

/// rskj `TxValidatorNonceEncodingValidator.hasCanonicalEncoding`: the nonce's
/// RLP payload fits in eight bytes and carries no leading zero (a single
/// zero byte is tolerated; `[0x00, 0x01]` is not).
pub fn nonce_bytes_are_canonical(nonce: &[u8]) -> bool {
    if nonce.len() > 8 {
        return false;
    }
    if nonce.len() > 1 && nonce[0] == 0 {
        return false;
    }
    true
}

/// The nonce's bytes: the payload of the first item of a transaction's
/// encoding. `None` if the bytes are not a transaction list.
fn raw_nonce_bytes(raw: &[u8]) -> Option<&[u8]> {
    let mut buf = raw;
    let list = alloy_rlp::Header::decode(&mut buf).ok()?;
    if !list.list {
        return None;
    }
    let mut body = &buf[..list.payload_length.min(buf.len())];
    let item = alloy_rlp::Header::decode(&mut body).ok()?;
    if item.list || item.payload_length > body.len() {
        return None;
    }
    Some(&body[..item.payload_length])
}

#[derive(Debug)]
pub enum PoolError {
    /// rskj `internalAddTransaction`: the pending transactions hold one of
    /// this hash.
    AlreadyPending,
    /// The same, of the queued ones.
    AlreadyQueued,
    NonceTooLow,
    NonceTooHigh,
    InsufficientFunds,
    /// rskj `TxValidatorGasLimitValidator`: the transaction's gas limit, and
    /// the limit it had to fit, which is the block's or, under RSKIP144, the
    /// larger sublist's. rskj's message calls it the block's either way.
    GasLimitExceeded {
        gas_limit: U256,
        bound: u64,
    },
    GasPriceTooLow,
    IntrinsicGasTooHigh,
    ReplacementGasPriceTooLow,
    /// rskj `TxPendingValidator.isValid`: the transaction's size, and the
    /// most it may be.
    TxTooLarge {
        size: usize,
        max: usize,
    },
    PoolFull,
    InvalidSignature(String),
    InsufficientFundsForPendingAndNew,
    AccountExceedsQuota,
    RlpDecode(String),
    StoreError(String),
    /// rskj `TxValidatorMaximumGasPriceValidator`: over 80 times the block
    /// minimum once RSKIP252 is active.
    GasPriceAboveCap,
    /// rskj `TxValidatorNonceEncodingValidator`: a nonce with leading zeros.
    NonCanonicalNonce,
    /// The same validator: a nonce of more than eight bytes, this many.
    NonceTooLong(usize),
    /// rskj `TxPendingValidator.isValid`: the state holds no account for the
    /// sender of a transaction that costs something.
    SenderMissing,
    /// The same: a creation whose init code is past RSKIP438's limit.
    InitCodeTooLarge,
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPending => write!(f, "pending transaction with same hash already exists"),
            Self::AlreadyQueued => write!(f, "queued transaction with same hash already exists"),
            Self::NonceTooLow => write!(f, "transaction nonce too low"),
            Self::NonceTooHigh => write!(f, "transaction nonce too high"),
            Self::InsufficientFunds => write!(f, "insufficient funds"),
            Self::GasLimitExceeded { gas_limit, bound } => write!(
                f,
                "transaction's gas limit of {gas_limit} is higher than the block's gas limit of {bound}"
            ),
            Self::GasPriceTooLow => write!(f, "transaction's gas price lower than block's minimum"),
            Self::IntrinsicGasTooHigh => write!(f, "transaction's basic cost is above the gas limit"),
            Self::ReplacementGasPriceTooLow => write!(f, "gas price not enough to bump transaction"),
            Self::TxTooLarge { size, max } => {
                write!(f, "transaction's size is higher than defined maximum: {size} > {max}")
            }
            Self::PoolFull => write!(f, "transaction pool is full"),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::InsufficientFundsForPendingAndNew => {
                write!(f, "insufficient funds to pay for pending and new transactions")
            }
            Self::AccountExceedsQuota => write!(f, "account exceeds quota"),
            Self::RlpDecode(e) => write!(f, "RLP decode error: {e}"),
            Self::StoreError(e) => write!(f, "store error: {e}"),
            Self::GasPriceAboveCap => write!(f, "transaction's gas price exceeds cap"),
            Self::NonCanonicalNonce => write!(f, "transaction nonce has non-canonical encoding"),
            Self::NonceTooLong(length) => {
                write!(f, "transaction nonce byte length exceeds maximum: {length} > 8")
            }
            Self::SenderMissing => write!(f, "the sender account doesn't exist"),
            Self::InitCodeTooLarge => write!(f, "transaction's init code size is invalid"),
        }
    }
}

impl std::error::Error for PoolError {}

impl PoolError {
    /// A short, stable label for the activity summary. Deliberately a
    /// `&'static str` so the counters cannot grow without bound.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::AlreadyPending | Self::AlreadyQueued => "already-known",
            Self::NonceTooLow => "nonce-too-low",
            Self::NonceTooHigh => "nonce-too-high",
            Self::InsufficientFunds => "insufficient-funds",
            Self::GasLimitExceeded { .. } => "gas-limit-exceeded",
            Self::GasPriceTooLow => "gas-price-too-low",
            Self::IntrinsicGasTooHigh => "intrinsic-gas-too-high",
            Self::ReplacementGasPriceTooLow => "replacement-underpriced",
            Self::TxTooLarge { .. } => "too-large",
            Self::PoolFull => "pool-full",
            Self::InvalidSignature(_) => "invalid-signature",
            Self::InsufficientFundsForPendingAndNew => "insufficient-funds-pending",
            Self::AccountExceedsQuota => "quota",
            Self::RlpDecode(_) => "rlp-decode",
            Self::StoreError(_) => "store-error",
            Self::GasPriceAboveCap => "gas-price-above-cap",
            Self::NonCanonicalNonce | Self::NonceTooLong(_) => "non-canonical-nonce",
            Self::SenderMissing => "sender-missing",
            Self::InitCodeTooLarge => "init-code-too-large",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PooledTx {
    pub tx: Transaction,
    pub hash: B256,
    pub sender: Address,
    pub added_block: u64,
    pub added_time: Instant,
    pub encoded_size: usize,
}

/// Transactions grouped by sender, each sender's ordered by nonce.
pub type PoolGroups = Vec<(Address, Vec<(u64, Transaction)>)>;

/// Where the pool put a transaction it took: rskj's
/// `TransactionPoolAddResult.okPendingTransaction` and `okQueuedTransaction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admitted {
    Pending,
    Queued,
}

struct PoolInner {
    pending: HashMap<Address, BTreeMap<u64, PooledTx>>,
    queued: HashMap<Address, BTreeMap<u64, PooledTx>>,
    by_hash: HashMap<B256, Address>,
}

impl PoolInner {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            queued: HashMap::new(),
            by_hash: HashMap::new(),
        }
    }

    /// rskj `internalAddTransaction`'s first two questions: refused where
    /// the pending transactions hold one of this hash, or the queued ones.
    fn refuse_held(&self, hash: &B256) -> Result<(), PoolError> {
        let Some(sender) = self.by_hash.get(hash) else {
            return Ok(());
        };
        let pending = self
            .pending
            .get(sender)
            .is_some_and(|by_nonce| by_nonce.values().any(|held| held.hash == *hash));
        Err(if pending {
            PoolError::AlreadyPending
        } else {
            PoolError::AlreadyQueued
        })
    }

    /// rskj `PendingState.getNonce`: the nonce after the sender's last
    /// pending transaction, or the state's where that is further on.
    fn next_nonce(&self, sender: &Address, state_nonce: u64) -> u64 {
        self.pending
            .get(sender)
            .and_then(|by_nonce| by_nonce.keys().last())
            .map_or(state_nonce, |last| last.saturating_add(1).max(state_nonce))
    }
}

pub struct TransactionPool {
    inner: RwLock<PoolInner>,
    config: PoolConfig,
    chain_id: u64,
    store: Arc<BlockStore>,
    trie_store: Arc<dyn TrieStore>,
    /// rskj `TxQuotaChecker`. Behind its own lock: the quota decision is taken
    /// before the pool lock is acquired, so a slow quota refresh never holds up
    /// readers of the pool.
    quota: RwLock<crate::quota::QuotaChecker>,
    /// Shared with the executor, so a sender recovered here is not recovered
    /// again when the block carrying this transaction arrives. `None`
    /// disables it and every recovery is recomputed.
    sender_cache: Option<Arc<rustock_execution::sender_cache::SenderCache>>,
    /// Activity since the last summary.
    ///
    /// Not part of the rskj port -- rskj keeps no such counter. It exists
    /// because every line in the transaction path logs at `debug` and the node
    /// runs at `info`, so the pool is otherwise entirely unobservable.
    stats: RwLock<PoolStats>,
    /// Supplies the fee-market average for the low-gas-price factor. `None`
    /// keeps rskj's skip branch.
    gas_price: Option<Arc<crate::gas_price::GasPriceTracker>>,
    /// The chain's activations and constants, for the checks that depend on
    /// them. `None` keeps the plain checks.
    chain_rules: Option<ChainRules>,
    /// Told of every transaction admitted: rskj's
    /// `onPendingTransactionsReceived`, which the miner listens to. A slot
    /// rather than a builder argument because the miner is built after the
    /// pool.
    on_added: RwLock<Option<Arc<dyn Fn(&Transaction) + Send + Sync>>>,
}

/// What passed through the pool since the last time anyone asked.
///
/// The pool is otherwise silent at `info`: every line in the transaction path
/// logs at `debug` or `trace`, so without this there is no way to tell "the
/// rate limiter never fires because traffic is healthy" from "it never fires
/// because no transaction ever arrives". Those need very different responses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PoolActivity {
    /// Transactions offered to the pool, from peers and over RPC.
    pub offered: u64,
    /// Offered and accepted.
    pub accepted: u64,
    /// Removed because a block contained them.
    pub mined: u64,
    /// Rejections by reason, most common first.
    pub rejections: Vec<(&'static str, u64)>,
    /// Distinct senders the rate limiter refused.
    ///
    /// Read against the `quota` entry in `rejections`: one sender refused many
    /// times is the limiter working; many senders refused once each is the
    /// limiter misfiring on ordinary traffic.
    pub quota_senders: usize,
    /// The sender the limiter refused most often, and how often.
    pub quota_worst: Option<(Address, u64)>,
}

impl PoolActivity {
    /// True when nothing at all happened, so the reporter can stay quiet.
    pub fn is_empty(&self) -> bool {
        self.offered == 0 && self.mined == 0
    }

    pub fn rejected(&self) -> u64 {
        self.rejections.iter().map(|(_, n)| n).sum()
    }
}

#[derive(Default)]
struct PoolStats {
    offered: u64,
    accepted: u64,
    mined: u64,
    rejections: HashMap<&'static str, u64>,
    quota_by_sender: HashMap<Address, u64>,
}

impl TransactionPool {
    pub fn new(
        config: PoolConfig,
        chain_id: u64,
        store: Arc<BlockStore>,
        trie_store: Arc<dyn TrieStore>,
    ) -> Self {
        // rskj `TxValidatorNonceRangeValidator(accountSlots)` throws on
        // anything under one: zero slots would refuse every transaction as
        // "nonce too high", silently.
        assert!(config.account_slots >= 1, "account_slots must be at least 1, got {}", config.account_slots);
        let quota = crate::quota::QuotaChecker::new(config.quota.clone());
        Self {
            inner: RwLock::new(PoolInner::new()),
            config,
            chain_id,
            store,
            trie_store,
            quota: RwLock::new(quota),
            stats: RwLock::new(PoolStats::default()),
            gas_price: None,
            sender_cache: None,
            chain_rules: None,
            on_added: RwLock::new(None),
        }
    }

    /// Call `listener` with every transaction admitted from now on.
    pub fn set_on_added(&self, listener: Arc<dyn Fn(&Transaction) + Send + Sync>) {
        *self
            .on_added
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(listener);
    }

    /// Apply the checks that depend on the chain's activations and
    /// constants: the RSKIP252 per-transaction price cap, the sublist gas
    /// limit under RSKIP144, and the free Bridge transactions.
    pub fn with_chain_rules(mut self, rules: ChainRules) -> Self {
        self.chain_rules = Some(rules);
        self
    }

    /// Share the executor's sender cache, so a transaction recovered on
    /// admission is not recovered again when its block executes. Handing the
    /// same `Arc` to both is the whole point; a pool-private cache would miss
    /// exactly the hop worth caching.
    pub fn with_sender_cache(
        mut self,
        cache: Arc<rustock_execution::sender_cache::SenderCache>,
    ) -> Self {
        self.sender_cache = Some(cache);
        self
    }

    /// Attach the gas-price tracker, which enables the rate limiter's
    /// low-gas-price factor whenever the fee market is working.
    ///
    /// Without it the limiter takes rskj's own `createSkippingGasPriceFactor`
    /// branch, which pins that factor to 1 -- so a transaction priced at the
    /// block minimum costs four times less virtual gas than it should, and
    /// pricing at the floor is precisely the optimal play for the flooding
    /// this limiter exists to stop.
    pub fn with_gas_price_tracker(mut self, tracker: Arc<crate::gas_price::GasPriceTracker>) -> Self {
        self.gas_price = Some(tracker);
        self
    }

    /// Activity since the previous call, clearing the counters.
    ///
    /// Intended for a periodic reporter that stays silent when nothing
    /// happened, so a line in the log always means something did.
    pub fn take_activity(&self) -> PoolActivity {
        let mut stats = self.stats.write().unwrap_or_else(PoisonError::into_inner);
        let mut rejections: Vec<(&'static str, u64)> =
            stats.rejections.iter().map(|(k, v)| (*k, *v)).collect();
        rejections.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let quota_senders = stats.quota_by_sender.len();
        let quota_worst = stats
            .quota_by_sender
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(addr, n)| (*addr, *n));
        let activity = PoolActivity {
            offered: stats.offered,
            accepted: stats.accepted,
            mined: stats.mined,
            rejections,
            quota_senders,
            quota_worst,
        };
        *stats = PoolStats::default();
        activity
    }

    /// rskj `TransactionPoolImpl`'s `TxQuotaCleanerTimer`, which it schedules at
    /// `transaction.accountTxRateLimit.cleanerPeriod` minutes. Exposed rather
    /// than spawned internally so the caller owns the task; returns how many
    /// accounts were dropped.
    pub fn clean_quotas(&self) -> usize {
        self.quota
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clean_max_quotas(Instant::now())
    }

    /// The cleaner interval, or `None` when the clean is disabled.
    pub fn quota_cleaner_period(&self) -> Option<std::time::Duration> {
        self.quota
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .cleaner_period()
    }

    /// Virtual gas currently available to `address`, for diagnostics and tests.
    pub fn quota_of(&self, address: &Address) -> Option<f64> {
        self.quota
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .quota_of(address)
    }

    /// An address's quota as `debug_accountTransactionQuota` reports it.
    pub fn quota_report_of(&self, address: &Address) -> Option<(f64, u64)> {
        self.quota
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .quota_report_of(address, Instant::now())
    }

    /// Add a raw RLP-encoded transaction to the pool.
    /// Add a raw RLP-encoded transaction to the pool, recording the outcome.
    pub fn add_transaction(&self, raw: &[u8]) -> Result<B256, PoolError> {
        let result = self.add_transaction_inner(raw);
        {
            let mut stats = self.stats.write().unwrap_or_else(PoisonError::into_inner);
            stats.offered += 1;
            match &result {
                Ok(_) => stats.accepted += 1,
                Err(e) => *stats.rejections.entry(e.reason()).or_insert(0) += 1,
            }
        }
        result
    }

    /// rskj `TransactionPoolImpl.addTransaction`: the transaction itself
    /// ([`Self::admit`]) and then, where it went pending, the queued ones
    /// that were waiting for it ([`Self::promote_successors`]).
    fn add_transaction_inner(&self, raw: &[u8]) -> Result<B256, PoolError> {
        let tx = Transaction::decode(&mut &raw[..])
            .map_err(|e| PoolError::RlpDecode(format!("{e}")))?;

        // rskj keys a transaction by its hash (`getHash`), of the encoding it
        // rebuilds rather than of the bytes as sent (`Transaction::from_rskj`),
        // and measures it by that encoding too (`getSize`).
        let hash = tx.tx_hash();
        let encoded_size = tx.rlp_for_trie().len();

        // rskj asks whether it holds the hash before anything else, so a
        // transaction sent twice is told that, whatever has become of its
        // sender since.
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .refuse_held(&hash)?;

        // A transaction offered twice -- re-broadcast, or seen by both a peer
        // and the RPC -- is recovered once. The write goes to the pool tier,
        // which is what execution reads when the block carrying it arrives.
        let cached = self
            .sender_cache
            .as_ref()
            .and_then(|c| c.get_many(&[hash]).pop().flatten());
        let sender = match cached {
            Some(sender) => sender,
            None => {
                let recovered = tx
                    .recover_sender(self.chain_id)
                    .map_err(|e| PoolError::InvalidSignature(format!("{e}")))?;
                if let Some(c) = &self.sender_cache {
                    c.put_many(
                        rustock_execution::sender_cache::Origin::Pool,
                        [(hash, recovered)],
                    );
                }
                recovered
            }
        };

        let head_header = self.head_header()?;
        let account = self.account_state(&head_header, &sender);
        let nonce = tx.nonce;
        let pooled = PooledTx {
            tx: tx.clone(),
            hash,
            sender,
            added_block: head_header.number,
            added_time: Instant::now(),
            encoded_size,
        };

        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if self.admit(&mut inner, pooled, &head_header, account)? == Admitted::Pending {
            self.promote_successors(&mut inner, sender, nonce, &head_header, account);
        }

        debug!(tx_hash = %hash, sender = %sender, nonce, "Transaction added to pool");
        drop(inner);
        let listener = self
            .on_added
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(listener) = listener {
            listener(&tx);
        }
        Ok(hash)
    }

    /// rskj `TransactionPoolImpl.internalAddTransaction`, in its order: the
    /// hash, the validation against the head's state, the pending
    /// transaction it would replace, and then where it goes. A nonce past the
    /// sender's next one is queued, in the place of any queued one of that
    /// nonce, and nothing more is asked of it. Any other is pending, once the
    /// rate limiter takes it and the sender can pay for it along with their
    /// other pending transactions.
    fn admit(
        &self,
        inner: &mut PoolInner,
        pooled: PooledTx,
        header: &Header,
        account: Option<(u64, U256)>,
    ) -> Result<Admitted, PoolError> {
        inner.refuse_held(&pooled.hash)?;
        self.validate_tx(
            &pooled.tx,
            &pooled.sender,
            pooled.encoded_size,
            header,
            account,
        )?;
        let (state_nonce, balance) = account.unwrap_or_default();
        let (hash, sender, nonce) = (pooled.hash, pooled.sender, pooled.tx.nonce);

        // rskj `isBumpingGasPriceForSameNonceTx`: a higher price, and no less
        // than the old one raised by the bump, which rskj reckons in whole
        // numbers (`Coin.multiply`). Where the bump rounds to nothing, the
        // same price again doesn't replace. The rate limiter prices a
        // replacement by how much it overbids the transaction it displaces,
        // so it needs the displaced one.
        let replaced = inner
            .pending
            .get(&sender)
            .and_then(|by_nonce| by_nonce.get(&nonce))
            .map(|old| {
                (
                    old.hash,
                    old.tx.gas_price,
                    tx_facts(&old.tx, old.encoded_size),
                )
            });
        if let Some((_, old_price, _)) = &replaced {
            let new_price = pooled.tx.gas_price;
            let bumped = alloy_primitives::U512::from(*old_price)
                * alloy_primitives::U512::from(100 + self.config.gas_price_bump)
                / alloy_primitives::U512::from(100);
            if *old_price >= new_price || bumped > alloy_primitives::U512::from(new_price) {
                return Err(PoolError::ReplacementGasPriceTooLow);
            }
        }

        let queues = nonce > inner.next_nonce(&sender, state_nonce);
        let displaced = if queues {
            inner
                .queued
                .get(&sender)
                .and_then(|by_nonce| by_nonce.get(&nonce))
                .map(|old| old.hash)
        } else {
            replaced.as_ref().map(|(old_hash, ..)| *old_hash)
        };

        // This pool's own ceiling, which rskj's has none of. A transaction
        // that takes another's place needs no room; any other has the
        // furthest-out queued transaction make way for it, once everything
        // else is settled. Queued entries have future nonces, so they are not
        // executable yet and are the class an attacker can most cheaply pile
        // up. Pending transactions are never evicted.
        let needs_room =
            displaced.is_none() && inner.by_hash.len() >= self.config.max_pool_transactions;
        if needs_room && inner.queued.is_empty() {
            return Err(PoolError::PoolFull);
        }

        if !queues {
            self.take_quota(&pooled, replaced.as_ref().map(|(.., facts)| facts), header)?;

            // rskj `senderCanPayPendingTransactionsAndNewTx`, after the rate
            // limiter. `getTxBaseCost`: the value, plus the gas only when the
            // transaction costs anything -- a free Bridge transaction carries
            // its value and nothing else.
            let base_cost = |t: &Transaction| -> Option<U256> {
                let free = self
                    .chain_rules
                    .as_ref()
                    .is_some_and(|r| r.is_free_tx(t, &sender, header.number));
                if free {
                    Some(t.value)
                } else {
                    tx_cost(t)
                }
            };
            let mut total_cost = base_cost(&pooled.tx);
            if let Some(pending_map) = inner.pending.get(&sender) {
                for (other, ptx) in pending_map {
                    if *other != nonce {
                        total_cost = total_cost
                            .zip(base_cost(&ptx.tx))
                            .and_then(|(total, cost)| total.checked_add(cost));
                    }
                }
            }
            // rskj adds these up in whole numbers (`Coin`): a sum past 256
            // bits is more than any balance.
            if total_cost.is_none_or(|total| total > balance) {
                return Err(PoolError::InsufficientFundsForPendingAndNew);
            }
        }

        // All checks passed: the pool changes.
        if needs_room {
            Self::evict_one_queued(inner);
        }
        if let Some(old_hash) = displaced {
            inner.by_hash.remove(&old_hash);
        }
        inner.by_hash.insert(hash, sender);
        let side = if queues {
            &mut inner.queued
        } else {
            &mut inner.pending
        };
        side.entry(sender).or_default().insert(nonce, pooled);
        Ok(if queues {
            Admitted::Queued
        } else {
            Admitted::Pending
        })
    }

    /// rskj `TxQuotaChecker.acceptTx`, where `internalAddTransaction` asks
    /// it: of a transaction on its way to pending, after every validation
    /// and after the replacement has been resolved, and before the sender's
    /// funds are counted. A queued transaction is not asked about until it
    /// is promoted, and an invalid one never, so neither consumes an honest
    /// account's virtual gas.
    fn take_quota(
        &self,
        pooled: &PooledTx,
        replaced: Option<&crate::quota::TxFacts>,
        header: &Header,
    ) -> Result<(), PoolError> {
        let accounts = TrieAccountView::new(header.state_root, &*self.trie_store);
        // rskj supplies the average only when the fee market is working --
        // `isFeeMarketWorking()` false takes its
        // `createSkippingGasPriceFactor` branch, which pins the
        // low-gas-price factor to 1. On a chain with spare capacity that
        // is the usual path on rskj too; the difference is that it
        // recovers when blocks fill up, which this now does.
        let avg_gas_price = self
            .gas_price
            .as_ref()
            .and_then(|t| t.is_fee_market_working().then(|| t.gas_price()));
        let ctx = crate::quota::QuotaContext::of(header, avg_gas_price);
        let tx = &pooled.tx;
        let receiver = (tx.to.len() == 20).then(|| Address::from_slice(tx.to.as_ref()));
        let accepted = self
            .quota
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .accept_tx(
                pooled.sender,
                receiver,
                &tx_facts(tx, pooled.encoded_size),
                replaced,
                &ctx,
                &accounts,
                Instant::now(),
            );
        if accepted {
            return Ok(());
        }
        debug!(
            tx_hash = %pooled.hash, sender = %pooled.sender, nonce = tx.nonce,
            "Transaction refused: account exceeds virtual gas quota"
        );
        *self
            .stats
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .quota_by_sender
            .entry(pooled.sender)
            .or_insert(0) += 1;
        Err(PoolError::AccountExceedsQuota)
    }

    /// rskj `addSuccessors`: the queued transaction next in line after one
    /// that went pending is taken out of the queue and offered again, as a
    /// new one would be, and so on until one doesn't go pending. One that is
    /// refused then is gone.
    fn promote_successors(
        &self,
        inner: &mut PoolInner,
        sender: Address,
        after: u64,
        header: &Header,
        account: Option<(u64, U256)>,
    ) {
        let mut nonce = after;
        loop {
            let Some(next) = nonce.checked_add(1) else {
                return;
            };
            nonce = next;
            let Some(queue) = inner.queued.get_mut(&sender) else {
                return;
            };
            let Some(mut successor) = queue.remove(&nonce) else {
                return;
            };
            if queue.is_empty() {
                inner.queued.remove(&sender);
            }
            inner.by_hash.remove(&successor.hash);
            // rskj notes the block and the time again, as for a new one.
            successor.added_block = header.number;
            successor.added_time = Instant::now();
            if !matches!(
                self.admit(inner, successor, header, account),
                Ok(Admitted::Pending)
            ) {
                return;
            }
        }
    }

    /// rskj `TxPendingValidator.isValid`, step by step and in its order, so
    /// that of two faults the one rskj names is the one named here.
    /// `account` is the sender's nonce and balance in the head's state, or
    /// none where the state holds no such account.
    fn validate_tx(
        &self,
        tx: &Transaction,
        sender: &Address,
        encoded_size: usize,
        header: &Header,
        account: Option<(u64, U256)>,
    ) -> Result<(), PoolError> {
        let rules = self.chain_rules.as_ref();
        // rskj `basicTxCost == 0`: a free Bridge transaction.
        let is_free = rules.is_some_and(|r| r.is_free_tx(tx, sender, header.number));

        // Before the steps: an account to pay for it, unless it costs
        // nothing; RSKIP438's limit on a creation's init code; and the size
        // (`TX_MAX_SIZE`).
        if account.is_none() && !is_free {
            return Err(PoolError::SenderMissing);
        }
        let (state_nonce, balance) = account.unwrap_or_default();
        let metered = rules.is_some_and(|r| r.hardfork_cfg.has_initcode_metering(header.number));
        if metered && tx.to.is_empty() && tx.input.len() > MAX_INIT_CODE_SIZE {
            return Err(PoolError::InitCodeTooLarge);
        }
        if encoded_size > self.config.max_tx_size {
            return Err(PoolError::TxTooLarge {
                size: encoded_size,
                max: self.config.max_tx_size,
            });
        }

        // 1. Not null (`TxNotNullValidator`), and 2. not REMASC
        //    (`TxValidatorNotRemascTxValidator`): rskj refuses a
        //    `RemascTransaction`, which only a block's last transaction is,
        //    so never one offered alone.

        // 3. Gas limit (`TxValidatorGasLimitValidator`), against the block's
        //    limit or, under RSKIP144, the larger sublist's.
        let bound = rules.map_or(header.gas_limit.saturating_to::<u64>(), |r| r.gas_limit_bound(header));
        if tx.gas_limit > U256::from(bound) || tx.gas_limit > U256::from(TRANSACTION_GAS_CAP) {
            return Err(PoolError::GasLimitExceeded {
                gas_limit: tx.gas_limit,
                bound,
            });
        }

        // 4. The account's state (`TxValidatorAccountStateValidator`): a
        //    missing one was refused above, and a deleted one is a mark only
        //    a repository being written to carries.

        // 5. The nonce's encoding (`TxValidatorNonceEncodingValidator`), on
        //    the nonce's bytes as rskj holds them (`getNonce`), which the
        //    encoding rskj rebuilds keeps.
        let encoded = tx.rlp_for_trie();
        match raw_nonce_bytes(&encoded) {
            Some(nonce) if nonce.len() > 8 => return Err(PoolError::NonceTooLong(nonce.len())),
            Some(nonce) if nonce_bytes_are_canonical(nonce) => {}
            _ => return Err(PoolError::NonCanonicalNonce),
        }

        // 6. Nonce range (`TxValidatorNonceRangeValidator`)
        if tx.nonce < state_nonce {
            return Err(PoolError::NonceTooLow);
        }
        if tx.nonce >= state_nonce + self.config.account_slots {
            return Err(PoolError::NonceTooHigh);
        }

        // 7. Balance >= gas cost (`TxValidatorAccountBalanceValidator`),
        //    which a free transaction skips. rskj multiplies in whole
        //    numbers (`Coin.multiply`), so a cost past 256 bits is more
        //    than any balance.
        if !is_free {
            let gas_cost = tx.gas_price.checked_mul(tx.gas_limit);
            if gas_cost.is_none_or(|gas_cost| balance < gas_cost) {
                return Err(PoolError::InsufficientFunds);
            }
        }

        // 8. Minimum gas price (`TxValidatorMinimuGasPriceValidator`)
        if tx.gas_price < header.minimum_gas_price {
            return Err(PoolError::GasPriceTooLow);
        }

        // 9. Intrinsic gas (`TxValidatorIntrinsicGasLimitValidator`): a free
        //    transaction costs nothing, so any limit, zero included, fits.
        let intrinsic = match rules {
            _ if is_free => 0,
            Some(rules) => rules.transaction_cost(tx, header.number),
            None => intrinsic_gas(tx),
        };
        if U256::from(intrinsic) > tx.gas_limit {
            return Err(PoolError::IntrinsicGasTooHigh);
        }

        // 10. Price cap (`TxValidatorMaximumGasPriceValidator`), RSKIP252.
        if let Some(cap) = rules.and_then(|r| r.gas_price_cap(header)) {
            if tx.gas_price > cap {
                return Err(PoolError::GasPriceAboveCap);
            }
        }

        Ok(())
    }

    /// Remove transactions that are included in a newly imported block.
    /// Drops the queued transaction with the highest nonce, returning whether
    /// one was removed. Highest nonce is the furthest from being executable and
    /// so the least valuable entry to keep.
    fn evict_one_queued(inner: &mut PoolInner) -> bool {
        let victim = inner
            .queued
            .iter()
            .filter_map(|(addr, m)| m.keys().last().map(|&nonce| (*addr, nonce)))
            .max_by_key(|(_, nonce)| *nonce);

        let Some((addr, nonce)) = victim else {
            return false;
        };

        let removed = inner.queued.get_mut(&addr).and_then(|m| m.remove(&nonce));
        if let Some(tx) = removed {
            inner.by_hash.remove(&tx.hash);
            if inner.queued.get(&addr).is_some_and(|m| m.is_empty()) {
                inner.queued.remove(&addr);
            }
            debug!("Pool full: evicted queued tx {:?} nonce {}", tx.hash, nonce);
            true
        } else {
            false
        }
    }

    pub fn remove_mined(&self, transactions: &[Transaction]) {
        let mut removed = 0u64;
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        for tx in transactions {
            let hash = tx.tx_hash();
            if Self::remove_by_hash(&mut inner, &hash, tx.nonce) {
                removed += 1;
            }
        }
        drop(inner);
        if removed > 0 {
            self.stats
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .mined += removed;
        }
    }

    /// Remove transactions the miner found invalid while building a
    /// template: rskj `BlockToMineBuilder.removePendingTransactions` on
    /// `BlockResult.getInvalidTransactions()`. Returns how many were there.
    pub fn remove_by_hashes(&self, hashes: &[B256]) -> usize {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let mut removed = 0;
        for hash in hashes {
            let nonce = inner
                .by_hash
                .get(hash)
                .and_then(|sender| {
                    inner.pending.get(sender).or_else(|| inner.queued.get(sender)).and_then(|m| {
                        m.iter().find(|(_, p)| p.hash == *hash).map(|(n, _)| *n)
                    })
                });
            if let Some(nonce) = nonce {
                if Self::remove_by_hash(&mut inner, hash, nonce) {
                    removed += 1;
                }
            }
        }
        removed
    }

    /// Drop one transaction by hash from every index. True if it was there.
    fn remove_by_hash(inner: &mut PoolInner, hash: &B256, nonce: u64) -> bool {
        let Some(sender) = inner.by_hash.remove(hash) else {
            return false;
        };
        if let Some(map) = inner.pending.get_mut(&sender) {
            map.remove(&nonce);
            if map.is_empty() {
                inner.pending.remove(&sender);
            }
        }
        if let Some(map) = inner.queued.get_mut(&sender) {
            map.remove(&nonce);
            if map.is_empty() {
                inner.queued.remove(&sender);
            }
        }
        true
    }

    /// Evict transactions older than the configured thresholds.
    pub fn evict_outdated(&self, current_block: u64) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let threshold = self.config.outdated_threshold;
        let timeout = std::time::Duration::from_secs(self.config.outdated_timeout_secs);
        let now = Instant::now();

        let mut to_remove = Vec::new();

        for map in [&inner.pending, &inner.queued] {
            for (sender, nonce_map) in map {
                for (nonce, ptx) in nonce_map {
                    let by_block = current_block > ptx.added_block + threshold;
                    let by_time = now.duration_since(ptx.added_time) > timeout;
                    if by_block || by_time {
                        to_remove.push((*sender, *nonce, ptx.hash));
                    }
                }
            }
        }

        for (sender, nonce, hash) in to_remove {
            inner.by_hash.remove(&hash);
            if let Some(map) = inner.pending.get_mut(&sender) {
                map.remove(&nonce);
                if map.is_empty() {
                    inner.pending.remove(&sender);
                }
            }
            if let Some(map) = inner.queued.get_mut(&sender) {
                map.remove(&nonce);
                if map.is_empty() {
                    inner.queued.remove(&sender);
                }
            }
        }
    }

    /// Get a transaction from the pool by hash.
    pub fn get(&self, hash: &B256) -> Option<PooledTx> {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let sender = inner.by_hash.get(hash)?;
        for map in [&inner.pending, &inner.queued] {
            if let Some(nonce_map) = map.get(sender) {
                for ptx in nonce_map.values() {
                    if ptx.hash == *hash {
                        return Some(ptx.clone());
                    }
                }
            }
        }
        None
    }

    /// Return all pending transactions ordered by gas price (desc), nonce (asc) per sender.
    pub fn pending_transactions(&self) -> Vec<PooledTx> {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let mut result = Vec::new();
        for nonce_map in inner.pending.values() {
            for ptx in nonce_map.values() {
                result.push(ptx.clone());
            }
        }
        result.sort_by(|a, b| {
            b.tx.gas_price.cmp(&a.tx.gas_price).then(a.tx.nonce.cmp(&b.tx.nonce))
        });
        result
    }

    /// The whole pool, grouped by sender and ordered by nonce within each
    /// sender -- the shape `txpool_content` and `txpool_inspect` report.
    ///
    /// Taken under one read lock so the two halves cannot disagree: a
    /// transaction promoted from queued to pending between two separate reads
    /// would otherwise appear twice, or vanish.
    #[allow(clippy::type_complexity)]
    pub fn content(&self) -> (PoolGroups, PoolGroups) {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let collect = |side: &HashMap<Address, BTreeMap<u64, PooledTx>>| -> PoolGroups {
            let mut out: Vec<(Address, Vec<(u64, Transaction)>)> = side
                .iter()
                .map(|(addr, by_nonce)| {
                    (
                        *addr,
                        by_nonce
                            .iter()
                            .map(|(nonce, ptx)| (*nonce, ptx.tx.clone()))
                            .collect(),
                    )
                })
                .collect();
            // The senders come out of a HashMap, so without this the same pool
            // renders in a different order on every call.
            out.sort_by_key(|(addr, _)| *addr);
            out
        };
        (collect(&inner.pending), collect(&inner.queued))
    }

    /// Return counts of pending and queued transactions.
    pub fn status(&self) -> (usize, usize) {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let pending: usize = inner.pending.values().map(|m| m.len()).sum();
        let queued: usize = inner.queued.values().map(|m| m.len()).sum();
        (pending, queued)
    }

    /// Return the pending nonce for an address (state nonce + pending count).
    pub fn pending_nonce(&self, addr: &Address) -> Option<u64> {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        inner
            .pending
            .get(addr)
            .and_then(|m| m.keys().last().map(|n| n + 1))
    }

    fn head_header(&self) -> Result<Header, PoolError> {
        let hash = self
            .store
            .head()
            .map_err(|e| PoolError::StoreError(format!("{e}")))?
            .ok_or_else(|| PoolError::StoreError("no head".into()))?;
        self.store
            .header(hash)
            .map_err(|e| PoolError::StoreError(format!("{e}")))?
            .ok_or_else(|| PoolError::StoreError("head header not found".into()))
    }

    /// The nonce and balance of `addr` in the state `header` names, or none
    /// where that state holds no such account: rskj's `getAccountState`,
    /// which is null then.
    fn account_state(&self, header: &Header, addr: &Address) -> Option<(u64, U256)> {
        let root_data = self.trie_store.get(header.state_root.as_slice())?;
        let root = TrieNode::from_message(&root_data, &*self.trie_store);
        let key = account_key(addr);
        let data = root.get(&TrieKeySlice::from_key(&key), &*self.trie_store)?;
        let account = AccountState::decode(&data).ok()?;
        Some((account.nonce.to::<u64>(), account.balance))
    }
}

/// `AccountView` over the state trie at a given root — what the rate limiter
/// needs to ask about an address (rskj's `RepositorySnapshot` and
/// `PendingState` in one).
///
/// The root node is resolved once and reused: `accept_tx` asks about both the
/// sender and the receiver, and each question is a trie descent.
struct TrieAccountView<'a> {
    root: Option<TrieNode>,
    store: &'a dyn TrieStore,
}

impl<'a> TrieAccountView<'a> {
    fn new(state_root: B256, store: &'a dyn TrieStore) -> Self {
        let root = store
            .get(state_root.as_slice())
            .map(|d| TrieNode::from_message(&d, store));
        Self { root, store }
    }

    fn lookup(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        let root = self.root.as_ref()?;
        root.get(&TrieKeySlice::from_key(&key), self.store)
    }
}

impl crate::quota::AccountView for TrieAccountView<'_> {
    fn nonce(&self, address: &Address) -> u64 {
        self.lookup(account_key(address))
            .and_then(|d| AccountState::decode(&d).ok())
            .map(|a| a.nonce.to::<u64>())
            .unwrap_or(0)
    }

    /// rskj `isContract`: the account has code associated with it. In the
    /// unitrie that is a node under the account's code key.
    fn is_contract(&self, address: &Address) -> bool {
        self.lookup(code_key(address)).is_some_and(|c| !c.is_empty())
    }

    /// rskj `isExist`: the account node is present at all.
    fn exists(&self, address: &Address) -> bool {
        self.lookup(account_key(address)).is_some()
    }
}

/// The facts the rate limiter needs from a transaction.
fn tx_facts(tx: &Transaction, encoded_size: usize) -> crate::quota::TxFacts {
    crate::quota::TxFacts {
        nonce: tx.nonce,
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price,
        size: encoded_size,
    }
}

/// Compute the cost of a transaction: value + gas_price * gas_limit. `None`
/// where that is past 256 bits, and so more than any balance: rskj reckons it
/// in whole numbers (`TransactionPoolImpl.getTxBaseCost`).
fn tx_cost(tx: &Transaction) -> Option<U256> {
    tx.gas_price
        .checked_mul(tx.gas_limit)?
        .checked_add(tx.value)
}

/// Compute the intrinsic gas cost of a transaction (matching rskj).
pub fn intrinsic_gas(tx: &Transaction) -> u64 {
    let base = if tx.to.is_empty() { 53_000u64 } else { 21_000u64 };

    let calldata_cost: u64 = tx
        .input
        .iter()
        .map(|&b| if b == 0 { 4u64 } else { 16u64 })
        .sum();

    base + calldata_cost
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bloom, Bytes, U256};
    use alloy_rlp::Encodable;
    use k256::ecdsa::SigningKey;
    use rustock_trie::MemoryTrieStore;
    use sha3::{Digest, Keccak256};
    use tempfile::tempdir;

    fn test_config() -> PoolConfig {
        PoolConfig {
            account_slots: 16,
            gas_price_bump: 40,
            outdated_threshold: 10,
            outdated_timeout_secs: 650,
            max_tx_size: MAX_TX_SIZE,
            max_pool_transactions: MAX_POOL_TRANSACTIONS,
            // The production default, so the pool's own tests exercise the
            // configuration the node actually runs.
            quota: crate::quota::QuotaConfig::default(),
        }
    }

    fn test_header() -> Header {
        Header {
            number: 100,
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::ZERO,
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(59_240_000),
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

    fn setup_pool_with_account(
        balance: U256,
        nonce: u64,
    ) -> (TransactionPool, SigningKey, Address) {
        setup_pool_with_config(balance, nonce, test_config())
    }

    fn setup_pool_with_config(
        balance: U256,
        nonce: u64,
        config: PoolConfig,
    ) -> (TransactionPool, SigningKey, Address) {
        setup_pool_with_rules(balance, nonce, config, None)
    }

    /// A pool with the chain rules rskj's `TxPendingValidator` reads.
    fn setup_pool_with_rules(
        balance: U256,
        nonce: u64,
        config: PoolConfig,
        rules: Option<ChainRules>,
    ) -> (TransactionPool, SigningKey, Address) {
        setup_pool_on(test_header(), balance, nonce, config, rules)
    }

    /// [`setup_pool_with_rules`] on a head of the test's own choosing.
    fn setup_pool_on(
        mut header: Header,
        balance: U256,
        nonce: u64,
        config: PoolConfig,
        rules: Option<ChainRules>,
    ) -> (TransactionPool, SigningKey, Address) {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(nonce), balance);
        let key = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        // Keep dir alive by leaking it (temp dir will be cleaned up on process exit)
        let mut pool = TransactionPool::new(config, 33, store, trie_store);
        if let Some(rules) = rules {
            pool = pool.with_chain_rules(rules);
        }
        std::mem::forget(dir);
        (pool, signing_key, addr)
    }

    /// `rules` for a chain where everything, RSKIP252 included, is active
    /// from genesis and a transaction to the Bridge is never free.
    fn regtest_rules() -> ChainRules {
        ChainRules::for_chain(rustock_execution::hardfork::RskHardforkConfig::all_active(33), 6_800_000)
    }

    /// A node on rskj's regtest (an rskj genesis file) gives the pool rskj's
    /// regtest Bridge constants, so the pool counts the federators' Bridge
    /// calls free as the block processor does; rustock's own regtest has none.
    #[test]
    fn the_pool_takes_rskj_regtests_free_senders() {
        let rskj = rustock_execution::bridge::constants::BridgeConstants::rskj_regtest();
        let expected = rustock_execution::executor::free_bridge_senders(&rskj);
        let rules = regtest_rules().with_bridge_constants(&rskj);
        assert_eq!(rules.free_bridge_senders, expected);
        // rskj's regtest adds its three federators to the five authorizers.
        assert_eq!(
            regtest_rules().free_bridge_senders.len() + 3,
            expected.len()
        );
    }

    fn sign_tx(tx: &mut Transaction, key: &SigningKey, chain_id: u64) {
        let hash = tx.signing_hash_eip155(chain_id);
        let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = key
            .sign_prehash_recoverable(hash.as_slice())
            .unwrap();
        let sig_bytes = signature.to_bytes();
        tx.r = U256::from_be_slice(&sig_bytes[..32]);
        tx.s = U256::from_be_slice(&sig_bytes[32..]);
        tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
    }

    fn make_tx(nonce: u64, gas_price: u64) -> Transaction {
        Transaction {
            nonce,
            gas_price: U256::from(gas_price),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(1000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        }
    }

    fn encode_tx(tx: &Transaction) -> Vec<u8> {
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        buf
    }

    /// A transaction signed for `chain_id` (not 0) over its six fields as
    /// given, each already an RLP item, as rskj signs and sends what its own
    /// builder writes: a zero gas limit, for one, is the byte 0x00 there,
    /// where canonical RLP writes zero empty, and rskj cannot read empty.
    fn rskj_signed(fields: &[u8], key: &SigningKey, chain_id: u64) -> Vec<u8> {
        fn list(payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            alloy_rlp::Header {
                list: true,
                payload_length: payload.len(),
            }
            .encode(&mut out);
            out.extend_from_slice(payload);
            out
        }
        let mut unsigned = fields.to_vec();
        chain_id.encode(&mut unsigned);
        unsigned.extend_from_slice(&[0x80, 0x80]);
        let hash: [u8; 32] = Keccak256::digest(list(&unsigned)).into();
        let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            key.sign_prehash_recoverable(&hash).unwrap();
        let sig_bytes = signature.to_bytes();
        let mut signed = fields.to_vec();
        (chain_id * 2 + 35 + u64::from(recid.to_byte())).encode(&mut signed);
        U256::from_be_slice(&sig_bytes[..32]).encode(&mut signed);
        U256::from_be_slice(&sig_bytes[32..]).encode(&mut signed);
        list(&signed)
    }

    // ========== Account transaction rate limiting (rskj TxQuotaChecker) ==========

    /// The abuse the limiter exists to stop, end to end through the pool:
    /// broadcast a large transaction, replace it, repeat. Every node that
    /// accepts it stores and relays it; nothing is ever paid because nothing is
    /// ever mined.
    ///
    /// Each replacement is priced by how little it overbids (rskj's
    /// `replacementFactor = 1 + 1/ratio`), so a sender doing this at the
    /// minimum 40% bump runs out of virtual gas and is refused with
    /// `AccountExceedsQuota`.
    #[test]
    fn test_quota_refuses_an_endless_replacement_flood() {
        // The 40% bump compounds, so the balance must be absurd for this test
        // to be about the quota rather than about running out of money. With
        // 1e22 the sender goes broke after ~51 replacements, before the quota
        // bites at ~126 -- which is a different test.
        let balance = U256::from(10u64).pow(U256::from(60));
        let (pool, key, _addr) = setup_pool_with_account(balance, 5);

        // The price is tracked in U256: 40% compounding overruns u64 after
        // about 65 replacements, long before the quota bites.
        let mut gas_price = U256::from(59_240_000u64);
        let mut accepted = 0usize;
        let mut refused_for_quota = false;

        for _ in 0..500 {
            let mut tx = make_tx(5, 0);
            tx.gas_price = gas_price;
            // A full-block gas limit is what makes this expensive to relay.
            tx.gas_limit = U256::from(6_800_000u64);
            sign_tx(&mut tx, &key, 33);
            match pool.add_transaction(&encode_tx(&tx)) {
                Ok(_) => accepted += 1,
                Err(PoolError::AccountExceedsQuota) => {
                    refused_for_quota = true;
                    break;
                }
                Err(e) => panic!("unexpected rejection: {e}"),
            }
            gas_price = gas_price * U256::from(140) / U256::from(100); // the pool's bump
        }

        assert!(accepted > 0, "the first replacements must be accepted");
        assert!(
            refused_for_quota,
            "an account replacing a full-block transaction forever must eventually \
             be refused; {accepted} were accepted"
        );
    }

    /// The limiter must not disturb ordinary use. A normal account sending
    /// normal transactions never notices it.
    #[test]
    fn test_quota_does_not_affect_ordinary_transactions() {
        let balance = U256::from(10u64).pow(U256::from(20));
        let (pool, key, _addr) = setup_pool_with_account(balance, 0);

        for nonce in 0..16u64 {
            let mut tx = make_tx(nonce, 59_240_000);
            sign_tx(&mut tx, &key, 33);
            pool.add_transaction(&encode_tx(&tx))
                .unwrap_or_else(|e| panic!("ordinary tx at nonce {nonce} rejected: {e}"));
        }
        assert_eq!(pool.status().0, 16);
    }

    /// With the limiter switched off, the same flood that is refused above is
    /// accepted — proving the rejection comes from the limiter and not from
    /// some other pool rule.
    #[test]
    fn test_quota_disabled_accepts_what_it_would_otherwise_refuse() {
        let config = PoolConfig {
            quota: crate::quota::QuotaConfig { enabled: false, ..Default::default() },
            ..test_config()
        };
        let balance = U256::from(10u64).pow(U256::from(60));
        let (pool, key, _addr) = setup_pool_with_config(balance, 5, config);

        let mut gas_price = U256::from(59_240_000u64);
        for i in 0..200 {
            let mut tx = make_tx(5, 0);
            tx.gas_price = gas_price;
            tx.gas_limit = U256::from(6_800_000u64);
            sign_tx(&mut tx, &key, 33);
            match pool.add_transaction(&encode_tx(&tx)) {
                Ok(_) => {}
                Err(e) => panic!("replacement {i} rejected with the limiter off: {e}"),
            }
            gas_price = gas_price * U256::from(140) / U256::from(100);
        }
    }

    /// A stricter configuration refuses sooner. This is what makes the tunables
    /// worth exposing: an operator under pressure can tighten them without a
    /// rebuild.
    #[test]
    fn test_quota_configuration_tightens_the_limit() {
        let count_accepted = |percent: f64, multiplier: u64| {
            let config = PoolConfig {
                quota: crate::quota::QuotaConfig {
                    max_gas_per_second_percent: percent,
                    max_quota_gas_multiplier: multiplier,
                    ..Default::default()
                },
                ..test_config()
            };
            let balance = U256::from(10u64).pow(U256::from(60));
            let (pool, key, _addr) = setup_pool_with_config(balance, 5, config);
            let mut gas_price = U256::from(59_240_000u64);
            let mut n = 0;
            for _ in 0..500 {
                let mut tx = make_tx(5, 0);
                tx.gas_price = gas_price;
                tx.gas_limit = U256::from(6_800_000u64);
                sign_tx(&mut tx, &key, 33);
                if pool.add_transaction(&encode_tx(&tx)).is_err() {
                    break;
                }
                n += 1;
                gas_price = gas_price * U256::from(140) / U256::from(100);
            }
            n
        };

        let lenient = count_accepted(0.9, 2_000);
        let strict = count_accepted(0.9, 10);
        assert!(
            strict < lenient,
            "a smaller quota multiplier must refuse sooner: strict {strict}, lenient {lenient}"
        );
    }

    /// The quota check is the LAST gate. An invalid transaction must be
    /// rejected for its own reason and must not consume the sender's virtual
    /// gas — otherwise anyone could drain an honest account's quota by
    /// broadcasting rubbish signed with its key.
    #[test]
    fn test_invalid_transactions_do_not_consume_quota() {
        let balance = U256::from(10u64).pow(U256::from(20));
        let (pool, key, addr) = setup_pool_with_account(balance, 5);

        // Prime the account so it is tracked, then read its quota.
        let mut good = make_tx(5, 59_240_000);
        sign_tx(&mut good, &key, 33);
        pool.add_transaction(&encode_tx(&good)).unwrap();
        let after_good = pool.quota_of(&addr).expect("sender is tracked");

        // A transaction below the block's minimum gas price is refused by an
        // earlier rule.
        let mut bad = make_tx(6, 1);
        sign_tx(&mut bad, &key, 33);
        assert!(matches!(
            pool.add_transaction(&encode_tx(&bad)),
            Err(PoolError::GasPriceTooLow)
        ));

        let after_bad = pool.quota_of(&addr).expect("sender is still tracked");
        assert_eq!(
            after_good, after_bad,
            "a transaction rejected by an earlier rule must not cost virtual gas"
        );
    }

    /// The periodic sweep is reachable from the pool, and reports what it did.
    #[test]
    fn test_quota_cleaner_is_wired_to_the_pool() {
        let balance = U256::from(10u64).pow(U256::from(20));
        let (pool, key, addr) = setup_pool_with_account(balance, 5);

        let mut tx = make_tx(5, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).unwrap();
        assert!(pool.quota_of(&addr).is_some());

        // Default period is rskj's 30 minutes.
        assert_eq!(
            pool.quota_cleaner_period(),
            Some(std::time::Duration::from_secs(30 * 60))
        );

        // Immediately after spending, the account is BELOW the ceiling, so the
        // sweep must keep it -- dropping it here would lose the record of what
        // it just spent.
        assert_eq!(pool.clean_quotas(), 0, "an account below the ceiling is kept");
        assert!(pool.quota_of(&addr).is_some());

        // It spent ~35,000 virtual gas out of 12.24 billion, and accrues 6.12
        // million per second, so it is back at the ceiling within microseconds.
        // Once there it carries no information and is dropped.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let dropped = pool.clean_quotas();
        assert_eq!(dropped, 1, "an account at the ceiling carries no information");
        assert!(pool.quota_of(&addr).is_none());
    }

    /// The rejection counter is what makes a misfiring limiter visible. The
    /// summary must distinguish one abusive sender from many ordinary ones,
    /// because that is the difference between "working" and "broken".
    #[test]
    fn test_quota_rejections_are_counted_and_reported() {
        let balance = U256::from(10u64).pow(U256::from(60));
        let (pool, key, addr) = setup_pool_with_account(balance, 5);

        // Nothing has happened yet: the report must be empty, not absent.
        assert!(pool.take_activity().is_empty());

        let mut gas_price = U256::from(59_240_000u64);
        let mut refusals = 0u64;
        for _ in 0..500 {
            let mut tx = make_tx(5, 0);
            tx.gas_price = gas_price;
            tx.gas_limit = U256::from(6_800_000u64);
            sign_tx(&mut tx, &key, 33);
            if matches!(
                pool.add_transaction(&encode_tx(&tx)),
                Err(PoolError::AccountExceedsQuota)
            ) {
                refusals += 1;
                if refusals == 3 {
                    break;
                }
                continue;
            }
            gas_price = gas_price * U256::from(140) / U256::from(100);
        }
        assert_eq!(refusals, 3, "the flood must be refused at some point");

        let a = pool.take_activity();
        assert_eq!(a.rejections.iter().find(|(r, _)| *r == "quota").map(|(_, n)| *n), Some(3));
        assert_eq!(a.quota_senders, 1, "one abusive sender, not many");
        assert_eq!(a.quota_worst, Some((addr, 3)));

        // Taking the summary clears it, so each report covers one window.
        assert!(pool.take_activity().is_empty());
    }

    /// The summary is what makes the pool observable at all: every line in the
    /// transaction path logs at `debug` and the node runs at `info`, so without
    /// this an empty `txpool_status` is equally consistent with healthy traffic
    /// already mined and with nothing ever arriving.
    #[test]
    fn test_pool_activity_is_counted_across_every_outcome() {
        let balance = U256::from(10u64).pow(U256::from(20));
        let (pool, key, _addr) = setup_pool_with_account(balance, 0);

        // Silent when nothing has happened.
        assert!(pool.take_activity().is_empty());

        // One accepted.
        let mut good = make_tx(0, 59_240_000);
        sign_tx(&mut good, &key, 33);
        let raw = encode_tx(&good);
        pool.add_transaction(&raw).unwrap();

        // The same one again: rejected as already known, which is ordinary --
        // several peers relay the same transaction.
        assert!(matches!(
            pool.add_transaction(&raw),
            Err(PoolError::AlreadyPending)
        ));

        // One rejected for an unrelated reason.
        let mut cheap = make_tx(1, 1);
        sign_tx(&mut cheap, &key, 33);
        assert!(matches!(
            pool.add_transaction(&encode_tx(&cheap)),
            Err(PoolError::GasPriceTooLow)
        ));

        // And one mined away.
        pool.remove_mined(std::slice::from_ref(&good));

        let a = pool.take_activity();
        assert_eq!(a.offered, 3, "every call counts as offered, accepted or not");
        assert_eq!(a.accepted, 1);
        assert_eq!(a.mined, 1);
        assert_eq!(a.rejected(), 2);
        assert!(!a.is_empty());

        // Reasons are reported most common first, so a change in the mix shows
        // up without turning on debug logging.
        let reasons: Vec<&str> = a.rejections.iter().map(|(r, _)| *r).collect();
        assert!(reasons.contains(&"already-known"), "{reasons:?}");
        assert!(reasons.contains(&"gas-price-too-low"), "{reasons:?}");

        // Taking it clears it, so each report covers exactly one window.
        assert!(pool.take_activity().is_empty());
    }

    /// A transaction that never reaches the pool -- undecodable bytes -- is
    /// still "offered". Counting only well-formed transactions would hide a
    /// peer sending us rubbish.
    #[test]
    fn test_undecodable_transactions_still_count_as_offered() {
        let (pool, _key, _addr) = setup_pool_with_account(U256::from(10u64).pow(U256::from(20)), 0);
        assert!(matches!(
            pool.add_transaction(&[0xff, 0xff, 0xff]),
            Err(PoolError::RlpDecode(_))
        ));
        let a = pool.take_activity();
        assert_eq!(a.offered, 1);
        assert_eq!(a.accepted, 0);
        assert_eq!(a.rejections, vec![("rlp-decode", 1)]);
    }

    // ========== Intrinsic gas ==========

    #[test]
    fn test_intrinsic_gas_simple_transfer() {
        let tx = make_tx(0, 1);
        assert_eq!(intrinsic_gas(&tx), 21_000);
    }

    #[test]
    fn test_intrinsic_gas_contract_creation() {
        let mut tx = make_tx(0, 1);
        tx.to = Bytes::new();
        assert_eq!(intrinsic_gas(&tx), 53_000);
    }

    #[test]
    fn test_intrinsic_gas_with_calldata() {
        let mut tx = make_tx(0, 1);
        tx.input = Bytes::from(vec![0x00, 0x01, 0x00, 0xff]);
        // 21000 + 4(zero) + 16(non-zero) + 4(zero) + 16(non-zero)
        assert_eq!(intrinsic_gas(&tx), 21_000 + 4 + 16 + 4 + 16);
    }

    // ========== rskj: addAndGetPendingTransaction ==========

    #[test]
    fn test_add_pending_transaction() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        let hash = pool.add_transaction(&raw).unwrap();
        assert!(pool.get(&hash).is_some());
        let (pending, queued) = pool.status();
        assert_eq!(pending, 1);
        assert_eq!(queued, 0);
    }

    // ========== rskj: addAndGetQueuedTransaction ==========

    #[test]
    fn test_add_queued_transaction() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(4, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        let hash = pool.add_transaction(&raw).unwrap();
        assert!(pool.get(&hash).is_some());
        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 1);
    }

    // ========== rskj: addAndGetTwoQueuedTransactionAsPendingOnes ==========

    #[test]
    fn test_promotion_queued_to_pending() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        // Add nonce 1 and 2 first — they go to queued
        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx2 = make_tx(2, 59_240_000);
        sign_tx(&mut tx2, &key, 33);
        pool.add_transaction(&encode_tx(&tx2)).unwrap();

        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 2);

        // Add nonce 0 — it goes to pending and promotes 1, 2
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let (pending, queued) = pool.status();
        assert_eq!(pending, 3);
        assert_eq!(queued, 0);
    }

    /// `content()` must report the same split `status()` counts, and must
    /// order each sender's transactions by nonce -- that ordering is what
    /// `txpool_content` presents, and the pool's senders live in a HashMap.
    #[test]
    fn test_content_splits_pending_from_queued_and_orders_by_nonce() {
        let (pool, key, addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        // Out of nonce order on purpose: 2 and 1 queue behind the gap at 0.
        for nonce in [2u64, 1] {
            let mut tx = make_tx(nonce, 59_240_000);
            sign_tx(&mut tx, &key, 33);
            pool.add_transaction(&encode_tx(&tx)).unwrap();
        }

        let (pending, queued) = pool.content();
        assert!(pending.is_empty(), "nothing can execute behind a nonce gap");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].0, addr);
        assert_eq!(
            queued[0].1.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![1, 2],
            "nonce order, not insertion order"
        );

        // Filling the gap promotes both.
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let (pending, queued) = pool.content();
        assert!(queued.is_empty(), "the gap is filled");
        assert_eq!(
            pending[0].1.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let (p, q) = pool.status();
        assert_eq!(
            (p, q),
            (
                pending.iter().map(|(_, txs)| txs.len()).sum::<usize>(),
                queued.iter().map(|(_, txs)| txs.len()).sum::<usize>()
            ),
            "status and content must not disagree about the same pool"
        );
    }

    // ========== rskj: addTwiceAndGetPendingTransaction ==========

    #[test]
    fn test_duplicate_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        pool.add_transaction(&raw).unwrap();
        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::AlreadyPending));
    }

    // ========== rskj: checkTxWithSameNonceIsRejected ==========

    #[test]
    fn test_same_nonce_low_gas_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx1 = make_tx(0, 100_000_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        // Same nonce, same gas price — should be rejected (needs 140%)
        let mut tx2 = make_tx(0, 100_000_000);
        tx2.value = U256::from(2000); // different tx, different hash
        sign_tx(&mut tx2, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx2)).unwrap_err();
        assert!(matches!(err, PoolError::ReplacementGasPriceTooLow));
    }

    // ========== rskj: checkTxWithSameNonceBumpedIsAccepted ==========

    #[test]
    fn test_same_nonce_bumped_accepted() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx1 = make_tx(0, 100_000_000);
        sign_tx(&mut tx1, &key, 33);
        let hash1 = pool.add_transaction(&encode_tx(&tx1)).unwrap();

        // 2x gas price — should replace
        let mut tx2 = make_tx(0, 200_000_000);
        sign_tx(&mut tx2, &key, 33);
        let hash2 = pool.add_transaction(&encode_tx(&tx2)).unwrap();

        assert_ne!(hash1, hash2);
        assert!(pool.get(&hash1).is_none());
        assert!(pool.get(&hash2).is_some());
    }

    // ========== rskj: checkTxWithHighGasLimitIsRejected ==========

    #[test]
    fn test_high_gas_limit_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.gas_limit = U256::from(9_000_000); // > 8M block gas limit
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::GasLimitExceeded { .. }));
    }

    // ========== rskj: checkTxWithHighNonceIsRejected ==========

    /// Finding 5: the pool must have a global ceiling, not only a per-account
    /// one. At the cap a queued (future-nonce) transaction is evicted to make
    /// room, since those are not executable and are the cheapest class for an
    /// attacker to pile up.
    #[test]
    fn test_pool_full_evicts_queued() {
        let config = PoolConfig {
            max_pool_transactions: 2,
            ..test_config()
        };
        let (pool, key, _addr) =
            setup_pool_with_config(U256::from(10u64.pow(18)), 0, config);

        // nonce 0 is executable -> pending
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        // nonce 2 is not contiguous -> queued. Pool is now at the cap.
        let mut tx2 = make_tx(2, 59_240_000);
        sign_tx(&mut tx2, &key, 33);
        let hash2 = pool.add_transaction(&encode_tx(&tx2)).unwrap();

        // nonce 3 forces an eviction rather than unbounded growth.
        let mut tx3 = make_tx(3, 59_240_000);
        sign_tx(&mut tx3, &key, 33);
        pool.add_transaction(&encode_tx(&tx3)).unwrap();

        let (pending, queued) = pool.status();
        assert_eq!(pending + queued, 2, "pool must not exceed its cap");
        assert!(pool.get(&hash2).is_none(), "highest queued nonce evicted");
    }

    /// Finding 5: with nothing evictable, admission is refused outright instead
    /// of letting the pool grow past its bound.
    #[test]
    fn test_pool_full_rejects_when_nothing_evictable() {
        let config = PoolConfig {
            max_pool_transactions: 1,
            ..test_config()
        };
        let (pool, key, _addr) =
            setup_pool_with_config(U256::from(10u64.pow(18)), 0, config);

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        // Contiguous, so this is pending too -- and pending is never evicted.
        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx1)).unwrap_err();
        assert!(matches!(err, PoolError::PoolFull), "got {:?}", err);

        let (pending, queued) = pool.status();
        assert_eq!(pending + queued, 1);
    }

    #[test]
    fn test_high_nonce_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(16, 59_240_000); // account_slots = 16, so nonce 16 is out of range
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::NonceTooHigh));
    }

    // ========== rskj: checkTxWithLowNonceIsRejected ==========

    #[test]
    fn test_low_nonce_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 5);
        let mut tx = make_tx(4, 59_240_000); // state nonce is 5
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::NonceTooLow));
    }

    // ========== rskj: checkRemascTxIsRejected ==========

    /// rskj refuses a `RemascTransaction`, which only a block's last
    /// transaction is. REMASC's own encoding, offered alone, carries no
    /// signature, and is refused for that, as rskj refuses it on arrival
    /// (`acceptTransactionSignature`). A signed transaction of its shape is
    /// an ordinary transaction to the REMASC contract, and refused as any
    /// other would be: for its zero gas price, below the block's minimum,
    /// and at that minimum for a gas limit below a transfer's cost.
    #[test]
    fn test_remasc_tx_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let remasc = Transaction::remasc(10);
        let err = pool.add_transaction(&remasc.rlp_for_trie()).unwrap_err();
        assert!(matches!(err, PoolError::InvalidSignature(_)), "{err}");

        let remasc_shaped = |gas_price: &[u8]| {
            let mut fields = vec![0x80]; // nonce 0
            fields.extend_from_slice(gas_price);
            fields.push(0x00); // gas limit zero, the byte 0x00 as in REMASC's
            rustock_execution::precompiles::REMASC_ADDR
                .as_slice()
                .encode(&mut fields);
            fields.extend_from_slice(&[0x80, 0x80]); // value 0, no data
            rskj_signed(&fields, &key, 33)
        };
        let err = pool.add_transaction(&remasc_shaped(&[0x00])).unwrap_err();
        assert!(matches!(err, PoolError::GasPriceTooLow), "{err}");

        let mut minimum = Vec::new();
        U256::from(59_240_000).encode(&mut minimum);
        let err = pool.add_transaction(&remasc_shaped(&minimum)).unwrap_err();
        assert!(matches!(err, PoolError::IntrinsicGasTooHigh), "{err}");
    }

    // ========== rskj: checkTxWithLowGasPriceIsRejected ==========

    #[test]
    fn test_low_gas_price_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 1); // below min gas price of 59_240_000
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::GasPriceTooLow));
    }

    // ========== rskj: checkTxFromAccountWithLowBalanceIsRejected ==========

    #[test]
    fn test_insufficient_balance_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(100), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::InsufficientFunds));
    }

    // ========== rskj: checkTxWithHighIntrinsicGasIsRejected ==========

    #[test]
    fn test_intrinsic_gas_exceeded() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.gas_limit = U256::from(100); // way below 21000
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::IntrinsicGasTooHigh));
    }

    // ========== rskj: checkTxWhichCanNotBePaidIsRejected ==========

    #[test]
    fn test_aggregate_balance_exceeded() {
        // Balance enough for 1 tx but not 2
        let gas_price = 59_240_000u64;
        let gas_limit = 21_000u64;
        let cost_per_tx = gas_price as u128 * gas_limit as u128 + 1000; // gas + value
        let balance = U256::from(cost_per_tx * 3 / 2); // enough for 1.5 txs

        let (pool, key, _addr) = setup_pool_with_account(balance, 0);

        let mut tx1 = make_tx(0, gas_price);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx2 = make_tx(1, gas_price);
        sign_tx(&mut tx2, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx2)).unwrap_err();
        assert!(matches!(err, PoolError::InsufficientFundsForPendingAndNew));
    }

    /// rskj reckons what a transaction costs in whole numbers (`Coin`, a
    /// `BigInteger`), so a cost past 256 bits is more than any balance. In
    /// 256 bits it wraps: 2^240 a gas for 65,536 gas comes to nothing, and so
    /// do two transactions of 2^255 each.
    #[test]
    fn a_cost_past_256_bits_is_more_than_any_balance() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(1), 0);
        let mut tx = make_tx(0, 0);
        tx.gas_price = U256::from(1) << 240;
        tx.gas_limit = U256::from(65_536);
        tx.value = U256::ZERO;
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::InsufficientFunds), "{err}");

        let half = U256::from(1) << 255;
        let gas = U256::from(59_240_000u64 * 21_000);
        let (pool, key, _addr) = setup_pool_with_account(half, 0);
        let costing_half = |nonce: u64| {
            let mut tx = make_tx(nonce, 59_240_000);
            tx.value = half - gas;
            sign_tx(&mut tx, &key, 33);
            pool.add_transaction(&encode_tx(&tx))
        };
        costing_half(0).expect("the account holds what the first costs");
        let err = costing_half(1).unwrap_err();
        assert!(
            matches!(err, PoolError::InsufficientFundsForPendingAndNew),
            "{err}"
        );
    }

    /// rskj replaces a pending transaction only with one that pays more
    /// (`isBumpingGasPriceForSameNonceTx`: `oldGasPrice < newGasPrice`, and
    /// no less than the old price raised by the bump). Where the bump rounds
    /// to nothing -- a price of 0, 1 or 2 -- the same price again is not
    /// enough.
    #[test]
    fn a_replacement_has_to_pay_more() {
        let mut header = test_header();
        header.minimum_gas_price = U256::ZERO;
        let (pool, key, _addr) =
            setup_pool_on(header, U256::from(10u64.pow(18)), 0, test_config(), None);
        let mut value = 1_000;
        let mut offer = |gas_price: u64| {
            // A new value each time: another transaction, of another hash.
            value += 1;
            let mut tx = make_tx(0, gas_price);
            tx.value = U256::from(value);
            sign_tx(&mut tx, &key, 33);
            pool.add_transaction(&encode_tx(&tx))
        };
        offer(0).expect("the first");
        for (gas_price, replaces) in [
            (0, false),
            (1, true),
            (1, false),
            (2, true),
            (2, false),
            (3, true),
            // 3 raised by 40% is 4.
            (3, false),
            (4, true),
        ] {
            let added = offer(gas_price);
            if replaces {
                added.unwrap_or_else(|err| panic!("{gas_price} replaces: {err}"));
            } else {
                assert!(
                    matches!(added, Err(PoolError::ReplacementGasPriceTooLow)),
                    "{gas_price} does not replace: {added:?}"
                );
            }
        }
    }

    // ========== rskj: removeObsoletePendingTransactionsByBlock ==========

    #[test]
    fn test_evict_outdated_by_block() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();

        assert!(pool.get(&hash).is_some());
        // Current block is 100, outdated_threshold is 10, so at block 111 the tx should be evicted
        pool.evict_outdated(111);
        assert!(pool.get(&hash).is_none());
    }

    // ========== rskj: processBestBlockRemovesTransactionsInBlock ==========

    #[test]
    fn test_remove_mined_transactions() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();

        assert!(pool.get(&hash).is_some());
        pool.remove_mined(&[tx]);
        assert!(pool.get(&hash).is_none());
        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 0);
    }

    // ========== Nonce range boundary tests ==========

    #[test]
    fn test_nonce_range_one_slot() {
        let config = PoolConfig {
            account_slots: 1,
            ..test_config()
        };
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(1), U256::from(10u64.pow(18)));
        let key_bytes = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key_bytes), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(config, 33, store, trie_store);

        // nonce 0 should be rejected (< state_nonce=1)
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx0)), Err(PoolError::NonceTooLow)));

        // nonce 1 should be accepted (= state_nonce)
        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &signing_key, 33);
        assert!(pool.add_transaction(&encode_tx(&tx1)).is_ok());

        // nonce 2 should be rejected (>= state_nonce + account_slots = 2)
        let mut tx2 = make_tx(2, 59_240_000);
        sign_tx(&mut tx2, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx2)), Err(PoolError::NonceTooHigh)));

        std::mem::forget(dir);
    }

    // ========== Gas price bump math ==========

    #[test]
    fn test_gas_price_bump_exact_threshold() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let base_price = 100_000_000u64;

        let mut tx1 = make_tx(0, base_price);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        // 139% should be rejected (bump is 40%, need >= 140%)
        let mut tx2 = make_tx(0, base_price * 139 / 100);
        tx2.value = U256::from(2000);
        sign_tx(&mut tx2, &key, 33);
        assert!(matches!(
            pool.add_transaction(&encode_tx(&tx2)),
            Err(PoolError::ReplacementGasPriceTooLow)
        ));

        // 140% should be accepted
        let mut tx3 = make_tx(0, base_price * 140 / 100);
        tx3.value = U256::from(3000);
        sign_tx(&mut tx3, &key, 33);
        assert!(pool.add_transaction(&encode_tx(&tx3)).is_ok());
    }

    // ========== pending_nonce ==========

    #[test]
    fn test_pending_nonce() {
        let (pool, key, addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        assert_eq!(pool.pending_nonce(&addr), None);

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        assert_eq!(pool.pending_nonce(&addr), Some(1));

        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        assert_eq!(pool.pending_nonce(&addr), Some(2));
    }

    // ========== status ==========

    #[test]
    fn test_pool_status() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        let (p, q) = pool.status();
        assert_eq!(p, 0);
        assert_eq!(q, 0);

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let (p, q) = pool.status();
        assert_eq!(p, 1);
        assert_eq!(q, 0);

        let mut tx5 = make_tx(5, 59_240_000);
        sign_tx(&mut tx5, &key, 33);
        pool.add_transaction(&encode_tx(&tx5)).unwrap();

        let (p, q) = pool.status();
        assert_eq!(p, 1);
        assert_eq!(q, 1);
    }

    /// rskj `BlockToMineBuilder.removePendingTransactions` on
    /// `BlockResult.getInvalidTransactions()`: the miner names the hashes
    /// it refused, and they leave the pool; unknown hashes are ignored.
    #[test]
    fn remove_by_hashes_drops_what_the_miner_refused_and_nothing_else() {
        let balance = U256::from(10u64).pow(U256::from(18));
        let (pool, key, _addr) = setup_pool_with_account(balance, 0);
        let mut hashes = Vec::new();
        for nonce in 0..3 {
            let mut tx = make_tx(nonce, 59_240_000);
            sign_tx(&mut tx, &key, 33);
            let raw = encode_tx(&tx);
            hashes.push(tx.tx_hash());
            pool.add_transaction(&raw).expect("admitted");
        }
        assert_eq!(pool.pending_transactions().len(), 3);

        let removed = pool.remove_by_hashes(&[hashes[1], B256::repeat_byte(0x77)]);
        assert_eq!(removed, 1, "one known hash, one unknown");
        let left: Vec<B256> = pool.pending_transactions().iter().map(|p| p.hash).collect();
        assert!(!left.contains(&hashes[1]), "the refused one is gone");
        assert!(left.contains(&hashes[0]) && left.contains(&hashes[2]), "the others stay");
        assert_eq!(pool.remove_by_hashes(&[hashes[1]]), 0, "and it is not there to remove twice");
    }

    // ========== rskj co.rsk.net.handler.txvalidator ==========

    /// rskj `TxValidatorMaximumGasPriceValidatorTest.validate_whenRskip252DisabledThenTxValidRegardlessGasPrice`:
    /// before RSKIP252 (mainnet's height, with the head at 100) there is no
    /// cap, and a price a trillion over it is admitted.
    #[test]
    fn validate_when_rskip252_disabled_then_tx_valid_regardless_gas_price() {
        let rules = ChainRules::for_chain(rustock_execution::hardfork::RskHardforkConfig::mainnet(), 10_000_000);
        assert_eq!(rules.rskip252_height, 5_468_000);
        // It is fingerroot500's height, wherever the chain has that.
        let (moved, _) = rustock_execution::hardfork::RskHardforkConfig::mainnet()
            .with_rskj_overrides(&[("fingerroot500".to_string(), Some(6_000_000))], &[])
            .unwrap();
        assert_eq!(
            ChainRules::for_chain(moved, 10_000_000).rskip252_height,
            6_000_000
        );
        let (pool, key, _) =
            setup_pool_with_rules(U256::from(10u64).pow(U256::from(20)), 0, test_config(), Some(rules));
        let cap = 59_240_000 * TX_GAS_PRICE_CAP_MULTIPLIER;

        let mut tx = make_tx(0, cap - 1);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).expect("under the cap");
        let mut tx = make_tx(1, cap + 1_000_000_000_000);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).expect("no cap before RSKIP252");
    }

    /// rskj `TxValidatorMaximumGasPriceValidatorTest.validate_whenRskip252EnabledThenTxWithMoreGasPriceThanCapInvalid`:
    /// 80 times the block's minimum is the cap; one wei over is refused.
    #[test]
    fn validate_when_rskip252_enabled_then_tx_with_more_gas_price_than_cap_invalid() {
        let (pool, key, _) = setup_pool_with_rules(
            U256::from(10u64).pow(U256::from(20)),
            0,
            test_config(),
            Some(regtest_rules()),
        );
        let cap = 59_240_000 * TX_GAS_PRICE_CAP_MULTIPLIER;

        let mut tx = make_tx(0, cap - 1);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).expect("under the cap");
        let mut tx = make_tx(1, cap + 1);
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::GasPriceAboveCap), "got {err}");
    }

    /// rskj `TxValidatorNonceEncodingValidatorTest.validateNonceEncoding`,
    /// case for case (the null nonce has no Rust counterpart).
    #[test]
    fn validate_nonce_encoding() {
        let cases: [(&str, &[u8], bool); 9] = [
            ("empty nonce", &[], true),
            ("single byte zero", &[0x00], true),
            ("single byte non-zero", &[0x01], true),
            ("two bytes, no leading zero", &[0x01, 0x00], true),
            ("eight bytes, no leading zeros", &[1, 2, 3, 4, 5, 6, 7, 8], true),
            ("nine bytes (all zeros)", &[0; 9], false),
            ("nine bytes (non-zero first byte)", &[1, 0, 0, 0, 0, 0, 0, 0, 0], false),
            ("two bytes with leading zero", &[0x00, 0x01], false),
            ("three bytes with leading zeros", &[0x00, 0x00, 0x05], false),
        ];
        for (description, nonce, expected) in cases {
            assert_eq!(nonce_bytes_are_canonical(nonce), expected, "{description}");
        }
    }

    /// The same rule on the wire: a transaction whose nonce is sent as
    /// `00 01` is refused by the pool, although it decodes to nonce 1 and its
    /// signature is its sender's. rskj signs over the nonce's bytes as they
    /// came, so the signature is made over them here too: over the canonical
    /// form it would be another account's, one the state doesn't hold, and
    /// rskj asks for the account before it looks at the nonce.
    #[test]
    fn a_non_canonical_nonce_is_refused_on_admission() {
        let (pool, key, _) = setup_pool_with_account(U256::from(10u64.pow(18)), 1);
        let mut tx = make_tx(1, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let canonical = encode_tx(&tx);

        // The nonce item `0x01` as `0x82 0x00 0x01`, and the other five
        // fields as they are.
        let mut fields = vec![0x82, 0x00, 0x01];
        tx.gas_price.encode(&mut fields);
        tx.gas_limit.encode(&mut fields);
        tx.to.encode(&mut fields);
        tx.value.encode(&mut fields);
        tx.input.encode(&mut fields);
        let raw = rskj_signed(&fields, &key, 33);

        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::NonCanonicalNonce), "got {err}");
        pool.add_transaction(&canonical).expect("the canonical form is fine");
    }

    /// rskj keys a transaction by the encoding it rebuilds (`getEncoded`),
    /// not by the bytes it came in: a gas price sent with a leading zero is
    /// the same transaction as the one sent minimal, with the same hash, so
    /// the second is already known.
    #[test]
    fn the_pool_keys_a_transaction_by_rskjs_hash() {
        let (pool, key, _) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let canonical = encode_tx(&tx);

        // Splice the gas price item: `0x84 03 87 ee 40` becomes
        // `0x85 00 03 87 ee 40`.
        let mut buf = &canonical[..];
        let list = alloy_rlp::Header::decode(&mut buf).unwrap();
        assert_eq!(
            buf[..6],
            [0x80, 0x84, 0x03, 0x87, 0xee, 0x40],
            "nonce 0, then the gas price"
        );
        let mut payload = vec![0x80, 0x85, 0x00, 0x03, 0x87, 0xee, 0x40];
        payload.extend_from_slice(&buf[6..list.payload_length]);
        let mut raw = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut raw);
        raw.extend_from_slice(&payload);

        let hash = pool
            .add_transaction(&raw)
            .expect("rskj reads the gas price as 59,240,000");
        assert_eq!(hash, tx.tx_hash(), "rskj's hash, of the minimal encoding");
        assert_ne!(hash, B256::from_slice(&Keccak256::digest(&raw)));
        let err = pool.add_transaction(&canonical).unwrap_err();
        assert!(matches!(err, PoolError::AlreadyPending), "got {err}");
    }

    /// A free Bridge transaction, as rskj has them before `areBridgeTxsPaid`:
    /// the head is at 100, mainnet pays from 370,000, and the sender is one
    /// of the free ones.
    fn free_bridge_rules(sender: Address) -> ChainRules {
        let mut rules = ChainRules::for_chain(rustock_execution::hardfork::RskHardforkConfig::mainnet(), 10_000_000);
        rules.free_bridge_senders = vec![sender];
        rules
    }

    fn bridge_tx(nonce: u64, gas_limit: u64, data: &[u8]) -> Transaction {
        let mut tx = make_tx(nonce, 59_240_000);
        tx.to = Bytes::copy_from_slice(rustock_execution::precompiles::BRIDGE_ADDR.as_slice());
        tx.gas_limit = U256::from(gas_limit);
        tx.input = Bytes::copy_from_slice(data);
        tx.value = U256::ZERO;
        tx
    }

    /// rskj `TxValidatorAccountBalanceValidatorTest.balanceIsNotValidatedIfFreeTx`:
    /// with nothing in the account, a free transaction is admitted where the
    /// same transaction from anyone else is "insufficient funds".
    #[test]
    fn balance_is_not_validated_if_free_tx() {
        let (pool, key, addr) = setup_pool_with_rules(U256::ZERO, 0, test_config(), None);
        let mut tx = bridge_tx(0, 21_071, &[0x00, 0x01]);
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::InsufficientFunds), "not free: {err}");

        let (pool, key, _) = setup_pool_with_rules(U256::ZERO, 0, test_config(), Some(free_bridge_rules(addr)));
        let mut tx = bridge_tx(0, 21_071, &[0x00, 0x01]);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).expect("free: the balance is not looked at");
    }

    /// rskj `TxValidatorIntrinsicGasLimitValidatorTest.validIntrinsicGasPrice`,
    /// its `tx4`: a free Bridge transaction declaring no gas at all costs
    /// nothing, so the zero limit covers it. rskj's builder writes that zero
    /// as the byte 0x00 (`BigIntegers.asUnsignedByteArray`), as here.
    #[test]
    fn valid_intrinsic_gas_price_for_a_free_bridge_tx_with_zero_gas_limit() {
        let zero_gas = |key: &SigningKey| {
            let mut fields = vec![0x80]; // nonce 0
            U256::from(59_240_000).encode(&mut fields);
            fields.push(0x00); // gas limit zero
            rustock_execution::precompiles::BRIDGE_ADDR
                .as_slice()
                .encode(&mut fields);
            fields.extend_from_slice(&[0x80, 0x80]); // value 0, no data
            rskj_signed(&fields, key, 33)
        };
        let (_, _, addr) = setup_pool_with_rules(U256::ZERO, 0, test_config(), None);
        let (pool, key, _) = setup_pool_with_rules(U256::ZERO, 0, test_config(), Some(free_bridge_rules(addr)));
        pool.add_transaction(&zero_gas(&key))
            .expect("free, zero gas");

        // Paid from 370,000 on: the same transaction is then over its own
        // intrinsic cost.
        let mut paid = free_bridge_rules(addr);
        paid.hardfork_cfg = rustock_execution::hardfork::RskHardforkConfig::all_active(33);
        let (pool, key, _) = setup_pool_with_rules(U256::ZERO, 0, test_config(), Some(paid));
        let err = pool.add_transaction(&zero_gas(&key)).unwrap_err();
        assert!(matches!(err, PoolError::IntrinsicGasTooHigh), "got {err}");
    }

    /// rskj's regtest never reaches `afterBridgeSync`, so a free sender's
    /// Bridge call costs nothing at any height there, as the block processor
    /// counts it; on rustock's own regtest the same call is paid from block 0.
    /// The head is at #100, past every height regtest moves a rule to.
    #[test]
    fn on_rskj_regtest_a_free_senders_bridge_call_stays_free() {
        let (_, _, addr) = setup_pool_with_rules(U256::ZERO, 0, test_config(), None);
        let rules = |ladder| {
            let mut rules = ChainRules::for_chain(ladder, 6_800_000);
            rules.free_bridge_senders = vec![addr];
            rules
        };
        let call = |key: &SigningKey| {
            let mut tx = bridge_tx(0, 21_071, &[0x00, 0x01]);
            sign_tx(&mut tx, key, 33);
            encode_tx(&tx)
        };
        let rskj = rules(rustock_execution::hardfork::RskHardforkConfig::rskj_regtest());
        let (pool, key, _) = setup_pool_with_rules(U256::ZERO, 0, test_config(), Some(rskj));
        pool.add_transaction(&call(&key))
            .expect("free on rskj's regtest");

        let own = rules(rustock_execution::hardfork::RskHardforkConfig::regtest());
        let (pool, key, _) = setup_pool_with_rules(U256::ZERO, 0, test_config(), Some(own));
        let err = pool.add_transaction(&call(&key)).unwrap_err();
        assert!(
            matches!(err, PoolError::InsufficientFunds),
            "paid on rustock's own: {err}"
        );
    }

    /// rskj `TxValidatorNonceRangeValidatorTest.illegalAccountSlotsValue_Zero`:
    /// a pool with no slots would refuse everything, so it is refused itself.
    #[test]
    #[should_panic(expected = "account_slots must be at least 1")]
    fn illegal_account_slots_value_zero() {
        let config = PoolConfig { account_slots: 0, ..test_config() };
        let _ = setup_pool_with_config(U256::ZERO, 0, config);
    }

    /// rskj `TxPendingValidator.isValid` with RSKIP351 and RSKIP144 active:
    /// the bound is the larger sublist's limit, not the block's. On an 8 M
    /// block with the sequential sublist guaranteed 6.8 M, a 7 M transaction
    /// fits the block and no sublist.
    #[test]
    fn gas_limit_is_bounded_by_the_larger_sublist_under_rskip144() {
        let parallel = ChainRules::for_chain(
            rustock_execution::hardfork::RskHardforkConfig::all_active_parallel(33),
            6_800_000,
        );
        assert_eq!(parallel.gas_limit_bound(&test_header()), 6_800_000);
        assert_eq!(regtest_rules().gas_limit_bound(&test_header()), 8_000_000, "no RSKIP144, the block's");

        let (pool, key, _) =
            setup_pool_with_rules(U256::from(10u64).pow(U256::from(20)), 0, test_config(), Some(parallel));
        let mut tx = make_tx(0, 59_240_000);
        tx.gas_limit = U256::from(7_000_000);
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::GasLimitExceeded { .. }), "got {err}");
        tx.gas_limit = U256::from(6_800_000);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).expect("at the sublist limit");
    }

    // ========== Invalid signature ==========

    /// A v with r and s left empty cannot be read, as rskj cannot build its
    /// signature (`ECDSASignature.fromComponents` on no bytes); r and s of
    /// zero, the byte 0x00 each, are read and refused as no signature.
    #[test]
    fn test_invalid_signature_rejected() {
        let (pool, _key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.v = 27;
        tx.r = U256::ZERO;
        tx.s = U256::ZERO;
        let mut raw = encode_tx(&tx);
        assert_eq!(raw[raw.len() - 3..], [0x1b, 0x80, 0x80]);
        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::RlpDecode(_)), "got {err}");

        let at = raw.len() - 2;
        raw[at..].copy_from_slice(&[0x00, 0x00]);
        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::InvalidSignature(_)), "got {err}");
    }

    // ========== Size limit ==========

    #[test]
    fn test_tx_too_large() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.input = Bytes::from(vec![0xAA; 129 * 1024]); // > 128KB
        tx.gas_limit = U256::from(8_000_000); // high enough for calldata
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::TxTooLarge { .. }));
    }

    // ========== rskj: checkTxMaxSizeAccepted ==========

    #[test]
    fn test_tx_size_exactly_at_limit() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        // RLP overhead is ~100 bytes; fill input with enough data to be just under the limit
        tx.input = Bytes::from(vec![0xAA; 127 * 1024]);
        tx.gas_limit = U256::from(8_000_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);
        assert!(raw.len() <= MAX_TX_SIZE, "encoded size {} should be <= {}", raw.len(), MAX_TX_SIZE);
        assert!(pool.add_transaction(&raw).is_ok());
    }

    // ========== rskj: checkTxBumpIsNotConsideredOnTotalCosts ==========

    #[test]
    fn test_bump_excluded_from_aggregate_balance() {
        // balance just enough for one tx at the bump price, not two
        let gas_price = 100_000_000u64;
        let gas_limit = 21_000u64;
        let bumped_price = gas_price * 140 / 100;
        let tx_cost_bumped = bumped_price as u128 * gas_limit as u128 + 1000;
        // enough for bumped tx0 + tx1, but NOT for two tx1s at once
        let balance = U256::from(tx_cost_bumped * 2 + 1);

        let (pool, key, _addr) = setup_pool_with_account(balance, 0);

        // tx0 at base price
        let mut tx0 = make_tx(0, gas_price);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        // Replace tx0 with bumped price
        let mut tx0_bumped = make_tx(0, bumped_price);
        tx0_bumped.value = U256::from(1000);
        sign_tx(&mut tx0_bumped, &key, 33);
        pool.add_transaction(&encode_tx(&tx0_bumped)).unwrap();

        // tx1 should succeed since only the replacement's cost is counted
        let mut tx1 = make_tx(1, gas_price);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let (pending, _queued) = pool.status();
        assert_eq!(pending, 2);
    }

    // ========== rskj: checkTxFromNullStateIsRejected ==========

    #[test]
    fn a_sender_the_state_does_not_hold_is_refused() {
        // rskj `TxPendingValidator.isValid`: no account, and the transaction
        // costs something, so "the sender account doesn't exist".
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        // Put an empty trie root
        let mut root = TrieNode::empty();
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(test_config(), 33, store, trie_store);

        let signing_key = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &signing_key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::SenderMissing), "got {err}");

        std::mem::forget(dir);
    }

    // ========== rskj: removeObsoleteQueuedTransactionsByBlock ==========

    #[test]
    fn test_evict_queued_by_block() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(5, 59_240_000); // queued (nonce gap)
        sign_tx(&mut tx, &key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();

        let (_, queued) = pool.status();
        assert_eq!(queued, 1);

        pool.evict_outdated(111);
        assert!(pool.get(&hash).is_none());
        let (_, queued) = pool.status();
        assert_eq!(queued, 0);
    }

    // ========== rskj: addTwiceAndGetQueuedTransaction ==========

    #[test]
    fn test_duplicate_queued_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(5, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        pool.add_transaction(&raw).unwrap();
        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::AlreadyQueued));
    }

    // ========== rskj: pending sorted by nonce ==========

    #[test]
    fn test_pending_sorted_by_nonce() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        // Add nonce 1 first (queued), then nonce 0 (triggers promotion)
        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let pending = pool.pending_transactions();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].tx.nonce, 0);
        assert_eq!(pending[1].tx.nonce, 1);
    }

    // ========== rskj: processBestBlockRemovesTransactionsInBlock (partial) ==========

    #[test]
    fn test_partial_remove_mined() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        let hash1 = pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let (pending, _) = pool.status();
        assert_eq!(pending, 2);

        // Only mine tx0
        pool.remove_mined(&[tx0]);
        let (pending, _) = pool.status();
        assert_eq!(pending, 1);
        assert!(pool.get(&hash1).is_some());
    }

    // ========== rskj: fiveSlotsRange ==========

    #[test]
    fn test_nonce_range_five_slots() {
        let config = PoolConfig {
            account_slots: 5,
            ..test_config()
        };
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(1), U256::from(10u64.pow(18)));
        let key_bytes = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key_bytes), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(config, 33, store, trie_store);

        // nonce 0 should be rejected (< state_nonce=1)
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx0)), Err(PoolError::NonceTooLow)));

        // nonces 1-5 should be accepted
        for n in 1..=5 {
            let mut tx = make_tx(n, 59_240_000);
            tx.value = U256::from(n); // unique value per nonce
            sign_tx(&mut tx, &signing_key, 33);
            assert!(pool.add_transaction(&encode_tx(&tx)).is_ok(), "nonce {} should be accepted", n);
        }

        // nonce 6 should be rejected (>= state_nonce + account_slots = 6)
        let mut tx6 = make_tx(6, 59_240_000);
        sign_tx(&mut tx6, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx6)), Err(PoolError::NonceTooHigh)));

        std::mem::forget(dir);
    }

    // ========== rskj: eviction by timeout ==========

    #[test]
    fn test_evict_outdated_by_timeout() {
        let config = PoolConfig {
            outdated_timeout_secs: 0, // 0 seconds means any tx is immediately evictable
            ..test_config()
        };
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(0), U256::from(10u64.pow(18)));
        let key_bytes = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key_bytes), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(config, 33, store, trie_store);

        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &signing_key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();
        assert!(pool.get(&hash).is_some());

        // Wait a tiny bit to ensure elapsed > 0 seconds
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Evict with a current block that doesn't trigger block-based eviction
        pool.evict_outdated(100);
        assert!(pool.get(&hash).is_none());

        std::mem::forget(dir);
    }

    // ========== rskj: two queued transactions ==========

    #[test]
    fn test_two_queued_transactions() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx2 = make_tx(2, 59_240_000);
        sign_tx(&mut tx2, &key, 33);
        pool.add_transaction(&encode_tx(&tx2)).unwrap();

        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 2);
    }

    // ========== PoolError Display ==========

    #[test]
    fn test_pool_error_display() {
        assert_eq!(
            PoolError::AlreadyPending.to_string(),
            "pending transaction with same hash already exists"
        );
        assert_eq!(
            PoolError::AlreadyQueued.to_string(),
            "queued transaction with same hash already exists"
        );
        assert_eq!(PoolError::NonceTooLow.to_string(), "transaction nonce too low");
        assert_eq!(PoolError::NonceTooHigh.to_string(), "transaction nonce too high");
        assert_eq!(PoolError::InsufficientFunds.to_string(), "insufficient funds");
        let over = PoolError::GasLimitExceeded {
            gas_limit: U256::from(9_000_000),
            bound: 8_000_000,
        };
        assert_eq!(
            over.to_string(),
            "transaction's gas limit of 9000000 is higher than the block's gas limit of 8000000"
        );
        assert_eq!(PoolError::GasPriceTooLow.to_string(), "transaction's gas price lower than block's minimum");
        assert_eq!(PoolError::IntrinsicGasTooHigh.to_string(), "transaction's basic cost is above the gas limit");
        assert_eq!(PoolError::ReplacementGasPriceTooLow.to_string(), "gas price not enough to bump transaction");
        let large = PoolError::TxTooLarge {
            size: 131_106,
            max: 131_072,
        };
        assert_eq!(
            large.to_string(),
            "transaction's size is higher than defined maximum: 131106 > 131072"
        );
        assert_eq!(
            PoolError::InsufficientFundsForPendingAndNew.to_string(),
            "insufficient funds to pay for pending and new transactions"
        );
    }

    // ========== rskj's own answers ==========

    /// The bytes a testdata line writes in hex, a run of one byte as
    /// `(bb*count)`. `None` for anything else.
    fn written_bytes(text: &str) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut rest = text;
        while !rest.is_empty() {
            if let Some(run) = rest.strip_prefix('(') {
                let (value, after) = run.split_once('*')?;
                let (count, after) = after.split_once(')')?;
                let value = u8::from_str_radix(value, 16).ok()?;
                bytes.extend(std::iter::repeat_n(value, count.parse().ok()?));
                rest = after;
            } else {
                bytes.push(u8::from_str_radix(rest.get(..2)?, 16).ok()?);
                rest = &rest[2..];
            }
        }
        Some(bytes)
    }

    /// The one parameter of an `eth_sendRawTransaction` a testdata line
    /// records, as rskj reads hex: its `0x` optional, blanks passed over.
    fn sent_bytes(asked: &str) -> Option<Vec<u8>> {
        let (_, parameter) = asked.split_once(" eth_sendRawTransaction [\"")?;
        let written = parameter.strip_suffix("\"]")?;
        let digits: String = written
            .strip_prefix("0x")
            .unwrap_or(written)
            .chars()
            .filter(|c| *c != ' ')
            .collect();
        written_bytes(&digits.to_lowercase())
    }

    /// A pool on rskj's regtest whose head is block `number`, over a state
    /// that holds `accounts`.
    fn rskj_regtest_pool(
        (number, gas_limit, minimum_gas_price): (u64, u64, U256),
        accounts: &[(Address, u64, U256)],
    ) -> TransactionPool {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let mut root = TrieNode::empty();
        for (address, nonce, balance) in accounts {
            let account = AccountState::new(U256::from(*nonce), *balance);
            let key = account_key(address);
            root = root.put(
                &TrieKeySlice::from_key(&key),
                &account.encode(),
                &*trie_store,
            );
        }
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.number = number;
        header.gas_limit = U256::from(gas_limit);
        header.minimum_gas_price = minimum_gas_price;
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();
        std::mem::forget(dir);
        let rules = ChainRules::for_chain(
            rustock_execution::hardfork::RskHardforkConfig::rskj_regtest(),
            6_800_000,
        );
        TransactionPool::new(test_config(), 33, store, trie_store).with_chain_rules(rules)
    }

    /// What a testdata line shows of the transactions one side of the pool
    /// holds: how many, and the start of each one's hash, in order.
    fn held(side: &PoolGroups) -> String {
        let mut hashes: Vec<String> = side
            .iter()
            .flat_map(|(_, transactions)| transactions)
            .map(|(_, tx)| hex_of(&tx.tx_hash()[..4]))
            .collect();
        hashes.sort();
        match hashes.len() {
            0 => "0".to_string(),
            count => format!("{count} {}", hashes.join(",")),
        }
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The text between `before` and the next `after` of a JSON answer.
    fn between<'a>(answer: &'a str, before: &str, after: &str) -> Option<&'a str> {
        let (_, rest) = answer.split_once(before)?;
        Some(rest.split_once(after)?.0)
    }

    /// rskj `Transaction.transactionCost`, upgrade by upgrade, at mainnet's
    /// heights: a data byte that isn't zero costs 68 until RSKIP400
    /// (arrowhead600) and 16 from it, and from RSKIP438 (lovell700) a
    /// creation pays 2 for every 32 bytes of init code, the last ones
    /// counted whole.
    #[test]
    fn the_basic_cost_follows_the_upgrades() {
        let rules = ChainRules::for_chain(
            rustock_execution::hardfork::RskHardforkConfig::mainnet(),
            6_800_000,
        );
        let mut tx = make_tx(0, 1);
        tx.input = Bytes::from(vec![0x01, 0x00, 0x02]);
        assert_eq!(rules.transaction_cost(&tx, 6_223_699), 21_000 + 68 + 4 + 68);
        assert_eq!(rules.transaction_cost(&tx, 6_223_700), 21_000 + 16 + 4 + 16);

        tx.to = Bytes::new();
        tx.input = Bytes::from(vec![0x01; 33]);
        assert_eq!(rules.transaction_cost(&tx, 7_338_023), 53_000 + 33 * 16);
        assert_eq!(
            rules.transaction_cost(&tx, 7_338_024),
            53_000 + 33 * 16 + 2 * 2
        );
        tx.input = Bytes::new();
        assert_eq!(
            rules.transaction_cost(&tx, 7_338_024),
            53_000,
            "no init code, nothing more"
        );
    }

    /// The pool answers every transaction rskj's release was sent as that
    /// release's pool answered it, and holds afterwards what that pool held:
    /// `testdata/rskj_pool_answers.txt` is the release's own run. A pool
    /// refusal is rskj's error -32010, whose message is the pool's reason; a
    /// transaction rskj refused before its pool saw it is not given to this
    /// one either.
    #[test]
    fn the_pool_answers_as_rskjs_pool_answers() {
        let data = include_str!("testdata/rskj_pool_answers.txt");
        let mut head = None;
        let mut accounts = Vec::new();
        let mut pool: Option<TransactionPool> = None;
        // Set once rskj's pool took a transaction this test has no bytes
        // for, which its node signed itself: nothing after it can be compared.
        let mut out_of_step = false;
        let mut given = 0;
        for line in data.lines() {
            let mut words = line.split(' ');
            let kind = words.next().unwrap_or_default();
            match kind {
                "scenario" => {
                    head = None;
                    accounts.clear();
                    pool = None;
                    out_of_step = false;
                    continue;
                }
                "head" => {
                    let mut number = || words.next().unwrap().parse::<u64>().unwrap();
                    let (number, gas_limit) = (number(), number());
                    let minimum = U256::from_str_radix(words.next().unwrap(), 10).unwrap();
                    head = Some((number, gas_limit, minimum));
                    continue;
                }
                "account" => {
                    let address: Address = words.nth(1).unwrap().parse().unwrap();
                    let nonce = words.next().unwrap();
                    if nonce != "none" {
                        let balance = U256::from_str_radix(words.next().unwrap(), 10).unwrap();
                        accounts.push((address, nonce.parse().unwrap(), balance));
                    }
                    continue;
                }
                "tx" | "call" => {}
                _ => continue,
            }
            let pool = pool.get_or_insert_with(|| rskj_regtest_pool(head.unwrap(), &accounts));
            let (asked, rest) = line.split_once(" => ").unwrap();
            let (answer, rest) = rest.split_once(" | pending ").unwrap();
            let (pending, queued) = rest.split_once(" | queued ").unwrap();
            let raw = match kind {
                "tx" => written_bytes(asked.rsplit(' ').next().unwrap()),
                _ => sent_bytes(asked),
            };
            let refusal =
                between(answer, "\"code\":", ",").zip(between(answer, "\"message\":\"", "\"}}"));
            let hash = between(answer, "\"result\":\"", "\"");
            let answered = |pool: &TransactionPool, raw: &[u8]| {
                pool.add_transaction(raw)
                    .map(|hash| format!("{hash:#x}"))
                    .map_err(|refusal| refusal.to_string())
            };
            match (raw, refusal, hash) {
                // rskj's pool refused it: `transactionError`, with its reason.
                (Some(raw), Some(("-32010", reason)), _) => {
                    assert!(!out_of_step, "{asked}: after a transaction the node signed");
                    assert_eq!(answered(pool, &raw), Err(reason.to_string()), "{asked}");
                    given += 1;
                }
                // rskj's pool took it.
                (Some(raw), None, Some(hash)) => {
                    assert!(!out_of_step, "{asked}: after a transaction the node signed");
                    assert_eq!(answered(pool, &raw), Ok(hash.to_string()), "{asked}");
                    given += 1;
                }
                // rskj refused it before its pool saw it.
                (_, Some(_), _) => {}
                // The node signed a transaction itself and its pool took it.
                (None, None, _) => out_of_step = true,
                (Some(_), None, None) => panic!("{asked}: no answer read"),
            }
            if !out_of_step {
                let (now_pending, now_queued) = pool.content();
                assert_eq!(held(&now_pending), pending, "pending after {asked}");
                assert_eq!(held(&now_queued), queued, "queued after {asked}");
            }
        }
        assert_eq!(given, 66, "transactions given to the pool");
    }
}
