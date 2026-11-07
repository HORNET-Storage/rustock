use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use rustock_core::{Header, Transaction};
use rustock_storage::BlockStore;
use rustock_trie::{account_key, code_key, AccountState, TrieKeySlice, TrieNode, TrieStore};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::debug;

const TRANSACTION_GAS_CAP: u64 = 1u64 << 60;
const MAX_TX_SIZE: usize = 128 * 1024;

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
            rskip252_height: rustock_execution::processor::rskip252_height_for(hardfork_cfg.chain_id),
            min_sequential_set_gas_limit,
            hardfork_cfg,
        }
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

/// The nonce's raw RLP payload, as the sender encoded it: the first item of
/// the transaction list. `None` if the bytes are not a transaction list.
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
    AlreadyKnown,
    NonceTooLow,
    NonceTooHigh,
    InsufficientFunds,
    GasLimitExceeded,
    GasPriceTooLow,
    IntrinsicGasTooHigh,
    ReplacementGasPriceTooLow,
    TxTooLarge,
    PoolFull,
    InvalidSignature(String),
    InsufficientFundsForPendingAndNew,
    IsRemascTransaction,
    AccountExceedsQuota,
    RlpDecode(String),
    StoreError(String),
    /// rskj `TxValidatorMaximumGasPriceValidator`: over 80 times the block
    /// minimum once RSKIP252 is active.
    GasPriceAboveCap,
    /// rskj `TxValidatorNonceEncodingValidator`: a nonce with leading zeros
    /// or more than eight bytes.
    NonCanonicalNonce,
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyKnown => write!(f, "transaction with same hash already exists"),
            Self::NonceTooLow => write!(f, "transaction nonce too low"),
            Self::NonceTooHigh => write!(f, "transaction nonce too high"),
            Self::InsufficientFunds => write!(f, "insufficient funds"),
            Self::GasLimitExceeded => write!(f, "transaction's gas limit exceeds block gas limit"),
            Self::GasPriceTooLow => write!(f, "transaction's gas price lower than block's minimum"),
            Self::IntrinsicGasTooHigh => write!(f, "transaction's basic cost is above the gas limit"),
            Self::ReplacementGasPriceTooLow => write!(f, "gas price not enough to bump transaction"),
            Self::TxTooLarge => write!(f, "transaction's size is higher than defined maximum"),
            Self::PoolFull => write!(f, "transaction pool is full"),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::InsufficientFundsForPendingAndNew => {
                write!(f, "insufficient funds to pay for pending and new transactions")
            }
            Self::IsRemascTransaction => write!(f, "transaction is a remasc transaction"),
            Self::AccountExceedsQuota => write!(f, "account exceeds quota"),
            Self::RlpDecode(e) => write!(f, "RLP decode error: {e}"),
            Self::StoreError(e) => write!(f, "store error: {e}"),
            Self::GasPriceAboveCap => write!(f, "transaction's gas price exceeds cap"),
            Self::NonCanonicalNonce => write!(f, "transaction nonce has non-canonical encoding"),
        }
    }
}

impl std::error::Error for PoolError {}

impl PoolError {
    /// A short, stable label for the activity summary. Deliberately a
    /// `&'static str` so the counters cannot grow without bound.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::AlreadyKnown => "already-known",
            Self::NonceTooLow => "nonce-too-low",
            Self::NonceTooHigh => "nonce-too-high",
            Self::InsufficientFunds => "insufficient-funds",
            Self::GasLimitExceeded => "gas-limit-exceeded",
            Self::GasPriceTooLow => "gas-price-too-low",
            Self::IntrinsicGasTooHigh => "intrinsic-gas-too-high",
            Self::ReplacementGasPriceTooLow => "replacement-underpriced",
            Self::TxTooLarge => "too-large",
            Self::PoolFull => "pool-full",
            Self::InvalidSignature(_) => "invalid-signature",
            Self::InsufficientFundsForPendingAndNew => "insufficient-funds-pending",
            Self::IsRemascTransaction => "remasc",
            Self::AccountExceedsQuota => "quota",
            Self::RlpDecode(_) => "rlp-decode",
            Self::StoreError(_) => "store-error",
            Self::GasPriceAboveCap => "gas-price-above-cap",
            Self::NonCanonicalNonce => "non-canonical-nonce",
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
        *self.on_added.write().unwrap() = Some(listener);
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
        let mut stats = self.stats.write().unwrap();
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
        self.quota.write().unwrap().clean_max_quotas(Instant::now())
    }

    /// The cleaner interval, or `None` when the clean is disabled.
    pub fn quota_cleaner_period(&self) -> Option<std::time::Duration> {
        self.quota.read().unwrap().cleaner_period()
    }

    /// Virtual gas currently available to `address`, for diagnostics and tests.
    pub fn quota_of(&self, address: &Address) -> Option<f64> {
        self.quota.read().unwrap().quota_of(address)
    }

    /// An address's quota as `debug_accountTransactionQuota` reports it.
    pub fn quota_report_of(&self, address: &Address) -> Option<(f64, u64)> {
        self.quota.read().unwrap().quota_report_of(address, Instant::now())
    }

    /// Add a raw RLP-encoded transaction to the pool.
    /// Add a raw RLP-encoded transaction to the pool, recording the outcome.
    pub fn add_transaction(&self, raw: &[u8]) -> Result<B256, PoolError> {
        let result = self.add_transaction_inner(raw);
        {
            let mut stats = self.stats.write().unwrap();
            stats.offered += 1;
            match &result {
                Ok(_) => stats.accepted += 1,
                Err(e) => *stats.rejections.entry(e.reason()).or_insert(0) += 1,
            }
        }
        result
    }

    fn add_transaction_inner(&self, raw: &[u8]) -> Result<B256, PoolError> {
        let tx = Transaction::decode(&mut &raw[..])
            .map_err(|e| PoolError::RlpDecode(format!("{e}")))?;

        let hash = tx_hash(raw);

        // rskj `TxValidatorNonceEncodingValidator`, on the bytes as sent:
        // the lenient decoder above has already dropped the leading zeros,
        // and admitting such a transaction would key it by one hash and
        // relay it under another.
        if !raw_nonce_bytes(raw).is_some_and(nonce_bytes_are_canonical) {
            return Err(PoolError::NonCanonicalNonce);
        }

        let mut encoded = Vec::new();
        tx.encode(&mut encoded);
        let encoded_size = encoded.len();

        // A transaction offered twice -- re-broadcast, or seen by both a peer
        // and the RPC -- is recovered once. The write goes to the pool tier,
        // which is what execution reads when the block carrying it arrives.
        let tx_hash_for_cache = tx.tx_hash();
        let cached = self
            .sender_cache
            .as_ref()
            .and_then(|c| c.get_many(&[tx_hash_for_cache]).pop().flatten());
        let sender = match cached {
            Some(sender) => sender,
            None => {
                let recovered = tx
                    .recover_sender(self.chain_id)
                    .map_err(|e| PoolError::InvalidSignature(format!("{e}")))?;
                if let Some(c) = &self.sender_cache {
                    c.put_many(
                        rustock_execution::sender_cache::Origin::Pool,
                        [(tx_hash_for_cache, recovered)],
                    );
                }
                recovered
            }
        };

        let head_header = self.head_header()?;
        let (state_nonce, balance) = self.account_state(&head_header, &sender);

        self.validate_tx(&tx, &sender, encoded_size, &head_header, state_nonce, balance)?;

        let current_block = head_header.number;
        let pooled = PooledTx {
            tx: tx.clone(),
            hash,
            sender,
            added_block: current_block,
            added_time: Instant::now(),
            encoded_size,
        };

        let mut inner = self.inner.write().unwrap();

        if inner.by_hash.contains_key(&hash) {
            return Err(PoolError::AlreadyKnown);
        }

        if inner.by_hash.len() >= self.config.max_pool_transactions {
            // Try to make room by dropping the furthest-out queued transaction.
            // Queued entries have future nonces, so they are not executable yet
            // and are the class an attacker can most cheaply pile up. Pending
            // transactions are never evicted here.
            if !Self::evict_one_queued(&mut inner) {
                return Err(PoolError::PoolFull);
            }
        }

        let goes_to_pending = if tx.nonce == state_nonce {
            true
        } else if let Some(pending_map) = inner.pending.get(&sender) {
            pending_map
                .keys()
                .last()
                .is_some_and(|&last| tx.nonce == last + 1)
        } else {
            false
        };

        // Check for replacement (same nonce, different hash)
        let target_map = if goes_to_pending {
            &inner.pending
        } else {
            &inner.queued
        };
        let mut old_hash_to_remove: Option<B256> = None;
        // The rate limiter prices a replacement by how much it overbids the
        // transaction it displaces, so it needs the displaced one.
        let mut replaced_facts: Option<crate::quota::TxFacts> = None;
        if let Some(nonce_map) = target_map.get(&sender) {
            if let Some(existing) = nonce_map.get(&tx.nonce) {
                if existing.hash == hash {
                    return Err(PoolError::AlreadyKnown);
                }
                let bump_threshold = existing.tx.gas_price
                    * U256::from(100 + self.config.gas_price_bump)
                    / U256::from(100);
                if tx.gas_price < bump_threshold {
                    return Err(PoolError::ReplacementGasPriceTooLow);
                }
                old_hash_to_remove = Some(existing.hash);
                replaced_facts = Some(tx_facts(&existing.tx, existing.encoded_size));
            }
        }

        // Aggregate balance check for pending txs
        if goes_to_pending {
            // rskj `getTxBaseCost`: the value, plus the gas only when the
            // transaction costs anything -- a free Bridge transaction carries
            // its value and nothing else.
            let base_cost = |t: &Transaction| -> U256 {
                let free = self
                    .chain_rules
                    .as_ref()
                    .is_some_and(|r| r.is_free_tx(t, &sender, current_block));
                if free { t.value } else { tx_cost(t) }
            };
            let mut total_cost = base_cost(&tx);
            if let Some(pending_map) = inner.pending.get(&sender) {
                for (nonce, ptx) in pending_map {
                    if *nonce != tx.nonce {
                        total_cost += base_cost(&ptx.tx);
                    }
                }
            }
            if total_cost > balance {
                return Err(PoolError::InsufficientFundsForPendingAndNew);
            }
        }

        // rskj `TransactionPoolImpl.internalAddTransaction`: the quota check is
        // the LAST gate, after every cheaper validation and after the
        // replacement has been resolved. Running it earlier would let an
        // invalid transaction consume an honest account's virtual gas.
        {
            let accounts = TrieAccountView::new(head_header.state_root, &*self.trie_store);
            let ctx = crate::quota::QuotaContext {
                block_gas_limit: head_header.gas_limit.try_into().unwrap_or(u64::MAX),
                block_min_gas_price: head_header
                    .minimum_gas_price
                    .try_into()
                    .unwrap_or(u64::MAX),
                // rskj supplies the average only when the fee market is
                // working -- `isFeeMarketWorking()` false takes its
                // `createSkippingGasPriceFactor` branch, which pins the
                // low-gas-price factor to 1. On a chain with spare capacity
                // that is the usual path on rskj too; the difference is that
                // it recovers when blocks fill up, which this now does.
                avg_gas_price: self.gas_price.as_ref().and_then(|t| {
                    t.is_fee_market_working().then(|| t.gas_price().try_into().unwrap_or(u64::MAX))
                }),
            };
            let receiver = (tx.to.len() == 20).then(|| Address::from_slice(tx.to.as_ref()));
            let accepted = self.quota.write().unwrap().accept_tx(
                sender,
                receiver,
                &tx_facts(&tx, encoded_size),
                replaced_facts.as_ref(),
                &ctx,
                &accounts,
                Instant::now(),
            );
            if !accepted {
                debug!(
                    tx_hash = %hash, sender = %sender, nonce = tx.nonce,
                    "Transaction refused: account exceeds virtual gas quota"
                );
                *self.stats.write().unwrap().quota_by_sender.entry(sender).or_insert(0) += 1;
                return Err(PoolError::AccountExceedsQuota);
            }
        }

        // All checks passed — mutate the pool
        if let Some(old_hash) = old_hash_to_remove {
            inner.by_hash.remove(&old_hash);
        }

        let sender_map = if goes_to_pending {
            inner.pending.entry(sender).or_default()
        } else {
            inner.queued.entry(sender).or_default()
        };
        sender_map.insert(tx.nonce, pooled);
        inner.by_hash.insert(hash, sender);

        if goes_to_pending {
            self.promote_queued(&mut inner, sender, state_nonce);
        }

        debug!(tx_hash = %hash, sender = %sender, nonce = tx.nonce, "Transaction added to pool");
        drop(inner);
        let listener = self.on_added.read().unwrap().clone();
        if let Some(listener) = listener {
            listener(&tx);
        }
        Ok(hash)
    }

    /// rskj `TxPendingValidator.isValid`, step by step and in its order.
    fn validate_tx(
        &self,
        tx: &Transaction,
        sender: &Address,
        encoded_size: usize,
        header: &Header,
        state_nonce: u64,
        balance: U256,
    ) -> Result<(), PoolError> {
        let rules = self.chain_rules.as_ref();
        // rskj `basicTxCost == 0`: a free Bridge transaction.
        let is_free = rules.is_some_and(|r| r.is_free_tx(tx, sender, header.number));

        // 1. Not REMASC (`TxValidatorNotRemascTxValidator`)
        if is_remasc_tx(tx) {
            return Err(PoolError::IsRemascTransaction);
        }

        // 2. Size limit (`TX_MAX_SIZE`)
        if encoded_size > self.config.max_tx_size {
            return Err(PoolError::TxTooLarge);
        }

        // 3. Gas limit (`TxValidatorGasLimitValidator`), against the block's
        //    limit or, under RSKIP144, the larger sublist's.
        let gas_limit = tx.gas_limit.saturating_to::<u64>();
        let bound = rules.map_or(header.gas_limit.saturating_to::<u64>(), |r| r.gas_limit_bound(header));
        if gas_limit > bound || gas_limit > TRANSACTION_GAS_CAP {
            return Err(PoolError::GasLimitExceeded);
        }

        // 4. Nonce range (`TxValidatorNonceRangeValidator`)
        if tx.nonce < state_nonce {
            return Err(PoolError::NonceTooLow);
        }
        if tx.nonce >= state_nonce + self.config.account_slots {
            return Err(PoolError::NonceTooHigh);
        }

        // 5. Balance >= gas cost (`TxValidatorAccountBalanceValidator`),
        //    which a free transaction skips.
        if !is_free {
            let gas_cost = tx.gas_price * tx.gas_limit;
            if balance < gas_cost {
                return Err(PoolError::InsufficientFunds);
            }
        }

        // 6. Minimum gas price (`TxValidatorMinimuGasPriceValidator`)
        if tx.gas_price < header.minimum_gas_price {
            return Err(PoolError::GasPriceTooLow);
        }

        // 7. Intrinsic gas (`TxValidatorIntrinsicGasLimitValidator`): a free
        //    transaction costs nothing, so any limit, zero included, fits.
        let intrinsic = if is_free { 0 } else { intrinsic_gas(tx) };
        if U256::from(intrinsic) > tx.gas_limit {
            return Err(PoolError::IntrinsicGasTooHigh);
        }

        // 8. Price cap (`TxValidatorMaximumGasPriceValidator`), RSKIP252.
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
        let mut inner = self.inner.write().unwrap();
        for tx in transactions {
            let mut buf = Vec::new();
            tx.encode(&mut buf);
            let hash = tx_hash(&buf);
            if Self::remove_by_hash(&mut inner, &hash, tx.nonce) {
                removed += 1;
            }
        }
        drop(inner);
        if removed > 0 {
            self.stats.write().unwrap().mined += removed;
        }
    }

    /// Remove transactions the miner found invalid while building a
    /// template: rskj `BlockToMineBuilder.removePendingTransactions` on
    /// `BlockResult.getInvalidTransactions()`. Returns how many were there.
    pub fn remove_by_hashes(&self, hashes: &[B256]) -> usize {
        let mut inner = self.inner.write().unwrap();
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
        let mut inner = self.inner.write().unwrap();
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

    /// Promote any consecutive queued txs for a sender into pending.
    fn promote_queued(&self, inner: &mut PoolInner, sender: Address, state_nonce: u64) {
        let pending_map = inner.pending.entry(sender).or_default();
        let next_nonce = pending_map
            .keys()
            .last()
            .map(|n| n + 1)
            .unwrap_or(state_nonce);

        if let Some(queued_map) = inner.queued.get_mut(&sender) {
            let mut nonce = next_nonce;
            while let Some(ptx) = queued_map.remove(&nonce) {
                pending_map.insert(nonce, ptx);
                nonce += 1;
            }
            if queued_map.is_empty() {
                inner.queued.remove(&sender);
            }
        }
    }

    /// Get a transaction from the pool by hash.
    pub fn get(&self, hash: &B256) -> Option<PooledTx> {
        let inner = self.inner.read().unwrap();
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
        let inner = self.inner.read().unwrap();
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
        let inner = self.inner.read().unwrap();
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
        let inner = self.inner.read().unwrap();
        let pending: usize = inner.pending.values().map(|m| m.len()).sum();
        let queued: usize = inner.queued.values().map(|m| m.len()).sum();
        (pending, queued)
    }

    /// Return the pending nonce for an address (state nonce + pending count).
    pub fn pending_nonce(&self, addr: &Address) -> Option<u64> {
        let inner = self.inner.read().unwrap();
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

    fn account_state(&self, header: &Header, addr: &Address) -> (u64, U256) {
        let root_hash = header.state_root;
        let root_data = match self.trie_store.get(root_hash.as_slice()) {
            Some(d) => d,
            None => return (0, U256::ZERO),
        };
        let root = TrieNode::from_message(&root_data, &*self.trie_store);
        let key = account_key(addr);
        let expanded = TrieKeySlice::from_key(&key);
        match root.get(&expanded, &*self.trie_store) {
            Some(data) => match AccountState::decode(&data) {
                Ok(acct) => (acct.nonce.to::<u64>(), acct.balance),
                Err(_) => (0, U256::ZERO),
            },
            None => (0, U256::ZERO),
        }
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
        gas_limit: tx.gas_limit.try_into().unwrap_or(u64::MAX),
        gas_price: tx.gas_price,
        size: encoded_size,
    }
}

/// Compute the cost of a transaction: value + gas_price * gas_limit.
fn tx_cost(tx: &Transaction) -> U256 {
    tx.value + tx.gas_price * tx.gas_limit
}

/// Compute the keccak256 hash of raw transaction bytes.
pub fn tx_hash(raw: &[u8]) -> B256 {
    B256::from_slice(&Keccak256::digest(raw))
}

/// Check if a transaction is a REMASC transaction.
fn is_remasc_tx(tx: &Transaction) -> bool {
    if tx.to.len() != 20 {
        return false;
    }
    let remasc_bytes: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 8];
    tx.to.as_ref() == remasc_bytes
        && tx.gas_price.is_zero()
        && tx.gas_limit.is_zero()
        && tx.value.is_zero()
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
    use k256::ecdsa::SigningKey;
    use rustock_trie::MemoryTrieStore;
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

        let mut header = test_header();
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
        assert!(matches!(pool.add_transaction(&raw), Err(PoolError::AlreadyKnown)));

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
        assert!(matches!(err, PoolError::AlreadyKnown));
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
        assert!(matches!(err, PoolError::GasLimitExceeded));
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

    #[test]
    fn test_remasc_tx_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let remasc_addr: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 8];
        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::from(remasc_addr.to_vec()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::IsRemascTransaction));
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
            hashes.push(tx_hash(&raw));
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
    /// signature is good.
    #[test]
    fn a_non_canonical_nonce_is_refused_on_admission() {
        let (pool, key, _) = setup_pool_with_account(U256::from(10u64.pow(18)), 1);
        let mut tx = make_tx(1, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let canonical = encode_tx(&tx);

        // Splice the nonce item: `0x01` becomes `0x82 0x00 0x01`.
        let mut buf = &canonical[..];
        let list = alloy_rlp::Header::decode(&mut buf).unwrap();
        assert_eq!(buf[0], 0x01, "nonce 1 is a single byte");
        let mut payload = vec![0x82, 0x00, 0x01];
        payload.extend_from_slice(&buf[1..list.payload_length]);
        let mut raw = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut raw);
        raw.extend_from_slice(&payload);

        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::NonCanonicalNonce), "got {err}");
        pool.add_transaction(&canonical).expect("the canonical form is fine");
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
    /// nothing, so the zero limit covers it.
    #[test]
    fn valid_intrinsic_gas_price_for_a_free_bridge_tx_with_zero_gas_limit() {
        let (_, _, addr) = setup_pool_with_rules(U256::ZERO, 0, test_config(), None);
        let (pool, key, _) = setup_pool_with_rules(U256::ZERO, 0, test_config(), Some(free_bridge_rules(addr)));
        let mut tx = bridge_tx(0, 0, &[]);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).expect("free, zero gas");

        // Paid from 370,000 on: the same transaction is then over its own
        // intrinsic cost.
        let mut paid = free_bridge_rules(addr);
        paid.hardfork_cfg = rustock_execution::hardfork::RskHardforkConfig::all_active(33);
        let (pool, key, _) = setup_pool_with_rules(U256::ZERO, 0, test_config(), Some(paid));
        let mut tx = bridge_tx(0, 0, &[]);
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::IntrinsicGasTooHigh), "got {err}");
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
        assert!(matches!(err, PoolError::GasLimitExceeded), "got {err}");
        tx.gas_limit = U256::from(6_800_000);
        sign_tx(&mut tx, &key, 33);
        pool.add_transaction(&encode_tx(&tx)).expect("at the sublist limit");
    }

    // ========== Invalid signature ==========

    #[test]
    fn test_invalid_signature_rejected() {
        let (pool, _key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.v = 27;
        tx.r = U256::ZERO;
        tx.s = U256::ZERO;
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::InvalidSignature(_)));
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
        assert!(matches!(err, PoolError::TxTooLarge));
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
    fn test_null_sender_insufficient_funds() {
        // An account not in the trie has balance=0. Any tx requiring gas should fail.
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
        assert!(matches!(err, PoolError::InsufficientFunds));

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
        assert!(matches!(err, PoolError::AlreadyKnown));
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
        assert_eq!(PoolError::AlreadyKnown.to_string(), "transaction with same hash already exists");
        assert_eq!(PoolError::NonceTooLow.to_string(), "transaction nonce too low");
        assert_eq!(PoolError::NonceTooHigh.to_string(), "transaction nonce too high");
        assert_eq!(PoolError::InsufficientFunds.to_string(), "insufficient funds");
        assert_eq!(PoolError::GasLimitExceeded.to_string(), "transaction's gas limit exceeds block gas limit");
        assert_eq!(PoolError::GasPriceTooLow.to_string(), "transaction's gas price lower than block's minimum");
        assert_eq!(PoolError::IntrinsicGasTooHigh.to_string(), "transaction's basic cost is above the gas limit");
        assert_eq!(PoolError::ReplacementGasPriceTooLow.to_string(), "gas price not enough to bump transaction");
        assert_eq!(PoolError::TxTooLarge.to_string(), "transaction's size is higher than defined maximum");
        assert_eq!(PoolError::IsRemascTransaction.to_string(), "transaction is a remasc transaction");
        assert_eq!(
            PoolError::InsufficientFundsForPendingAndNew.to_string(),
            "insufficient funds to pay for pending and new transactions"
        );
    }
}
