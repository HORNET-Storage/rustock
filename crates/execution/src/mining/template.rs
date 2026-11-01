//! Building the RSK block a miner searches for.
//!
//! The load-bearing hook is that [`BlockProcessor::execute_block`] executes
//! without checking the header's roots while `process_block` checks them: a
//! template can be assembled with placeholder roots, executed, and then have
//! the real roots written back from the result. There is no second execution
//! path for mining, so a block this builds is executed by exactly the code
//! that will later re-execute it on the way in.

use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use rustock_core::config::ChainConfig;
use rustock_core::validation::DifficultyRule;
use rustock_core::validation::block_rules::BlockTxsMaxGasPriceRule;
use rustock_core::{Block, Header, Transaction, ordered_tx_trie_root};
use rustock_trie::{AccountState, TrieKeySlice, TrieNode, TrieStore, account_key};
use std::collections::HashMap;
use std::sync::Arc;

use crate::hardfork::RskHardforkConfig;
use crate::mining::fork_detection;
use crate::processor::{BlockProcessor, ProcessError, compute_ommers_hash};

/// Knobs an operator sets for the blocks this node builds. None of them are
/// consensus: a block is valid whatever is chosen here, within the bounds the
/// header rules impose.
#[derive(Debug, Clone)]
pub struct MiningConfig {
    /// Where block rewards are paid. REMASC credits this address.
    pub coinbase_address: Address,
    /// `extra_data`, capped at 32 bytes by the header rules.
    pub extra_data: Bytes,
    /// Gas limit to steer towards, one step per block. `None` inherits the
    /// parent's, which is always valid and never drifts.
    pub gas_limit_target: Option<U256>,
    /// Minimum gas price to steer towards, one step per block. `None`
    /// inherits the parent's.
    pub min_gas_price_target: Option<U256>,
    /// How many templates to keep for submissions that arrive late.
    pub work_cache_size: usize,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            coinbase_address: Address::ZERO,
            extra_data: Bytes::new(),
            gas_limit_target: None,
            min_gas_price_target: None,
            // rskj MinerServerImpl.CACHE_SIZE.
            work_cache_size: 20,
        }
    }
}

/// A block ready to be mined, plus everything a submission needs to be matched
/// back to it.
/// A block's transactions in sublist order, with the edges that describe it.
struct Partitioned {
    transactions: Vec<Transaction>,
    edges: Vec<i16>,
}

#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// The block itself, with every field filled except the three
    /// merged-mining ones a solution supplies.
    pub block: Block,
    /// The 32 bytes a coinbase must carry after `RSKBLOCK:`: the first 20 of
    /// the header's merged-mining hash, then RSKIP110 fork-detection data.
    /// This, not the block hash, is what a submission is looked up by.
    pub hash_for_merged_mining: B256,
    /// `U256::MAX / difficulty`: the Bitcoin block hash, read little-endian,
    /// must not exceed this.
    pub target: U256,
    /// Fees this block would pay its miner, for a pool deciding whether the
    /// work is worth switching to.
    pub fees_paid_to_miner: U256,
    /// State root the block was executed against -- so a submission can
    /// re-execute from the same point without hunting for it.
    pub parent_state_root: B256,
}

impl BlockTemplate {
    /// The parent this template builds on.
    pub fn parent_hash(&self) -> B256 {
        self.block.header.parent_hash
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("no parent state root {root} in the trie store: the parent has not been executed")]
    ParentStateMissing { root: B256 },
    #[error("executing the template failed: {0}")]
    Execution(#[from] ProcessError),
    /// The partition probe runs the executor directly rather than the
    /// processor, so its failures arrive unwrapped.
    #[error("partitioning the template failed: {0}")]
    Partition(#[from] crate::executor::ExecutionError),
    #[error("storage error: {0}")]
    Storage(#[from] anyhow::Error),
}

/// A transaction waiting to be mined, with its sender already recovered.
///
/// The pool lives in the sync crate and recovers senders on admission; the
/// builder would otherwise recover every sender again on every rebuild, once a
/// minute per pending transaction.
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    pub tx: Transaction,
    pub sender: Address,
    pub hash: B256,
}

/// Where the builder gets transactions. A trait because the pool lives in the
/// sync crate, which depends on this one.
pub trait PendingTransactionSource: Send + Sync {
    fn pending(&self) -> Vec<PendingTransaction>;
}

/// Nothing to mine but the REMASC transaction. Useful on regtest and in tests,
/// and it is what an operator mining an idle chain effectively has.
pub struct NoPendingTransactions;

impl PendingTransactionSource for NoPendingTransactions {
    fn pending(&self) -> Vec<PendingTransaction> {
        Vec::new()
    }
}

pub struct BlockTemplateBuilder {
    processor: Arc<BlockProcessor>,
    trie_store: Arc<dyn TrieStore>,
    chain_config: Arc<ChainConfig>,
    hardfork_cfg: RskHardforkConfig,
    mining_config: MiningConfig,
}

impl BlockTemplateBuilder {
    pub fn new(
        processor: Arc<BlockProcessor>,
        trie_store: Arc<dyn TrieStore>,
        chain_config: Arc<ChainConfig>,
        hardfork_cfg: RskHardforkConfig,
        mining_config: MiningConfig,
    ) -> Self {
        Self { processor, trie_store, chain_config, hardfork_cfg, mining_config }
    }

    pub fn mining_config(&self) -> &MiningConfig {
        &self.mining_config
    }

    pub fn processor(&self) -> &BlockProcessor {
        &self.processor
    }

    pub fn trie_store(&self) -> Arc<dyn TrieStore> {
        self.trie_store.clone()
    }

    /// Build a template on top of `mainchain[0]`.
    ///
    /// `mainchain` is the best chain in descending order. Only the first entry
    /// is needed to build the block; the rest feed the fork-detection data,
    /// and passing fewer than [`fork_detection::REQUIRED_MAINCHAIN_BLOCKS`]
    /// simply produces a header without it -- which is correct for a chain
    /// that short and wrong for one that is not, so callers should pass what
    /// they have.
    pub fn build(
        &self,
        mainchain: &[Header],
        ommers: Vec<Header>,
        pending: &dyn PendingTransactionSource,
    ) -> Result<BlockTemplate, TemplateError> {
        let parent = &mainchain[0];
        let parent_state_root = parent.state_root;
        let state_root = self.load_state_root(parent_state_root)?;

        let number = parent.number + 1;
        let timestamp = timestamp_for_child(parent.timestamp);
        let difficulty = DifficultyRule { config: self.chain_config.clone() }
            .difficulty_for_child(parent, number, timestamp, ommers.len() as u64);
        let gas_limit = next_gas_limit(parent, self.mining_config.gas_limit_target);
        let minimum_gas_price =
            next_minimum_gas_price(parent.minimum_gas_price, self.mining_config.min_gas_price_target);

        let mut transactions = self.select_transactions(
            pending,
            &state_root,
            number,
            minimum_gas_price,
            gas_limit,
        );
        // Not appended by the executor: REMASC is an ordinary entry in the
        // block's transaction list, recognised by shape. A template without it
        // executes to a different state root, and the failure reads as an
        // execution bug rather than a missing transaction.
        transactions.push(remasc_transaction(number));

        let rskip126 = self.hardfork_cfg.has_unitrie_state_root(number);
        // rskj sets ummRoot to the empty byte array from papyrus200 on (the
        // UMM contracts were never deployed, so it is never non-empty). Its
        // mere presence changes both the block hash and the merged-mining
        // hash, so a header built without it is rejected by every peer.
        let umm_root = if number >= self.chain_config.activation_heights.papyrus200 {
            Some(Bytes::new())
        } else {
            None
        };

        #[allow(unused_mut)]
        let mut header = Header {
            parent_hash: parent.hash(),
            ommers_hash: compute_ommers_hash(&ommers),
            beneficiary: self.mining_config.coinbase_address,
            // Placeholders: execute_block does not check them, and they are
            // written back from the result below.
            state_root: B256::ZERO,
            transactions_root: ordered_tx_trie_root(&transactions, rskip126),
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            version_fields: None,
            difficulty,
            number,
            gas_limit,
            gas_used: 0,
            timestamp,
            extra_data: self.mining_config.extra_data.clone(),
            paid_fees: U256::ZERO,
            minimum_gas_price,
            uncle_count: ommers.len() as u64,
            umm_root,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };

        // RSKIP-144: decide the partition, which also decides the order.
        //
        // The transactions are executed once in selection order to learn what
        // each one touches, the partitioner places them from that, and the
        // block is then rebuilt in sublist order and executed again. rskj
        // does the first pass and reorders its receipts rather than
        // re-executing, relying on a collision-free partition reaching the
        // same state either way -- which is true, and is the theorem the
        // validator exists to check rather than assume. Executing the block
        // that will actually be published is the cheaper thing to be sure of,
        // and the receipts have to be rebuilt regardless: `cumulativeGasUsed`
        // restarts at each sublist.
        let partitioned = self.partition(number, gas_limit, &transactions, &header, &state_root)?;
        if let Some(partitioned) = partitioned {
            transactions = partitioned.transactions;
            header.transactions_root = ordered_tx_trie_root(&transactions, rskip126);
            header.version_fields = Some(rustock_core::types::header::HeaderVersionFields {
                // RSKIP-351 travels with RSKIP-144; the extension is what
                // carries the edges.
                version: 1,
                edges: Some(partitioned.edges),
                base_event: None,
            });
        }

        let block = Block { header: header.clone(), transactions, ommers };
        let executed =
            self.processor.execute_block(&block, &state_root, self.trie_store.clone())?;

        header.state_root = executed.state_root_hash;
        header.receipts_root = executed.receipts_root;
        header.logs_bloom = executed.logs_bloom;
        header.gas_used = executed.gas_used;
        header.paid_fees = executed.paid_fees;

        let fork_data = fork_detection::calculate(mainchain);
        let hash_for_merged_mining =
            fork_detection::apply_to_hash(header.hash_for_merged_mining(), &fork_data);

        Ok(BlockTemplate {
            block: Block { header, ..block },
            hash_for_merged_mining,
            target: difficulty_to_target(difficulty),
            fees_paid_to_miner: executed.paid_fees,
            parent_state_root,
        })
    }

    /// Place the block's transactions in sublists, as rskj's miner does.
    ///
    /// `None` when the block declares no partition: RSKIP-144 inactive, or
    /// the partition came out all-sequential, which rskj spells as an empty
    /// edges array and we spell as no extension at all.
    ///
    /// The transactions are executed once here, in selection order, only to
    /// learn what each one touches. That is also how rskj learns it, and it
    /// is an approximation on purpose: a transaction is placed from an
    /// execution against the accumulating sequential state, while its
    /// sublist will run against the parent state. Where the two differ the
    /// partition is wrong, and the validator is what catches it -- which is
    /// why the validator re-checks instead of trusting the header.
    fn partition(
        &self,
        number: u64,
        gas_limit: U256,
        transactions: &[Transaction],
        header: &Header,
        state_root: &TrieNode,
    ) -> Result<Option<Partitioned>, TemplateError> {
        if !self.hardfork_cfg.has_rskip144(number) {
            return Ok(None);
        }

        let chain_id = self.hardfork_cfg.chain_id;
        let with_senders: Vec<(Transaction, Address)> = transactions
            .iter()
            .map(|tx| {
                let sender = tx.recover_sender(chain_id).unwrap_or_default();
                (tx.clone(), sender)
            })
            .collect();

        crate::collision::start_per_transaction(crate::collision::write_semantics(number));
        let executed = self.processor.executor().execute_block(
            header,
            &with_senders,
            state_root,
            self.trie_store.clone(),
        );
        // Taken whether or not execution succeeded, so a failure cannot leave
        // this probe's keys behind for the next template.
        let touched = crate::collision::finish().unwrap_or_default();
        let executed = executed?;

        let mut partitioner = crate::mining::partition::SublistPartitioner::new(
            rustock_core::validation::block_rules::TX_EXECUTION_THREADS,
            gas_limit.saturating_to::<u64>(),
            self.chain_config.min_sequential_set_gas_limit,
        );

        let mut placed: Vec<usize> = Vec::with_capacity(transactions.len());
        for (index, tx) in transactions.iter().enumerate() {
            let Some(result) = executed.tx_results.get(index) else {
                continue;
            };

            // REMASC closes the sequential sublist and is not placed by the
            // ordinary rule -- it is the block's last transaction by
            // definition.
            if index + 1 == transactions.len() && crate::mining::template::is_remasc(tx) {
                partitioner.add_remasc(index, result.gas_used);
                placed.push(index);
                continue;
            }

            let keys = touched.keys(index);
            let footprint = crate::mining::partition::TxFootprint {
                sender: with_senders[index].1,
                gas_limit: tx.gas_limit.saturating_to::<u64>(),
                gas_used: result.gas_used,
                reads: keys.map(|k| k.read().iter().cloned().collect()).unwrap_or_default(),
                writes: keys.map(|k| k.written().iter().cloned().collect()).unwrap_or_default(),
            };

            // A transaction that reached REMASC or the Bridge may go nowhere
            // but the sequential sublist: a parallel one makes the block
            // invalid (`SEQUENTIAL_ONLY_PRECOMPILES`).
            let seat = if result.reached_sequential_only {
                partitioner.add_to_sequential(index, &footprint)
            } else {
                partitioner.add(index, &footprint)
            };
            // `None` is "it fits nowhere"; the transaction is dropped from
            // the block rather than overflowing a sublist.
            if seat.is_some() {
                placed.push(index);
            }
        }

        let edges = partitioner.edges();
        if edges.is_empty() {
            return Ok(None);
        }

        let order = partitioner.transactions_in_order();
        debug_assert_eq!(order.len(), placed.len(), "every placed transaction is ordered");
        Ok(Some(Partitioned {
            transactions: order.iter().map(|&i| transactions[i].clone()).collect(),
            edges,
        }))
    }

    /// Reload the parent's state root from the trie store.
    pub fn load_state_root(&self, root: B256) -> Result<TrieNode, TemplateError> {
        if root == rustock_trie::TrieNode::empty().compute_hash(self.trie_store.as_ref()) {
            return Ok(TrieNode::empty());
        }
        self.trie_store
            .get(root.as_slice())
            .map(|data| TrieNode::from_message(&data, self.trie_store.as_ref()))
            .ok_or(TemplateError::ParentStateMissing { root })
    }

    /// Pick transactions to include: best price first, each sender's
    /// transactions in nonce order and starting from the nonce the state
    /// expects, skipping anything underpriced, *overpriced*, or that no
    /// longer fits.
    ///
    /// **Both ends of the price range are consensus rules, not policy.** The
    /// floor is `TxsMinGasPriceRule` and the ceiling is
    /// [`BlockTxsMaxGasPriceRule`] -- RSKIP252, 100x the block's
    /// `minimumGasPrice`. A miner that applies only the floor seals blocks
    /// that every validator on the network rejects, which is worse than
    /// mining nothing: the work is spent and the block is refused. rskj drops
    /// both in `MinerUtils.filterTransactions` (`isHighGasPriced`), and this
    /// is the same filter on the same rule the import path already enforces.
    ///
    /// REMASC needs no exemption here even though the rule grants it one: it
    /// is never in the pool, and `build` appends it after this returns.
    fn select_transactions(
        &self,
        pending: &dyn PendingTransactionSource,
        state_root: &TrieNode,
        number: u64,
        minimum_gas_price: U256,
        block_gas_limit: U256,
    ) -> Vec<Transaction> {
        let ordered = order_by_price_sender_and_nonce(pending.pending());

        // `TxGasPriceCap.isSurpassed` short-circuits on a zero minimum, so a
        // chain whose minimum is zero -- regtest, and mainnet before the fee
        // market moved -- has no ceiling at all. Matching that is what keeps
        // this filter from dropping everything on such a chain.
        let max_gas_price = (number >= self.chain_config.activation_heights.fingerroot500
            && !minimum_gas_price.is_zero())
        .then(|| {
            minimum_gas_price.saturating_mul(U256::from(
                BlockTxsMaxGasPriceRule::FOR_BLOCK_MULTIPLIER,
            ))
        });

        let mut next_nonce: HashMap<Address, u64> = HashMap::new();
        let mut gas_committed = U256::ZERO;
        let mut selected = Vec::new();

        for candidate in ordered {
            if candidate.tx.gas_price < minimum_gas_price {
                continue;
            }
            if max_gas_price.is_some_and(|cap| candidate.tx.gas_price > cap) {
                continue;
            }

            let expected = *next_nonce.entry(candidate.sender).or_insert_with(|| {
                account_nonce(state_root, self.trie_store.as_ref(), &candidate.sender)
            });
            if candidate.tx.nonce != expected {
                // A gap, or a nonce already used. Later transactions from this
                // sender cannot execute either, but they are cheap to skip and
                // dropping the sender outright would need a second pass.
                continue;
            }

            // The executor charges each transaction its own gas limit against
            // the block's; there is no partial inclusion, so a transaction
            // that does not fit is skipped and a cheaper one may still fit.
            let after = gas_committed + candidate.tx.gas_limit;
            if after > block_gas_limit {
                continue;
            }

            gas_committed = after;
            next_nonce.insert(candidate.sender, expected + 1);
            selected.push(candidate.tx);
        }

        selected
    }
}

/// rskj `PendingState.sortByPriceTakingIntoAccountSenderAndNonce`: cluster by
/// sender, order each cluster by nonce, then merge the clusters by price,
/// always comparing only each sender's next transaction. Ordering purely by
/// price would interleave a sender's own transactions out of nonce order and
/// strand all but the first.
#[cfg(test)]
pub(crate) fn order_by_price_sender_and_nonce_for_test(
    pending: Vec<PendingTransaction>,
) -> Vec<PendingTransaction> {
    order_by_price_sender_and_nonce(pending)
}

fn order_by_price_sender_and_nonce(pending: Vec<PendingTransaction>) -> Vec<PendingTransaction> {
    let mut by_sender: HashMap<Address, Vec<PendingTransaction>> = HashMap::new();
    for ptx in pending {
        by_sender.entry(ptx.sender).or_default().push(ptx);
    }

    for txs in by_sender.values_mut() {
        txs.sort_by(|a, b| {
            a.tx.nonce
                .cmp(&b.tx.nonce)
                .then(b.tx.gas_price.cmp(&a.tx.gas_price))
                .then(a.hash.cmp(&b.hash))
        });
        // Cheapest-last, so the next transaction is always `pop`.
        txs.reverse();
    }

    let mut queues: Vec<Vec<PendingTransaction>> = by_sender.into_values().collect();
    let mut out = Vec::new();
    loop {
        let best = queues
            .iter()
            .enumerate()
            .filter_map(|(i, q)| q.last().map(|t| (i, t)))
            .max_by(|(ai, a), (bi, b)| {
                a.tx.gas_price
                    .cmp(&b.tx.gas_price)
                    // Deterministic across runs: a HashMap hands the senders
                    // back in whatever order it likes, and two senders
                    // offering the same price must still be mined in the same
                    // order on every rebuild of the same template.
                    .then(b.hash.cmp(&a.hash))
                    .then(bi.cmp(ai))
            })
            .map(|(i, _)| i);
        match best {
            Some(i) => out.push(queues[i].pop().expect("non-empty queue")),
            None => break,
        }
    }
    out
}

fn account_nonce(state_root: &TrieNode, store: &dyn TrieStore, addr: &Address) -> u64 {
    let key = account_key(addr);
    let expanded = TrieKeySlice::from_key(&key);
    match state_root.get(&expanded, store) {
        Some(data) => AccountState::decode(&data).map(|a| a.nonce.to::<u64>()).unwrap_or(0),
        None => 0,
    }
}

/// The REMASC transaction for a block, byte-for-byte as rskj encodes it.
///
/// `cached_rlp` is not an optimisation here. rskj writes the zero gas price
/// and gas limit as a literal `0x00` byte and the zero value as `0x80`, which
/// canonical RLP would render the other way round; re-encoding this
/// transaction would give it a different hash and put a different
/// transactions root in the header. rskj `RemascTransaction(long blockNumber)`
/// with `Transaction.encode`.
/// Whether `tx` is the REMASC system transaction, by shape.
pub fn is_remasc(tx: &Transaction) -> bool {
    tx.to.as_ref() == crate::precompiles::REMASC_ADDR.as_slice()
        && tx.r.is_zero()
        && tx.s.is_zero()
}

pub fn remasc_transaction(block_number: u64) -> Transaction {
    let nonce = block_number.saturating_sub(1);
    let to = Bytes::copy_from_slice(crate::precompiles::REMASC_ADDR.as_slice());

    let mut payload = Vec::new();
    // nonce: minimal big-endian, and empty when zero
    if nonce == 0 {
        payload.push(0x80);
    } else {
        let bytes = nonce.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).expect("nonce is non-zero");
        let minimal = &bytes[start..];
        if minimal.len() == 1 && minimal[0] < 0x80 {
            payload.push(minimal[0]);
        } else {
            payload.push(0x80 + minimal.len() as u8);
            payload.extend_from_slice(minimal);
        }
    }
    payload.push(0x00); // gasPrice: RLP.encodeCoinNonNullZero(ZERO) -> {0}
    payload.push(0x00); // gasLimit: RLP.encodeElement({0}) -> {0}
    payload.push(0x80 + 20); // to
    payload.extend_from_slice(&to);
    payload.push(0x80); // value: RLP.encodeCoinNullZero(ZERO) -> encodeByte(0) -> 0x80
    payload.push(0x80); // data: null
    payload.push(0x80); // v: unsigned, chainId 0
    payload.push(0x80); // r
    payload.push(0x80); // s

    let mut rlp = Vec::with_capacity(payload.len() + 3);
    if payload.len() < 56 {
        rlp.push(0xc0 + payload.len() as u8);
    } else {
        let len_bytes = (payload.len() as u64).to_be_bytes();
        let start = len_bytes.iter().position(|b| *b != 0).expect("non-empty payload");
        rlp.push(0xf7 + (8 - start) as u8);
        rlp.extend_from_slice(&len_bytes[start..]);
    }
    rlp.extend_from_slice(&payload);

    Transaction {
        nonce,
        gas_price: U256::ZERO,
        gas_limit: U256::ZERO,
        to,
        value: U256::ZERO,
        input: Bytes::new(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: Some(rlp),
    }
}

/// rskj `MinerClock.calculateTimestampForChild`: wall clock, but never at or
/// before the parent -- a header with a timestamp not strictly greater than
/// its parent's is rejected outright.
fn timestamp_for_child(parent_timestamp: u64) -> u64 {
    // `dev::now_with_offset` is wall clock plus whatever `evm_increaseTime`
    // has accumulated -- zero unless a development chain moved it, so this is
    // the same wall clock everywhere else.
    let now = crate::mining::dev::now_with_offset();
    now.max(parent_timestamp + 1)
}

/// One step towards `target`, bounded by what the parent allows.
///
/// The consensus rule is only that a child's gas limit stays within
/// `parent / 1024` of the parent's, so inheriting it unchanged -- which is
/// what `None` does -- is always valid. rskj `GasLimitCalculator`.
fn next_gas_limit(parent: &Header, target: Option<U256>) -> U256 {
    let parent_limit = parent.gas_limit;
    let Some(target) = target else {
        return parent_limit;
    };
    let delta = parent_limit / U256::from(1024);
    if target > parent_limit {
        target.min(parent_limit + delta)
    } else {
        target.max(parent_limit.saturating_sub(delta))
    }
}

/// One step towards `target`, bounded by what the parent allows.
///
/// rskj `MinimumGasPriceCalculator` (RSKIP-09) with `BlockGasPriceRange`: a
/// child may move the minimum gas price by at most 1% of the parent's, or by
/// one wei when 1% rounds to nothing. The parent's own value is always in
/// range, so `None` -- inherit -- is always valid.
fn next_minimum_gas_price(parent_price: U256, target: Option<U256>) -> U256 {
    let Some(target) = target else {
        return parent_price;
    };
    let mut delta = parent_price / U256::from(100);
    if delta.is_zero() {
        delta = U256::from(1);
    }
    let upper = parent_price + delta;
    let lower = parent_price.saturating_sub(delta);
    target.clamp(lower, upper)
}

/// rskj `DifficultyUtils.difficultyToTarget`.
pub fn difficulty_to_target(difficulty: U256) -> U256 {
    if difficulty.is_zero() {
        U256::MAX
    } else {
        U256::MAX / difficulty
    }
}
