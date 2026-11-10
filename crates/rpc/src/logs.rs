use crate::dto::LogDto;
use crate::helpers::{parse_b256, to_hex_b256, to_hex_u64};
use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::{Address, B256};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

/// Block range an `eth_getLogs` may span when the operator has set no limit.
///
/// rskj's equivalent is `rpc.logs.maxBlocksToQuery`, default 5000. Ours is
/// more generous, which is safe in the direction that matters: a client that
/// works against rskj works against this node. Operators who want rskj's
/// number, or a tighter one on a public endpoint, set it.
///
/// Measured at #9,275,036 with a 10,000-block span: 0.16 s when the bloom
/// rejects every block, 2.9 s when the query genuinely matches. The cap is
/// what bounds this query -- see #122.
pub const DEFAULT_MAX_BLOCK_RANGE: u64 = 10_000;

/// In-memory filter storage for eth_newFilter / eth_getFilterChanges.
#[derive(Clone)]
pub struct FilterStore {
    filters: Arc<RwLock<HashMap<u64, Filter>>>,
    next_id: Arc<AtomicU64>,
}

impl Default for FilterStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterStore {
    pub fn new() -> Self {
        Self {
            filters: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn insert(&self, filter: Filter) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.filters
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, filter);
        id
    }

    fn get(&self, id: u64) -> Option<Filter> {
        self.filters
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    fn update_last_polled(&self, id: u64, block: u64) {
        if let Some(f) = self
            .filters
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&id)
        {
            f.last_polled_block = block;
        }
    }

    /// Replace a pending-transaction filter's seen-set with the pool as it is
    /// now. Called straight after the difference has been handed to the
    /// caller.
    fn replace_reported(&self, id: u64, now: std::collections::HashSet<B256>) {
        if let Some(f) = self
            .filters
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&id)
        {
            if let FilterKind::PendingTransaction { reported } = &mut f.kind {
                *reported = now;
            }
        }
    }

    fn remove(&self, id: u64) -> bool {
        self.filters
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id)
            .is_some()
    }
}

#[derive(Clone, Debug)]
enum FilterKind {
    Log(LogFilter),
    Block,
    /// `reported` is the pool as this filter last saw it. A poll answers the
    /// difference and then replaces it, which bounds the set by the pool's own
    /// size rather than letting it grow for the filter's lifetime. A
    /// transaction that leaves the pool and comes back is reported again,
    /// which is correct: it is pending again.
    PendingTransaction { reported: std::collections::HashSet<B256> },
}

#[derive(Clone, Debug)]
struct Filter {
    kind: FilterKind,
    last_polled_block: u64,
}

#[derive(Clone, Debug)]
struct LogFilter {
    from_block: Option<u64>,
    to_block: Option<u64>,
    addresses: Vec<Address>,
    topics: Vec<Option<Vec<B256>>>,
}

pub fn eth_get_logs(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_obj) = params.get(0) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing filter object");
    };

    let head_num = head_number(&state.store).unwrap_or(0);
    let filter = match parse_log_filter(filter_obj, head_num) {
        Ok(filter) => filter,
        Err((code, message)) => return JsonRpcResponse::error(id, code, message),
    };

    let from = filter.from_block.unwrap_or(head_num);
    let to = filter.to_block.unwrap_or(head_num);

    let max_range = state.logs_max_blocks.max(1);
    // Measured as a difference, which cannot overflow: a `fromBlock` near 2^64
    // would carry `from + max_range` past the top.
    if to.saturating_sub(from) > max_range {
        return JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            format!("Block range exceeds maximum ({max_range})"),
        );
    }

    let logs = collect_logs(from, to, &filter, state);
    JsonRpcResponse::success(id, serde_json::to_value(&logs).unwrap())
}

pub fn eth_new_filter(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_obj) = params.get(0) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing filter object");
    };

    let head_num = head_number(&state.store).unwrap_or(0);
    let log_filter = match parse_log_filter(filter_obj, head_num) {
        Ok(filter) => filter,
        Err((code, message)) => return JsonRpcResponse::error(id, code, message),
    };

    let filter = Filter {
        kind: FilterKind::Log(log_filter),
        last_polled_block: head_num,
    };

    let filter_id = state.filter_store.insert(filter);
    JsonRpcResponse::success(id, json!(to_hex_u64(filter_id)))
}

pub fn eth_new_block_filter(id: Value, state: &RpcState) -> JsonRpcResponse {
    let head_num = head_number(&state.store).unwrap_or(0);
    let filter = Filter {
        kind: FilterKind::Block,
        last_polled_block: head_num,
    };
    let filter_id = state.filter_store.insert(filter);
    JsonRpcResponse::success(id, json!(to_hex_u64(filter_id)))
}

/// A filter over transactions entering the pool.
///
/// This used to answer the constant `"0x0"` with the comment "no mempool
/// support". There is a mempool now -- `txpool_status` and `txpool_content`
/// both read it -- but the stub outlived it, with three consequences a caller
/// can see: every filter had the same id, so two were indistinguishable; id
/// zero is not a real filter, so `eth_uninstallFilter` answered false and the
/// filter could not be removed; and `eth_getFilterChanges` special-cases zero
/// to an empty array, so it never reported anything.
pub fn eth_new_pending_transaction_filter(id: Value, state: &RpcState) -> JsonRpcResponse {
    // Seeded with what is already pending, so the first poll reports what
    // arrives *after* the filter was created rather than replaying the pool.
    let filter = Filter {
        kind: FilterKind::PendingTransaction { reported: pool_hashes(state) },
        last_polled_block: head_number(&state.store).unwrap_or(0),
    };
    let filter_id = state.filter_store.insert(filter);
    JsonRpcResponse::success(id, json!(to_hex_u64(filter_id)))
}

/// Every transaction hash currently in the pool, pending or queued.
fn pool_hashes(state: &RpcState) -> std::collections::HashSet<B256> {
    let Some(pool) = &state.tx_pool else {
        return std::collections::HashSet::new();
    };
    let content = pool.pool_content();
    content
        .pending
        .iter()
        .chain(content.queued.iter())
        .flat_map(|(_, txs)| txs.iter().map(|(_, tx)| tx.tx_hash()))
        .collect()
}

pub fn eth_get_filter_changes(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_id) = params.get(0).and_then(|v| v.as_str()).and_then(parse_hex_u64) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid filter id");
    };

    if filter_id == 0 {
        return JsonRpcResponse::success(id, json!([]));
    }

    let Some(filter) = state.filter_store.get(filter_id) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Filter not found");
    };

    let head_num = head_number(&state.store).unwrap_or(0);

    match &filter.kind {
        FilterKind::Log(log_filter) => {
            let from = filter.last_polled_block + 1;
            let to = head_num;
            if from > to {
                return JsonRpcResponse::success(id, json!([]));
            }
            let logs = collect_logs(from, to, log_filter, state);
            state.filter_store.update_last_polled(filter_id, head_num);
            JsonRpcResponse::success(id, serde_json::to_value(&logs).unwrap())
        }
        FilterKind::Block => {
            let from = filter.last_polled_block + 1;
            let to = head_num;
            let mut hashes = Vec::new();
            for num in from..=to {
                if let Some(hash) = state.store.canonical_hash(num).ok().flatten() {
                    hashes.push(to_hex_b256(&hash));
                }
            }
            state.filter_store.update_last_polled(filter_id, head_num);
            JsonRpcResponse::success(id, json!(hashes))
        }
        FilterKind::PendingTransaction { reported } => {
            let now = pool_hashes(state);
            let mut fresh: Vec<String> =
                now.difference(reported).map(to_hex_b256).collect();
            // `HashSet` has no order and a caller reading a diff should not
            // see one invented at random between polls.
            fresh.sort();
            state.filter_store.replace_reported(filter_id, now);
            JsonRpcResponse::success(id, json!(fresh))
        }
    }
}

pub fn eth_get_filter_logs(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_id) = params.get(0).and_then(|v| v.as_str()).and_then(parse_hex_u64) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid filter id");
    };

    let Some(filter) = state.filter_store.get(filter_id) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Filter not found");
    };

    match &filter.kind {
        FilterKind::Log(log_filter) => {
            let head_num = head_number(&state.store).unwrap_or(0);
            let from = log_filter.from_block.unwrap_or(head_num);
            let to = log_filter.to_block.unwrap_or(head_num);
            let logs = collect_logs(from, to, log_filter, state);
            JsonRpcResponse::success(id, serde_json::to_value(&logs).unwrap())
        }
        _ => JsonRpcResponse::success(id, json!([])),
    }
}

pub fn eth_uninstall_filter(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_id) = params.get(0).and_then(|v| v.as_str()).and_then(parse_hex_u64) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid filter id");
    };
    let removed = state.filter_store.remove(filter_id);
    JsonRpcResponse::success(id, json!(removed))
}

// --- internal helpers ---

fn collect_logs(from: u64, to: u64, filter: &LogFilter, state: &RpcState) -> Vec<LogDto> {
    let mut result = Vec::new();
    // Only worth reading a header to test its bloom when the query actually
    // constrains something. An unfiltered `eth_getLogs` wants every log, so
    // the test could never skip a block and would be a read per block for
    // nothing.
    let use_bloom = filter_constrains_anything(filter);

    // Nothing above the head has a block to read, and a range a client names
    // may end anywhere up to 2^64 - 1 (an installed filter's is never checked
    // against the cap). Walked number by number, the rest would be a request
    // that never ends, holding a worker thread for good.
    let to = to.min(head_number(&state.store).unwrap_or(0));
    for num in from..=to {
        let Some(block_hash) = state.store.canonical_hash(num).ok().flatten() else {
            continue;
        };

        // The cheap rejection: one header read and three bit tests per
        // filtered term, against a receipt list that may hold hundreds of
        // logs. The header's `logs_bloom` is the OR of its receipts' blooms
        // and is validated against the recomputed value when the block is
        // executed (`ProcessError::LogsBloomMismatch`), so it can be trusted
        // to be complete.
        if use_bloom {
            if let Some(header) = state.store.header(block_hash).ok().flatten() {
                if !bloom_may_match(&header.logs_bloom, filter) {
                    continue;
                }
            }
        }

        let Some(receipts) = state.store.receipts(block_hash).ok().flatten() else {
            continue;
        };
        let transactions = state.store.body(block_hash).ok().flatten()
            .map(|(txs, _)| txs)
            .unwrap_or_default();

        let mut global_log_index = 0u32;
        for (tx_idx, receipt) in receipts.iter().enumerate() {
            let tx_hash = transactions.get(tx_idx)
                .map(compute_tx_hash)
                .unwrap_or(B256::ZERO);

            for log in &receipt.logs {
                if matches_filter(log, filter) {
                    result.push(LogDto::from_log(
                        log,
                        block_hash,
                        num,
                        tx_hash,
                        tx_idx as u32,
                        global_log_index,
                    ));
                }
                global_log_index += 1;
            }
        }
    }

    result
}

/// Does this query name anything a bloom could be tested against?
fn filter_constrains_anything(filter: &LogFilter) -> bool {
    !filter.addresses.is_empty()
        || filter.topics.iter().flatten().any(|allowed| !allowed.is_empty())
}

/// Could a block with this logs bloom hold a log matching `filter`?
///
/// **`false` is certain, `true` is a maybe.** A bloom filter has no false
/// negatives, so a `false` here means no log in the block can match and the
/// block is safe to skip without reading its receipts. A `true` proves
/// nothing and every candidate is still confirmed by `matches_filter`.
///
/// The logic mirrors `matches_filter`: addresses are OR-ed, topic positions
/// are AND-ed with the alternatives at each position OR-ed.
fn bloom_may_match(bloom: &alloy_primitives::Bloom, filter: &LogFilter) -> bool {
    use rustock_core::bloom::may_contain;

    if !filter.addresses.is_empty()
        && !filter.addresses.iter().any(|a| may_contain(bloom, a.as_slice()))
    {
        return false;
    }

    for allowed in filter.topics.iter().flatten() {
        // An empty alternatives list at a position means "the log must have
        // **no** topic here" (see `matches_filter`). There is nothing to look
        // up, so the bloom says nothing about it and the block must be read.
        if allowed.is_empty() {
            continue;
        }
        if !allowed.iter().any(|t| may_contain(bloom, t.as_slice())) {
            return false;
        }
    }

    true
}

fn matches_filter(log: &rustock_core::Log, filter: &LogFilter) -> bool {
    if !filter.addresses.is_empty() && !filter.addresses.contains(&log.address) {
        return false;
    }

    for (i, topic_filter) in filter.topics.iter().enumerate() {
        if let Some(allowed) = topic_filter {
            match log.topics.get(i) {
                Some(t) if allowed.contains(t) => {}
                None if allowed.is_empty() => {}
                _ => return false,
            }
        }
    }

    true
}

/// A log filter as rskj reads it. Its blocks are read as
/// `crate::helpers::parse_filter_block` says, and one rskj can't read is an
/// error, not the head.
fn parse_log_filter(obj: &Value, head_num: u64) -> Result<LogFilter, (i64, String)> {
    let block = |key: &str| {
        obj.get(key)
            .map(|value| crate::helpers::parse_filter_block(value, head_num))
            .transpose()
    };
    let from_block = block("fromBlock")?;
    let to_block = block("toBlock")?;

    let addresses = parse_address_filter(obj.get("address"));

    let topics = obj.get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().map(|t| {
                if t.is_null() {
                    None
                } else if let Some(s) = t.as_str() {
                    parse_b256(s).map(|h| vec![h])
                } else if let Some(arr) = t.as_array() {
                    let topics: Vec<B256> = arr.iter()
                        .filter_map(|v| v.as_str().and_then(parse_b256))
                        .collect();
                    if topics.is_empty() { None } else { Some(topics) }
                } else {
                    None
                }
            }).collect()
        })
        .unwrap_or_default();

    Ok(LogFilter {
        from_block,
        to_block,
        addresses,
        topics,
    })
}

fn parse_address_filter(v: Option<&Value>) -> Vec<Address> {
    match v {
        None => vec![],
        Some(Value::String(s)) => s.parse::<Address>().ok().into_iter().collect(),
        Some(Value::Array(arr)) => arr.iter()
            .filter_map(|v| v.as_str()?.parse::<Address>().ok())
            .collect(),
        _ => vec![],
    }
}

/// The canonical transaction hash -- see `helpers::tx_hash`. A log's
/// `transactionHash` must match what the transaction is indexed under, or a
/// caller cannot fetch the transaction a log came from.
fn compute_tx_hash(tx: &rustock_core::Transaction) -> B256 {
    tx.tx_hash()
}

fn head_number(store: &rustock_storage::BlockStore) -> Option<u64> {
    store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}
