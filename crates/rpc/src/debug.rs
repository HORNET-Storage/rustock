//! The `debug_*` namespace.
//!
//! Shapes come from rskj's `Web3DebugModule` / `DebugModuleImpl`, not from
//! go-ethereum, which has different methods here entirely. Differences worth
//! knowing are in `docs/debug-namespace.md`.

use crate::server::RpcState;
use crate::types::*;
use serde_json::{json, Map, Value};

/// `debug_wireProtocolQueueSize()` → a hex quantity **string**.
///
/// rskj: `HexUtils.toQuantityJsonHex(messageHandler.getMessageQueueSize())` --
/// inbound messages received from peers and not yet handled. The equivalent
/// here is the depth of the `SyncEvent` channel, which is where inbound wire
/// work waits for this node.
///
/// A string rather than a number, because that is what `toQuantityJsonHex`
/// produces; `txpool_status`'s counts in the same server are JSON numbers,
/// because rskj builds those with `numberNode`. The inconsistency is rskj's.
pub fn debug_wire_protocol_queue_size(id: Value, state: &RpcState) -> JsonRpcResponse {
    let depth = state
        .wire_queue_depth
        .as_ref()
        .map(|d| d.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    JsonRpcResponse::success(id, json!(format!("0x{depth:x}")))
}

/// `debug_accountTransactionQuota(address)` → `{timestamp, availableVirtualGas}`,
/// or `null` for an address the limiter is not tracking.
///
/// rskj returns `txQuotaChecker.getTxQuota(address)`, a straight map lookup
/// that yields `null` when the address has no entry -- which is the normal
/// answer, because an entry is only created when an account's transaction is
/// admitted. Serialised, `TxQuota` exposes exactly two `@JsonProperty` fields,
/// `timestamp` (epoch milliseconds) and `availableVirtualGas` (a double).
///
/// The double is deliberate and must not be rounded: the virtual-gas cost of a
/// transaction is a product of six fractional factors, so a quota is rarely a
/// whole number and the fractional part is what separates one admitted
/// transaction from the next.
pub fn debug_account_transaction_quota(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(address) = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<alloy_primitives::Address>().ok())
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };

    let Some(pool) = &state.tx_pool else {
        return crate::server::execution_not_available(id, "debug_accountTransactionQuota");
    };

    match pool.quota_report(&address) {
        Some((available_virtual_gas, timestamp)) => JsonRpcResponse::success(
            id,
            json!({ "timestamp": timestamp, "availableVirtualGas": available_virtual_gas }),
        ),
        None => JsonRpcResponse::success(id, Value::Null),
    }
}

// ---------------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------------

/// How many opcodes a single RPC trace may record.
///
/// A full trace of a large transaction is tens of megabytes, and the
/// transaction someone most wants to look at is exactly the one that runs
/// longest. rskj bounds its trace through `vmTrace` config; this is the same
/// idea as a constant. A truncated trace says so in `truncated` rather than
/// looking short.
const MAX_STRUCT_LOGS: usize = 200_000;

/// `debug_traceTransaction(txHash)` → rskj's `DetailedProgramTrace`.
///
/// **Only recent transactions can be traced.** A trace needs the state before
/// the transaction, which does not exist anywhere: the state before
/// transaction *i* of block *N* is the state after *N-1* plus transactions
/// 0..*i*, and only per-block roots are stored. So the block is replayed from
/// its parent -- and the parent's state has to still be in the trie, which for
/// this node means roughly the GC burial depth. Older transactions get an
/// error saying so rather than an answer from the wrong state.
///
/// The output shape is rskj's, not go-ethereum's: `contractAddress`,
/// `structLogs`, `result`, `error`, `reverted`, `storageSize`,
/// `currentStorage`. See `docs/debug-namespace.md`.
pub fn debug_trace_transaction(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(tx_hash) = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(crate::helpers::parse_b256)
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid transaction hash");
    };
    // On the main chain only, as rskj's tracer looks it up
    // (`receiptStore.getInMainChain`): a block that lost a reorg is no answer.
    let Some((block_hash, index)) = state
        .store
        .tx_location_in_main_chain(tx_hash)
        .ok()
        .flatten()
    else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    match trace_block_transaction(state, block_hash, index as usize) {
        Ok(Some(trace)) => JsonRpcResponse::success(id, trace),
        Ok(None) => JsonRpcResponse::success(id, Value::Null),
        Err(why) => JsonRpcResponse::error(id, INTERNAL_ERROR, why),
    }
}

/// `debug_traceBlockByHash(blockHash)` → one trace per transaction.
pub fn debug_trace_block_by_hash(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(hash) = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(crate::helpers::parse_b256)
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    trace_whole_block(id, state, hash)
}

/// `debug_traceBlockByNumber(bnOrId)` → one trace per transaction.
pub fn debug_trace_block_by_number(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(bn) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number");
    };
    let head = state
        .store
        .head()
        .ok()
        .flatten()
        .and_then(|h| state.store.header(h).ok().flatten())
        .map(|h| h.number)
        .unwrap_or(0);
    let Some(number) = crate::helpers::parse_block_number(bn, head) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number");
    };
    let Some(hash) = state.store.canonical_hash(number).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };
    trace_whole_block(id, state, hash)
}

fn trace_whole_block(
    id: Value,
    state: &RpcState,
    block_hash: alloy_primitives::B256,
) -> JsonRpcResponse {
    let Some((transactions, _)) = state.store.body(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };
    let mut traces = Vec::with_capacity(transactions.len());
    for index in 0..transactions.len() {
        match trace_block_transaction(state, block_hash, index) {
            Ok(Some(trace)) => traces.push(trace),
            Ok(None) => {}
            Err(why) => return JsonRpcResponse::error(id, INTERNAL_ERROR, why),
        }
    }
    JsonRpcResponse::success(id, Value::Array(traces))
}

/// Replay `block_hash` from its parent's state, tracing transaction `index`.
fn trace_block_transaction(
    state: &RpcState,
    block_hash: alloy_primitives::B256,
    index: usize,
) -> Result<Option<Value>, String> {
    let (Some(trie_store), Some(hardfork_cfg)) =
        (state.trie_store.clone(), state.hardfork_cfg.clone())
    else {
        return Err("Execution engine not available".into());
    };

    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return Ok(None);
    };
    let Some((transactions, ommers)) = state.store.body(block_hash).ok().flatten() else {
        return Err("The node does not have this block's body, so it cannot be replayed".into());
    };
    let Some(parent) = state.store.header(header.parent_hash).ok().flatten() else {
        return Err("The parent block is not stored, so there is no state to replay from".into());
    };

    // The parent's state has to still be in the trie. Past the GC burial depth
    // it is not, and answering from a state we do have would be worse than
    // refusing.
    let Some(root_bytes) = trie_store.get(parent.state_root.as_slice()) else {
        return Err(format!(
            "State at the parent block #{} is no longer held, so transaction {index} of #{} \
             cannot be traced; only recent blocks are traceable",
            parent.number, header.number
        ));
    };
    let root = rustock_trie::TrieNode::from_message(&root_bytes, trie_store.as_ref());

    let block = rustock_core::Block {
        header,
        transactions,
        ommers,
    };
    let processor = rustock_execution::BlockProcessor::new(hardfork_cfg, state.store.clone());

    match processor.trace_transaction(&block, &root, trie_store, index, MAX_STRUCT_LOGS) {
        Ok(Some(trace)) => Ok(Some(render_trace(&trace))),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("Replay failed: {e}")),
    }
}

/// rskj's `DetailedProgramTrace` as JSON.
fn render_trace(trace: &rustock_execution::tracer::ProgramTrace) -> Value {
    let struct_logs: Vec<Value> = trace
        .struct_logs
        .iter()
        .map(|log| {
            json!({
                "op": log.op,
                "pc": log.pc,
                "depth": log.depth,
                "gas": log.gas,
                "gasCost": log.gas_cost,
                "stack": log.stack,
                "memory": log.memory,
                "storage": map_of(&log.storage),
            })
        })
        .collect();

    json!({
        "contractAddress": trace.contract_address,
        "structLogs": struct_logs,
        "result": trace.result,
        "error": trace.error,
        "reverted": trace.reverted,
        "storageSize": trace.storage_size,
        "currentStorage": map_of(&trace.current_storage),
        // Not an rskj field. rskj has no cap and so never needs to say it hit
        // one; a consumer here has to be able to tell a truncated trace from a
        // short one.
        "truncated": trace.truncated,
    })
}

fn map_of(m: &std::collections::BTreeMap<String, String>) -> Value {
    let mut out = Map::new();
    for (k, v) in m {
        out.insert(k.clone(), Value::String(v.clone()));
    }
    Value::Object(out)
}
