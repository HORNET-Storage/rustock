//! The `trace_*` namespace: call trees and internal transactions.
//!
//! Source of truth: rskj's `co.rsk.rpc.modules.trace` package --
//! `TraceModuleImpl`, `TraceTransformer`, `TraceAction`, `TraceResult`.
//! `docs/trace-namespace.md` records where the output differs from
//! go-ethereum's and from OpenEthereum's, which is what most tooling was
//! written against.
//!
//! # How this differs from `debug_traceTransaction`
//!
//! `debug_*` answers "what did the VM do, opcode by opcode". `trace_*` answers
//! "who called whom" -- the call tree an explorer renders as internal
//! transactions. Both come from the **same** inspector
//! (`rustock_execution::tracer::RskTracer`) so the two namespaces cannot
//! disagree about the same transaction; only the rendering differs.
//!
//! # No index: traces are recomputed, as rskj recomputes them
//!
//! `trace_filter` over a block range re-executes each block in the range.
//! That is rskj's design, not a shortcut -- `TraceModuleImpl.traceFilter`
//! loops over blocks calling `buildBlockTraces`, which calls
//! `blockExecutor.traceBlock` on each, with no index anywhere. The cost is
//! bounded the way rskj bounds it: a cap on traces per request
//! (`MAX_TRACES_PER_REQUEST`) and early termination once `after + count`
//! traces have been collected.
//!
//! An index built at execution time would answer faster and would **not**
//! match rskj: it would have to be built from the tip forward, so a node
//! restored from an import would answer `trace_filter` differently from a
//! node that executed the same blocks itself. Matching rskj is the point.

use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::{Address, B256, U256};
use rustock_execution::tracer::{ProgramTrace, Subtrace, SubtraceKind};
use serde_json::{json, Map, Value};

/// rskj's `rpcTraceMaxTracesPerRequest`, whose shipped default is 10,000.
const MAX_TRACES_PER_REQUEST: usize = 10_000;

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

/// `trace_transaction(txHash)` → the transaction's traces, flattened.
pub fn trace_transaction(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()).and_then(crate::helpers::parse_b256)
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid transaction hash");
    };
    let Some((block_hash, index)) = state.store.tx_location(tx_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    match block_traces(state, block_hash, Some(index as usize)) {
        Ok(traces) => JsonRpcResponse::success(id, Value::Array(traces)),
        Err(why) => JsonRpcResponse::error(id, INTERNAL_ERROR, why),
    }
}

/// `trace_block(blockHashOrNumber)` → every trace in the block.
///
/// rskj takes either form in one parameter and tells them apart by length:
/// `arg.length() < 20` means a block id (`"latest"`, `"0x1b4"`), otherwise a
/// hash. Reproduced, because a client that sends `"0x10"` meaning block 16
/// must not get a hash lookup.
pub fn trace_block(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(arg) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block argument");
    };
    let hash = match resolve_block_argument(state, arg) {
        Ok(Some(hash)) => hash,
        Ok(None) => return JsonRpcResponse::success(id, Value::Null),
        Err(why) => return JsonRpcResponse::error(id, INVALID_PARAMS, why),
    };
    match block_traces(state, hash, None) {
        Ok(traces) => JsonRpcResponse::success(id, Value::Array(traces)),
        Err(why) => JsonRpcResponse::error(id, INTERNAL_ERROR, why),
    }
}

/// `trace_get(txHash, positions)` → one trace.
///
/// **This is not OpenEthereum's `trace_get`, despite the name.** There,
/// `positions` is a trace-address path walking down the call tree. rskj
/// rejects more than one position outright (`TraceGetRequest`: "'positions'
/// accepts only one index") and then uses it to index the **whole block's**
/// flattened trace list -- `traces.get(positions.get(0))` where `traces` is
/// `buildBlockTraces(block)`, not the transaction's own traces. So
/// `trace_get(tx, ["0x0"])` on the second transaction of a block returns a
/// trace belonging to the *first*. Reproduced deliberately; see
/// `docs/trace-namespace.md`.
pub fn trace_get(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()).and_then(crate::helpers::parse_b256)
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "'transactionHash' cannot be null or empty");
    };
    let positions = match params.get(1) {
        Some(Value::Array(p)) if !p.is_empty() => p,
        _ => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "'positions' cannot be null or empty")
        }
    };
    if positions.len() > 1 {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "'positions' accepts only one index");
    }
    let Some(position) = positions[0]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .or_else(|| positions[0].as_u64())
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid position");
    };

    let Some((block_hash, _)) = state.store.tx_location(tx_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };
    match block_traces(state, block_hash, None) {
        Ok(traces) => match traces.into_iter().nth(position as usize) {
            Some(trace) => JsonRpcResponse::success(id, trace),
            None => JsonRpcResponse::success(id, Value::Null),
        },
        Err(why) => JsonRpcResponse::error(id, INTERNAL_ERROR, why),
    }
}

/// `trace_filter({fromBlock, toBlock, fromAddress, toAddress, after, count})`.
///
/// **The address filters select whole transactions, not individual traces.**
/// rskj filters `block.getTransactionsList()` by the transaction's own sender
/// and receive address and then emits *every* trace of the surviving
/// transactions, internal calls to unrelated addresses included. OpenEthereum
/// matches each trace. A client asking "which traces touched this address"
/// gets a different answer from the two, and this reproduces rskj's.
pub fn trace_filter(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(req) = params.get(0).and_then(|v| v.as_object()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid trace_filter parameters.");
    };

    let count = match req.get("count") {
        None | Some(Value::Null) => MAX_TRACES_PER_REQUEST,
        Some(v) => match as_usize(v) {
            Some(c) => c,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid count"),
        },
    };
    if count > MAX_TRACES_PER_REQUEST {
        return JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            format!("Count value too big. Maximum {MAX_TRACES_PER_REQUEST} traces allowed."),
        );
    }
    let after = match req.get("after") {
        None | Some(Value::Null) => 0,
        Some(v) => match as_usize(v) {
            Some(a) => a,
            // rskj's `after` is a Java `Integer`, so a negative value parses
            // and is then rejected by name.
            None if v.as_i64().is_some_and(|n| n < 0) => {
                return JsonRpcResponse::error(id, INVALID_PARAMS, "After value cannot be negative.")
            }
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid after"),
        },
    };
    if after > MAX_TRACES_PER_REQUEST {
        return JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            format!("After value too big. Maximum {MAX_TRACES_PER_REQUEST} traces allowed."),
        );
    }

    let head = head_number(state);
    // rskj's defaults: `fromBlock` is "earliest", `toBlock` is "latest".
    let from = match req.get("fromBlock").and_then(|v| v.as_str()) {
        None => 0,
        Some(s) => match crate::helpers::parse_block_number(s, head) {
            Some(n) => n,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, format!("invalid blocknumber {s}")),
        },
    };
    let to = match req.get("toBlock").and_then(|v| v.as_str()) {
        None => head,
        Some(s) => match crate::helpers::parse_block_number(s, head) {
            Some(n) => n,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, format!("invalid blocknumber {s}")),
        },
    };
    if from > to {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "fromBlock cannot be greater than toBlock");
    }

    let from_addresses = address_list(req.get("fromAddress"));
    let to_addresses = address_list(req.get("toAddress"));

    let mut collected: Vec<Value> = Vec::new();
    let mut seen = 0usize;
    let wanted = after.saturating_add(count);

    for number in from..=to {
        let Some(hash) = state.store.canonical_hash(number).ok().flatten() else {
            continue;
        };
        let built = match filtered_block_traces(state, hash, &from_addresses, &to_addresses) {
            Ok(traces) => traces,
            Err(why) => return JsonRpcResponse::error(id, INTERNAL_ERROR, why),
        };

        // rskj's windowing, kept literally: it slices each block's traces
        // rather than filtering a flat list, so `after` counts traces it never
        // materialises.
        if seen + built.len() > after {
            let start = after.saturating_sub(seen);
            let end = built.len().min(wanted.saturating_sub(seen));
            if start < end {
                collected.extend_from_slice(&built[start..end]);
            }
        }
        seen += built.len();
        if seen >= wanted {
            break;
        }
    }

    JsonRpcResponse::success(id, Value::Array(collected))
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// Replay `block_hash` and render its traces, optionally only one
/// transaction's.
///
/// The block is replayed **once** regardless -- rskj's `traceTransaction`
/// likewise traces the whole block and then picks one transaction's trace out
/// of the processor, because a transaction's pre-state only exists partway
/// through its block.
fn block_traces(
    state: &RpcState,
    block_hash: B256,
    only: Option<usize>,
) -> Result<Vec<Value>, String> {
    let (block, traces) = replay(state, block_hash)?;
    let receipts = state.store.receipts(block_hash).ok().flatten().unwrap_or_default();
    let chain_id = chain_id_of(state);

    let mut out = Vec::new();
    for (index, trace) in traces.iter().enumerate() {
        if only.is_some_and(|i| i != index) {
            continue;
        }
        let gas_used = receipts.get(index).map(|r| r.gas_used).unwrap_or(0);
        render_transaction(&mut out, &block, block_hash, index, gas_used, trace, chain_id);
    }
    Ok(out)
}

/// `block_traces` with rskj's transaction-level address filter applied.
fn filtered_block_traces(
    state: &RpcState,
    block_hash: B256,
    from_addresses: &[Address],
    to_addresses: &[Address],
) -> Result<Vec<Value>, String> {
    if from_addresses.is_empty() && to_addresses.is_empty() {
        return block_traces(state, block_hash, None);
    }
    let (block, traces) = replay(state, block_hash)?;
    let receipts = state.store.receipts(block_hash).ok().flatten().unwrap_or_default();
    let chain_id = chain_id_of(state);
    let senders = block
        .transactions
        .iter()
        .map(|tx| tx.recover_sender(chain_id).ok())
        .collect::<Vec<_>>();

    let mut out = Vec::new();
    for (index, trace) in traces.iter().enumerate() {
        let Some(tx) = block.transactions.get(index) else { continue };
        if !from_addresses.is_empty()
            && !senders.get(index).copied().flatten().is_some_and(|s| from_addresses.contains(&s))
        {
            continue;
        }
        if !to_addresses.is_empty() {
            // rskj: `tx.getReceiveAddress().getBytes().length > 0 &&
            // addresses.contains(...)`, so a contract-creation transaction
            // never matches a `toAddress` filter.
            let matched = tx.to.len() == 20
                && to_addresses.contains(&Address::from_slice(tx.to.as_ref()));
            if !matched {
                continue;
            }
        }
        let gas_used = receipts.get(index).map(|r| r.gas_used).unwrap_or(0);
        render_transaction(&mut out, &block, block_hash, index, gas_used, trace, chain_id);
    }
    Ok(out)
}

/// Load the block and re-execute it from its parent's state with the call
/// tracer attached.
fn replay(
    state: &RpcState,
    block_hash: B256,
) -> Result<(rustock_core::Block, Vec<ProgramTrace>), String> {
    let (Some(trie_store), Some(hardfork_cfg)) =
        (state.trie_store.clone(), state.hardfork_cfg.clone())
    else {
        return Err("Execution engine not available".into());
    };
    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return Err("No such block".into());
    };
    // rskj skips genesis outright: `buildBlockTraces` guards on
    // `block.getNumber() != 0`. It has no parent state to replay from either.
    if header.number == 0 {
        return Ok((
            rustock_core::Block { header, transactions: Vec::new(), ommers: Vec::new() },
            Vec::new(),
        ));
    }
    let Some((transactions, ommers)) = state.store.body(block_hash).ok().flatten() else {
        return Err("The node does not have this block's body, so it cannot be replayed".into());
    };
    let Some(parent) = state.store.header(header.parent_hash).ok().flatten() else {
        return Err("The parent block is not stored, so there is no state to replay from".into());
    };
    let Some(root_bytes) = trie_store.get(parent.state_root.as_slice()) else {
        return Err(format!(
            "State at the parent block #{} is no longer held, so #{} cannot be traced; \
             only recent blocks are traceable",
            parent.number, header.number
        ));
    };
    let root = rustock_trie::TrieNode::from_message(&root_bytes, trie_store.as_ref());
    let block = rustock_core::Block { header, transactions, ommers };
    let processor = rustock_execution::BlockProcessor::new(hardfork_cfg, state.store.clone());
    let traces = processor
        .trace_block_calls(&block, &root, trie_store)
        .map_err(|e| format!("Replay failed: {e}"))?;
    Ok((block, traces))
}

// ---------------------------------------------------------------------------
// Rendering -- rskj's TraceTransformer
// ---------------------------------------------------------------------------

/// Flatten one transaction's trace into rskj's depth-first `TransactionTrace`
/// list: the transaction's own frame first, then each subtree in order.
fn render_transaction(
    out: &mut Vec<Value>,
    block: &rustock_core::Block,
    block_hash: B256,
    index: usize,
    receipt_gas_used: u64,
    trace: &ProgramTrace,
    chain_id: u64,
) {
    let Some(tx) = block.transactions.get(index) else { return };
    let is_creation = tx.to.is_empty();
    let tx_hash = tx.tx_hash();

    // rskj's top-level trace is built from the receipt, not from a frame: a
    // synthetic `ProgramResult` carrying only `receipt.getGasUsed()` and the
    // revert flag.
    let error = if trace.reverted {
        Some("Reverted".to_string())
    } else if trace.error.is_empty() {
        None
    } else {
        Some(trace.error.clone())
    };

    let mut action = Map::new();
    if is_creation {
        // `callType` is CallType.NONE for a creation, which rskj serialises as
        // absent rather than as "none".
        insert_addr(&mut action, "from", &sender_of(block, index, chain_id));
        action.insert("gas".into(), quantity(trace.root_gas));
        action.insert("init".into(), unformatted(tx.input.as_ref()));
        action.insert("value".into(), quantity_u256(&tx.value));
    } else {
        action.insert("callType".into(), Value::String("call".into()));
        insert_addr(&mut action, "from", &sender_of(block, index, chain_id));
        insert_addr(&mut action, "to", &Address::from_slice(tx.to.as_ref()));
        action.insert("gas".into(), quantity(trace.root_gas));
        action.insert("input".into(), unformatted(tx.input.as_ref()));
        action.insert("value".into(), quantity_u256(&tx.value));
    }

    let result = if error.is_some() {
        Value::Null
    } else if is_creation {
        // rskj: `createdCode = Hex.decode(trace.getResult())`, the deployed
        // code, and the address derived from sender and nonce.
        let created = sender_of(block, index, chain_id).create(tx.nonce);
        create_result(
            receipt_gas_used,
            &Value::String(format!("0x{}", trace.result)),
            &created,
        )
    } else {
        json!({
            "gasUsed": quantity(receipt_gas_used),
            "output": Value::String(format!("0x{}", trace.result)),
        })
    };

    out.push(transaction_trace(
        Value::Object(action),
        block_hash,
        block.header.number,
        tx_hash,
        index,
        if is_creation { "create" } else { "call" },
        trace.subtraces.len(),
        &[],
        result,
        error,
    ));

    for (k, subtrace) in trace.subtraces.iter().enumerate() {
        render_subtrace(out, block_hash, block.header.number, tx_hash, index, subtrace, &[k]);
    }
}

fn render_subtrace(
    out: &mut Vec<Value>,
    block_hash: B256,
    block_number: u64,
    tx_hash: B256,
    tx_index: usize,
    subtrace: &Subtrace,
    address: &[usize],
) {
    let mut action = Map::new();
    let mut result = Value::Null;
    let mut error = None;

    match subtrace.kind {
        SubtraceKind::Suicide => {
            // rskj's `toAction`: `address = from; from = null;`, the balance is
            // the call value, and `refundAddress` is the invoke's owner. A
            // SUICIDE gets neither `result` nor `error` -- `toTrace` skips
            // both for this trace type.
            insert_addr(&mut action, "address", &subtrace.caller);
            insert_addr(&mut action, "refundAddress", &subtrace.owner);
            action.insert("balance".into(), quantity_u256(&subtrace.value));
        }
        SubtraceKind::Create => {
            action.insert("gas".into(), quantity(subtrace.gas));
            insert_addr(&mut action, "from", &subtrace.caller);
            action.insert("init".into(), unformatted(&subtrace.input));
            action.insert(
                "creationMethod".into(),
                Value::String(if subtrace.is_create2 { "create2" } else { "create" }.into()),
            );
            action.insert("value".into(), quantity_u256(&subtrace.value));
            error = subtrace_error(subtrace);
            if error.is_none() {
                result = create_result(
                    subtrace.gas_used,
                    &unformatted(&subtrace.output),
                    &subtrace.created_address.unwrap_or(subtrace.owner),
                );
            }
        }
        SubtraceKind::Call => {
            let kind = subtrace.call_kind.map(|k| k.as_str()).unwrap_or("call");
            action.insert("callType".into(), Value::String(kind.into()));
            // rskj's DELEGATECALL swap: `from` becomes the frame's owner (the
            // contract whose storage is in scope) and `to` becomes the code
            // address, so the pair reads as "this contract is running that
            // contract's code".
            if kind == "delegatecall" {
                insert_addr(&mut action, "from", &subtrace.owner);
                if let Some(code) = subtrace.code_address {
                    insert_addr(&mut action, "to", &code);
                }
            } else {
                insert_addr(&mut action, "from", &subtrace.caller);
                insert_addr(&mut action, "to", &subtrace.owner);
            }
            action.insert("gas".into(), quantity(subtrace.gas));
            action.insert("input".into(), unformatted(&subtrace.input));
            action.insert("value".into(), quantity_u256(&subtrace.value));
            error = subtrace_error(subtrace);
            if error.is_none() {
                result = json!({
                    "gasUsed": quantity(subtrace.gas_used),
                    "output": unformatted(&subtrace.output),
                });
            }
        }
    }

    out.push(transaction_trace(
        Value::Object(action),
        block_hash,
        block_number,
        tx_hash,
        tx_index,
        match subtrace.kind {
            SubtraceKind::Call => "call",
            SubtraceKind::Create => "create",
            SubtraceKind::Suicide => "suicide",
        },
        subtrace.subtraces.len(),
        address,
        result,
        error,
    ));

    for (k, child) in subtrace.subtraces.iter().enumerate() {
        let mut child_address = address.to_vec();
        child_address.push(k);
        render_subtrace(out, block_hash, block_number, tx_hash, tx_index, child, &child_address);
    }
}

/// rskj: the halt's `toString()` first, then `"Reverted"` for a REVERT.
fn subtrace_error(subtrace: &Subtrace) -> Option<String> {
    if let Some(error) = &subtrace.error {
        return Some(error.clone());
    }
    if subtrace.reverted {
        return Some("Reverted".into());
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn transaction_trace(
    action: Value,
    block_hash: B256,
    block_number: u64,
    tx_hash: B256,
    tx_index: usize,
    kind: &str,
    subtraces: usize,
    trace_address: &[usize],
    result: Value,
    error: Option<String>,
) -> Value {
    let mut out = Map::new();
    out.insert("action".into(), action);
    out.insert("blockHash".into(), Value::String(crate::helpers::to_hex_b256(&block_hash)));
    // A JSON **number**, not a hex string: rskj's `blockNumber` is a Java
    // `long` serialised by Jackson. `transactionPosition` and `subtraces` are
    // `int`s for the same reason. Nothing else in the RPC surface mixes the
    // two like this, and a client that assumes hex everywhere reads zero.
    out.insert("blockNumber".into(), Value::from(block_number));
    out.insert("transactionHash".into(), Value::String(crate::helpers::to_hex_b256(&tx_hash)));
    out.insert("transactionPosition".into(), Value::from(tx_index));
    out.insert("type".into(), Value::String(kind.into()));
    out.insert("subtraces".into(), Value::from(subtraces));
    out.insert(
        "traceAddress".into(),
        Value::Array(trace_address.iter().map(|i| Value::from(*i)).collect()),
    );
    // `result` is `@JsonInclude(ALWAYS)` in rskj even though the class is
    // `NON_NULL`, so a failed trace carries an explicit `"result": null` while
    // a successful one carries no `"error"` key at all.
    out.insert("result".into(), result);
    if let Some(error) = error {
        out.insert("error".into(), Value::String(error));
    }
    Value::Object(out)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// rskj `HexUtils.toQuantityJsonHex`: `0x`-prefixed, minimal digits.
fn quantity(v: u64) -> Value {
    Value::String(crate::helpers::to_hex_u64(v))
}

fn quantity_u256(v: &U256) -> Value {
    Value::String(crate::helpers::to_hex_u256(v))
}

/// rskj `HexUtils.toUnformattedJsonHex`: `0x`-prefixed, every byte.
fn unformatted(v: &[u8]) -> Value {
    Value::String(crate::helpers::to_hex_bytes(v))
}

/// rskj `RskAddress.toJsonString()`: `0x` plus 40 hex digits -- **except**
/// for the zero address, which it returns as `null`:
///
/// ```java
/// public String toJsonString() {
///     if (NULL_ADDRESS.equals(this)) { return null; }
///     return HexUtils.toUnformattedJsonHex(this.getBytes());
/// }
/// ```
///
/// `TraceAction` is `@JsonInclude(NON_NULL)`, so the key disappears entirely
/// rather than carrying `"0x0000…"`. `insert_addr` below does that; anything
/// calling this directly must handle the null.
///
/// Note this is **not** `RskAddress.toString()`, which is bare hex -- the
/// `debug_` tracer uses that one. Both appear in rskj's own output.
fn addr_json(a: &Address) -> Value {
    if a.is_zero() {
        return Value::Null;
    }
    Value::String(format!("0x{}", hex::encode(a.as_slice())))
}

/// rskj's `TraceResult` for a CREATE: gas, the deployed code, and the
/// address. `TraceResult` is `@JsonInclude(NON_NULL)` too, so a null address
/// drops the key rather than emitting `null`.
fn create_result(gas_used: u64, code: &Value, address: &Address) -> Value {
    let mut out = Map::new();
    out.insert("gasUsed".into(), quantity(gas_used));
    out.insert("code".into(), code.clone());
    insert_addr(&mut out, "address", address);
    Value::Object(out)
}

/// Set an address field, omitting it when rskj would serialise `null`.
fn insert_addr(action: &mut Map<String, Value>, key: &str, a: &Address) {
    let value = addr_json(a);
    if !value.is_null() {
        action.insert(key.into(), value);
    }
}

/// The transaction's sender, recovered.
///
/// rskj reads it from a `SignatureCache`; here it is recovered per render.
/// A transaction whose signature will not recover cannot have been executed,
/// so `Address::ZERO` is unreachable in practice and is not worth an error
/// path through every caller.
fn sender_of(block: &rustock_core::Block, index: usize, chain_id: u64) -> Address {
    block
        .transactions
        .get(index)
        .and_then(|tx| tx.recover_sender(chain_id).ok())
        .unwrap_or(Address::ZERO)
}

use crate::helpers::chain_id_of;

fn as_usize(v: &Value) -> Option<usize> {
    v.as_u64().map(|n| n as usize).or_else(|| {
        v.as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .map(|n| n as usize)
    })
}

fn address_list(v: Option<&Value>) -> Vec<Address> {
    let Some(Value::Array(items)) = v else { return Vec::new() };
    items
        .iter()
        .filter_map(|i| i.as_str())
        .filter_map(|s| s.trim_start_matches("0x").parse::<Address>().ok().or_else(|| s.parse().ok()))
        .collect()
}

fn head_number(state: &RpcState) -> u64 {
    state
        .store
        .head()
        .ok()
        .flatten()
        .and_then(|h| state.store.header(h).ok().flatten())
        .map(|h| h.number)
        .unwrap_or(0)
}

/// rskj `TraceModuleImpl.getByJsonArgument`: shorter than 20 characters means
/// a block id, otherwise a hash.
fn resolve_block_argument(state: &RpcState, arg: &str) -> Result<Option<B256>, String> {
    if arg.len() < 20 {
        let head = head_number(state);
        let Some(number) = crate::helpers::parse_block_number(arg, head) else {
            return Err(format!("invalid blocknumber {arg}"));
        };
        Ok(state.store.canonical_hash(number).ok().flatten())
    } else {
        let Some(hash) = crate::helpers::parse_b256(arg) else {
            return Err(format!("invalid block hash {arg}"));
        };
        Ok(state.store.header(hash).ok().flatten().map(|_| hash))
    }
}
