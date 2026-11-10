use crate::dto::CallRequest;
use crate::server::RpcState;
use crate::state::resolve_state_root;
use crate::types::*;
use alloy_primitives::{Address, Bytes, U256};
use rustock_core::Transaction;
use rustock_execution::RskExecutor;
use serde_json::{json, Value};

use crate::helpers::to_hex_bytes;

/// The gas `eth_call` runs with when the call names none, and the most it
/// runs with when it names more: rskj's `rpc.callGasCap` as its
/// `reference.conf` ships it. `CallArgumentsToByteArray.gasLimitForCall`
/// takes the call's gas, or `0x5AF3107A4000` when it names none
/// (`getGasLimit`), and the cap when that is more.
///
/// A local call is no longer held to the block's gas limit (see
/// `RskHandler::as_local_call`), so this is what bounds its run.
pub const CALL_GAS_CAP: u64 = 10_000_000;

/// The gas every `eth_estimateGas` runs with, whatever the call names, and
/// the most it answers: rskj's `rpc.gasEstimationCap` as its `reference.conf`
/// ships it (`EthModule.estimateGas` passes it as the gas limit;
/// `internalEstimateGas` caps the answer at it).
pub const GAS_ESTIMATION_CAP: u64 = 6_800_000;

pub fn eth_call(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(call_req) = params.get(0).and_then(CallRequest::from_json) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid call request");
    };
    let block_param = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");
    let block_param = match crate::helpers::execution_block(block_param, false) {
        Ok(block) => block,
        Err((code, message)) => return JsonRpcResponse::error(id, code, message),
    };

    let Some((trie_store, hardfork_cfg)) = state.trie_store.clone().zip(state.hardfork_cfg.clone()) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Execution engine not available");
    };

    let Some((root, header)) = resolve_state_root(&block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let sender = call_req.from.unwrap_or(Address::ZERO);
    let tx = build_call_tx(&call_req, &root, sender, state);
    let executor = RskExecutor::new(hardfork_cfg, state.store.clone());

    match executor.execute_local_call(&header, &tx, sender, &root, trie_store) {
        Ok(result) => {
            if result.output.is_empty() {
                JsonRpcResponse::success(id, json!("0x"))
            } else {
                JsonRpcResponse::success(id, json!(to_hex_bytes(&result.output)))
            }
        }
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("Execution failed: {e}")),
    }
}

pub fn eth_estimate_gas(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(call_req) = params.get(0).and_then(CallRequest::from_json) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid call request");
    };
    let block_param = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");
    let block_param = match crate::helpers::execution_block(block_param, true) {
        Ok(block) => block,
        Err((code, message)) => return JsonRpcResponse::error(id, code, message),
    };

    let Some((trie_store, hardfork_cfg)) = state.trie_store.clone().zip(state.hardfork_cfg.clone()) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Execution engine not available");
    };

    let Some((root, header)) = resolve_state_root(&block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let sender = call_req.from.unwrap_or(Address::ZERO);
    let executor = RskExecutor::new(hardfork_cfg, state.store.clone());

    // rskj runs every estimate at its cap; the call's own gas isn't read.
    let gas_cap = GAS_ESTIMATION_CAP;

    let mut tx = build_call_tx(&call_req, &root, sender, state);
    tx.gas_limit = U256::from(gas_cap);

    if state.gas_estimator_binary_search {
        return estimate_by_binary_search(
            id, &call_req, &header, &root, sender, state, &executor, trie_store, gas_cap,
        );
    }

    // One execution, at the cap, with the estimation inspector attached. See
    // `rustock_execution::gas_estimator` for why the three things it records
    // are enough to answer without searching.
    match executor.estimate_gas_exact(&header, &tx, sender, &root, trie_store, gas_cap) {
        Ok((estimate, true, _)) => {
            JsonRpcResponse::success(id, json!(crate::helpers::to_hex_u64(estimate)))
        }
        Ok((_, false, _)) => {
            JsonRpcResponse::error(id, INTERNAL_ERROR, "Transaction would revert")
        }
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("Execution failed: {e}")),
    }
}

/// The estimator this node used before the single-pass one: execute at the
/// cap, then halve the interval until it closes.
///
/// Kept reachable behind `--gas-estimator-binary-search` rather than deleted.
/// It is the independent check on the new one -- a disagreement between them
/// is a bug in one or the other, and the test that compares them needs
/// something to compare against.
#[allow(clippy::too_many_arguments)]
fn estimate_by_binary_search(
    id: Value,
    call_req: &CallRequest,
    header: &rustock_core::types::header::Header,
    root: &rustock_trie::TrieNode,
    sender: Address,
    state: &RpcState,
    executor: &RskExecutor,
    trie_store: std::sync::Arc<dyn rustock_trie::TrieStore>,
    gas_cap: u64,
) -> JsonRpcResponse {
    // The invariant is "`lo` fails, `hi` succeeds", and the answer returned
    // is `hi`. So `lo` has to be a limit that genuinely fails -- and it used
    // to be 21,000, which was never tested and is the one value most likely
    // to *succeed*: it is the intrinsic cost of the simplest transaction
    // there is. A plain transfer needs exactly 21,000, and this search
    // answered 21,001, having assumed the true minimum away before it began.
    //
    // Zero is the only start that needs no assumption: nothing can pay its
    // intrinsic cost out of nothing. It costs at most one extra probe, which
    // is lost among the two dozen this already does.
    let mut lo = 0u64;
    let mut hi = gas_cap;

    // First check if the transaction even succeeds at the gas cap
    let mut tx = build_call_tx(call_req, root, sender, state);
    tx.gas_limit = U256::from(hi);
    match executor.execute_local_call(header, &tx, sender, root, trie_store.clone()) {
        Ok(result) if result.success => {}
        Ok(_) => {
            return JsonRpcResponse::error(id, INTERNAL_ERROR, "Transaction would revert");
        }
        Err(e) => {
            return JsonRpcResponse::error(id, INTERNAL_ERROR, format!("Execution failed: {e}"));
        }
    }

    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        let mut probe_tx = build_call_tx(call_req, root, sender, state);
        probe_tx.gas_limit = U256::from(mid);

        match executor.execute_local_call(header, &probe_tx, sender, root, trie_store.clone()) {
            Ok(result) if result.success => hi = mid,
            _ => lo = mid,
        }
    }

    JsonRpcResponse::success(id, json!(crate::helpers::to_hex_u64(hi)))
}

/// The transaction `eth_call` and `eth_estimateGas` run, with rskj's defaults
/// for what the call leaves out (`CallArgumentsToByteArray`): a gas price of
/// 0 (`getGasPrice`), [`CALL_GAS_CAP`]'s gas (`gasLimitForCall`; an estimate
/// sets its own), no value. The nonce is the sender's, as
/// `ReversibleTransactionExecutor` builds it; a local call doesn't check it.
fn build_call_tx(
    req: &CallRequest,
    root: &rustock_trie::TrieNode,
    sender: Address,
    state: &RpcState,
) -> Transaction {
    let sender_nonce = crate::state::trie_get_account(
        root,
        &rustock_trie::account_key(&sender),
        state,
    )
    .map(|a| a.nonce.to::<u64>())
    .unwrap_or(0);
    Transaction {
        nonce: sender_nonce,
        gas_price: req.gas_price.unwrap_or(U256::ZERO),
        gas_limit: U256::from(req.gas.map_or(CALL_GAS_CAP, |gas| gas.min(CALL_GAS_CAP))),
        to: req.to.map(|a| Bytes::copy_from_slice(a.as_slice())).unwrap_or_default(),
        value: req.value.unwrap_or(U256::ZERO),
        input: req.data.as_deref().map(Bytes::copy_from_slice).unwrap_or_default(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: None,
    }
}
