use crate::dto::{ReceiptDto, TransactionDto};
use crate::helpers::{parse_b256, parse_block_number, parse_hex_u32};
use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::{Address, B256};
use serde_json::Value;

pub fn eth_get_transaction_by_hash(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid tx hash");
    };

    // Check pool first for pending transactions
    if let Some(pool) = &state.tx_pool {
        if let Some((tx, sender, hash)) = pool.get_pending_tx(&tx_hash) {
            let dto = TransactionDto::from_tx(&tx, hash, None, None, None, sender);
            return JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap());
        }
    }

    let Some((block_hash, tx_index)) = state.store.tx_location(tx_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some((transactions, _ommers)) = state.store.body(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(tx) = transactions.get(tx_index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let sender = recover_sender_or_zero(tx, state);
    let dto = TransactionDto::from_tx(tx, tx_hash, Some(block_hash), Some(header.number), Some(tx_index), sender);
    JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap())
}

pub fn eth_get_transaction_by_block_hash_and_index(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(block_hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    let Some(index) = params.get(1).and_then(|v| v.as_str()).and_then(parse_hex_u32) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid index");
    };

    tx_by_block_and_index(id, block_hash, index, state)
}

pub fn eth_get_transaction_by_block_number_and_index(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(bn_str) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number");
    };
    let head_num = head_number(&state.store).unwrap_or(0);
    let Some(number) = parse_block_number(bn_str, head_num) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number");
    };
    let Some(block_hash) = state.store.canonical_hash(number).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };
    let Some(index) = params.get(1).and_then(|v| v.as_str()).and_then(parse_hex_u32) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid index");
    };

    tx_by_block_and_index(id, block_hash, index, state)
}

pub fn eth_get_transaction_receipt(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid tx hash");
    };

    let Some((block_hash, tx_index)) = state.store.tx_location(tx_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(receipts) = state.store.receipts(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(receipt) = receipts.get(tx_index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some((transactions, _)) = state.store.body(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(tx) = transactions.get(tx_index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let sender = recover_sender_or_zero(tx, state);

    // Compute log_index_start: sum of logs in preceding receipts
    let log_index_start: u32 = receipts[..tx_index as usize]
        .iter()
        .map(|r| r.logs.len() as u32)
        .sum();

    let dto = ReceiptDto::from_receipt(
        receipt, tx, tx_hash, block_hash, header.number, tx_index, sender, log_index_start,
    );
    JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap())
}

// --- helpers ---

fn tx_by_block_and_index(id: Value, block_hash: B256, index: u32, state: &RpcState) -> JsonRpcResponse {
    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some((transactions, _)) = state.store.body(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(tx) = transactions.get(index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let tx_hash = compute_tx_hash(tx);
    let sender = recover_sender_or_zero(tx, state);

    let dto = TransactionDto::from_tx(tx, tx_hash, Some(block_hash), Some(header.number), Some(index), sender);
    JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap())
}

fn head_number(store: &rustock_storage::BlockStore) -> Option<u64> {
    store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
}

/// The canonical transaction hash -- see `helpers::tx_hash`. This one feeds
/// `eth_getTransactionByBlockHashAndIndex` and
/// `eth_getTransactionByBlockNumberAndIndex`, which reported a hash that
/// disagreed with `eth_getBlockBy*` for the same transaction and resolved to
/// nothing.
pub(crate) fn compute_tx_hash(tx: &rustock_core::Transaction) -> B256 {
    tx.tx_hash()
}

/// The sender a transaction was signed by, or the zero address if it
/// cannot be recovered.
///
/// **The chain id has to come from the node's own configuration.** It
/// was hardcoded to 30 here, which is mainnet, so on any other chain
/// every EIP-155 signature failed to recover and every receipt and
/// transaction this module served reported `from` as the zero address:
/// `v` encodes the chain a transaction was signed for, and recovering
/// it against a different one puts the recovery id out of range. That
/// is testnet as much as regtest, and it was silent because the failure
/// path is an `unwrap_or` rather than an error.
///
/// Zero remains the fallback, because a transaction whose signature
/// does not recover is a real thing -- REMASC's has none at all -- and
/// a receipt with an obviously wrong field beats one that fails.
fn recover_sender_or_zero(tx: &rustock_core::Transaction, state: &RpcState) -> Address {
    tx.recover_sender(crate::helpers::chain_id_of(state)).unwrap_or(Address::ZERO)
}

