use crate::helpers::{parse_b256, parse_block_number, parse_storage_slot, to_hex_bytes, to_hex_u256};
use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::{Address, B256};
use rustock_core::Header;
use rustock_storage::BlockStore;
use rustock_trie::{account_key, code_key, storage_key, AccountState, TrieKeySlice, TrieNode};
use serde_json::{json, Value};

pub fn eth_get_balance(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let (root, _header) = match queried_state(&id, params.get(1), state) {
        Ok(found) => found,
        Err(refused) => return refused,
    };

    let key = account_key(&addr);
    match trie_get_account(&root, &key, state) {
        Some(acct) => JsonRpcResponse::success(id, json!(to_hex_u256(&acct.balance))),
        None => JsonRpcResponse::success(id, json!("0x0")),
    }
}

pub fn eth_get_transaction_count(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    // For "pending", return the pool's pending nonce if available
    if params.get(1).and_then(|v| v.as_str()) == Some("pending") {
        if let Some(pool) = &state.tx_pool {
            if let Some(pending_nonce) = pool.pending_nonce(&addr) {
                return JsonRpcResponse::success(
                    id,
                    json!(format!("0x{:x}", pending_nonce)),
                );
            }
        }
    }

    let (root, _header) = match queried_state(&id, params.get(1), state) {
        Ok(found) => found,
        Err(refused) => return refused,
    };

    let key = account_key(&addr);
    match trie_get_account(&root, &key, state) {
        Some(acct) => JsonRpcResponse::success(id, json!(to_hex_u256(&acct.nonce))),
        None => JsonRpcResponse::success(id, json!("0x0")),
    }
}

pub fn eth_get_code(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let (root, _header) = match queried_state(&id, params.get(1), state) {
        Ok(found) => found,
        Err(refused) => return refused,
    };

    let key = code_key(&addr);
    let expanded = TrieKeySlice::from_key(&key);

    let trie_store = match &state.trie_store {
        Some(ts) => ts.clone(),
        None => return JsonRpcResponse::success(id, json!("0x")),
    };

    match root.get(&expanded, &*trie_store) {
        Some(data) => JsonRpcResponse::success(id, json!(to_hex_bytes(&data))),
        None => JsonRpcResponse::success(id, json!("0x")),
    }
}

pub fn eth_get_storage_at(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    // A slot is a quantity, not a hash: `0x0` is what clients send for slot
    // zero, and demanding all 64 hex characters made this method unusable from
    // any ordinary wallet. See #179.
    let Some(slot) = params.get(1).and_then(|v| v.as_str()).and_then(parse_storage_slot) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid storage slot");
    };
    let (root, _header) = match queried_state(&id, params.get(2), state) {
        Ok(found) => found,
        Err(refused) => return refused,
    };

    let key = storage_key(&addr, &slot);
    let expanded = TrieKeySlice::from_key(&key);

    let trie_store = match &state.trie_store {
        Some(ts) => ts.clone(),
        None => {
            let zero = B256::ZERO;
            return JsonRpcResponse::success(id, json!(format!("{:#066x}", zero)));
        }
    };

    match root.get(&expanded, &*trie_store) {
        Some(data) => {
            let mut padded = [0u8; 32];
            let start = 32usize.saturating_sub(data.len());
            padded[start..].copy_from_slice(&data[..data.len().min(32)]);
            let val = B256::from(padded);
            JsonRpcResponse::success(id, json!(format!("{:#066x}", val)))
        }
        None => {
            let zero = B256::ZERO;
            JsonRpcResponse::success(id, json!(format!("{:#066x}", zero)))
        }
    }
}

/// Why a block parameter gives no state to read.
pub(crate) enum NoState {
    /// The node has no such block.
    Block,
    /// It has the block, and not the state the block left.
    State(B256),
}

/// The state a query reads. Its block parameter is read as rskj's
/// `BlockRefParam` reads it (`helpers::block_ref`) and looked up as
/// `Web3InformationRetriever.getInformationProvider` looks it up, which
/// answers `-32600` for a block the node doesn't have and for a state it
/// doesn't hold. Otherwise the answer rskj gives in its place.
pub(crate) fn queried_state(
    id: &Value,
    block: Option<&Value>,
    state: &RpcState,
) -> Result<(TrieNode, Header), JsonRpcResponse> {
    let refuse = |(code, message): (i64, String)| JsonRpcResponse::error(id.clone(), code, message);
    let (identifier, _) = crate::helpers::block_ref(block, &state.store).map_err(refuse)?;
    let lookup = crate::helpers::information_block(&identifier).map_err(refuse)?;
    state_at(&lookup, state).map_err(|none| {
        refuse(match none {
            NoState::Block => (INVALID_REQUEST, format!("Block {identifier} not found")),
            NoState::State(hash) => (INVALID_REQUEST, stateless(hash)),
        })
    })
}

/// The state a local call runs on, at the block `helpers::call_block` or
/// `estimate_block` gave, or the answer rskj gives where there is none
/// ([`no_execution_state`]).
pub(crate) fn execution_state(
    id: &Value,
    block: &str,
    state: &RpcState,
) -> Result<(TrieNode, Header), JsonRpcResponse> {
    state_at(block, state).map_err(|none| no_execution_state(id, block, none))
}

/// What rskj answers a local call that has no state to run on.
/// `ExecutionBlockRetriever` refuses a number that has no block, `-32602`;
/// a state the node doesn't hold is an exception nobody catches
/// (`RepositoryLocator.snapshotAt`), `-32603`.
pub(crate) fn no_execution_state(id: &Value, block: &str, none: NoState) -> JsonRpcResponse {
    let number = block
        .strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok());
    let (code, message) = match (none, number) {
        (NoState::Block, Some(number)) => {
            (INVALID_PARAMS, format!("Invalid block number {number}"))
        }
        (NoState::Block, None) => (INTERNAL_ERROR, "Internal server error".to_string()),
        (NoState::State(hash), _) => (INTERNAL_ERROR, stateless(hash)),
    };
    JsonRpcResponse::error(id.clone(), code, message)
}

/// rskj's words for a block whose state the node doesn't hold. It prints the
/// hash bare (`Keccak256.toString`).
fn stateless(block: B256) -> String {
    format!("State not found for block with hash {}", hex::encode(block))
}

/// Resolves a block parameter to a state root and header.
pub fn resolve_state_root(block_param: &str, state: &RpcState) -> Option<(TrieNode, Header)> {
    state_at(block_param, state).ok()
}

/// [`resolve_state_root`], saying what was missing where it finds no state.
pub(crate) fn state_at(block_param: &str, state: &RpcState) -> Result<(TrieNode, Header), NoState> {
    let store = &state.store;

    // State queries against "latest" must use the EXECUTED head — the
    // download head can be far ahead and its state doesn't exist yet.
    // Fall back to the chain head when no exec head is tracked.
    let header = match block_param {
        "latest" | "pending" => store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(exec_hash, _)| store.header(exec_hash).ok().flatten())
            .or_else(|| resolve_header(block_param, store)),
        _ => resolve_header(block_param, store),
    }
    .ok_or(NoState::Block)?;
    let no_state = NoState::State(header.hash());
    let Some(trie_store) = state.trie_store.as_ref() else {
        return Err(no_state);
    };

    // Pre-RSKIP126 (wasabi100) headers carry the legacy Ethereum-style state
    // root, which doesn't exist in the Unitrie store. For the executed head
    // the Unitrie root is tracked alongside it; older pre-wasabi blocks
    // cannot be resolved.
    let root_hash = if trie_store.get(header.state_root.as_slice()).is_some() {
        header.state_root
    } else {
        match store.exec_head().ok().flatten() {
            Some((exec_hash, exec_root)) if exec_hash == header.hash() => exec_root,
            _ => return Err(no_state),
        }
    };

    let Some(root_data) = trie_store.get(root_hash.as_slice()) else {
        return Err(no_state);
    };
    let root_node = TrieNode::from_message(&root_data, &**trie_store);
    Ok((root_node, header))
}

fn resolve_header(block_param: &str, store: &BlockStore) -> Option<Header> {
    let head_num = store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)?;

    match block_param {
        "latest" | "pending" => {
            let hash = store.head().ok()??;
            store.header(hash).ok()?
        }
        "earliest" => {
            let hash = store.canonical_hash(0).ok()??;
            store.header(hash).ok()?
        }
        s if s.starts_with("0x") && s.len() == 66 => {
            if let Some(hash) = parse_b256(s) {
                store.header(hash).ok()?
            } else {
                let num = parse_block_number(s, head_num)?;
                let hash = store.canonical_hash(num).ok()??;
                store.header(hash).ok()?
            }
        }
        s => {
            let num = parse_block_number(s, head_num)?;
            let hash = store.canonical_hash(num).ok()??;
            store.header(hash).ok()?
        }
    }
}

pub(crate) fn trie_get_account(root: &TrieNode, key: &[u8], state: &RpcState) -> Option<AccountState> {
    let trie_store = state.trie_store.as_ref()?;
    let expanded = TrieKeySlice::from_key(key);
    let data = root.get(&expanded, &**trie_store)?;
    AccountState::decode(&data).ok()
}
