//! `eth_getProof` over the unitrie.
//!
//! # What this returns, and what it does not
//!
//! EIP-1186 defines `accountProof` and `storageProof[].proof` as arrays of
//! **RLP-encoded Merkle-Patricia trie nodes**. RSK has no Merkle-Patricia
//! trie. It has a unitrie: one binary radix trie with path compression
//! holding accounts, code and storage together, with its own node encoding.
//!
//! So the envelope here is EIP-1186's -- `balance`, `nonce`, `codeHash`,
//! `storageHash`, and a `storageProof` entry per requested slot, which are
//! trie-agnostic and useful -- while the proof arrays carry **unitrie node
//! messages**, hex-encoded, deepest node first.
//!
//! **A stock EIP-1186 verifier will not verify these.** It will fail to parse
//! them, which is the safe failure, but a caller expecting Ethereum semantics
//! should know before it starts. Verification is described under "How to
//! check one" below.
//!
//! The encoding is not invented here. rskj already exposes proofs this way --
//! `RskModuleImpl.getTransactionReceiptNodesByHash` returns
//! `HexUtils.toUnformattedJsonHex(node.toMessage())` for each node of
//! `Trie.getNodes(...)` -- so a hex array of `toMessage()` bytes in
//! `findNodes` order is RSK's established shape for a Merkle proof. This
//! method reuses it rather than inventing a second one.
//!
//! rskj does not implement `eth_getProof` at all. Offering it is a deliberate
//! divergence, taken because the question it answers -- prove this balance,
//! this nonce, this slot, against a state root -- is worth answering, and
//! because no standard shape exists that RSK could satisfy instead.
//!
//! # The three paths
//!
//! The unitrie holds everything under one root, which makes the mapping onto
//! EIP-1186's fields more direct than it is on Ethereum, not less:
//!
//! | EIP-1186 | unitrie |
//! |---|---|
//! | `accountProof` | nodes on the path to `account_key(addr)` |
//! | `storageHash` | hash of the node at `storage_prefix_key(addr)` |
//! | `storageProof[i].proof` | nodes on the path to `storage_key(addr, slot)` |
//!
//! `storageHash` deserves a note. On Ethereum it is the root of a *separate*
//! storage trie. RSK has no such thing: an account's storage lives beneath
//! `account_key || 0x00` in the same trie. The hash of the node at that path
//! is the closest true analogue -- it commits to exactly that account's
//! storage and nothing else -- and it is what this returns. An account with
//! no storage has no such node, and gets `0x0…0`, mirroring Ethereum's empty
//! storage root being a constant the caller can recognise.
//!
//! # How to check one
//!
//! Walk the returned array from index 0 (the deepest node) upward. For each
//! node, decode the message, recompute its hash with the unitrie's rules, and
//! confirm it appears as the expected child reference of the next node in the
//! array. The last element is the root; its hash must equal the `stateRoot`
//! of the block that was asked about.
//!
//! A proof is returned only for a key the trie actually holds. `None` from
//! `nodes_on_path` means absent, and this answers an empty array rather than
//! a partial path -- an absence proof over a radix trie needs the divergence
//! point and its siblings, which is a different structure, and emitting a
//! truncated inclusion path would look like one without being one.

use crate::server::RpcState;

use crate::types::*;
use alloy_primitives::{Address, B256, U256};
use rustock_trie::{
    account_key, code_key, storage_key, storage_prefix_key, AccountState, TrieKeySlice, TrieNode,
    TrieStore,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

/// `keccak256("")`, what `codeHash` reports for an account with no code.
fn empty_code_hash() -> B256 {
    B256::from_slice(&Keccak256::digest([]))
}

/// Every node from the key's leaf up to the root, hex-encoded, deepest first.
///
/// Empty when the trie does not hold the key -- see the module note on why
/// that is not a truncated path.
fn path_messages(root: &TrieNode, key: &[u8], store: &dyn TrieStore) -> Vec<String> {
    let slice = TrieKeySlice::from_key(key);
    match root.nodes_on_path(&slice, store) {
        Some(nodes) => nodes
            .iter()
            .map(|n| format!("0x{}", hex::encode(n.to_message(store))))
            .collect(),
        None => Vec::new(),
    }
}

pub fn eth_get_proof(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };

    // The second parameter is an array of storage slots, and it is required
    // by EIP-1186 even when empty -- a caller that wants only the account
    // sends `[]`.
    let Some(slot_values) = params.get(1).and_then(|v| v.as_array()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing storage key array");
    };
    let mut slots: Vec<(String, B256)> = Vec::with_capacity(slot_values.len());
    for v in slot_values {
        // Accepted as a quantity, not a padded hash, for the reason
        // `eth_getStorageAt` accepts one: `0x0` is what wallets send for slot
        // zero, and demanding 64 hex characters makes the method unusable
        // from any of them (#179).
        let Some(raw) = v.as_str() else {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Storage key must be a string");
        };
        let Some(slot) = crate::helpers::parse_storage_slot(raw) else {
            return JsonRpcResponse::error(
                id,
                INVALID_PARAMS,
                format!("Invalid storage key: {raw}"),
            );
        };
        slots.push((raw.to_string(), slot));
    }

    // The block as the state queries read it: a tag, a number, or an
    // EIP-1898 object.
    let (root, _header) = match crate::state::queried_state(&id, params.get(2), state) {
        Ok(found) => found,
        Err(refused) => return refused,
    };
    let Some(trie_store) = state.trie_store.clone() else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "State not available");
    };
    let store = &*trie_store;

    // The account itself. An address the trie does not hold still gets a
    // well-formed answer -- zero balance, zero nonce, empty code hash, empty
    // proof -- which is what a caller asking about an unused address should
    // see, and is how Ethereum clients answer the same question.
    let acct_key = account_key(&addr);
    let account: Option<AccountState> = root
        .get(&TrieKeySlice::from_key(&acct_key), store)
        .and_then(|bytes| AccountState::decode(&bytes).ok());
    let (nonce, balance) = match &account {
        Some(a) => (a.nonce, a.balance),
        None => (U256::ZERO, U256::ZERO),
    };

    let code_hash = match root.get(&TrieKeySlice::from_key(&code_key(&addr)), store) {
        Some(code) if !code.is_empty() => B256::from_slice(&Keccak256::digest(&code)),
        _ => empty_code_hash(),
    };

    // The storage subtree's own node, which is what commits to this
    // account's storage and nothing else.
    // `nodes_on_path` is leaf-first, so element 0 is the node at the key
    // itself -- the root of this account's storage subtree. Taken this way
    // rather than through `find`, which is private to the trie: the proof
    // already needs the path walk, and widening the trie's surface for a
    // second way to do the same descent would be a poor trade.
    let storage_hash = root
        .nodes_on_path(&TrieKeySlice::from_key(&storage_prefix_key(&addr)), store)
        .and_then(|nodes| nodes.first().map(|n| n.compute_hash(store)))
        .unwrap_or(B256::ZERO);

    let storage_proof: Vec<Value> = slots
        .iter()
        .map(|(raw, slot)| {
            let key = storage_key(&addr, slot);
            let value = root
                .get(&TrieKeySlice::from_key(&key), store)
                .map(|bytes| {
                    // Stored minimally, as `eth_getStorageAt` also finds.
                    let mut padded = [0u8; 32];
                    let start = 32usize.saturating_sub(bytes.len());
                    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
                    U256::from_be_bytes(padded)
                })
                .unwrap_or(U256::ZERO);
            json!({
                "key": raw,
                "value": format!("{value:#x}"),
                "proof": path_messages(&root, &key, store),
            })
        })
        .collect();

    JsonRpcResponse::success(
        id,
        json!({
            "address": format!("{addr:#x}"),
            "balance": format!("{balance:#x}"),
            "codeHash": format!("{code_hash:#x}"),
            "nonce": format!("{nonce:#x}"),
            "storageHash": format!("{storage_hash:#x}"),
            "accountProof": path_messages(&root, &acct_key, store),
            "storageProof": storage_proof,
        }),
    )
}

/// `rsk_getStorageNodes(address, [slots], block)`: for each slot, whether the
/// state holds it, its value, and the unitrie nodes from the slot's key up to
/// the state root -- for a slot that is absent as much as for one that is not.
///
/// `eth_getProof` answers an absent key with an empty array, on purpose (see
/// the module note), which leaves a caller no way to prove a slot empty. On
/// Rootstock that is also the only way to prove a slot holds zero, because a
/// slot set to zero is deleted from the trie (rskj
/// `MutableRepository.addStorageBytes`). So this answers both cases with the
/// path toward the key, and says which case it is, so that a path is never
/// read as inclusion when it is not:
///
/// - `present: true`: the deepest node is the slot's own, and holds its value.
/// - `present: false`: the deepest node is where the key leaves the trie: its
///   shared path parts from the key's, or the key ends inside it, or the child
///   the key would take is empty, or the key ends at it and it holds nothing.
///
/// A caller checks the nodes as `eth_getProof`'s are checked, walking the key
/// down from the root, and must reach the same answer as `present`. The block
/// is named in the answer, so the caller knows which header's state root the
/// nodes hang from. A node the store cannot produce is an error, never an
/// absence. A value too long to sit in its node (over 32 bytes, as some of
/// the Bridge's cells are) is stored apart from it: one of those the store
/// has lost is answered as absent, though the slot's node still carries its
/// hash and length, so a caller that walks the nodes, as it must, finds it
/// held and the answer wrong.
pub fn rsk_get_storage_nodes(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let Some(slot_values) = params.get(1).and_then(|v| v.as_array()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing storage key array");
    };
    let mut slots: Vec<(String, B256)> = Vec::with_capacity(slot_values.len());
    for v in slot_values {
        let Some(raw) = v.as_str() else {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Storage key must be a string");
        };
        let Some(slot) = crate::helpers::parse_storage_slot(raw) else {
            return JsonRpcResponse::error(
                id,
                INVALID_PARAMS,
                format!("Invalid storage key: {raw}"),
            );
        };
        slots.push((raw.to_string(), slot));
    }

    let (root, header) = match crate::state::queried_state(&id, params.get(2), state) {
        Ok(found) => found,
        Err(refused) => return refused,
    };
    let Some(trie_store) = state.trie_store.clone() else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "State not available");
    };
    let store = &*trie_store;

    let mut storage: Vec<Value> = Vec::with_capacity(slots.len());
    for (raw, slot) in &slots {
        let key = TrieKeySlice::from_key(&storage_key(&addr, slot));
        let incomplete = |missing: B256| {
            JsonRpcResponse::error(
                id.clone(),
                INTERNAL_ERROR,
                format!("The state is incomplete here: node {missing:#x} is missing"),
            )
        };
        let nodes = match root.try_nodes_toward(&key, store) {
            Ok(nodes) => nodes,
            Err(missing) => return incomplete(missing),
        };
        let value = match root.try_get(&key, store) {
            Ok(value) => value.filter(|v| !v.is_empty()),
            Err(missing) => return incomplete(missing),
        };
        // Stored minimally, as `eth_getStorageAt` also finds.
        let number = value.as_ref().map_or(U256::ZERO, |bytes| {
            let mut padded = [0u8; 32];
            let start = 32usize.saturating_sub(bytes.len());
            padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
            U256::from_be_bytes(padded)
        });
        storage.push(json!({
            "key": raw,
            "present": value.is_some(),
            "value": format!("{number:#x}"),
            "nodes": nodes
                .iter()
                .map(|n| format!("0x{}", hex::encode(n.to_message(store))))
                .collect::<Vec<_>>(),
        }));
    }

    JsonRpcResponse::success(
        id,
        json!({
            "address": format!("{addr:#x}"),
            "blockNumber": format!("{:#x}", header.number),
            "blockHash": format!("{:#x}", header.hash()),
            "stateRoot": format!("{:#x}", header.state_root),
            "storage": storage,
        }),
    )
}

/// The most keys that one `rsk_getStateNodes` call walks along.
pub const MAX_STATE_KEYS: usize = 64;

/// The longest key that `rsk_getStateNodes` walks along, in bytes: more than
/// any key the unitrie holds, the longest being a storage key's 74.
pub const MAX_STATE_KEY: usize = 128;

/// `rsk_getStateNodes(blockHash, [keys])`: for each key, the unitrie nodes of
/// the walk along it from the state root of the block with hash `blockHash`,
/// from where the walk ends up to the root, as [`TrieNode::try_nodes_toward`]
/// gives them; or null if this node doesn't hold the block's header, or the
/// state at its state root.
///
/// A key is the trie's own, raw (`code_key`, `storage_key`, ...), so one call
/// proves a contract's code and its slots together. The walk hangs from the
/// header's own state root and no other, as that is what a caller checks it
/// against, so a header from before wasabi, whose state root is no unitrie's,
/// has no state here. Whether a key is held is the caller's to read from the
/// nodes, as `rsk_getStorageNodes` describes. A node the store cannot produce
/// is an error, never an absence.
pub fn rsk_get_state_nodes(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(hash) = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(crate::helpers::parse_b256)
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    let Some(listed) = params.get(1).and_then(|v| v.as_array()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing key array");
    };
    if listed.len() > MAX_STATE_KEYS {
        return JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            format!("At most {MAX_STATE_KEYS} keys at a time"),
        );
    }
    let mut keys = Vec::with_capacity(listed.len());
    for key in listed {
        match key.as_str().and_then(parse_state_key) {
            Some(key) => keys.push(key),
            None => {
                return JsonRpcResponse::error(id, INVALID_PARAMS, format!("Invalid key: {key}"))
            }
        }
    }

    let header = match state.store.header(hash) {
        Ok(Some(header)) => header,
        Ok(None) => return JsonRpcResponse::success(id, Value::Null),
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                INTERNAL_ERROR,
                format!("Failed to read the header: {e}"),
            )
        }
    };
    let Some(trie_store) = state.trie_store.clone() else {
        return JsonRpcResponse::success(id, Value::Null);
    };
    let store = &*trie_store;
    let Some(message) = store.get(header.state_root.as_slice()) else {
        return JsonRpcResponse::success(id, Value::Null);
    };
    let root = TrieNode::from_message(&message, store);

    let mut walks: Vec<Vec<String>> = Vec::with_capacity(keys.len());
    for key in &keys {
        match root.try_nodes_toward(&TrieKeySlice::from_key(key), store) {
            Ok(nodes) => walks.push(
                nodes
                    .iter()
                    .map(|n| format!("0x{}", hex::encode(n.to_message(store))))
                    .collect(),
            ),
            Err(missing) => {
                return JsonRpcResponse::error(
                    id,
                    INTERNAL_ERROR,
                    format!("The state is incomplete here: node {missing:#x} is missing"),
                )
            }
        }
    }
    JsonRpcResponse::success(id, json!(walks))
}

/// A trie key as `0x`-prefixed hex, at most [`MAX_STATE_KEY`] bytes.
fn parse_state_key(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x")?;
    if digits.len() > 2 * MAX_STATE_KEY {
        return None;
    }
    hex::decode(digits).ok()
}
