//! `eth_accounts`, `eth_sign`, `eth_signTransaction`, `eth_sendTransaction`.
//!
//! All four answer out of [`crate::wallet::Wallet`], and all four behave
//! as they did before it existed when the operator supplied no wallet:
//! an empty account list, and `METHOD_NOT_FOUND` for the three that sign.
//! A node that was never given keys is indistinguishable from one built
//! without the feature, which is the property the tests that predate this
//! module were written to hold.
//!
//! `eth_sendTransaction` does not have its own path into the pool. It
//! fills in what the caller left out, signs, and hands the bytes to the
//! same [`crate::server::TxSubmitter`] that `eth_sendRawTransaction`
//! uses, so a locally-signed transaction is validated, priced and relayed
//! by exactly the code a peer's transaction goes through.

use alloy_primitives::{Address, U256};
use serde_json::{json, Value};

use crate::server::RpcState;
use crate::types::{JsonRpcResponse, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};

/// The refusal a node with no wallet gives, unchanged from before there
/// was one to give it.
fn no_wallet(id: Value, method: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        METHOD_NOT_FOUND,
        format!("Method {method} requires a wallet, which this node was not given"),
    )
}

/// rskj returns the wallet's accounts; with no wallet the list is empty,
/// which is what it has always been here.
pub fn eth_accounts(id: Value, state: &RpcState) -> JsonRpcResponse {
    let accounts: Vec<String> = match &state.wallet {
        Some(w) => w.accounts().iter().map(|a| format!("{a:#x}")).collect(),
        None => Vec::new(),
    };
    JsonRpcResponse::success(id, json!(accounts))
}

/// `eth_sign(address, message)` — 65 bytes over the EIP-191 digest.
pub fn eth_sign(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(wallet) = &state.wallet else { return no_wallet(id, "eth_sign") };

    let Some(address) = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let Some(message) = params.get(1).and_then(|v| v.as_str()).and_then(parse_hex) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid message hex");
    };

    match wallet.sign_message(&address, &message) {
        Some(sig) => JsonRpcResponse::success(id, json!(format!("0x{}", hex::encode(sig)))),
        None => unknown_account(id, &address),
    }
}

/// `eth_signTransaction` — the signed RLP, not sent.
pub fn eth_sign_transaction(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    if state.wallet.is_none() {
        return no_wallet(id, "eth_signTransaction");
    }
    match build_and_sign(params, state) {
        Ok((_from, raw)) => {
            JsonRpcResponse::success(id, json!(format!("0x{}", hex::encode(raw))))
        }
        Err(e) => e.into_response(id),
    }
}

/// `eth_sendTransaction` — sign, then go through the ordinary relay path.
pub async fn eth_send_transaction(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    if state.wallet.is_none() {
        return no_wallet(id, "eth_sendTransaction");
    }

    // Built before the relay is looked for, so a request naming an
    // account this node has no key for is told that, rather than being
    // told the relay is missing -- which is true but is not the caller's
    // problem and sends them looking in the wrong place.
    let raw = match build_and_sign(params, state) {
        Ok((_from, raw)) => raw,
        Err(e) => return e.into_response(id),
    };

    let Some(submitter) = &state.tx_submitter else {
        return JsonRpcResponse::error(id, METHOD_NOT_FOUND, "Transaction relay not available");
    };

    match submitter.submit_transaction(alloy_primitives::Bytes::from(raw)).await {
        Ok(hash) => JsonRpcResponse::success(id, json!(format!("0x{hash:x}"))),
        Err(e) => JsonRpcResponse::error(id, INVALID_PARAMS, e),
    }
}

fn unknown_account(id: Value, address: &Address) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        INVALID_PARAMS,
        format!("No key for {address:#x}; this node signs only for the accounts it was given"),
    )
}

enum SignError {
    Params(String),
    Unknown(Address),
    NoChainId,
}

impl SignError {
    fn into_response(self, id: Value) -> JsonRpcResponse {
        match self {
            SignError::Params(m) => JsonRpcResponse::error(id, INVALID_PARAMS, m),
            SignError::Unknown(a) => unknown_account(id, &a),
            SignError::NoChainId => JsonRpcResponse::error(
                id,
                INTERNAL_ERROR,
                "No chain configuration, so no chain id to sign against",
            ),
        }
    }
}

/// Fill in what the caller left out, then sign.
///
/// The defaults are rskj's (`TransactionArgumentsUtil.processArguments`): no
/// value, a gas price of 0, the gas named as `gas` or else as `gasLimit`, or
/// else 90,000 (`GasCost.TRANSACTION_DEFAULT`), and the sender's pending nonce
/// (`EthModuleTransactionBase.sendTransaction`).
fn build_and_sign(params: &Value, state: &RpcState) -> Result<(Address, Vec<u8>), SignError> {
    let wallet = state.wallet.as_ref().expect("checked by the caller");

    let obj = params
        .get(0)
        .filter(|v| v.is_object())
        .ok_or_else(|| SignError::Params("Missing transaction object".into()))?;

    let from = obj
        .get("from")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())
        .ok_or_else(|| SignError::Params("Missing or invalid `from`".into()))?;
    if !wallet.holds(&from) {
        return Err(SignError::Unknown(from));
    }

    // `to` absent or null is a contract creation, which RSK encodes as an
    // empty recipient rather than a zero address.
    let to = match obj.get("to") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| SignError::Params("Invalid `to`".into()))?;
            s.parse::<Address>()
                .map_err(|_| SignError::Params("Invalid `to`".into()))?
                .to_vec()
        }
    };

    let input = match obj.get("data").or_else(|| obj.get("input")) {
        Some(Value::Null) | None => Vec::new(),
        Some(v) => v
            .as_str()
            .and_then(parse_hex)
            .ok_or_else(|| SignError::Params("Invalid `data`".into()))?,
    };

    let value = quantity(obj.get("value"))?.unwrap_or(U256::ZERO);

    // The pending nonce, not the latest: a harness that fires several
    // transactions from one sender without waiting would otherwise give
    // them all the same nonce and have all but one rejected.
    let nonce = match quantity(obj.get("nonce"))? {
        Some(n) => n.to::<u64>(),
        None => state
            .tx_pool
            .as_ref()
            .and_then(|p| p.pending_nonce(&from))
            .unwrap_or_else(|| account_nonce(&from, state)),
    };

    let gas_price = quantity(obj.get("gasPrice"))?.unwrap_or(U256::ZERO);

    let gas_limit = match quantity(obj.get("gas"))? {
        Some(g) => g,
        None => quantity(obj.get("gasLimit"))?.unwrap_or(U256::from(TRANSACTION_DEFAULT_GAS)),
    };

    let chain_id = state.hardfork_cfg.as_ref().map(|c| c.chain_id).ok_or(SignError::NoChainId)?;

    let mut tx = rustock_core::Transaction {
        nonce,
        gas_price,
        gas_limit,
        to: alloy_primitives::Bytes::from(to),
        value,
        input: alloy_primitives::Bytes::from(input),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: None,
    };

    if !wallet.sign_transaction(&from, &mut tx, chain_id) {
        return Err(SignError::Unknown(from));
    }
    Ok((from, tx.rlp_for_trie()))
}

/// A hex quantity, as every numeric field of the transaction object is.
fn quantity(v: Option<&Value>) -> Result<Option<U256>, SignError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let body = s.strip_prefix("0x").unwrap_or(s);
            U256::from_str_radix(body, 16)
                .map(Some)
                .map_err(|_| SignError::Params(format!("Invalid quantity {s}")))
        }
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|x| Some(U256::from(x)))
            .ok_or_else(|| SignError::Params("Invalid quantity".into())),
        Some(_) => Err(SignError::Params("Invalid quantity".into())),
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()
}

fn account_nonce(address: &Address, state: &RpcState) -> u64 {
    let reply = crate::state::eth_get_transaction_count(
        Value::Null,
        &json!([format!("{address:#x}"), "latest"]),
        state,
    );
    reply
        .result
        .as_ref()
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
        .unwrap_or(0)
}

/// The gas a sent transaction names when the caller names none: rskj's
/// `GasCost.TRANSACTION_DEFAULT`.
const TRANSACTION_DEFAULT_GAS: u64 = 90_000;
