//! `eth_accounts`, `eth_sign`, `eth_signTransaction`, `eth_sendTransaction`.
//!
//! All four answer out of [`crate::wallet::Wallet`]. When the operator
//! supplied none they answer as rskj does with its wallet off, which is its
//! default (`EthModuleWalletDisabled`, `EthModuleTransactionDisabled`): an
//! empty account list, and `eth_sign` and `eth_sendTransaction` refused,
//! -32602 "Local wallet is disabled in this node". rskj has no
//! `eth_signTransaction`, so without a wallet that one is "method not
//! found", as rskj answers it.
//!
//! With one they answer as rskj does with its wallet on
//! (`EthModuleWalletEnabled`, `EthModuleTransactionBase`). Either way their
//! parameters are read as rskj reads them, before the method runs
//! ([`crate::params`], [`CallArguments`]), and a transaction is written as
//! rskj writes one it builds: what is signed here is what rskj would sign
//! for the same request.
//!
//! `eth_sendTransaction` does not have its own path into the pool. It
//! fills in what the caller left out, signs, and hands the bytes to the
//! same [`crate::server::TxSubmitter`] that `eth_sendRawTransaction`
//! uses, so a locally-signed transaction is validated, priced and relayed
//! by exactly the code a peer's transaction goes through.

use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Encodable;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

use crate::dto::{CallArguments, TransactionArguments};
use crate::params::{hex_address, hex_data, text, uncaught, Refusal};
use crate::server::RpcState;
use crate::types::{JsonRpcResponse, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::wallet::Wallet;

fn refuse(id: Value, (code, message): Refusal) -> JsonRpcResponse {
    JsonRpcResponse::error(id, code, message)
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
    // jsonrpc4j makes an address and data of the two before the method runs
    // (`HexAddressParam`, `HexDataParam`), and leaves a `null` as it is.
    let address = params.get(0).and_then(text).map(|text| hex_address(&text));
    let address = match address.transpose() {
        Ok(address) => address,
        Err(refusal) => return refuse(id, refusal),
    };
    let message = params.get(1).and_then(text).map(|text| hex_data(&text));
    let message = match message.transpose() {
        Ok(message) => message,
        Err(refusal) => return refuse(id, refusal),
    };
    // rskj's `Web3EthModule.eth_sign` reads both arguments before its wallet
    // module sees them (L46-48), so a null one is a NullPointerException,
    // which `RskErrorResolver` answers as an internal error (L56-58), wallet
    // or no wallet.
    let (Some(address), Some(message)) = (address, message) else {
        return refuse(id, uncaught());
    };
    let Some(wallet) = &state.wallet else {
        return crate::stubs::local_wallet_disabled(id);
    };

    match wallet.sign_message(&address, &message) {
        Some(sig) => JsonRpcResponse::success(id, json!(format!("0x{}", hex::encode(sig)))),
        // `EthModuleWalletEnabled.sign`.
        None => JsonRpcResponse::error(id, INVALID_PARAMS, "Account not found"),
    }
}

/// `eth_signTransaction` — the signed RLP, not sent. rskj has no such
/// method; its transaction is read as `eth_sendTransaction` reads one.
pub fn eth_sign_transaction(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(wallet) = &state.wallet else {
        // rskj has no such method.
        return crate::stubs::method_not_found(id);
    };
    if params.get(0).is_none() {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing transaction object");
    }
    match arguments(params).and_then(|arguments| sign(arguments, wallet, state)) {
        Ok(raw) => JsonRpcResponse::success(id, json!(format!("0x{}", hex::encode(raw)))),
        Err(refusal) => refuse(id, refusal),
    }
}

/// `eth_sendTransaction` — sign, then go through the ordinary relay path.
pub async fn eth_send_transaction(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    // The arguments are checked before the method runs, wallet or no wallet.
    let arguments = match arguments(params) {
        Ok(arguments) => arguments,
        Err(refusal) => return refuse(id, refusal),
    };
    let Some(wallet) = &state.wallet else {
        return crate::stubs::local_wallet_disabled(id);
    };

    // Built before the relay is looked for, so a request naming an
    // account this node has no key for is told that, rather than being
    // told the relay is missing -- which is true but is not the caller's
    // problem and sends them looking in the wrong place.
    let raw = match sign(arguments, wallet, state) {
        Ok(raw) => raw,
        Err(refusal) => return refuse(id, refusal),
    };

    let Some(submitter) = &state.tx_submitter else {
        return JsonRpcResponse::error(id, METHOD_NOT_FOUND, "Transaction relay not available");
    };

    match submitter.submit_transaction(alloy_primitives::Bytes::from(raw)).await {
        Ok(hash) => JsonRpcResponse::success(id, json!(format!("0x{hash:x}"))),
        Err(e) => JsonRpcResponse::error(id, INVALID_PARAMS, e),
    }
}

/// A transaction's arguments, checked as rskj's `CallArgumentsParam` checks
/// them before the method runs. `None` for `null`, and for none given, which
/// reach the method as no arguments at all.
fn arguments(params: &Value) -> Result<Option<CallArguments>, Refusal> {
    match params.get(0) {
        None | Some(Value::Null) => Ok(None),
        Some(arguments) => CallArguments::read(arguments).map(Some),
    }
}

/// `EthModuleTransactionBase.sendTransaction`, as far as the signed bytes:
/// the sender, who has to be named and held; the arguments
/// ([`CallArguments::transaction`]); the sender's next nonce where they name
/// none; and the signature, for the node's chain, which is the only chain the
/// arguments may name (`acceptTransactionSignature`).
fn sign(
    arguments: Option<CallArguments>,
    wallet: &Wallet,
    state: &RpcState,
) -> Result<Vec<u8>, Refusal> {
    let invalid = |message: String| (INVALID_PARAMS, message);
    // No arguments at all is a NullPointerException where the method reads
    // them, which nothing catches.
    let arguments = arguments.ok_or_else(uncaught)?;
    let from = arguments
        .from()
        .ok_or_else(|| invalid("from is null".to_string()))?;
    let unknown = || invalid(format!("Could not find account for address: {from:#x}"));
    if !wallet.holds(&from) {
        return Err(unknown());
    }
    let arguments = arguments.transaction()?;

    // The pending nonce, not the latest: a harness that fires several
    // transactions from one sender without waiting would otherwise give
    // them all the same nonce and have all but one rejected.
    let nonce = arguments.nonce.unwrap_or_else(|| {
        let pending = state
            .tx_pool
            .as_ref()
            .and_then(|pool| pool.pending_nonce(&from))
            .unwrap_or_else(|| account_nonce(&from, state));
        U256::from(pending)
    });

    let chain = state
        .hardfork_cfg
        .as_ref()
        .map(|config| config.chain_id)
        .ok_or_else(|| {
            (
                INTERNAL_ERROR,
                "No chain configuration, so no chain id to sign against".to_string(),
            )
        })?;
    if let Some((named, written)) = &arguments.chain_id {
        if u64::from(*named) != chain {
            return Err(invalid(format!("Invalid chainId: {written}")));
        }
    }

    let fields = signed_fields(nonce, &arguments);
    // What the signature signs (`getEncodedRaw`): the fields, the chain
    // (`RLP.encodeByte`) and two empty items.
    let mut unsigned = fields.clone();
    chain.encode(&mut unsigned);
    unsigned.extend_from_slice(&[alloy_rlp::EMPTY_STRING_CODE; 2]);
    let digest = B256::from_slice(&Keccak256::digest(list(&unsigned)));
    let (recovery_id, signature) = wallet.sign_digest(&from, digest).ok_or_else(unknown)?;

    // The transaction (`getEncoded`): the fields, v by the chain, and r and
    // s in as few bytes as hold them.
    let mut signed = fields;
    (chain * 2 + 35 + u64::from(recovery_id)).encode(&mut signed);
    U256::from_be_slice(&signature[..32]).encode(&mut signed);
    U256::from_be_slice(&signature[32..]).encode(&mut signed);
    Ok(list(&signed))
}

/// The six fields a signature covers, of a transaction rskj builds from
/// `arguments`, each as rskj writes it (`TransactionBuilder
/// .withTransactionArguments`, then `Transaction.encode`).
///
/// Each number is written in as few bytes as hold it, and none for zero,
/// but for the gas price: rskj writes a gas price of zero `0x00`
/// (`RLP.encodeCoinNonNullZero`), where canonical RLP writes it empty, which
/// is another transaction with another hash. A sent transaction's gas price
/// is zero unless its arguments name one.
fn signed_fields(nonce: U256, arguments: &TransactionArguments) -> Vec<u8> {
    let to: &[u8] = arguments.to.as_ref().map_or(&[], |to| to.as_slice());
    let mut fields = Vec::with_capacity(128 + arguments.data.len());
    nonce.encode(&mut fields);
    if arguments.gas_price.is_zero() {
        fields.push(0);
    } else {
        arguments.gas_price.encode(&mut fields);
    }
    arguments.gas_limit.encode(&mut fields);
    to.encode(&mut fields);
    arguments.value.encode(&mut fields);
    arguments.data.as_slice().encode(&mut fields);
    fields
}

/// The RLP list of `payload`.
fn list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(payload);
    out
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
