//! The methods rskj answers with a fixed value or as unsupported, and the
//! refusals its JSON-RPC server gives before a method runs.
//!
//! rskj serves JSON-RPC through jsonrpc4j 1.6's `JsonRpcBasicServer`, under
//! its own `JsonRpcCustomServer`, with `JsonRpcMethodFilter` as the request
//! interceptor and `RskErrorResolver` first among the error resolvers
//! (`JsonRpcWeb3ServerHandler` L59-65). A call meets, in this order:
//!
//! 1. its name: one the `Web3` service doesn't have is -32601 "method not
//!    found" (`JsonRpcCustomServer` L57-60);
//! 2. the count of its parameters: one that no method of that name takes is
//!    -32602 "method parameters invalid" (`JsonRpcBasicServer.handleObject`
//!    L440-443, with `allowExtraParams` and `allowLessParams` false, L73-74);
//! 3. the modules: a method whose module is off makes `JsonRpcMethodFilter`
//!    throw "Method not supported: <name>" (L50-58), which `RskErrorResolver`
//!    answers as it answers an `UnsupportedOperationException`, -32601 "the
//!    method <name> does not exist/is not available" (L51-55);
//! 4. the method itself.
//!
//! This node has no module settings, so this follows rskj's defaults: the
//! modules `reference.conf` lists (L486-534), where `db` isn't one, and the
//! wallet off (`RskSystemProperties.isWalletEnabled` L205-207).

use serde_json::{json, Value};

use crate::types::{JsonRpcResponse, INVALID_PARAMS, METHOD_NOT_FOUND};

/// rskj's answer to a name its `Web3` service doesn't have
/// (`JsonRpcCustomServer.METHOD_NOT_FOUND_MSG`, L37).
pub const METHOD_NOT_FOUND_MESSAGE: &str = "method not found";

/// `DisabledWalletException`'s code (L23).
const DISABLED_WALLET: i64 = -32604;

/// The answer to a name rskj's `Web3` service doesn't have.
pub fn method_not_found(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::error(id, METHOD_NOT_FOUND, METHOD_NOT_FOUND_MESSAGE)
}

/// How many parameters rskj's method of this name takes, for the methods
/// whose answer this module gives. Each has one signature in rskj: `Web3`
/// L46 (`rsk_protocolVersion`), L51-55 (`db_`) and L57-64 (`personal_`),
/// and `Web3EthModule` L42, L46, L64, L108, L123, L130-136 and L154-156.
pub fn arity(method: &str) -> Option<usize> {
    Some(match method {
        "eth_accounts"
        | "eth_pendingTransactions"
        | "eth_protocolVersion"
        | "rsk_protocolVersion"
        | "eth_getCompilers"
        | "db_putString"
        | "db_getString"
        | "db_putHex"
        | "db_getHex"
        | "personal_listAccounts" => 0,
        "eth_sendTransaction"
        | "eth_compileLLL"
        | "eth_compileSerpent"
        | "eth_compileSolidity"
        | "personal_newAccountWithSeed"
        | "personal_newAccount"
        | "personal_lockAccount"
        | "personal_dumpRawKey" => 1,
        "eth_sign"
        | "eth_submitHashrate"
        | "personal_importRawKey"
        | "personal_sendTransaction" => 2,
        "eth_submitWork" | "personal_unlockAccount" => 3,
        _ => return None,
    })
}

/// How many parameters jsonrpc4j counts in `params`, or `None` where no
/// method of rskj's can take them.
///
/// Absent or null is none (`hasNoParameters`, L749-751), and an array is its
/// length (L727-728). An object is matched by the parameters' names, and
/// rskj names none (it has no `@JsonRpcParam`), so only an empty one is
/// taken, as none (`findBestMethodUsingParamNames` L872-896, `ParameterCount`
/// L1247-1270 and L1315-1320). jsonrpc4j throws at any other value outside
/// its error handling, and rskj answers that -32099 "Unexpected error" with
/// no id (`JsonRpcWeb3ServerHandler` L105-110); here it's a count no method
/// takes.
fn param_count(params: &Value) -> Option<usize> {
    match params {
        Value::Null => Some(0),
        Value::Array(items) => Some(items.len()),
        Value::Object(fields) if fields.is_empty() => Some(0),
        _ => None,
    }
}

/// jsonrpc4j's refusal of a call whose parameters rskj's method of this name
/// can't take, which comes before anything the method says. `None` lets the
/// call through, and so does a method `arity` doesn't know.
pub fn wrong_arity(id: &Value, method: &str, params: &Value) -> Option<JsonRpcResponse> {
    let arity = arity(method)?;
    (param_count(params) != Some(arity))
        .then(|| JsonRpcResponse::error(id.clone(), INVALID_PARAMS, "method parameters invalid"))
}

/// `RskErrorResolver`'s answer to an `UnsupportedOperationException`, and to
/// a method `JsonRpcMethodFilter` refuses (L51-55), naming the method.
pub fn not_available(id: Value, method: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        METHOD_NOT_FOUND,
        format!("the method {method} does not exist/is not available"),
    )
}

/// `eth_getCompilers` (`Web3Impl` L952-962). rskj compiles nothing: its
/// `eth_compileSolidity` throws (L974-977).
pub fn eth_get_compilers(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!(["solidity"]))
}

/// `eth_sign` and `eth_sendTransaction` with the wallet off:
/// `EthModuleWalletDisabled.sign` (L49-53) and
/// `EthModuleTransactionDisabled.sendTransaction` (L38-42) throw
/// `invalidParamError`, -32602.
pub fn local_wallet_disabled(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::error(id, INVALID_PARAMS, "Local wallet is disabled in this node")
}

/// The `personal_` methods as rskj answers them with the wallet off:
/// `PersonalModuleWalletDisabled` throws `DisabledWalletException` from every
/// one (L27-74), -32604 "The local wallet feature is disabled", once
/// `Web3Impl` has refused a null seed or passphrase (L1130-1144). A name rskj
/// doesn't have is "method not found".
///
/// This node has no personal module, so it answers so whether or not
/// `--wallet-file` gave it keys, which serve only the `eth_` methods that
/// sign.
pub fn personal(id: Value, method: &str, params: &Value) -> JsonRpcResponse {
    match method {
        "personal_newAccountWithSeed" if params[0].is_null() => {
            JsonRpcResponse::error(id, INVALID_PARAMS, "Seed is null")
        }
        "personal_newAccount" if params[0].is_null() => {
            JsonRpcResponse::error(id, INVALID_PARAMS, "Passphrase is null")
        }
        "personal_newAccountWithSeed"
        | "personal_newAccount"
        | "personal_listAccounts"
        | "personal_importRawKey"
        | "personal_sendTransaction"
        | "personal_unlockAccount"
        | "personal_lockAccount"
        | "personal_dumpRawKey" => {
            JsonRpcResponse::error(id, DISABLED_WALLET, "The local wallet feature is disabled")
        }
        _ => method_not_found(id),
    }
}
