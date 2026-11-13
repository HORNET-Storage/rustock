use serde::{Deserialize, Serialize};

/// Standard JSON-RPC 2.0 error codes.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// rskj's own, `RskJsonRpcRequestException.transactionError`: a transaction
/// its pool refuses.
pub const TRANSACTION_ERROR: i64 = -32010;
/// rskj's own, `RskJsonRpcRequestException.executionError`: a call or an
/// estimate whose program ended with REVERT. Its `data` is what the program
/// reverted with.
pub const EXECUTION_ERROR: i64 = -32015;

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    /// What rskj's `RskJsonRpcRequestException` carries as `revertData`: only
    /// a revert has it, and every other error is written without the field.
    /// Boxed, to keep a response the size it was for those.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Box<serde_json::Value>>,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Serialise for a transport that writes frames rather than HTTP bodies.
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            // A response that cannot be serialised is a bug, but dropping the
            // connection over it would be worse than telling the caller.
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#
                .to_string()
        })
    }

    pub fn error(id: serde_json::Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    /// An error that carries `data`, as rskj's answer to a revert does.
    pub fn error_with_data(
        id: serde_json::Value,
        code: i64,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        let mut response = Self::error(id, code, message);
        if let Some(error) = &mut response.error {
            error.data = Some(Box::new(data));
        }
        response
    }
}
