#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub const ERR_PARSE: i32 = -32700;
pub const ERR_INVALID_REQUEST: i32 = -32600;
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
pub const ERR_INVALID_PARAMS: i32 = -32602;
pub const ERR_RATE_LIMITED: i32 = -32000;
pub const ERR_UNAUTHORIZED: i32 = -32001;
pub const ERR_PAYLOAD_TOO_LARGE: i32 = -32002;
pub const ERR_BATCH_LIMIT: i32 = -32003;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
