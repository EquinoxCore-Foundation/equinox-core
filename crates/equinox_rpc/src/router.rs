#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::errors::{
    RpcError, ERR_BATCH_LIMIT, ERR_INVALID_PARAMS, ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND,
    ERR_PARSE, ERR_PAYLOAD_TOO_LARGE, ERR_RATE_LIMITED, ERR_UNAUTHORIZED,
};
use crate::metrics::ExplorerMetrics;
use crate::ratelimit::{RpcSecurityGuard, MAX_RPC_BATCH_SIZE, MAX_RPC_BODY_BYTES};
use crate::subscriptions::{SubscriptionHub, SubscriptionTopic};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Value,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Value,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    fn err(id: Value, code: i32, msg: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcError::new(code, msg)),
            id,
        }
    }
}

pub struct RpcRouter {
    pub guard: RpcSecurityGuard,
    pub metrics: ExplorerMetrics,
    pub subscriptions: SubscriptionHub,
    pub balances: HashMap<String, u128>,
    pub mining_enabled: bool,
}

impl RpcRouter {
    pub fn new(admin_token: Option<String>) -> Self {
        Self {
            guard: RpcSecurityGuard::new(60, 20, admin_token),
            metrics: ExplorerMetrics::default(),
            subscriptions: SubscriptionHub::new(512, 64),
            balances: HashMap::new(),
            mining_enabled: false,
        }
    }

    /// Processes raw JSON-RPC 2.0 HTTP/WS text with full anti-DoS, batch, and auth enforcement.
    pub fn handle_raw(
        &mut self,
        client_ip: IpAddr,
        now_ms: u64,
        bearer_token: Option<&str>,
        raw_body: &str,
    ) -> String {
        if raw_body.len() > MAX_RPC_BODY_BYTES {
            let resp = JsonRpcResponse::err(Value::Null, ERR_PAYLOAD_TOO_LARGE, "Payload exceeds 1 MiB limit");
            return serde_json::to_string(&resp).unwrap();
        }
        if !self.guard.allow_request(client_ip, now_ms) {
            let resp = JsonRpcResponse::err(Value::Null, ERR_RATE_LIMITED, "RPC rate limit exceeded");
            return serde_json::to_string(&resp).unwrap();
        }

        let parsed: Value = match serde_json::from_str(raw_body) {
            Ok(v) => v,
            Err(_) => {
                let resp = JsonRpcResponse::err(Value::Null, ERR_PARSE, "Invalid JSON");
                return serde_json::to_string(&resp).unwrap();
            }
        };

        if let Value::Array(items) = parsed {
            if items.is_empty() {
                let resp = JsonRpcResponse::err(Value::Null, ERR_INVALID_REQUEST, "Empty batch");
                return serde_json::to_string(&resp).unwrap();
            }
            if items.len() > MAX_RPC_BATCH_SIZE {
                let resp = JsonRpcResponse::err(
                    Value::Null,
                    ERR_BATCH_LIMIT,
                    "Batch exceeds 20-call anti-DoS limit",
                );
                return serde_json::to_string(&resp).unwrap();
            }
            let responses: Vec<JsonRpcResponse> = items
                .into_iter()
                .map(|item| self.dispatch_value(item, bearer_token))
                .collect();
            return serde_json::to_string(&responses).unwrap();
        }

        let resp = self.dispatch_value(parsed, bearer_token);
        serde_json::to_string(&resp).unwrap()
    }

    fn dispatch_value(&mut self, val: Value, bearer_token: Option<&str>) -> JsonRpcResponse {
        let req: JsonRpcRequest = match serde_json::from_value(val) {
            Ok(r) => r,
            Err(_) => {
                return JsonRpcResponse::err(
                    Value::Null,
                    ERR_INVALID_REQUEST,
                    "Malformed JSON-RPC 2.0 object",
                );
            }
        };

        if req.jsonrpc != "2.0" {
            return JsonRpcResponse::err(req.id, ERR_INVALID_REQUEST, "jsonrpc must be 2.0");
        }

        // Strict constant-time Bearer token check for all admin_* methods
        if req.method.starts_with("admin_") && !self.guard.verify_admin_token(bearer_token) {
            return JsonRpcResponse::err(req.id, ERR_UNAUTHORIZED, "Admin authorization required");
        }

        match req.method.as_str() {
            "eqx_chainId" => JsonRpcResponse::ok(req.id, json!(self.metrics.chain_id)),
            "eqx_blockNumber" => JsonRpcResponse::ok(req.id, json!(self.metrics.block_height)),
            "eqx_getExplorerStats" => {
                JsonRpcResponse::ok(req.id, serde_json::to_value(&self.metrics).unwrap())
            }
            "eqx_getBalance" => {
                let addr = req
                    .params
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str());
                match addr {
                    Some(a) if a.starts_with('E') && a.len() == 34 => {
                        let bal = self.balances.get(a).copied().unwrap_or(0);
                        JsonRpcResponse::ok(req.id, json!({ "address": a, "balance_atomic": bal.to_string() }))
                    }
                    _ => JsonRpcResponse::err(req.id, ERR_INVALID_PARAMS, "Expected valid 34-char E... address"),
                }
            }
            "eqx_subscribe" => {
                let topic_name = req
                    .params
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str());
                let topic = match topic_name {
                    Some("newHeads") => SubscriptionTopic::NewHeads,
                    Some("newPendingTransactions") => SubscriptionTopic::NewPendingTransactions,
                    Some("addressActivity") => {
                        match req.params.as_array().and_then(|a| a.get(1)).and_then(|v| v.as_str()) {
                            Some(addr) if addr.starts_with('E') && addr.len() == 34 => {
                                SubscriptionTopic::AddressActivity(addr.to_string())
                            }
                            _ => {
                                return JsonRpcResponse::err(
                                    req.id,
                                    ERR_INVALID_PARAMS,
                                    "addressActivity requires a valid E... address",
                                );
                            }
                        }
                    }
                    _ => return JsonRpcResponse::err(req.id, ERR_INVALID_PARAMS, "Unknown topic"),
                };
                match self.subscriptions.subscribe(topic) {
                    Some(sub_id) => JsonRpcResponse::ok(req.id, json!({ "subscription_id": sub_id })),
                    None => JsonRpcResponse::err(req.id, ERR_RATE_LIMITED, "Max WebSocket subscribers reached"),
                }
            }
            "admin_setMining" => {
                let enable = req
                    .params
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_bool());
                match enable {
                    Some(flag) => {
                        self.mining_enabled = flag;
                        JsonRpcResponse::ok(req.id, json!({ "mining_enabled": flag }))
                    }
                    None => JsonRpcResponse::err(req.id, ERR_INVALID_PARAMS, "Expected boolean flag"),
                }
            }
            _ => JsonRpcResponse::err(req.id, ERR_METHOD_NOT_FOUND, "Method not found"),
        }
    }
}
