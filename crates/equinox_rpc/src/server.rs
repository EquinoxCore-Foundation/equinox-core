#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::errors::{
    RpcErrorObject, ERR_INVALID_PARAMS, ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, ERR_PARSE,
    ERR_PAYLOAD_TOO_LARGE, ERR_RATE_LIMITED, ERR_UNAUTHORIZED,
};
use crate::metrics::ChainMetrics;
use crate::ratelimit::RpcSecurityGuard;
use crate::ws::{SubscriptionHub, SubscriptionTopic};

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub id: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
    pub id: Value,
}

impl JsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn err(id: Value, code: i32, msg: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcErrorObject::new(code, msg)),
            id,
        }
    }
}

pub struct EquinoxRpcServer {
    pub metrics: ChainMetrics,
    pub balances: HashMap<String, u128>,
    pub guard: RpcSecurityGuard,
    pub ws_hub: SubscriptionHub,
}

impl EquinoxRpcServer {
    pub fn new(admin_token: Option<String>) -> Self {
        Self {
            metrics: ChainMetrics::default(),
            balances: HashMap::new(),
            guard: RpcSecurityGuard::new(60, 20, admin_token),
            ws_hub: SubscriptionHub::new(1_024, 64),
        }
    }

    pub fn handle_raw_request(
        &mut self,
        client_ip: IpAddr,
        now_ms: u64,
        auth_bearer: Option<&str>,
        raw_body: &[u8],
    ) -> JsonRpcResponse {
        if !self.guard.check_body_size(raw_body.len()) {
            return JsonRpcResponse::err(Value::Null, ERR_PAYLOAD_TOO_LARGE, "Request body exceeds 256 KiB limit");
        }
        if !self.guard.check_rate_limit(client_ip, now_ms) {
            return JsonRpcResponse::err(Value::Null, ERR_RATE_LIMITED, "RPC rate limit exceeded");
        }

        let req: JsonRpcRequest = match serde_json::from_slice(raw_body) {
            Ok(r) => r,
            Err(_) => return JsonRpcResponse::err(Value::Null, ERR_PARSE, "Malformed JSON payload"),
        };

        if req.jsonrpc != "2.0" {
            return JsonRpcResponse::err(req.id, ERR_INVALID_REQUEST, "jsonrpc must be '2.0'");
        }

        match req.method.as_str() {
            "eqx_getChainInfo" => JsonRpcResponse::ok(
                req.id,
                json!({
                    "chain_id": self.metrics.chain_id,
                    "height": self.metrics.tip_height,
                    "tip_hash": self.metrics.tip_hash_hex,
                    "peers": self.metrics.connected_peers
                }),
            ),
            "eqx_getMetrics" => match serde_json::to_value(&self.metrics) {
                Ok(v) => JsonRpcResponse::ok(req.id, v),
                Err(_) => JsonRpcResponse::err(req.id, ERR_INVALID_REQUEST, "Metrics serialization failed"),
            },
            "eqx_getBalance" => {
                let addr = req.params.get(0).and_then(|v| v.as_str());
                match addr {
                    Some(a) if a.starts_with('E') && a.len() == 34 => {
                        let bal = self.balances.get(a).copied().unwrap_or(0);
                        JsonRpcResponse::ok(req.id, json!({ "address": a, "balance_atomic": bal.to_string() }))
                    }
                    _ => JsonRpcResponse::err(req.id, ERR_INVALID_PARAMS, "Expected valid 34-char EQX address"),
                }
            }
            "eqx_subscribe" => {
                let topic_str = req.params.get(0).and_then(|v| v.as_str());
                let topic = match topic_str {
                    Some("newHeads") => SubscriptionTopic::NewHeads,
                    Some("pendingTransactions") => SubscriptionTopic::PendingTransactions,
                    Some("addressActivity") => {
                        match req.params.get(1).and_then(|v| v.as_str()) {
                            Some(a) if a.starts_with('E') => SubscriptionTopic::AddressActivity(a.to_string()),
                            _ => return JsonRpcResponse::err(req.id, ERR_INVALID_PARAMS, "Missing valid address for addressActivity"),
                        }
                    }
                    _ => return JsonRpcResponse::err(req.id, ERR_INVALID_PARAMS, "Unknown subscription topic"),
                };
                match self.ws_hub.subscribe(topic) {
                    Some(sub_id) => JsonRpcResponse::ok(req.id, json!({ "subscription_id": sub_id })),
                    None => JsonRpcResponse::err(req.id, ERR_RATE_LIMITED, "Max WebSocket subscribers reached"),
                }
            }
            "eqx_adminStatus" => {
                if !self.guard.verify_admin_token(auth_bearer) {
                    return JsonRpcResponse::err(req.id, ERR_UNAUTHORIZED, "Invalid or missing admin bearer token");
                }
                JsonRpcResponse::ok(req.id, json!({ "status": "authorized", "chain_id": self.metrics.chain_id }))
            }
            _ => JsonRpcResponse::err(req.id, ERR_METHOD_NOT_FOUND, "Unknown RPC method"),
        }
    }
}
