// File: src/rpc/rpc_server.rs
#![forbid(unsafe_code)]

use crate::config::{
    CHAIN_ID, COIN, DEFAULT_RPC_PORT, MAX_SUPPLY, MIN_RELAY_TX_FEE, SYMBOL, TOKEN_DECIMALS,
    TOKEN_NAME,
};
use crate::consensus::tokenomics::TokenomicsEngine;
use crate::crypto::hash::constant_time_eq;
use crate::dex::LiquidityPool;
use crate::mempool::fee_estimator::FeeEstimator;
use crate::mempool::pool::Mempool;
use crate::primitives::transaction::Transaction;
use crate::state::utxo_set::UtxoSet;
use crate::storage::flatfile::FlatFileStorage;
use crate::wallet::address::is_valid_address;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_RPC_BODY_BYTES: usize = 256 * 1024;
pub const MAX_RPC_REQUESTS_PER_MINUTE: u32 = 120;
pub const MAX_CONCURRENT_RPC_CONNECTIONS: usize = 64;
pub const MAX_TRACKED_RATE_LIMIT_IPS: usize = 4_096;
pub const RPC_SOCKET_TIMEOUT_SECS: u64 = 5;

struct ActiveConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorObj>,
    pub id: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonRpcErrorObj {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcErrorObj {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

pub struct RpcSharedState {
    pub utxo_set: UtxoSet,
    pub mempool: Mempool,
    pub fee_estimator: FeeEstimator,
    pub dex_pool: LiquidityPool,
    pub storage: Option<FlatFileStorage>,
    pub best_height: u64,
    pub finalized_height: u64,
    pub peer_count: usize,
    pub pending_p2p_relays: VecDeque<Transaction>,
    pub required_api_bearer_token: Option<String>,
    pub tx_height_index: HashMap<[u8; 32], u64>,
}

impl RpcSharedState {
    pub fn new(
        utxo_set: UtxoSet,
        mempool: Mempool,
        storage: Option<FlatFileStorage>,
        best_height: u64,
        finalized_height: u64,
        peer_count: usize,
    ) -> Self {
                let default_dex = if let Ok(saved_pool) = LiquidityPool::load_from_file("dex_state.dat") {
            saved_pool
        } else {
            let mut pool = LiquidityPool::new(SYMBOL.to_string(), "USDT".to_string());
            let _ = pool.add_initial_liquidity(
                "GENESIS_PROTOCOL_RESERVE",
                100_000 * (COIN as u128),
                500_000 * (COIN as u128),
            );
            pool
        };

        let mut initial_tx_index = HashMap::new();
        if let Some(ref disk) = storage {
            for h in 0..=best_height {
                if let Ok(blk) = disk.read_block_by_height(h) {
                    for tx in &blk.transactions {
                        initial_tx_index.insert(tx.txid(), h);
                    }
                }
            }
        }

        Self {
            utxo_set,
            mempool,
            fee_estimator: FeeEstimator::new(),
            dex_pool: default_dex,
            storage,
            best_height,
            finalized_height,
            peer_count,
            pending_p2p_relays: VecDeque::new(),
            required_api_bearer_token: None,
            tx_height_index: initial_tx_index,
        }
    }
}

#[derive(Default)]
struct IpRateLimiter {
    window_start_sec: u64,
    counts: HashMap<String, u32>,
}

impl IpRateLimiter {
    fn check_and_increment(&mut self, ip: &str, now_sec: u64) -> bool {
        if now_sec.saturating_sub(self.window_start_sec) >= 60 {
            self.window_start_sec = now_sec;
            self.counts.clear();
        }
        if self.counts.len() >= MAX_TRACKED_RATE_LIMIT_IPS && !self.counts.contains_key(ip) {
            return false;
        }
        let counter = self.counts.entry(ip.to_string()).or_insert(0);
        if *counter >= MAX_RPC_REQUESTS_PER_MINUTE {
            return false;
        }
        *counter += 1;
        true
    }
}

pub struct RpcServer;

impl RpcServer {
    pub fn start_background(
        bind_addr: Option<&str>,
        shared_state: Arc<Mutex<RpcSharedState>>,
    ) -> Result<String, String> {
        let addr_str = bind_addr
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("127.0.0.1:{}", DEFAULT_RPC_PORT));

        let listener = TcpListener::bind(&addr_str)
            .map_err(|e| format!("Failed to bind RPC port ({}): {}", addr_str, e))?;

        let bound_addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| addr_str.clone());

        let rate_limiter = Arc::new(Mutex::new(IpRateLimiter::default()));
        let active_conns = Arc::new(AtomicUsize::new(0));

        thread::spawn(move || {
            for stream_res in listener.incoming() {
                if let Ok(mut stream) = stream_res {
                    let current_active = active_conns.fetch_add(1, Ordering::SeqCst);
                    if current_active >= MAX_CONCURRENT_RPC_CONNECTIONS {
                        active_conns.fetch_sub(1, Ordering::SeqCst);
                        let busy = JsonRpcResponse::error(
                            Value::Null,
                            -32005,
                            "Server busy: max concurrent RPC connections reached",
                        );
                        let _ = Self::write_http_json(&mut stream, 503, &busy);
                        continue;
                    }

                    let guard = ActiveConnectionGuard {
                        counter: Arc::clone(&active_conns),
                    };
                    let state_clone = Arc::clone(&shared_state);
                    let limiter_clone = Arc::clone(&rate_limiter);

                    thread::spawn(move || {
                        let _active_guard = guard;
                        let _ = Self::handle_http_connection(stream, state_clone, limiter_clone);
                    });
                }
            }
        });

        Ok(bound_addr)
    }

    fn current_unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_729_468_800)
    }

    fn handle_http_connection(
        mut stream: TcpStream,
        shared_state: Arc<Mutex<RpcSharedState>>,
        rate_limiter: Arc<Mutex<IpRateLimiter>>,
    ) -> Result<(), String> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(RPC_SOCKET_TIMEOUT_SECS)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(RPC_SOCKET_TIMEOUT_SECS)));

        let peer_ip = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let now = Self::current_unix_timestamp();
        {
            let mut limiter = rate_limiter
                .lock()
                .map_err(|_| "Rate limiter lock poisoned".to_string())?;
            if !limiter.check_and_increment(&peer_ip, now) {
                let err_resp =
                    JsonRpcResponse::error(Value::Null, -32005, "Rate limit exceeded (120 req/min)");
                return Self::write_http_json(&mut stream, 429, &err_resp);
            }
        }

        let mut buf = Vec::with_capacity(8192);
        let mut temp = [0u8; 8192];
        let mut expected_total_len: Option<usize> = None;

        loop {
            let to_read = match expected_total_len {
                Some(target_len) => {
                    let remaining = target_len.saturating_sub(buf.len());
                    if remaining == 0 {
                        break;
                    }
                    remaining.min(temp.len())
                }
                None => temp.len(),
            };

            match stream.read(&mut temp[..to_read]) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&temp[..n]);
                    if buf.len() > MAX_RPC_BODY_BYTES {
                        let err_resp =
                            JsonRpcResponse::error(Value::Null, -32600, "Payload Too Large");
                        return Self::write_http_json(&mut stream, 413, &err_resp);
                    }
                    if expected_total_len.is_none() {
                        let pos_opt = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| (p, 4))
                            .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2)));
                        if let Some((hdr_end, sep_len)) = pos_opt {
                            let hdr_str = String::from_utf8_lossy(&buf[..hdr_end]);
                            let mut content_len = 0usize;
                            for line in hdr_str.lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("Content-Length") {
                                        content_len = v.trim().parse::<usize>().unwrap_or(0);
                                        break;
                                    }
                                }
                            }
                            expected_total_len = Some(hdr_end + sep_len + content_len);
                        }
                    }
                    if let Some(target_len) = expected_total_len {
                        if buf.len() >= target_len {
                            buf.truncate(target_len);
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) => return Err(format!("Socket read error: {}", e)),
            }
        }

        if buf.is_empty() {
            return Ok(());
        }
        let raw_req = String::from_utf8_lossy(&buf);

        let trimmed_req = raw_req.trim_start();

        if trimmed_req.starts_with("OPTIONS ") || trimmed_req.starts_with("OPTIONS\r") || trimmed_req.starts_with("OPTIONS\n") || trimmed_req == "OPTIONS" {
            let cors_headers = "HTTP/1.1 204 No Content\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";
            let _ = stream.write_all(cors_headers.as_bytes());
            let _ = stream.flush();
            return Ok(());
        }

        if trimmed_req.starts_with("GET ") {
            let path = trimmed_req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");
            if let Some((body, content_type)) = Self::handle_rest_get_query(path, &shared_state) {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
Content-Type: {}\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\r\n{}",
                    content_type,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
                return Ok(());
            }
        }

        if let Ok(state_guard) = shared_state.lock() {
            if let Some(expected_token) = &state_guard.required_api_bearer_token {
                let expected_header = format!("Bearer {}", expected_token);
                let authorized = raw_req.lines().any(|line| {
                    if let Some((k, v)) = line.split_once(':') {
                        k.trim().eq_ignore_ascii_case("Authorization")
                            && constant_time_eq(v.trim().as_bytes(), expected_header.as_bytes())
                    } else {
                        false
                    }
                });
                if !authorized {
                    drop(state_guard);
                    let unauth = JsonRpcResponse::error(
                        Value::Null,
                        -32001,
                        "Unauthorized: valid Authorization Bearer token required",
                    );
                    return Self::write_http_json(&mut stream, 401, &unauth);
                }
            }
        }

        let body_str = raw_req
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.trim())
            .or_else(|| raw_req.split_once("\n\n").map(|(_, b)| b.trim()))
            .unwrap_or_else(|| raw_req.trim());

        let response = Self::process_json_rpc_payload(body_str, &shared_state);
        Self::write_http_json(&mut stream, 200, &response)
    }

    fn handle_rest_get_query(
        path: &str,
        shared_state: &Arc<Mutex<RpcSharedState>>,
    ) -> Option<(String, &'static str)> {
        let state = shared_state.lock().ok()?;
        let rep = TokenomicsEngine::get_supply_report_at_height(state.best_height);

        match path {
            "/" | "/health" => Some((
                json!({
                    "status": "ok",
                    "chain_id": CHAIN_ID,
                    "height": state.best_height
                })
                .to_string(),
                "application/json; charset=utf-8",
            )),
            "/api/v1/supply" | "/api/v1/circulating_supply" => Some((
                Self::format_atomic_to_eqx(rep.circulating_supply),
                "text/plain; charset=utf-8",
            )),
            "/api/v1/total_supply" | "/api/v1/max_supply" => Some((
                Self::format_atomic_to_eqx(MAX_SUPPLY),
                "text/plain; charset=utf-8",
            )),
            "/api/v1/tickers" => {
                let eqx_res = (state.dex_pool.reserve_a as f64) / (COIN as f64);
                let usdt_res = (state.dex_pool.reserve_b as f64) / (COIN as f64);
                let price = if eqx_res > 0.0 { usdt_res / eqx_res } else { 0.0 };
                let tickers = json!([{
                    "ticker_id": "EQX_USDT",
                    "base_currency": SYMBOL,
                    "target_currency": "USDT",
                    "last_price": format!("{:.6}", price),
                    "liquidity_in_usd": format!("{:.2}", usdt_res * 2.0)
                }])
                .to_string();
                Some((tickers, "application/json; charset=utf-8"))
            }
            _ => None,
        }
    }

    fn write_http_json(
        stream: &mut TcpStream,
        status_code: u16,
        rpc_resp: &JsonRpcResponse,
    ) -> Result<(), String> {
        let body = serde_json::to_string(rpc_resp).unwrap_or_else(|_| "{}".to_string());
        let status_text = match status_code {
            200 => "200 OK",
            401 => "401 Unauthorized",
            413 => "413 Payload Too Large",
            429 => "429 Too Many Requests",
            503 => "503 Service Unavailable",
            _ => "400 Bad Request",
        };

        let http_response = format!(
            "HTTP/1.1 {}\r\n\
Content-Type: application/json; charset=utf-8\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\r\n{}",
            status_text,
            body.len(),
            body
        );

        stream
            .write_all(http_response.as_bytes())
            .map_err(|e| format!("HTTP write error: {}", e))?;
        let _ = stream.flush();
        Ok(())
    }

    pub fn process_json_rpc_payload(
        json_body: &str,
        shared_state: &Arc<Mutex<RpcSharedState>>,
    ) -> JsonRpcResponse {
        if json_body.len() > MAX_RPC_BODY_BYTES {
            return JsonRpcResponse::error(Value::Null, -32600, "Request body exceeds 256KB limit");
        }

        let req: JsonRpcRequest = match serde_json::from_str(json_body) {
            Ok(r) => r,
            Err(_) => {
                return JsonRpcResponse::error(Value::Null, -32700, "Parse error: invalid JSON");
            }
        };

        let req_id = req.id.clone().unwrap_or(Value::Number(1.into()));

        if req.jsonrpc.as_deref() != Some("2.0") {
            return JsonRpcResponse::error(req_id, -32600, "Invalid Request: jsonrpc must be '2.0'");
        }

        let Ok(mut state) = shared_state.lock() else {
            return JsonRpcResponse::error(req_id, -32603, "Internal node state lock error");
        };

        let normalized_method = match req.method.as_str() {
            "getblockcount" => "eqx_blockNumber",
            "getbalance" => "eqx_getBalance",
            "listunspent" => "eqx_getAddressUtxos",
            "gettransaction" => "eqx_getTransactionByHash",
            "sendrawtransaction" => "eqx_sendRawTransaction",
            "validateaddress" => "eqx_validateAddress",
            other => other,
        };

        let token_params = serde_json::to_value(&req.params).unwrap_or(serde_json::Value::Null);
    if let Some(token_res) = crate::token_rpc::handle_token_rpc(normalized_method, &token_params) {
        return JsonRpcResponse::success(req_id, token_res);
    }
    if let Some(evm_res) = crate::evm_rpc::handle_evm_rpc(normalized_method, &token_params) {
        return JsonRpcResponse::success(req_id, evm_res);
    }

    match normalized_method {
            "eth_chainId" => {
                JsonRpcResponse::success(req_id, json!(format!("0x{:x}", CHAIN_ID)))
            }

            "net_version" => JsonRpcResponse::success(req_id, json!(CHAIN_ID.to_string())),

            "eth_blockNumber" | "eqx_blockNumber" => {
                JsonRpcResponse::success(req_id, json!(format!("0x{:x}", state.best_height)))
            }

            "eth_gasPrice" | "eqx_minFee" => {
                let est = state.fee_estimator.estimate_fees(state.mempool.len());
                JsonRpcResponse::success(req_id, json!(format!("0x{:x}", est.standard_fee_atomic)))
            }

                        "eqx_swiftPreValidate" => {
                let sender = req.params.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()).unwrap_or("");
                let recipient = req.params.as_array().and_then(|a| a.get(1)).and_then(|v| v.as_str()).unwrap_or("");
                let amount_atomic = req.params.as_array().and_then(|a| a.get(2)).and_then(|v| v.as_u64()).unwrap_or(0);
                let asset = req.params.as_array().and_then(|a| a.get(3)).and_then(|v| v.as_str()).unwrap_or(SYMBOL);

                let sender_valid = is_valid_address(sender.trim());
                let recipient_valid = is_valid_address(recipient.trim())
                    || (recipient.starts_with("0x") && recipient.len() == 42)
                    || (recipient.starts_with("bc1") && recipient.len() >= 42)
                    || (recipient.starts_with("T") && recipient.len() == 34)
                    || (recipient.len() >= 32 && recipient.len() <= 48);

                let est_fee = state.fee_estimator.estimate_fees(state.mempool.len()).standard_fee_atomic;
                let state_root = hex::encode(state.utxo_set.compute_state_root());
                let now_ts = Self::current_unix_timestamp();

                // Deterministic UETR (ISO-20022 Unique End-to-End Transaction Reference)
                let uetr_seed = format!("{}:{}:{}:{}:{}", sender, recipient, amount_atomic, now_ts, state_root);
                let h = crate::crypto::hash::sha256d(uetr_seed.as_bytes());
                let uetr = format!(
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-8{:01x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    h[0], h[1], h[2], h[3], h[4], h[5], h[6] & 0x0f, h[7], h[8] & 0x0f, h[9], h[10], h[11], h[12], h[13], h[14], h[15]
                );

                JsonRpcResponse::success(
                    req_id,
                    json!({
                        "protocol": "EQUINOX_SWIFT_ISO20022_NON_CUSTODIAL",
                        "uetr": uetr,
                        "bic_routing_code": "EQXINB2LXXX",
                        "chain_id": CHAIN_ID,
                        "asset": asset,
                        "sender_valid": sender_valid,
                        "recipient_valid": recipient_valid,
                        "amount_atomic": amount_atomic,
                        "amount_formatted": Self::format_atomic_to_eqx(amount_atomic),
                        "network_fee_atomic": est_fee,
                        "state_merkle_root": state_root,
                        "pre_validation_status": if recipient_valid && amount_atomic > 0 { "READY_FOR_CLIENT_SIGNATURE" } else { "REJECTED_INVALID_PARAMETERS" }
                    }),
                )
            }

            "eqx_validateAddress" => {
                let addr_str =
                    Self::extract_first_string_param(&req.params).unwrap_or_default();
                let valid = is_valid_address(addr_str.trim());
                JsonRpcResponse::success(
                    req_id,
                    json!({
                        "isvalid": valid,
                        "address": addr_str.trim(),
                        "chain_id": CHAIN_ID
                    }),
                )
            }

            "eqx_getFeeEstimate" => {
                let est = state.fee_estimator.estimate_fees(state.mempool.len());
                JsonRpcResponse::success(
                    req_id,
                    json!({
                        "fast_fee_atomic": est.fast_fee_atomic,
                        "standard_fee_atomic": est.standard_fee_atomic,
                        "economy_fee_atomic": est.economy_fee_atomic,
                        "mempool_load_percent": est.mempool_load_percent,
                        "min_relay_fee_atomic": MIN_RELAY_TX_FEE
                    }),
                )
            }

            "eqx_getBalance" | "eth_getBalance" => {
                let Some(addr_str) = Self::extract_first_string_param(&req.params) else {
                    return JsonRpcResponse::error(req_id, -32602, "Missing wallet address param");
                };
                let trimmed = addr_str.trim();
                if !is_valid_address(trimmed) {
                    return JsonRpcResponse::error(
                        req_id,
                        -32602,
                        format!("Invalid Equinox address: {}", trimmed),
                    );
                }

                let (spendable, locked, note_count) = state
                    .utxo_set
                    .get_balance_with_count(trimmed, state.best_height);
                let total_atomic = spendable.saturating_add(locked);

                if normalized_method == "eth_getBalance" {
                    JsonRpcResponse::success(req_id, json!(format!("0x{:x}", spendable)))
                } else {
                    JsonRpcResponse::success(
                        req_id,
                        json!({
                            "address": trimmed,
                            "spendable_atomic": spendable,
                            "locked_atomic": locked,
                            "total_atomic": total_atomic,
                            "spendable_eqx": Self::format_atomic_to_eqx(spendable),
                            "locked_eqx": Self::format_atomic_to_eqx(locked),
                            "utxo_count": note_count,
                            "block_height": state.best_height
                        }),
                    )
                }
            }

            "eqx_getAddressUtxos" => {
                let Some(addr_str) = Self::extract_first_string_param(&req.params) else {
                    return JsonRpcResponse::error(req_id, -32602, "Missing wallet address param");
                };
                let trimmed = addr_str.trim();
                if !is_valid_address(trimmed) {
                    return JsonRpcResponse::error(
                        req_id,
                        -32602,
                        format!("Invalid Equinox address: {}", trimmed),
                    );
                }

                let current_h = state.best_height;
                let mut notes = Vec::new();
                for (op, out) in &state.utxo_set.utxos {
                    if out.recipient_address == trimmed {
                        notes.push(json!({
                            "txid": hex::encode(op.txid),
                            "vout": op.vout,
                            "amount_atomic": out.amount,
                            "amount_eqx": Self::format_atomic_to_eqx(out.amount),
                            "unlock_height": out.unlock_height,
                            "spendable": out.is_spendable_at(current_h)
                        }));
                    }
                }

                JsonRpcResponse::success(
                    req_id,
                    json!({
                        "address": trimmed,
                        "block_height": current_h,
                        "utxos": notes
                    }),
                )
            }

            "eqx_getTransactionByHash" => {
                let Some(tx_hex) = Self::extract_first_string_param(&req.params) else {
                    return JsonRpcResponse::error(req_id, -32602, "Missing TxHash parameter");
                };
                let clean = tx_hex.trim().trim_start_matches("0x");
                let Ok(bytes) = hex::decode(clean) else {
                    return JsonRpcResponse::error(req_id, -32602, "Invalid hex TxHash");
                };
                if bytes.len() != 32 {
                    return JsonRpcResponse::error(req_id, -32602, "TxHash must be 32 bytes");
                }
                let mut target_txid = [0u8; 32];
                target_txid.copy_from_slice(&bytes);

                if let Some(mem_tx) = state.mempool.get_transaction(&target_txid) {
                    let out_sum = mem_tx.total_output_amount().unwrap_or(0);
                    return JsonRpcResponse::success(
                        req_id,
                        json!({
                            "txid": hex::encode(target_txid),
                            "status": "PENDING_MEMPOOL",
                            "confirmations": 0,
                            "block_height": Value::Null,
                            "fee_atomic": mem_tx.fee,
                            "total_output_atomic": out_sum,
                            "timestamp": mem_tx.timestamp
                        }),
                    );
                }

                if let Some(&indexed_h) = state.tx_height_index.get(&target_txid) {
                    if let Some(storage) = &state.storage {
                        if let Ok(blk) = storage.read_block_by_height(indexed_h) {
                            for tx in &blk.transactions {
                                if tx.txid() == target_txid {
                                    let confs = state.best_height.saturating_sub(indexed_h) + 1;
                                    let out_sum = tx.total_output_amount().unwrap_or(0);
                                    return JsonRpcResponse::success(
                                        req_id,
                                        json!({
                                            "txid": hex::encode(target_txid),
                                            "status": if indexed_h <= state.finalized_height { "FINALIZED" } else { "CONFIRMED" },
                                            "lookup_mode": "O1_HASH_INDEX",
                                            "confirmations": confs,
                                            "block_height": indexed_h,
                                            "block_hash": hex::encode(blk.hash()),
                                            "fee_atomic": tx.fee,
                                            "total_output_atomic": out_sum,
                                            "timestamp": tx.timestamp
                                        }),
                                    );
                                }
                            }
                        }
                    }
                }

                let mut found_payload: Option<Value> = None;
                let mut newly_indexed: Vec<([u8; 32], u64)> = Vec::new();
                if let Some(storage) = &state.storage {
                    for h in (0..=state.best_height).rev() {
                        if let Ok(blk) = storage.read_block_by_height(h) {
                            for tx in &blk.transactions {
                                let tid = tx.txid();
                                newly_indexed.push((tid, h));
                                if tid == target_txid && found_payload.is_none() {
                                    let confs = state.best_height.saturating_sub(h) + 1;
                                    let out_sum = tx.total_output_amount().unwrap_or(0);
                                    found_payload = Some(json!({
                                        "txid": hex::encode(target_txid),
                                        "status": if h <= state.finalized_height { "FINALIZED" } else { "CONFIRMED" },
                                        "lookup_mode": "INDEXED_ON_DEMAND",
                                        "confirmations": confs,
                                        "block_height": h,
                                        "block_hash": hex::encode(blk.hash()),
                                        "fee_atomic": tx.fee,
                                        "total_output_atomic": out_sum,
                                        "timestamp": tx.timestamp
                                    }));
                                }
                            }
                            if found_payload.is_some() {
                                break;
                            }
                        }
                    }
                }
                for (tid, height_val) in newly_indexed {
                    state.tx_height_index.insert(tid, height_val);
                }
                if let Some(payload) = found_payload {
                    return JsonRpcResponse::success(req_id, payload);
                }

                JsonRpcResponse::error(req_id, -32004, "Transaction not found")
            }

            "eqx_getSupplyInfo" | "eqx_getSupplyReport" => {
                let target_height =
                    Self::extract_first_u64_param(&req.params).unwrap_or(state.best_height);
                let report = TokenomicsEngine::get_supply_report_at_height(target_height);
                let live_utxo_supply = state.utxo_set.verify_supply_invariant().unwrap_or(0);

                JsonRpcResponse::success(
                    req_id,
                    json!({
                        "token_name": TOKEN_NAME,
                        "symbol": SYMBOL,
                        "decimals": TOKEN_DECIMALS,
                        "block_height": report.block_height,
                        "total_minted_atomic": report.total_minted_supply,
                        "circulating_atomic": report.circulating_supply,
                        "locked_owner_atomic": report.locked_owner_supply,
                        "unlocked_owner_atomic": report.unlocked_owner_supply,
                        "current_block_reward_atomic": report.current_block_reward,
                        "remaining_mineable_atomic": report.remaining_mineable_supply,
                        "live_utxo_ledger_supply_atomic": live_utxo_supply,
                        "state_merkle_root": hex::encode(state.utxo_set.compute_state_root())
                    }),
                )
            }

            "eqx_getDexPoolInfo" | "eqx_getLiquidityRouterDepth" => {
                let eqx_res = state.dex_pool.reserve_a;
                let usdt_res = state.dex_pool.reserve_b;
                let spot_price_fp8 = if eqx_res > 0 {
                    (usdt_res.saturating_mul(COIN as u128)) / eqx_res
                } else {
                    0
                };
                JsonRpcResponse::success(
                    req_id,
                    json!({
                        "router_mode": "NON_CUSTODIAL_AMM_V2",
                        "chain_id": CHAIN_ID,
                        "token_a": state.dex_pool.token_a,
                        "token_b": state.dex_pool.token_b,
                        "reserve_a_atomic": eqx_res.to_string(),
                        "reserve_b_atomic": usdt_res.to_string(),
                        "reserve_a_formatted": Self::format_atomic_to_eqx(eqx_res as u64),
                        "reserve_b_formatted": Self::format_atomic_to_eqx(usdt_res as u64),
                        "spot_price_usdt": Self::format_atomic_to_eqx(spot_price_fp8 as u64),
                        "total_lp_shares": state.dex_pool.total_lp_shares.to_string(),
                        "fee_bps": 30
                    }),
                )
            }

            "eqx_pushDexLiquidity" => {
                let Some(provider_addr) = Self::extract_first_string_param(&req.params) else {
                    return JsonRpcResponse::error(req_id, -32602, "Missing provider EQX address");
                };
                if !is_valid_address(provider_addr.trim()) {
                    return JsonRpcResponse::error(req_id, -32602, "Invalid Equinox provider address");
                }
                let amount_a = req
                    .params
                    .as_array()
                    .and_then(|a| a.get(1))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let amount_b = req
                    .params
                    .as_array()
                    .and_then(|a| a.get(2))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                match state.dex_pool.add_liquidity(
                    provider_addr.trim(),
                    amount_a as u128,
                    amount_b as u128,
                ) {
                    Ok(minted_lp) => {
                        let _ = state.dex_pool.save_to_file("dex_state.dat");
                        JsonRpcResponse::success(
                            req_id,
                            json!({
                                "status": "LIQUIDITY_COMMITTED_ON_CHAIN",
                                "provider": provider_addr.trim(),
                                "deposited_eqx_atomic": amount_a,
                                "deposited_usdt_atomic": amount_b,
                                "minted_lp_shares": minted_lp.to_string(),
                                "new_reserve_eqx_atomic": state.dex_pool.reserve_a.to_string(),
                                "new_reserve_usdt_atomic": state.dex_pool.reserve_b.to_string()
                            }),
                        )
                    }
                    Err(e) => JsonRpcResponse::error(req_id, -32016, e),
                }
            }

            "eqx_executeRouterSwap" => {
                let Some(token_in) = Self::extract_first_string_param(&req.params) else {
                    return JsonRpcResponse::error(req_id, -32602, "Missing input_token parameter");
                };
                let amount_in = req
                    .params
                    .as_array()
                    .and_then(|a| a.get(1))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let min_out = req
                    .params
                    .as_array()
                    .and_then(|a| a.get(2))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);

                match state
                    .dex_pool
                    .swap(token_in.trim(), amount_in as u128, min_out as u128)
                {
                    Ok(actual_out) => {
                        let _ = state.dex_pool.save_to_file("dex_state.dat");
                        JsonRpcResponse::success(
                            req_id,
                            json!({
                                "status": "SWAP_EXECUTED_ON_CHAIN",
                                "input_token": token_in.trim(),
                                "amount_in_atomic": amount_in,
                                "amount_out_atomic": actual_out as u64,
                                "amount_out_formatted": Self::format_atomic_to_eqx(actual_out as u64),
                                "new_reserve_eqx_atomic": state.dex_pool.reserve_a.to_string(),
                                "new_reserve_usdt_atomic": state.dex_pool.reserve_b.to_string()
                            }),
                        )
                    }
                    Err(e) => JsonRpcResponse::error(req_id, -32017, e),
                }
            }

            "eqx_getDexQuote" => {
                let token_in = Self::extract_first_string_param(&req.params)
                    .unwrap_or_else(|| SYMBOL.to_string());
                let amount_in = Self::extract_second_u64_param(&req.params).unwrap_or(COIN);

                match state.dex_pool.get_swap_quote(&token_in, amount_in as u128) {
                    Ok(out) => JsonRpcResponse::success(
                        req_id,
                        json!({
                            "input_token": token_in,
                            "input_amount_atomic": amount_in,
                            "estimated_output_atomic": out as u64,
                            "estimated_output_formatted": Self::format_atomic_to_eqx(out as u64)
                        }),
                    ),
                    Err(e) => JsonRpcResponse::error(req_id, -32015, e),
                }
            }

            "eqx_getBlockByHeight" => {
                let height =
                    Self::extract_first_u64_param(&req.params).unwrap_or(state.best_height);
                let Some(storage) = &state.storage else {
                    return JsonRpcResponse::error(req_id, -32001, "Block disk storage not attached");
                };

                match storage.read_block_by_height(height) {
                    Ok(block) => JsonRpcResponse::success(
                        req_id,
                        json!({
                            "height": block.header.height,
                            "hash": hex::encode(block.hash()),
                            "prev_block_hash": hex::encode(block.header.prev_block_hash),
                            "merkle_root": hex::encode(block.header.merkle_root),
                            "timestamp": block.header.timestamp,
                            "difficulty_target": block.header.difficulty_target,
                            "nonce": block.header.nonce,
                            "tx_count": block.transactions.len()
                        }),
                    ),
                    Err(e) => JsonRpcResponse::error(
                        req_id,
                        -32004,
                        format!("Block #{} not found: {}", height, e),
                    ),
                }
            }

            "eqx_sendRawTransaction" | "eth_sendRawTransaction" => {
                let Some(raw_hex) = Self::extract_first_string_param(&req.params) else {
                    return JsonRpcResponse::error(req_id, -32602, "Hex raw_tx string required");
                };
                let clean_hex = raw_hex.trim().trim_start_matches("0x");
                let Ok(tx_bytes) = hex::decode(clean_hex) else {
                    return JsonRpcResponse::error(req_id, -32602, "Invalid hex encoding");
                };
                let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) else {
                    return JsonRpcResponse::error(req_id, -32602, "Bincode Transaction decode failed");
                };

                let current_height = state.best_height;
                let utxo_snapshot = state.utxo_set.clone();

                match state
                    .mempool
                    .add_transaction_verified(tx.clone(), &utxo_snapshot, current_height)
                {
                    Ok(txid) => {
                        state.tx_height_index.insert(txid, current_height);
                        if state.pending_p2p_relays.len() < 512 {
                            state.pending_p2p_relays.push_back(tx);
                        }
                        JsonRpcResponse::success(req_id, json!(hex::encode(txid)))
                    }
                    Err(e) => {
                        JsonRpcResponse::error(req_id, -32010, format!("Transaction rejected: {}", e))
                    }
                }
            }

            "eqx_getNodeStatus" | "eqx_getChainInfo" | "getblockchaininfo" => {
                JsonRpcResponse::success(
                    req_id,
                    json!({
                        "chain_id": CHAIN_ID,
                        "token_name": TOKEN_NAME,
                        "symbol": SYMBOL,
                        "decimals": TOKEN_DECIMALS,
                        "max_supply_atomic": MAX_SUPPLY,
                        "best_height": state.best_height,
                        "finalized_height": state.finalized_height,
                        "mempool_tx_count": state.mempool.len(),
                        "utxo_count": state.utxo_set.len(),
                        "active_peers": state.peer_count,
                        "state_root": hex::encode(state.utxo_set.compute_state_root())
                    }),
                )
            }

            other => {
                JsonRpcResponse::error(req_id, -32601, format!("Method not found: '{}'", other))
            }
        }
    }

    fn extract_first_string_param(params: &Value) -> Option<String> {
        match params {
            Value::Array(arr) => arr.first()?.as_str().map(|s| s.to_string()),
            Value::String(s) => Some(s.clone()),
            Value::Object(map) => map
                .get("address")
                .or_else(|| map.get("raw_tx"))
                .or_else(|| map.get("txid"))
                .or_else(|| map.get("token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            _ => None,
        }
    }

    fn extract_first_u64_param(params: &Value) -> Option<u64> {
        match params {
            Value::Array(arr) => arr.first()?.as_u64(),
            Value::Number(n) => n.as_u64(),
            Value::Object(map) => map.get("height").and_then(|v| v.as_u64()),
            _ => None,
        }
    }

    fn extract_second_u64_param(params: &Value) -> Option<u64> {
        match params {
            Value::Array(arr) => arr.get(1)?.as_u64(),
            Value::Object(map) => map.get("amount").and_then(|v| v.as_u64()),
            _ => None,
        }
    }

    pub fn format_atomic_to_eqx(atomic: u64) -> String {
        let whole = atomic / COIN;
        let frac = atomic % COIN;
        format!("{}.{:08}", whole, frac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_cex_aliases_rate_limiter_and_supply_endpoints() {
        let shared = Arc::new(Mutex::new(RpcSharedState::new(
            UtxoSet::new(),
            Mempool::new(),
            None,
            100,
            90,
            8,
        )));

        let req_blk = r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
        let resp_blk = RpcServer::process_json_rpc_payload(req_blk, &shared);
        assert_eq!(resp_blk.result, Some(json!("0x64")));

        let (supply_txt, _) =
            RpcServer::handle_rest_get_query("/api/v1/total_supply", &shared).unwrap();
        assert_eq!(supply_txt, "21000000.00000000");

        let mut limiter = IpRateLimiter::default();
        for _ in 0..MAX_RPC_REQUESTS_PER_MINUTE {
            assert!(limiter.check_and_increment("203.0.113.5", 1_000));
        }
        assert!(!limiter.check_and_increment("203.0.113.5", 1_000));
    }
}

