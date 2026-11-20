#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use equinox_consensus::MAX_SUPPLY_ATOMIC;
use equinox_crypto::address::decode_and_verify_address;
use equinox_network::protocol::WireMessage;
use serde_json::{json, Value};

use crate::genesis::{from_hex, to_hex};
use crate::runtime::{NodeState, PeerBroadcaster, SharedNode};
use crate::tx::SignedTransaction;

const MAX_HTTP_BYTES: usize = 262_144;

fn send_http_response(stream: &mut TcpStream, status: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn dispatch_rpc(body: &[u8], node: &SharedNode, broadcaster: &Arc<PeerBroadcaster>) -> Value {
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return json!({
                "jsonrpc": "2.0",
                "error": { "code": -32700, "message": "Malformed JSON payload" },
                "id": null
            });
        }
    };

    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!([]));

    let mut broadcast_tx: Option<Vec<u8>> = None;

    let reply = {
        let mut st = node.lock().unwrap();
        match method {
            "eqx_getChainInfo" => {
                let query_addr = params
                    .get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or(&st.miner_address);
                let bal = st.balances.get(query_addr).copied().unwrap_or(0);
                json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "network": st.mode.name(),
                        "chain_id": st.mode.chain_id(),
                        "height": st.storage.tip_height(),
                        "tip_hash": to_hex(&st.storage.tip_hash()),
                        "state_root": to_hex(&st.storage.compute_state_root()),
                        "peers": st.slots.total_connected(),
                        "pending_txns": st.mempool.len(),
                        "miner_address": st.miner_address,
                        "dao_address": st.dao_address,
                        "balance": bal as u64,
                        "balance_eqx": NodeState::format_eqx(bal)
                    },
                    "id": id
                })
            }
            "eqx_getMetrics" => json!({
                "jsonrpc": "2.0",
                "result": {
                    "network": st.mode.name(),
                    "chain_id": st.mode.chain_id(),
                    "tip_height": st.storage.tip_height(),
                    "finalized_height": st.bft.finalized_height,
                    "tip_hash": to_hex(&st.storage.tip_hash()),
                    "total_txns": st.total_txns,
                    "pending_txns": st.mempool.len(),
                    "utxo_count": st.storage.utxo_count(),
                    "total_addresses": st.balances.len(),
                    "circulating_supply_atomic": st.circulating_supply_atomic().to_string(),
                    "max_supply_atomic": MAX_SUPPLY_ATOMIC.to_string(),
                    "connected_peers": st.slots.total_connected()
                },
                "id": id
            }),
            "eqx_getMempoolInfo" => json!({
                "jsonrpc": "2.0",
                "result": {
                    "pending_txns": st.mempool.len(),
                    "min_fee_atomic": st.mempool.min_fee_atomic().to_string()
                },
                "id": id
            }),
            "eqx_getBalance" => {
                let addr = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
                if !addr.starts_with('E') || addr.len() != 34 {
                    json!({
                        "jsonrpc": "2.0",
                        "error": { "code": -32602, "message": "Invalid 34-char EQX address" },
                        "id": id
                    })
                } else {
                    let bal = st.balances.get(addr).copied().unwrap_or(0);
                    json!({
                        "jsonrpc": "2.0",
                        "result": {
                            "address": addr,
                            "balance_atomic": bal.to_string(),
                            "balance_eqx": NodeState::format_eqx(bal)
                        },
                        "id": id
                    })
                }
            }
            "eqx_getUtxos" => {
                let addr = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
                match decode_and_verify_address(addr) {
                    Ok(h160) => {
                        let list: Vec<Value> = st
                            .utxos_for_hash160(&h160)
                            .into_iter()
                            .map(|(op, val)| {
                                json!({
                                    "txid": to_hex(&op.txid),
                                    "vout": op.vout,
                                    "value_atomic": val.to_string()
                                })
                            })
                            .collect();
                        json!({ "jsonrpc": "2.0", "result": list, "id": id })
                    }
                    Err(_) => json!({
                        "jsonrpc": "2.0",
                        "error": { "code": -32602, "message": "Invalid Base58Check EQX address" },
                        "id": id
                    }),
                }
            }
            "eqx_sendRawTransaction" => {
                let raw_hex = match params.get(0).and_then(|v| v.as_str()) {
                    Some(h) => h,
                    None => {
                        return json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32602, "message": "Expected raw transaction hex string as params[0]" },
                            "id": id
                        });
                    }
                };
                let raw_bytes = match from_hex(raw_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32602, "message": e },
                            "id": id
                        });
                    }
                };
                let tx = match SignedTransaction::decode_bytes(&raw_bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        return json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32602, "message": e },
                            "id": id
                        });
                    }
                };
                match st.submit_transaction(tx) {
                    Ok((txid, fee)) => {
                        broadcast_tx = Some(raw_bytes);
                        json!({
                            "jsonrpc": "2.0",
                            "result": {
                                "txid": to_hex(&txid),
                                "fee_atomic": fee.to_string(),
                                "status": "accepted_in_mempool"
                            },
                            "id": id
                        })
                    }
                    Err(reason) => json!({
                        "jsonrpc": "2.0",
                        "error": { "code": -32010, "message": reason },
                        "id": id
                    }),
                }
            }
            "eqx_getRecentBlocks" => {
                let blocks: Vec<Value> = st
                    .recent_blocks
                    .iter()
                    .rev()
                    .take(15)
                    .map(|b| {
                        json!({
                            "height": b.height,
                            "hash": b.hash_hex,
                            "nonce": b.nonce,
                            "timestamp": b.timestamp,
                            "miner_reward_eqx": NodeState::format_eqx(b.miner_reward_atomic),
                            "dao_reward_eqx": NodeState::format_eqx(b.dao_reward_atomic),
                            "tx_count": b.tx_count
                        })
                    })
                    .collect();
                json!({ "jsonrpc": "2.0", "result": blocks, "id": id })
            }
            _ => json!({
                "jsonrpc": "2.0",
                "error": { "code": -32601, "message": format!("Method not found: {}", method) },
                "id": id
            }),
        }
    };

    if let Some(raw_tx) = broadcast_tx {
        broadcaster.broadcast(WireMessage::TxData(raw_tx), None);
    }

    reply
}

fn handle_http_client(
    mut stream: TcpStream,
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut header_end: Option<usize> = None;
    let mut content_length: usize = 0;

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_HTTP_BYTES {
                    send_http_response(
                        &mut stream,
                        "413 Payload Too Large",
                        r#"{"jsonrpc":"2.0","error":{"code":-32003,"message":"Payload too large"},"id":null}"#,
                    );
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if header_end.is_none() {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let headers_str = String::from_utf8_lossy(&buf[..pos]);
                        for line in headers_str.lines() {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.eq_ignore_ascii_case("Content-Length") {
                                    content_length = v.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                if let Some(h_end) = header_end {
                    if buf.len() >= h_end + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    let Some(h_end) = header_end else {
        return;
    };
    let head = String::from_utf8_lossy(&buf[..h_end]);
    if head.starts_with("OPTIONS ") {
        send_http_response(&mut stream, "204 No Content", "");
        return;
    }

    if head.starts_with("GET ") {
        let info = dispatch_rpc(
            br#"{"jsonrpc":"2.0","method":"eqx_getMetrics","params":[],"id":0}"#,
            &node,
            &broadcaster,
        );
        send_http_response(&mut stream, "200 OK", &info.to_string());
        return;
    }

    let body = &buf[h_end..buf.len().min(h_end + content_length)];
    let reply = dispatch_rpc(body, &node, &broadcaster);
    send_http_response(&mut stream, "200 OK", &reply.to_string());
}

pub fn spawn_rpc_server(
    bind_addr: &str,
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
    shutdown: Arc<AtomicBool>,
) -> Result<SocketAddr, String> {
    let listener =
        TcpListener::bind(bind_addr).map_err(|e| format!("RPC bind {} failed: {}", bind_addr, e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("RPC nonblocking error: {}", e))?;
    let local_addr = listener.local_addr().map_err(|e| e.to_string())?;

    thread::spawn(move || {
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let n = Arc::clone(&node);
                    let b = Arc::clone(&broadcaster);
                    thread::spawn(move || handle_http_client(stream, n, b));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(30));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });

    Ok(local_addr)
}
