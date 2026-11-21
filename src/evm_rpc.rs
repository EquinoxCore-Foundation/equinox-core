use std::sync::{Mutex, OnceLock};
use revm::primitives::{Address, U256};
use serde_json::{json, Value};
use crate::evm_engine::EquinoxEvmEngine;

static GLOBAL_EVM: OnceLock<Mutex<EquinoxEvmEngine>> = OnceLock::new();

fn evm_engine() -> &'static Mutex<EquinoxEvmEngine> {
    GLOBAL_EVM.get_or_init(|| Mutex::new(EquinoxEvmEngine::new(7777)))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.trim().strip_prefix("0x").or_else(|| s.trim().strip_prefix("0X")).unwrap_or(s.trim());
    if clean.is_empty() {
        return Ok(Vec::new());
    }
    if clean.len() % 2 != 0 {
        return Err("Odd-length hex string".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| "Invalid hex character".to_string()))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn parse_address(s: &str) -> Result<Address, String> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 20 {
        return Err("Address must be 20 bytes".to_string());
    }
    Ok(Address::from_slice(&bytes))
}

/// Handles eqx_evmFund, eqx_evmDeploy, and standard Ethereum eth_call.
pub fn handle_evm_rpc(method: &str, params: &Value) -> Option<Value> {
    match method {
        "eqx_evmFund" => {
            let addr_str = params.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let amount_wei = params
                .get("amount_wei")
                .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok()).or_else(|| v.as_u64().map(|n| n as u128)))
                .unwrap_or(10_000_000_000_000_000_000);

            let addr = match parse_address(addr_str) {
                Ok(a) => a,
                Err(e) => return Some(json!({"ok": false, "error": e})),
            };
            let mut eng = match evm_engine().lock() {
                Ok(g) => g,
                Err(_) => return Some(json!({"ok": false, "error": "EVM lock poisoned"})),
            };
            eng.fund_account(addr, U256::from(amount_wei));
            Some(json!({"ok": true, "address": encode_hex(addr.as_slice()), "credited_wei": amount_wei.to_string()}))
        }
        "eqx_evmDeploy" => {
            let caller_str = params.get("from").and_then(|v| v.as_str()).unwrap_or("0x1111111111111111111111111111111111111111");
            let bytecode_str = params.get("bytecode").and_then(|v| v.as_str()).unwrap_or("");
            let gas_limit = params.get("gas_limit").and_then(|v| v.as_u64()).unwrap_or(1_000_000);

            let caller = match parse_address(caller_str) {
                Ok(a) => a,
                Err(e) => return Some(json!({"ok": false, "error": e})),
            };
            let bytecode = match decode_hex(bytecode_str) {
                Ok(b) if !b.is_empty() => b,
                Ok(_) => return Some(json!({"ok": false, "error": "Empty bytecode"})),
                Err(e) => return Some(json!({"ok": false, "error": e})),
            };
            let mut eng = match evm_engine().lock() {
                Ok(g) => g,
                Err(_) => return Some(json!({"ok": false, "error": "EVM lock poisoned"})),
            };
            match eng.deploy_contract(caller, bytecode, gas_limit) {
                Ok((contract_addr, gas_used)) => Some(json!({
                    "ok": true,
                    "contract_address": encode_hex(contract_addr.as_slice()),
                    "gas_used": gas_used
                })),
                Err(e) => Some(json!({"ok": false, "error": e})),
            }
        }
        "eth_call" => {
            // Supports both standard Ethereum array params [callObj, "latest"] and direct object params
            let call_obj = if params.is_array() {
                params.get(0).unwrap_or(&Value::Null)
            } else {
                params
            };

            let caller_str = call_obj.get("from").and_then(|v| v.as_str()).unwrap_or("0x1111111111111111111111111111111111111111");
            let to_str = call_obj.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let data_str = call_obj
                .get("data")
                .or_else(|| call_obj.get("input"))
                .and_then(|v| v.as_str())
                .unwrap_or("0x");

            let caller = match parse_address(caller_str) {
                Ok(a) => a,
                Err(e) => return Some(json!({"ok": false, "error": e})),
            };
            let contract = match parse_address(to_str) {
                Ok(a) => a,
                Err(e) => return Some(json!({"ok": false, "error": e})),
            };
            let calldata = match decode_hex(data_str) {
                Ok(d) => d,
                Err(e) => return Some(json!({"ok": false, "error": e})),
            };

            let mut eng = match evm_engine().lock() {
                Ok(g) => g,
                Err(_) => return Some(json!({"ok": false, "error": "EVM lock poisoned"})),
            };

            match eng.call_contract(caller, contract, calldata, U256::ZERO, 1_000_000) {
                Ok((ret_bytes, _gas_used)) => Some(Value::String(encode_hex(&ret_bytes))),
                Err(e) => Some(json!({"ok": false, "error": e})),
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_rpc_deploy_and_eth_call() {
        let caller = "0x2222222222222222222222222222222222222222";
        let fund = handle_evm_rpc("eqx_evmFund", &json!({ "address": caller })).unwrap();
        assert_eq!(fund["ok"], true);

        let deploy = handle_evm_rpc(
            "eqx_evmDeploy",
            &json!({
                "from": caller,
                "bytecode": "0x69602a60005260206000f3600052600a6016f3"
            }),
        )
        .unwrap();
        assert_eq!(deploy["ok"], true);
        let contract_addr = deploy["contract_address"].as_str().unwrap();

        let call_res = handle_evm_rpc(
            "eth_call",
            &json!([{ "from": caller, "to": contract_addr, "data": "0x" }, "latest"]),
        )
        .unwrap();
        let hex_out = call_res.as_str().expect("eth_call should return hex string");
        assert!(hex_out.ends_with("2a"));
    }
}