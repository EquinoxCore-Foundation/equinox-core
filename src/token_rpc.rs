use std::sync::{Mutex, OnceLock};
use serde_json::{json, Value};
use crate::token_registry::NativeTokenRegistry;

static GLOBAL_TOKEN_REGISTRY: OnceLock<Mutex<NativeTokenRegistry>> = OnceLock::new();

/// Default persistence path for the native token registry.
const TOKEN_STATE_PATH: &str = "data/token_registry.json";

fn registry() -> &'static Mutex<NativeTokenRegistry> {
    GLOBAL_TOKEN_REGISTRY.get_or_init(|| {
        // Try to load existing state from disk; fall back to empty registry.
        let reg = NativeTokenRegistry::load_from_disk(TOKEN_STATE_PATH)
            .unwrap_or_default();
        Mutex::new(reg)
    })
}

/// Handles eqx_deployToken, eqx_transferToken, eqx_getTokenBalance, and eqx_listTokens.
/// Returns Some(json_result) if handled, or None if the method belongs to another handler.
pub fn handle_token_rpc(method: &str, params: &Value) -> Option<Value> {
    match method {
        "eqx_deployToken" => {
            let creator = params.get("creator").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let ticker = params.get("ticker").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let decimals = params.get("decimals").and_then(|v| v.as_u64()).unwrap_or(6) as u8;
            let total_supply = params
                .get("total_supply")
                .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok()).or_else(|| v.as_u64().map(|n| n as u128)))
                .unwrap_or(0);
            let nonce = params.get("nonce").and_then(|v| v.as_u64()).unwrap_or(1);

            let mut reg = match registry().lock() {
                Ok(g) => g,
                Err(_) => return Some(json!({"error": "Registry lock poisoned"})),
            };

            match reg.deploy_token(creator, name, ticker, decimals, total_supply, nonce) {
                Ok(meta) => Some(json!({
                    "ok": true,
                    "asset_id": meta.asset_id,
                    "name": meta.name,
                    "ticker": meta.ticker,
                    "decimals": meta.decimals,
                    "total_supply": meta.total_supply.to_string(),
                    "mintable": meta.mintable,
                    "freezable": meta.freezable
                })),
                Err(e) => Some(json!({"ok": false, "error": format!("{:?}", e)})),
            }
        }
        "eqx_transferToken" => {
            let asset_id = params.get("asset_id").and_then(|v| v.as_str()).unwrap_or("");
            let from = params.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let to = params.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let amount = params
                .get("amount")
                .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok()).or_else(|| v.as_u64().map(|n| n as u128)))
                .unwrap_or(0);

            let mut reg = match registry().lock() {
                Ok(g) => g,
                Err(_) => return Some(json!({"error": "Registry lock poisoned"})),
            };

            match reg.transfer(asset_id, from, to, amount) {
                Ok(()) => Some(json!({"ok": true})),
                Err(e) => Some(json!({"ok": false, "error": format!("{:?}", e)})),
            }
        }
        "eqx_getTokenBalance" => {
            let asset_id = params.get("asset_id").and_then(|v| v.as_str()).unwrap_or("");
            let owner = params.get("owner").and_then(|v| v.as_str()).unwrap_or("");

            let reg = match registry().lock() {
                Ok(g) => g,
                Err(_) => return Some(json!({"error": "Registry lock poisoned"})),
            };

            let bal = reg.balance_of(asset_id, owner);
            Some(json!({
                "ok": true,
                "asset_id": asset_id,
                "owner": owner,
                "balance": bal.to_string()
            }))
        }
        "eqx_listTokens" => {
            let reg = match registry().lock() {
                Ok(g) => g,
                Err(_) => return Some(json!({"error": "Registry lock poisoned"})),
            };

            let list: Vec<Value> = reg
                .assets
                .values()
                .map(|m| {
                    json!({
                        "asset_id": m.asset_id,
                        "name": m.name,
                        "ticker": m.ticker,
                        "decimals": m.decimals,
                        "total_supply": m.total_supply.to_string(),
                        "creator": m.creator,
                        "mintable": m.mintable,
                        "freezable": m.freezable
                    })
                })
                .collect();

            Some(json!({"ok": true, "tokens": list}))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_rpc_lifecycle() {
        let deploy = handle_token_rpc(
            "eqx_deployToken",
            &json!({
                "creator": "eqx1rpc_creator",
                "name": "Bengal Coin",
                "ticker": "BGL",
                "decimals": 6,
                "total_supply": "500000",
                "nonce": 7
            }),
        )
        .expect("should handle deploy");
        assert_eq!(deploy["ok"], true);
        let asset_id = deploy["asset_id"].as_str().unwrap().to_string();

        let tx = handle_token_rpc(
            "eqx_transferToken",
            &json!({
                "asset_id": asset_id,
                "from": "eqx1rpc_creator",
                "to": "eqx1rpc_bob",
                "amount": "125000"
            }),
        )
        .expect("should handle transfer");
        assert_eq!(tx["ok"], true);

        let bal = handle_token_rpc(
            "eqx_getTokenBalance",
            &json!({
                "asset_id": asset_id,
                "owner": "eqx1rpc_bob"
            }),
        )
        .expect("should handle balance");
        assert_eq!(bal["balance"], "125000");
    }
}

/// Shared accessor allowing EVM Precompile Bridge to read/mutate NativeTokenRegistry atomically.
pub fn with_registry<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut NativeTokenRegistry) -> R,
{
    let mut guard = registry().lock().map_err(|_| "Registry lock poisoned".to_string())?;
    let out = f(&mut guard);
    let _ = guard.save_to_disk(TOKEN_STATE_PATH);
    Ok(out)
}