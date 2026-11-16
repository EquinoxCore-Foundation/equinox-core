// File: Equinox-Super-Wallet/crates/signing-dex-mpc/src/broadcaster.rs
#![forbid(unsafe_code)]

use crate::{ExecutionError, RpcSecurityGuard, SignedRawTransaction};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestnetNetwork {
    EquinoxTestnet,  // Chain ID 9333
    EthereumSepolia, // Chain ID 11155111
    BscTestnet,      // Chain ID 97
    ArbitrumSepolia, // Chain ID 421614
    PolygonAmoy,     // Chain ID 80002
    BitcoinSignet,
    SolanaDevnet,
}

impl TestnetNetwork {
    pub fn expected_chain_id(&self) -> Option<u64> {
        match self {
            TestnetNetwork::EquinoxTestnet => Some(9333),
            TestnetNetwork::EthereumSepolia => Some(11_155_111),
            TestnetNetwork::BscTestnet => Some(97),
            TestnetNetwork::ArbitrumSepolia => Some(421_614),
            TestnetNetwork::PolygonAmoy => Some(80_002),
            TestnetNetwork::BitcoinSignet | TestnetNetwork::SolanaDevnet => None,
        }
    }

    pub fn env_key(&self) -> &'static str {
        match self {
            TestnetNetwork::EquinoxTestnet => "EQUINOX_TESTNET_RPC_URL",
            TestnetNetwork::EthereumSepolia => "ETH_SEPOLIA_RPC_URL",
            TestnetNetwork::BscTestnet => "BSC_TESTNET_RPC_URL",
            TestnetNetwork::ArbitrumSepolia => "ARBITRUM_SEPOLIA_RPC_URL",
            TestnetNetwork::PolygonAmoy => "POLYGON_AMOY_RPC_URL",
            TestnetNetwork::BitcoinSignet => "BTC_SIGNET_API_URL",
            TestnetNetwork::SolanaDevnet => "SOLANA_DEVNET_RPC_URL",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastReceipt {
    pub network: TestnetNetwork,
    pub on_chain_tx_hash: String,
    pub rpc_endpoint_used: String,
}

pub struct TestnetRpcConfig {
    pub endpoints: HashMap<TestnetNetwork, String>,
    pub timeout_secs: u64,
}

impl TestnetRpcConfig {
    /// `.env` ফাইল এবং OS এনভায়রনমেন্ট থেকে টেস্টনেট RPC URL লোড ও TLS যাচাই করে
    pub fn load_from_env_file<P: AsRef<Path>>(env_path: P) -> Result<Self, ExecutionError> {
        let mut raw_vars: HashMap<String, String> = std::env::vars().collect();

        if let Ok(content) = fs::read_to_string(env_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
                    raw_vars.insert(key, val);
                }
            }
        }

        let networks = [
            TestnetNetwork::EquinoxTestnet,
            TestnetNetwork::EthereumSepolia,
            TestnetNetwork::BscTestnet,
            TestnetNetwork::ArbitrumSepolia,
            TestnetNetwork::PolygonAmoy,
            TestnetNetwork::BitcoinSignet,
            TestnetNetwork::SolanaDevnet,
        ];

        let mut endpoints = HashMap::new();
        for net in networks {
            if let Some(url) = raw_vars.get(net.env_key()) {
                if !url.is_empty() {
                    RpcSecurityGuard::validate_endpoint_url(url)?;
                    endpoints.insert(net, url.clone());
                }
            }
        }

        let timeout_secs = raw_vars
            .get("RPC_TIMEOUT_SECS")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10)
            .clamp(2, 60);

        Ok(Self {
            endpoints,
            timeout_secs,
        })
    }

    pub fn get_url(&self, net: TestnetNetwork) -> Result<&str, ExecutionError> {
        self.endpoints
            .get(&net)
            .map(|s| s.as_str())
            .ok_or_else(|| {
                ExecutionError::RpcSecurityViolation(format!(
                    "Missing {} in .env configuration",
                    net.env_key()
                ))
            })
    }
}

pub struct LiveTestnetBroadcaster {
    config: TestnetRpcConfig,
    http_client: Client,
    security_guard: RpcSecurityGuard,
    next_rpc_id: u64,
}

impl LiveTestnetBroadcaster {
    pub fn new(config: TestnetRpcConfig, hmac_secret: [u8; 32]) -> Result<Self, ExecutionError> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| ExecutionError::RpcSecurityViolation(e.to_string()))?;

        Ok(Self {
            config,
            http_client,
            security_guard: RpcSecurityGuard::new(hmac_secret, 60),
            next_rpc_id: 1,
        })
    }

    fn parse_hex_u128(hex_str: &str) -> Result<u128, ExecutionError> {
        let clean = hex_str.trim().trim_start_matches("0x");
        u128::from_str_radix(clean, 16)
            .map_err(|e| ExecutionError::InvalidTransactionParams(e.to_string()))
    }

    /// JSON-RPC 2.0 রিকোয়েস্ট পাঠায় এবং রেট-লিমিট, পেলোড সাইজ ও রিকোয়েস্ট আইডি যাচাই করে
    fn send_json_rpc(
        &mut self,
        url: &str,
        method: &str,
        params: Value,
        current_unix: u64,
    ) -> Result<Value, ExecutionError> {
        RpcSecurityGuard::validate_endpoint_url(url)?;
        let req_id = self.next_rpc_id;
        self.next_rpc_id += 1;

        let body_json = json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        })
        .to_string();

        let hmac_sig = self
            .security_guard
            .sign_rpc_request_hmac(&body_json, current_unix);

        let resp = self
            .http_client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Equinox-Timestamp", current_unix.to_string())
            .header("X-Equinox-Signature", hmac_sig)
            .body(body_json)
            .send()
            .map_err(|e| ExecutionError::RpcSecurityViolation(format!("HTTP transport error: {}", e)))?;

        let raw_text = resp
            .text()
            .map_err(|e| ExecutionError::RpcSecurityViolation(e.to_string()))?;

        let validated = self
            .security_guard
            .verify_rate_limit_and_response(req_id, &raw_text, current_unix)?;

        if let Some(err_obj) = validated.get("error") {
            return Err(ExecutionError::RpcSecurityViolation(format!(
                "RPC node rejected request: {}",
                err_obj
            )));
        }

        validated
            .get("result")
            .cloned()
            .ok_or_else(|| ExecutionError::RpcSecurityViolation("Missing 'result' in RPC response".into()))
    }

    /// টেস্টনেট থেকে লাইভ একাউন্ট Nonce (`eth_getTransactionCount`) এবং `eth_gasPrice` নিয়ে আসে
    pub fn fetch_evm_nonce_and_gas_price(
        &mut self,
        network: TestnetNetwork,
        sender_address_0x: &str,
        current_unix: u64,
    ) -> Result<(u64, u128), ExecutionError> {
        let url = self.config.get_url(network)?.to_string();

        let nonce_val = self.send_json_rpc(
            &url,
            "eth_getTransactionCount",
            json!([sender_address_0x.trim(), "pending"]),
            current_unix,
        )?;
        let nonce_hex = nonce_val.as_str().ok_or_else(|| {
            ExecutionError::RpcSecurityViolation("Invalid nonce hex from RPC".into())
        })?;
        let nonce = Self::parse_hex_u128(nonce_hex)? as u64;

        let gas_val = self.send_json_rpc(&url, "eth_gasPrice", json!([]), current_unix)?;
        let gas_hex = gas_val.as_str().ok_or_else(|| {
            ExecutionError::RpcSecurityViolation("Invalid gasPrice hex from RPC".into())
        })?;
        let gas_price_wei = Self::parse_hex_u128(gas_hex)?;

        Ok((nonce, gas_price_wei))
    }

    /// স্বাক্ষরিত ট্রানজ্যাকশন (EVM / Equinox L1 / Bitcoin Signet / Solana Devnet) লাইভ টেস্টনেটে ব্রডকাস্ট করে
    pub fn broadcast_signed_transaction(
        &mut self,
        network: TestnetNetwork,
        signed_tx: &SignedRawTransaction,
        current_unix: u64,
    ) -> Result<BroadcastReceipt, ExecutionError> {
        if let Some(expected_cid) = network.expected_chain_id() {
            if signed_tx.chain_id != expected_cid {
                return Err(ExecutionError::ChainIdMismatch {
                    expected: expected_cid,
                    actual: signed_tx.chain_id,
                });
            }
        }

        let url = self.config.get_url(network)?.to_string();

        match network {
            TestnetNetwork::EquinoxTestnet => {
                let res = self.send_json_rpc(
                    &url,
                    "eqx_sendRawTransaction",
                    json!([signed_tx.raw_tx_hex]),
                    current_unix,
                )?;
                let tx_hash = res
                    .as_str()
                    .ok_or_else(|| {
                        ExecutionError::RpcSecurityViolation("Invalid txid from Equinox node".into())
                    })?
                    .to_string();

                Ok(BroadcastReceipt {
                    network,
                    on_chain_tx_hash: tx_hash,
                    rpc_endpoint_used: url,
                })
            }

            TestnetNetwork::EthereumSepolia
            | TestnetNetwork::BscTestnet
            | TestnetNetwork::ArbitrumSepolia
            | TestnetNetwork::PolygonAmoy => {
                let res = self.send_json_rpc(
                    &url,
                    "eth_sendRawTransaction",
                    json!([signed_tx.raw_tx_hex]),
                    current_unix,
                )?;
                let tx_hash = res
                    .as_str()
                    .ok_or_else(|| {
                        ExecutionError::RpcSecurityViolation("Invalid txHash from EVM RPC".into())
                    })?
                    .trim()
                    .to_string();

                if !tx_hash.starts_with("0x") || tx_hash.len() != 66 {
                    return Err(ExecutionError::RpcSecurityViolation(format!(
                        "Malformed EVM transaction hash returned: {}",
                        tx_hash
                    )));
                }

                Ok(BroadcastReceipt {
                    network,
                    on_chain_tx_hash: tx_hash,
                    rpc_endpoint_used: url,
                })
            }

            TestnetNetwork::BitcoinSignet => {
                RpcSecurityGuard::validate_endpoint_url(&url)?;
                let post_url = format!("{}/tx", url.trim_end_matches('/'));
                let clean_raw = signed_tx.raw_tx_hex.trim().trim_start_matches("0x");

                let resp = self
                    .http_client
                    .post(&post_url)
                    .header("Content-Type", "text/plain")
                    .body(clean_raw.to_string())
                    .send()
                    .map_err(|e| ExecutionError::RpcSecurityViolation(e.to_string()))?;

                if !resp.status().is_success() {
                    let err_txt = resp.text().unwrap_or_default();
                    return Err(ExecutionError::RpcSecurityViolation(format!(
                        "Bitcoin Signet broadcast rejected: {}",
                        err_txt
                    )));
                }

                let txid = resp
                    .text()
                    .map_err(|e| ExecutionError::RpcSecurityViolation(e.to_string()))?
                    .trim()
                    .to_string();

                if txid.len() != 64 || hex::decode(&txid).is_err() {
                    return Err(ExecutionError::RpcSecurityViolation(format!(
                        "Invalid Bitcoin Signet txid returned: {}",
                        txid
                    )));
                }

                Ok(BroadcastReceipt {
                    network,
                    on_chain_tx_hash: txid,
                    rpc_endpoint_used: post_url,
                })
            }

            TestnetNetwork::SolanaDevnet => {
                let res = self.send_json_rpc(
                    &url,
                    "sendTransaction",
                    json!([
                        signed_tx.raw_tx_hex,
                        { "encoding": "base58", "skipPreflight": false }
                    ]),
                    current_unix,
                )?;
                let sig = res
                    .as_str()
                    .ok_or_else(|| {
                        ExecutionError::RpcSecurityViolation("Invalid Solana signature".into())
                    })?
                    .to_string();

                Ok(BroadcastReceipt {
                    network,
                    on_chain_tx_hash: sig,
                    rpc_endpoint_used: url,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_env_loading_tls_enforcement_and_chain_id_guard() {
        let mut tmp_env = std::env::temp_dir();
        tmp_env.push("equinox_test_rpc.env");

        let env_content = "\
            EQUINOX_TESTNET_RPC_URL=http://127.0.0.1:8545\n\
            ETH_SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com\n\
            BSC_TESTNET_RPC_URL=https://bsc-testnet-rpc.publicnode.com\n\
            BTC_SIGNET_API_URL=https://mempool.space/signet/api\n\
            SOLANA_DEVNET_RPC_URL=https://api.devnet.solana.com\n\
            RPC_TIMEOUT_SECS=8\n";

        {
            let mut f = fs::File::create(&tmp_env).unwrap();
            f.write_all(env_content.as_bytes()).unwrap();
        }

        let cfg = TestnetRpcConfig::load_from_env_file(&tmp_env).unwrap();
        assert_eq!(
            cfg.get_url(TestnetNetwork::EthereumSepolia).unwrap(),
            "https://ethereum-sepolia-rpc.publicnode.com"
        );
        assert_eq!(cfg.timeout_secs, 8);

        let mut broadcaster = LiveTestnetBroadcaster::new(cfg, [0x77u8; 32]).unwrap();

        // Attempting to broadcast a BSC Testnet tx (Chain ID 97) to Ethereum Sepolia (Chain ID 11155111) must be blocked before network I/O!
        let wrong_chain_tx = SignedRawTransaction {
            chain_id: 97,
            tx_hash_hex: "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            raw_tx_hex: "0xf865...".into(),
        };

        assert_eq!(
            broadcaster.broadcast_signed_transaction(
                TestnetNetwork::EthereumSepolia,
                &wrong_chain_tx,
                1_760_000_000
            ),
            Err(ExecutionError::ChainIdMismatch {
                expected: 11_155_111,
                actual: 97
            })
        );

        let _ = fs::remove_file(&tmp_env);
    }
}