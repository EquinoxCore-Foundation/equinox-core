#![allow(dead_code)]
use std::net::SocketAddr;

pub const EQX_CHAIN_ID: u64 = 9333;
pub const EQX_ATOMIC_UNITS: u64 = 100_000_000;
pub const ALLOWED_READONLY_METHODS: &[&str] = &[
    "eth_chainId", "net_version", "eth_blockNumber", "eqx_blockNumber",
    "eth_gasPrice", "eqx_minFee", "eqx_getFeeEstimate", "eqx_getBalance",
    "eth_getBalance", "eqx_getSupplyInfo", "eqx_getSupplyReport",
    "eqx_getDexPoolInfo", "eqx_getDexQuote", "eqx_getBlockByHeight",
    "eqx_getNodeStatus", "eqx_getChainInfo"
];

pub struct EqxRpcClient {
    pub endpoint: String,
}

impl EqxRpcClient {
    pub fn with_endpoint(endpoint: &str) -> Result<Self, String> {
        let trimmed = endpoint.trim().trim_start_matches("http://");
        let addr: SocketAddr = trimmed.parse().map_err(|_| "Invalid endpoint".to_string())?;
        if !addr.ip().is_loopback() {
            return Err("Remote RPC requires TLS/Auth".to_string());
        }
        Ok(Self { endpoint: addr.to_string() })
    }

    pub fn validate_readonly_method(method: &str) -> Result<(), String> {
        if method == "eth_sendRawTransaction" || method == "eqx_sendRawTransaction" {
            return Err("Broadcast blocked on read-only channel".to_string());
        }
        if !ALLOWED_READONLY_METHODS.contains(&method) {
            return Err("Method not allowlisted".to_string());
        }
        Ok(())
    }

    pub fn format_atomic_to_eqx(atomic: u64) -> String {
        format!("{}.{:08}", atomic / EQX_ATOMIC_UNITS, atomic % EQX_ATOMIC_UNITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rpc_security_boundary() {
        assert_eq!(EQX_CHAIN_ID, 9333);
        assert_eq!(EqxRpcClient::format_atomic_to_eqx(245_000_000), "2.45000000");
        assert!(EqxRpcClient::validate_readonly_method("eqx_getBalance").is_ok());
        assert!(EqxRpcClient::validate_readonly_method("eqx_sendRawTransaction").is_err());
        assert!(EqxRpcClient::with_endpoint("127.0.0.1:8545").is_ok());
        assert!(EqxRpcClient::with_endpoint("88.198.10.20:8545").is_err());
    }
}
