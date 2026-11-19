#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Standardized Explorer & Analytics metrics payload (compatible with block explorers & indexers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorerMetrics {
    pub chain_id: u64,
    pub block_height: u64,
    pub total_txns: u64,
    pub pending_txns: u64,
    pub total_addresses: u64,
    pub active_peers: u32,
    pub circulating_supply_atomic: u128,
    pub max_supply_atomic: u128,
    pub target_block_secs: u64,
}

impl Default for ExplorerMetrics {
    fn default() -> Self {
        Self {
            chain_id: 9333,
            block_height: 0,
            total_txns: 0,
            pending_txns: 0,
            total_addresses: 4,
            active_peers: 0,
            circulating_supply_atomic: 2_000_000 * 100_000_000,
            max_supply_atomic: 21_000_000 * 100_000_000,
            target_block_secs: 15,
        }
    }
}
