use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// 0.0001 EQX assuming 8 decimal places (TON-style ultra-low native micro-fee).
pub const NATIVE_MICRO_FEE_ATOMIC: u128 = 10_000;

/// 1 Gwei minimum EVM base fee (ultra-cheap, never zero to block 0-gas DoS spam).
pub const EVM_MIN_BASE_FEE_WEI: u128 = 1_000_000_000;

/// Default P2P max frame size: 4 MiB.
pub const DEFAULT_MAX_P2P_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Default RPC max request payload size: 1 MiB.
pub const DEFAULT_MAX_RPC_BODY_BYTES: usize = 1024 * 1024;

// =====================================================================
// Anti-Spam Micro-Fee Policy (Zero-Burn Validator Pool)
// =====================================================================
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MicroFeePolicy {
    pub validator_fee_pool: u128,
    pub burned_total: u128,
}

impl MicroFeePolicy {
    pub fn new() -> Self {
        Self {
            validator_fee_pool: 0,
            burned_total: 0,
        }
    }

    /// Deducts transfer amount + 0.0001 EQX micro-fee from sender balance.
    /// Zero-burn invariant: 100% of collected fees go to validator_fee_pool.
    pub fn apply_native_micro_fee(
        &mut self,
        sender_balance: u128,
        transfer_amount: u128,
    ) -> Result<(u128, u128), String> {
        let total_required = transfer_amount
            .checked_add(NATIVE_MICRO_FEE_ATOMIC)
            .ok_or_else(|| "Fee arithmetic overflow".to_string())?;

        if sender_balance < total_required {
            return Err("Insufficient balance for transfer + 0.0001 EQX micro-fee".to_string());
        }

        let remaining_balance = sender_balance - total_required;
        self.validator_fee_pool = self
            .validator_fee_pool
            .checked_add(NATIVE_MICRO_FEE_ATOMIC)
            .ok_or_else(|| "Validator fee pool overflow".to_string())?;

        Ok((remaining_balance, NATIVE_MICRO_FEE_ATOMIC))
    }

    /// Enforces a non-zero minimum EVM gas price to prevent 0-gas DoS spam.
    pub fn effective_evm_gas_price(&self, requested_gas_price_wei: u128) -> u128 {
        requested_gas_price_wei.max(EVM_MIN_BASE_FEE_WEI)
    }
}

// =====================================================================
// Security Layer 3: Consensus State Root & Reorg Rollback Guard
// =====================================================================
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockStateSnapshot {
    pub block_height: u64,
    pub combined_state_root: [u8; 32],
    pub native_state_blob: Vec<u8>,
    pub evm_state_blob: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct ConsensusRollbackGuard {
    snapshots: HashMap<u64, BlockStateSnapshot>,
}

impl ConsensusRollbackGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes a deterministic BLAKE3 combined state root for Native + EVM state.
    pub fn compute_state_root(native_bytes: &[u8], evm_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"EQUINOX_STATE_ROOT_V1:");
        hasher.update(&(native_bytes.len() as u64).to_le_bytes());
        hasher.update(native_bytes);
        hasher.update(&(evm_bytes.len() as u64).to_le_bytes());
        hasher.update(evm_bytes);
        *hasher.finalize().as_bytes()
    }

    /// Commits a block snapshot and returns its deterministic BLAKE3 state root.
    pub fn commit_snapshot(
        &mut self,
        block_height: u64,
        native_state_blob: Vec<u8>,
        evm_state_blob: Vec<u8>,
    ) -> [u8; 32] {
        let root = Self::compute_state_root(&native_state_blob, &evm_state_blob);
        self.snapshots.insert(
            block_height,
            BlockStateSnapshot {
                block_height,
                combined_state_root: root,
                native_state_blob,
                evm_state_blob,
            },
        );
        root
    }

    /// Reverts state cleanly to `target_height` and prunes all orphaned future blocks.
    pub fn rollback_to(&mut self, target_height: u64) -> Result<BlockStateSnapshot, String> {
        let target = self
            .snapshots
            .get(&target_height)
            .cloned()
            .ok_or_else(|| format!("Snapshot for height {} not found", target_height))?;

        self.snapshots.retain(|&h, _| h <= target_height);
        Ok(target)
    }

    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }
}

// =====================================================================
// Security Layer 5: P2P Network DoS Shield & Auto-Ban List
// =====================================================================
#[derive(Debug)]
pub struct P2pDosShield {
    max_frame_bytes: usize,
    max_strikes: u32,
    strikes: HashMap<String, u32>,
    banned_peers: HashSet<String>,
}

impl P2pDosShield {
    pub fn new(max_frame_bytes: usize, max_strikes: u32) -> Self {
        Self {
            max_frame_bytes,
            max_strikes,
            strikes: HashMap::new(),
            banned_peers: HashSet::new(),
        }
    }

    pub fn is_banned(&self, peer_id: &str) -> bool {
        self.banned_peers.contains(peer_id)
    }

    /// Validates an incoming P2P frame size and auto-bans repeat offenders.
    pub fn validate_frame(&mut self, peer_id: &str, payload_len: usize) -> Result<(), String> {
        if self.is_banned(peer_id) {
            return Err(format!("Peer {} is banned", peer_id));
        }
        if payload_len == 0 || payload_len > self.max_frame_bytes {
            let count = self.strikes.entry(peer_id.to_string()).or_insert(0);
            *count += 1;
            if *count >= self.max_strikes {
                self.banned_peers.insert(peer_id.to_string());
                return Err(format!(
                    "Peer {} auto-banned after {} malformed/oversized frames",
                    peer_id, count
                ));
            }
            return Err(format!(
                "Invalid frame size {} bytes (max {})",
                payload_len, self.max_frame_bytes
            ));
        }
        Ok(())
    }
}

// =====================================================================
// Security Layer 6: RPC Payload Guard & Mainnet Faucet Lock
// =====================================================================
#[derive(Debug, Clone)]
pub struct RpcHardeningGuard {
    pub max_body_bytes: usize,
    pub is_mainnet: bool,
}

impl RpcHardeningGuard {
    pub fn from_env() -> Self {
        let net = std::env::var("EQUINOX_NETWORK").unwrap_or_else(|_| "testnet".to_string());
        let is_mainnet = net.eq_ignore_ascii_case("mainnet");
        Self {
            max_body_bytes: DEFAULT_MAX_RPC_BODY_BYTES,
            is_mainnet,
        }
    }

    /// Blocks oversized RPC bodies and disables faucet methods (`eqx_evmFund`) on mainnet.
    pub fn validate_rpc_request(&self, method: &str, body_len: usize) -> Result<(), String> {
        if body_len > self.max_body_bytes {
            return Err(format!(
                "RPC payload too large: {} bytes (limit {})",
                body_len, self.max_body_bytes
            ));
        }
        if self.is_mainnet && method == "eqx_evmFund" {
            return Err("eqx_evmFund is strictly disabled on mainnet".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_micro_fee_zero_burn_and_evm_min_base_fee() {
        let mut policy = MicroFeePolicy::new();
        let (remaining, fee) = policy
            .apply_native_micro_fee(1_000_000, 500_000)
            .expect("micro-fee deduction should succeed");

        assert_eq!(fee, NATIVE_MICRO_FEE_ATOMIC);
        assert_eq!(remaining, 490_000);
        assert_eq!(policy.validator_fee_pool, 10_000);
        assert_eq!(policy.burned_total, 0);

        // EVM gas price can never drop to 0
        assert_eq!(policy.effective_evm_gas_price(0), EVM_MIN_BASE_FEE_WEI);
        assert_eq!(
            policy.effective_evm_gas_price(2_000_000_000),
            2_000_000_000
        );
    }

    #[test]
    fn test_consensus_state_root_and_reorg_rollback() {
        let mut guard = ConsensusRollbackGuard::new();
        let root1 = guard.commit_snapshot(1, b"native_v1".to_vec(), b"evm_v1".to_vec());
        let root2 = guard.commit_snapshot(2, b"native_v2".to_vec(), b"evm_v2".to_vec());
        assert_ne!(root1, root2);
        assert_eq!(guard.snapshot_count(), 2);

        let reverted = guard.rollback_to(1).expect("rollback to height 1 should succeed");
        assert_eq!(reverted.combined_state_root, root1);
        assert_eq!(reverted.native_state_blob, b"native_v1");
        assert_eq!(guard.snapshot_count(), 1);
    }

    #[test]
    fn test_p2p_dos_shield_frame_limit_and_autoban() {
        let mut shield = P2pDosShield::new(DEFAULT_MAX_P2P_FRAME_BYTES, 2);
        assert!(shield.validate_frame("peer_good", 1024).is_ok());

        // 2 oversized frames trigger automatic ban
        assert!(shield.validate_frame("peer_spam", DEFAULT_MAX_P2P_FRAME_BYTES + 1).is_err());
        assert!(!shield.is_banned("peer_spam"));
        assert!(shield.validate_frame("peer_spam", DEFAULT_MAX_P2P_FRAME_BYTES + 1).is_err());
        assert!(shield.is_banned("peer_spam"));
        assert!(shield.validate_frame("peer_spam", 128).is_err());
    }

    #[test]
    fn test_rpc_hardening_payload_and_mainnet_lock() {
        let mainnet_guard = RpcHardeningGuard {
            max_body_bytes: 1024,
            is_mainnet: true,
        };
        assert!(mainnet_guard.validate_rpc_request("eth_call", 256).is_ok());
        assert!(mainnet_guard.validate_rpc_request("eth_call", 2048).is_err());
        assert!(mainnet_guard.validate_rpc_request("eqx_evmFund", 128).is_err());

        let testnet_guard = RpcHardeningGuard {
            max_body_bytes: 1024,
            is_mainnet: false,
        };
        assert!(testnet_guard.validate_rpc_request("eqx_evmFund", 128).is_ok());
    }
}