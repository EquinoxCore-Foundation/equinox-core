#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use equinox_consensus::{
    calculate_block_subsidy, AsertConfig, BftFinalityGuard, U256, ATOMIC_UNITS_PER_EQX,
    CHAIN_ID_MAINNET, GENESIS_PREMINE_ATOMIC, MAX_SUPPLY_ATOMIC,
};
use equinox_crypto::address::{decode_and_verify_address, encode_mainnet_address};
use equinox_crypto::signer::SecretSeed;
use equinox_network::banlist::BanManager;
use equinox_network::nat::ConnectionSlotManager;
use equinox_network::transport::{NodeStaticKey, MAINNET_PROLOGUE};
use equinox_storage::engine::UtxoStorageEngine;
use equinox_storage::types::{OutPoint, UtxoEntry, WriteBatch};
use equinox_wallet::mnemonic::mnemonic_to_seed;
use equinox_wallet::slip10::{equinox_hd_path, Slip10Key};
use sha2::{Digest, Sha256};

use crate::genesis::{
    build_mainnet_genesis_batch, to_hex, GenesisVaultSpec, DEVELOPER_VAULT_ATOMIC,
    FOUNDER_VAULT_ATOMIC, LIQUIDITY_VAULT_ATOMIC, MARKETING_VAULT_ATOMIC,
};

/// Safety switch: remains false during public Testnet until final offline Mainnet Ceremony.
pub const MAINNET_ACTIVATED: bool = false;
pub const CHAIN_ID_TESTNET: u64 = 9333;
pub const TESTNET_NOISE_PROLOGUE: &[u8] = b"EQX_TESTNET_9333_NOISE_XX_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Testnet,
    Mainnet,
}

impl NetworkMode {
    pub fn name(self) -> &'static str {
        match self {
            NetworkMode::Testnet => "equinox-testnet",
            NetworkMode::Mainnet => "equinox-mainnet",
        }
    }

    pub fn chain_id(self) -> u64 {
        match self {
            NetworkMode::Testnet => CHAIN_ID_TESTNET,
            NetworkMode::Mainnet => CHAIN_ID_MAINNET,
        }
    }

    pub fn noise_prologue(self) -> &'static [u8] {
        match self {
            NetworkMode::Testnet => TESTNET_NOISE_PROLOGUE,
            NetworkMode::Mainnet => MAINNET_PROLOGUE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockSummary {
    pub height: u64,
    pub hash_hex: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub miner_reward_atomic: u128,
    pub dao_reward_atomic: u128,
    pub tx_count: u32,
}

pub struct NodeState {
    pub mode: NetworkMode,
    pub storage: UtxoStorageEngine,
    pub asert: AsertConfig,
    pub bft: BftFinalityGuard,
    pub banlist: BanManager,
    pub slots: ConnectionSlotManager,
    pub node_key: NodeStaticKey,
    pub miner_address: String,
    pub miner_h160: [u8; 20],
    pub dao_address: String,
    pub dao_h160: [u8; 20],
    pub already_mined_atomic: u128,
    pub anchor_height: u64,
    pub anchor_timestamp: u64,
    pub anchor_target: U256,
    pub current_target: U256,
    pub last_block_timestamp: u64,
    pub total_txns: u64,
    pub balances: HashMap<String, u128>,
    pub recent_blocks: Vec<BlockSummary>,
}

pub type SharedNode = Arc<Mutex<NodeState>>;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl NodeState {
    pub fn bootstrap(
        mode: NetworkMode,
        wal_path: impl AsRef<Path>,
        custom_miner_addr: Option<String>,
    ) -> Result<Self, String> {
        if mode == NetworkMode::Mainnet && !MAINNET_ACTIVATED {
            return Err(
                "UPCOMING MAINNET GUARD: Mainnet is locked (MAINNET_ACTIVATED = false). Run with --testnet during the public testnet phase."
                    .to_string(),
            );
        }

        // Derive deterministic testnet genesis vaults so all testnet nodes share Block #0
        let testnet_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(testnet_phrase, "EquinoxTestnetGenesis9333")
            .map_err(|_| "Testnet genesis seed derivation failed".to_string())?;

        let mut vault_addrs = Vec::with_capacity(4);
        for idx in 0..4u32 {
            let path = equinox_hd_path(idx, 0, 0).map_err(|_| "Invalid HD path".to_string())?;
            let k = Slip10Key::derive_path(&*seed, &path)
                .map_err(|_| "SLIP-0010 derivation failed".to_string())?;
            vault_addrs.push(k.mainnet_address());
        }

        let genesis_ts = 1_795_000_000u64;
        let spec = GenesisVaultSpec {
            founder_address: vault_addrs[0].clone(),
            liquidity_address: vault_addrs[1].clone(),
            developer_address: vault_addrs[2].clone(),
            marketing_address: vault_addrs[3].clone(),
            timestamp_utc: genesis_ts,
        };
        let genesis = build_mainnet_genesis_batch(&spec)?;

        let mut storage = UtxoStorageEngine::open(wal_path, 50_000, mode == NetworkMode::Mainnet)
            .map_err(|e| format!("Failed to open WAL storage: {:?}", e))?;

        if storage.utxo_count() == 0 {
            storage
                .apply_block_batch(&genesis.write_batch)
                .map_err(|e| format!("Failed to commit Genesis Block #0: {:?}", e))?;
        }

        let (miner_address, miner_h160) = match custom_miner_addr {
            Some(addr) => {
                let h = decode_and_verify_address(&addr)
                    .map_err(|_| format!("Invalid --miner address: {}", addr))?;
                (addr, h)
            }
            None => {
                let fresh = SecretSeed::generate();
                let addr = encode_mainnet_address(&fresh.public_key_bytes());
                let h = decode_and_verify_address(&addr)
                    .map_err(|_| "Failed to decode generated miner address".to_string())?;
                (addr, h)
            }
        };

        let dao_address = vault_addrs[2].clone();
        let dao_h160 = decode_and_verify_address(&dao_address)
            .map_err(|_| "Invalid DAO treasury address".to_string())?;

        let mut balances = HashMap::new();
        balances.insert(vault_addrs[0].clone(), FOUNDER_VAULT_ATOMIC);
        balances.insert(vault_addrs[1].clone(), LIQUIDITY_VAULT_ATOMIC);
        balances.insert(vault_addrs[2].clone(), DEVELOPER_VAULT_ATOMIC);
        balances.insert(vault_addrs[3].clone(), MARKETING_VAULT_ATOMIC);
        balances.entry(miner_address.clone()).or_insert(0);

        // Accessible CPU PoW target for fast Testnet block discovery (~14 leading zero bits)
        let mut asert = AsertConfig::default();
        let initial_target = U256([u64::MAX, u64::MAX, u64::MAX, 0x0003_FFFF_FFFF_FFFF]);
        asert.max_target = U256([u64::MAX, u64::MAX, u64::MAX, 0x00FF_FFFF_FFFF_FFFF]);

        let node_key = NodeStaticKey::generate().map_err(|_| "Noise keygen failed".to_string())?;
        let tip_h = storage.tip_height();
        let tip_hash = storage.tip_hash();
        let now = now_secs();

        let genesis_summary = BlockSummary {
            height: 0,
            hash_hex: to_hex(&genesis.block_hash),
            nonce: 0,
            timestamp: genesis_ts,
            miner_reward_atomic: GENESIS_PREMINE_ATOMIC,
            dao_reward_atomic: 0,
            tx_count: 1,
        };

        Ok(Self {
            mode,
            storage,
            asert,
            bft: BftFinalityGuard::new(tip_hash),
            banlist: BanManager::mainnet_default(),
            slots: ConnectionSlotManager::mainnet_default(),
            node_key,
            miner_address,
            miner_h160,
            dao_address,
            dao_h160,
            already_mined_atomic: 0,
            anchor_height: tip_h,
            anchor_timestamp: now,
            anchor_target: initial_target,
            current_target: initial_target,
            last_block_timestamp: now,
            total_txns: 1 + tip_h,
            balances,
            recent_blocks: vec![genesis_summary],
        })
    }

    pub fn commit_mined_block(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        nonce: u64,
        timestamp: u64,
    ) -> Result<BlockSummary, String> {
        let split = calculate_block_subsidy(self.already_mined_atomic)
            .map_err(|e| format!("Subsidy calculation error: {:?}", e))?;

        let mut tx_h = Sha256::new();
        tx_h.update(b"EQX_COINBASE_TX_V1");
        tx_h.update(&height.to_le_bytes());
        tx_h.update(&block_hash);
        let coinbase_txid: [u8; 32] = tx_h.finalize().into();

        let mut creates = Vec::with_capacity(2);
        if split.miner_reward > 0 {
            creates.push((
                OutPoint {
                    txid: coinbase_txid,
                    vout: 0,
                },
                UtxoEntry {
                    value_atomic: split.miner_reward,
                    script_hash160: self.miner_h160,
                    height,
                    is_coinbase: true,
                },
            ));
        }
        if split.dao_treasury_reward > 0 {
            creates.push((
                OutPoint {
                    txid: coinbase_txid,
                    vout: 1,
                },
                UtxoEntry {
                    value_atomic: split.dao_treasury_reward,
                    script_hash160: self.dao_h160,
                    height,
                    is_coinbase: true,
                },
            ));
        }

        let batch = WriteBatch {
            height,
            block_hash,
            spends: Vec::new(),
            creates,
        };
        self.storage
            .apply_block_batch(&batch)
            .map_err(|e| format!("WAL commit failed: {:?}", e))?;

        self.already_mined_atomic = self
            .already_mined_atomic
            .saturating_add(split.total_subsidy);
        self.total_txns = self.total_txns.saturating_add(1);
        self.last_block_timestamp = timestamp;

        *self
            .balances
            .entry(self.miner_address.clone())
            .or_insert(0) += split.miner_reward;
        *self.balances.entry(self.dao_address.clone()).or_insert(0) += split.dao_treasury_reward;

        // Dynamically retarget next block using zero-floating-point ASERT3-2d
        if let Ok(next_t) = self.asert.calculate_next_target(
            self.anchor_height,
            self.anchor_timestamp,
            self.anchor_target,
            height,
            timestamp,
        ) {
            self.current_target = next_t;
        }

        let summary = BlockSummary {
            height,
            hash_hex: to_hex(&block_hash),
            nonce,
            timestamp,
            miner_reward_atomic: split.miner_reward,
            dao_reward_atomic: split.dao_treasury_reward,
            tx_count: 1,
        };
        self.recent_blocks.push(summary.clone());
        if self.recent_blocks.len() > 50 {
            self.recent_blocks.remove(0);
        }
        Ok(summary)
    }

    pub fn circulating_supply_atomic(&self) -> u128 {
        GENESIS_PREMINE_ATOMIC
            .saturating_add(self.already_mined_atomic)
            .min(MAX_SUPPLY_ATOMIC)
    }

    pub fn format_eqx(atomic: u128) -> String {
        let whole = atomic / ATOMIC_UNITS_PER_EQX;
        let frac = atomic % ATOMIC_UNITS_PER_EQX;
        format!("{}.{:08}", whole, frac)
    }
}
