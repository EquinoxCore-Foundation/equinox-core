#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use equinox_consensus::{
    calculate_block_subsidy, AsertConfig, BftFinalityGuard, U256, ATOMIC_UNITS_PER_EQX,
    CHAIN_ID_MAINNET, GENESIS_PREMINE_ATOMIC, MAX_SUPPLY_ATOMIC,
};
use equinox_crypto::address::{
    decode_and_verify_address, encode_from_hash160, encode_mainnet_address, hash160,
};
use equinox_crypto::signer::SecretSeed;
use equinox_network::banlist::BanManager;
use equinox_network::nat::ConnectionSlotManager;
use equinox_network::protocol::WireMessage;
use equinox_network::transport::{NodeStaticKey, MAINNET_PROLOGUE};
use equinox_storage::engine::UtxoStorageEngine;
use equinox_storage::types::{OutPoint, UtxoEntry, WriteBatch};
use equinox_wallet::mnemonic::mnemonic_to_seed;
use equinox_wallet::slip10::{equinox_hd_path, Slip10Key};
use sha2::{Digest, Sha256};

use crate::block::FullBlock;
use crate::genesis::{
    build_mainnet_genesis_batch, to_hex, GenesisVaultSpec, DEVELOPER_VAULT_ATOMIC,
    FOUNDER_VAULT_ATOMIC, LIQUIDITY_VAULT_ATOMIC, MARKETING_VAULT_ATOMIC,
};
use crate::mempool::{Mempool, DEFAULT_MAX_MEMPOOL_TXS, DEFAULT_MIN_FEE_ATOMIC};
use crate::tx::SignedTransaction;

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

/// Lock-isolated fanout hub pushing mined blocks & mempool transactions to all live P2P peers.
pub struct PeerBroadcaster {
    next_id: Mutex<u64>,
    peers: Mutex<Vec<(u64, Sender<WireMessage>)>>,
}

impl PeerBroadcaster {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            next_id: Mutex::new(1),
            peers: Mutex::new(Vec::new()),
        })
    }

    pub fn register(&self) -> (u64, Receiver<WireMessage>) {
        let (tx, rx) = mpsc::channel();
        let mut id_guard = self.next_id.lock().unwrap();
        let id = *id_guard;
        *id_guard = id_guard.saturating_add(1);
        drop(id_guard);

        self.peers.lock().unwrap().push((id, tx));
        (id, rx)
    }

    pub fn unregister(&self, id: u64) {
        self.peers.lock().unwrap().retain(|(pid, _)| *pid != id);
    }

    pub fn broadcast(&self, msg: WireMessage, exclude_peer: Option<u64>) {
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|(pid, tx)| {
            if Some(*pid) == exclude_peer {
                return true;
            }
            tx.send(msg.clone()).is_ok()
        });
    }
}

pub struct NodeState {
    pub mode: NetworkMode,
    pub storage: UtxoStorageEngine,
    pub mempool: Mempool,
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
    pub utxo_index: HashMap<[u8; 20], Vec<(OutPoint, u128)>>,
    pub blocks_by_height: BTreeMap<u64, FullBlock>,
    pub blocks_path: PathBuf,
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

fn load_saved_blocks(path: &Path) -> Vec<FullBlock> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut raw = Vec::new();
    if file.read_to_end(&mut raw).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= raw.len() {
        let len = u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if len == 0 || offset + len > raw.len() {
            break;
        }
        match FullBlock::decode_bytes(&raw[offset..offset + len]) {
            Ok(blk) => {
                out.push(blk);
                offset += len;
            }
            Err(_) => break,
        }
    }
    out
}

fn append_saved_block(path: &Path, blk: &FullBlock) -> Result<(), String> {
    let encoded = blk.encode_bytes();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Failed to open block store: {}", e))?;
    file.write_all(&(encoded.len() as u32).to_le_bytes())
        .map_err(|e| e.to_string())?;
    file.write_all(&encoded).map_err(|e| e.to_string())?;
    Ok(())
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

        let wal_ref = wal_path.as_ref();
        let blocks_path = wal_ref.with_extension("blocks");
        let mut storage = UtxoStorageEngine::open(wal_ref, 50_000, mode == NetworkMode::Mainnet)
            .map_err(|e| format!("Failed to open WAL storage: {:?}", e))?;

        let mut utxo_index: HashMap<[u8; 20], Vec<(OutPoint, u128)>> = HashMap::new();
        if storage.utxo_count() == 0 {
            storage
                .apply_block_batch(&genesis.write_batch)
                .map_err(|e| format!("Failed to commit Genesis Block #0: {:?}", e))?;
        }
        for (op, entry) in &genesis.write_batch.creates {
            if storage.get_utxo(op).is_some() {
                utxo_index
                    .entry(entry.script_hash160)
                    .or_default()
                    .push((*op, entry.value_atomic));
            }
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

        let mut asert = AsertConfig::default();
        let initial_target = U256([u64::MAX, u64::MAX, u64::MAX, 0x0003_FFFF_FFFF_FFFF]);
        asert.max_target = U256([u64::MAX, u64::MAX, u64::MAX, 0x00FF_FFFF_FFFF_FFFF]);

        let node_key = NodeStaticKey::generate().map_err(|_| "Noise keygen failed".to_string())?;
        let tip_h = storage.tip_height();
        let tip_hash = storage.tip_hash();

        let genesis_summary = BlockSummary {
            height: 0,
            hash_hex: to_hex(&genesis.block_hash),
            nonce: 0,
            timestamp: genesis_ts,
            miner_reward_atomic: GENESIS_PREMINE_ATOMIC,
            dao_reward_atomic: 0,
            tx_count: 1,
        };

        let mut state = Self {
            mode,
            storage,
            mempool: Mempool::new(DEFAULT_MAX_MEMPOOL_TXS, DEFAULT_MIN_FEE_ATOMIC),
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
            anchor_height: 0,
            anchor_timestamp: genesis_ts,
            anchor_target: initial_target,
            current_target: initial_target,
            last_block_timestamp: genesis_ts,
            total_txns: 1,
            balances,
            utxo_index,
            blocks_by_height: BTreeMap::new(),
            blocks_path: blocks_path.clone(),
            recent_blocks: vec![genesis_summary],
        };

        // Restore persisted full blocks & deterministic ASERT state after restart
        if tip_h > 0 {
            for blk in load_saved_blocks(&blocks_path) {
                if blk.height > 0 && blk.height <= tip_h {
                    state.replay_loaded_block_metadata(blk);
                }
            }
        }

        Ok(state)
    }

    fn replay_loaded_block_metadata(&mut self, blk: FullBlock) {
        let block_hash = blk.pow_hash();
        let split = match calculate_block_subsidy(self.already_mined_atomic) {
            Ok(s) => s,
            Err(_) => return,
        };
        self.already_mined_atomic = self
            .already_mined_atomic
            .saturating_add(split.total_subsidy);
        self.total_txns = self.total_txns.saturating_add(1 + blk.txs.len() as u64);
        self.last_block_timestamp = blk.timestamp;

        if blk.height == 1 {
            self.anchor_height = 1;
            self.anchor_timestamp = blk.timestamp;
            self.anchor_target = self.current_target;
        } else if self.anchor_height == 1 {
            if let Ok(next_t) = self.asert.calculate_next_target(
                self.anchor_height,
                self.anchor_timestamp,
                self.anchor_target,
                blk.height,
                blk.timestamp,
            ) {
                self.current_target = next_t;
            }
        }

        let summary = BlockSummary {
            height: blk.height,
            hash_hex: to_hex(&block_hash),
            nonce: blk.nonce,
            timestamp: blk.timestamp,
            miner_reward_atomic: split.miner_reward,
            dao_reward_atomic: split.dao_treasury_reward,
            tx_count: 1 + blk.txs.len() as u32,
        };
        self.recent_blocks.push(summary);
        if self.recent_blocks.len() > 50 {
            self.recent_blocks.remove(0);
        }
        self.blocks_by_height.insert(blk.height, blk);
    }

    pub fn submit_transaction(&mut self, tx: SignedTransaction) -> Result<([u8; 32], u128), String> {
        let chain_id = self.mode.chain_id();
        self.mempool
            .validate_and_insert(tx, &mut self.storage, chain_id)
    }

    pub fn utxos_for_hash160(&self, h160: &[u8; 20]) -> Vec<(OutPoint, u128)> {
        self.utxo_index.get(h160).cloned().unwrap_or_default()
    }

    pub fn get_blocks_from(&self, from_height: u64, max_count: usize) -> Vec<FullBlock> {
        let cap = max_count.min(25);
        self.blocks_by_height
            .range(from_height..)
            .take(cap)
            .map(|(_, blk)| blk.clone())
            .collect()
    }

    /// Commits a locally mined block using the exact same verifier as externally synced blocks.
    pub fn commit_mined_block(
        &mut self,
        height: u64,
        prev_hash: [u8; 32],
        state_root: [u8; 32],
        nonce: u64,
        timestamp: u64,
    ) -> Result<(BlockSummary, FullBlock), String> {
        if height != self.storage.tip_height().saturating_add(1)
            || prev_hash != self.storage.tip_hash()
            || state_root != self.storage.compute_state_root()
        {
            return Err("Stale mining template (tip advanced during mining)".to_string());
        }

        let selected = self.mempool.select_for_block(50);
        let full_block = FullBlock {
            height,
            prev_hash,
            state_root,
            miner_h160: self.miner_h160,
            timestamp,
            nonce,
            txs: selected.into_iter().map(|e| e.tx).collect(),
        };
        self.apply_verified_block(full_block)
    }

    /// Independently verifies and applies a FullBlock received from a remote Noise_XX peer.
    pub fn apply_synced_block(
        &mut self,
        block: FullBlock,
    ) -> Result<Option<(BlockSummary, FullBlock)>, String> {
        let tip = self.storage.tip_height();
        if block.height <= tip {
            return Ok(None);
        }
        if block.height != tip.saturating_add(1) {
            return Err(format!(
                "GAP: expected block #{}, received #{}",
                tip + 1,
                block.height
            ));
        }
        let applied = self.apply_verified_block(block)?;
        Ok(Some(applied))
    }

    /// Single deterministic block validation & state transition engine shared by local mining and P2P sync.
    fn apply_verified_block(&mut self, block: FullBlock) -> Result<(BlockSummary, FullBlock), String> {
        let expected_height = self.storage.tip_height().saturating_add(1);
        if block.height != expected_height {
            return Err(format!(
                "Height mismatch: expected {}, got {}",
                expected_height, block.height
            ));
        }
        if block.prev_hash != self.storage.tip_hash() {
            return Err("Block prev_hash does not match local chain tip".to_string());
        }
        if block.state_root != self.storage.compute_state_root() {
            return Err("Block pre-state_root mismatch".to_string());
        }

        let block_hash = block.pow_hash();
        if !U256::meets_target(block_hash, self.current_target) {
            return Err("Block Proof-of-Work fails current ASERT target".to_string());
        }

        let chain_id = self.mode.chain_id();
        let min_fee = self.mempool.min_fee_atomic();

        let mut seen_spends: HashSet<OutPoint> = HashSet::new();
        let mut total_fees: u128 = 0;
        let mut spends: Vec<OutPoint> = Vec::new();
        let mut spent_details: Vec<(OutPoint, UtxoEntry)> = Vec::new();
        let mut tx_creates: Vec<(OutPoint, UtxoEntry)> = Vec::new();
        let mut confirmed_txids: Vec<[u8; 32]> = Vec::with_capacity(block.txs.len());

        for tx in &block.txs {
            if tx.chain_id != chain_id {
                return Err("Block contains transaction with wrong chain_id".to_string());
            }
            tx.verify_signatures()?;
            let txid = tx.txid();

            let mut total_in: u128 = 0;
            for inp in &tx.inputs {
                let op = inp.outpoint();
                if !seen_spends.insert(op) {
                    return Err("Double-spend detected inside synced block".to_string());
                }
                let utxo = self
                    .storage
                    .get_utxo(&op)
                    .ok_or_else(|| "Block tx references missing or spent UTXO".to_string())?;
                if hash160(&inp.pubkey) != utxo.script_hash160 {
                    return Err("Block tx pubkey does not match UTXO owner".to_string());
                }
                total_in = total_in
                    .checked_add(utxo.value_atomic)
                    .ok_or_else(|| "Block tx input overflow".to_string())?;
                spends.push(op);
                spent_details.push((op, utxo));
            }

            let mut total_out: u128 = 0;
            for (vout, out) in tx.outputs.iter().enumerate() {
                if out.value_atomic == 0 {
                    return Err("Block tx contains zero-value output".to_string());
                }
                total_out = total_out
                    .checked_add(out.value_atomic)
                    .ok_or_else(|| "Block tx output overflow".to_string())?;
                tx_creates.push((
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    UtxoEntry {
                        value_atomic: out.value_atomic,
                        script_hash160: out.script_hash160,
                        height: block.height,
                        is_coinbase: false,
                    },
                ));
            }

            if total_in < total_out {
                return Err("Block tx outputs exceed inputs".to_string());
            }
            let fee = total_in - total_out;
            if fee < min_fee {
                return Err("Block tx fee below minimum policy".to_string());
            }
            total_fees = total_fees.saturating_add(fee);
            confirmed_txids.push(txid);
        }

        let split = calculate_block_subsidy(self.already_mined_atomic)
            .map_err(|e| format!("Subsidy calculation error: {:?}", e))?;

        let mut tx_h = Sha256::new();
        tx_h.update(b"EQX_COINBASE_TX_V1");
        tx_h.update(&block.height.to_le_bytes());
        tx_h.update(&block_hash);
        let coinbase_txid: [u8; 32] = tx_h.finalize().into();

        let miner_total = split.miner_reward.saturating_add(total_fees);
        let mut creates = Vec::with_capacity(2 + tx_creates.len());
        if miner_total > 0 {
            creates.push((
                OutPoint {
                    txid: coinbase_txid,
                    vout: 0,
                },
                UtxoEntry {
                    value_atomic: miner_total,
                    script_hash160: block.miner_h160,
                    height: block.height,
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
                    height: block.height,
                    is_coinbase: true,
                },
            ));
        }
        creates.extend(tx_creates);

        let batch = WriteBatch {
            height: block.height,
            block_hash,
            spends: spends.clone(),
            creates: creates.clone(),
        };
        self.storage
            .apply_block_batch(&batch)
            .map_err(|e| format!("WAL commit failed: {:?}", e))?;

        for (op, spent_entry) in spent_details {
            let owner_addr = encode_from_hash160(&spent_entry.script_hash160);
            if let Some(bal) = self.balances.get_mut(&owner_addr) {
                *bal = bal.saturating_sub(spent_entry.value_atomic);
            }
            if let Some(list) = self.utxo_index.get_mut(&spent_entry.script_hash160) {
                list.retain(|(existing_op, _)| *existing_op != op);
            }
        }
        for (op, new_entry) in creates {
            let owner_addr = encode_from_hash160(&new_entry.script_hash160);
            *self.balances.entry(owner_addr).or_insert(0) += new_entry.value_atomic;
            self.utxo_index
                .entry(new_entry.script_hash160)
                .or_default()
                .push((op, new_entry.value_atomic));
        }

        let included_user_txs = confirmed_txids.len() as u32;
        self.mempool.remove_confirmed(&confirmed_txids);
        self.mempool.prune_spent_outpoints(&spends);

        self.already_mined_atomic = self
            .already_mined_atomic
            .saturating_add(split.total_subsidy);
        self.total_txns = self
            .total_txns
            .saturating_add(1 + included_user_txs as u64);
        self.last_block_timestamp = block.timestamp;

        // Deterministic ASERT anchor locked to Block #1 timestamp so all synced nodes compute identical targets
        if block.height == 1 {
            self.anchor_height = 1;
            self.anchor_timestamp = block.timestamp;
            self.anchor_target = self.current_target;
        } else if self.anchor_height == 1 {
            if let Ok(next_t) = self.asert.calculate_next_target(
                self.anchor_height,
                self.anchor_timestamp,
                self.anchor_target,
                block.height,
                block.timestamp,
            ) {
                self.current_target = next_t;
            }
        }

        let _ = append_saved_block(&self.blocks_path, &block);
        self.blocks_by_height.insert(block.height, block.clone());

        let summary = BlockSummary {
            height: block.height,
            hash_hex: to_hex(&block_hash),
            nonce: block.nonce,
            timestamp: block.timestamp,
            miner_reward_atomic: miner_total,
            dao_reward_atomic: split.dao_treasury_reward,
            tx_count: 1 + included_user_txs,
        };
        self.recent_blocks.push(summary.clone());
        if self.recent_blocks.len() > 50 {
            self.recent_blocks.remove(0);
        }
        Ok((summary, block))
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
