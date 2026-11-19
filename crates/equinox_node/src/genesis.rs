#![forbid(unsafe_code)]

use equinox_consensus::{ATOMIC_UNITS_PER_EQX, CHAIN_ID_MAINNET, GENESIS_PREMINE_ATOMIC};
use equinox_crypto::address::decode_and_verify_address;
use equinox_storage::types::{OutPoint, UtxoEntry, WriteBatch};
use sha2::{Digest, Sha256};

pub const FOUNDER_VAULT_ATOMIC: u128 = 1_200_000 * ATOMIC_UNITS_PER_EQX;
pub const LIQUIDITY_VAULT_ATOMIC: u128 = 400_000 * ATOMIC_UNITS_PER_EQX;
pub const DEVELOPER_VAULT_ATOMIC: u128 = 200_000 * ATOMIC_UNITS_PER_EQX;
pub const MARKETING_VAULT_ATOMIC: u128 = 200_000 * ATOMIC_UNITS_PER_EQX;

#[derive(Debug, Clone)]
pub struct GenesisVaultSpec {
    pub founder_address: String,
    pub liquidity_address: String,
    pub developer_address: String,
    pub marketing_address: String,
    pub timestamp_utc: u64,
}

#[derive(Debug, Clone)]
pub struct GenesisAllocationResult {
    pub block_hash: [u8; 32],
    pub write_batch: WriteBatch,
    pub total_premine_atomic: u128,
}

pub fn build_mainnet_genesis_batch(spec: &GenesisVaultSpec) -> Result<GenesisAllocationResult, String> {
    let total = FOUNDER_VAULT_ATOMIC
        .checked_add(LIQUIDITY_VAULT_ATOMIC)
        .and_then(|v| v.checked_add(DEVELOPER_VAULT_ATOMIC))
        .and_then(|v| v.checked_add(MARKETING_VAULT_ATOMIC))
        .ok_or_else(|| "Premine arithmetic overflow".to_string())?;

    if total != GENESIS_PREMINE_ATOMIC {
        return Err("Genesis premine total does not match 2,000,000 EQX hard rule".to_string());
    }

    let allocations = [
        (&spec.founder_address, FOUNDER_VAULT_ATOMIC, 0u32),
        (&spec.liquidity_address, LIQUIDITY_VAULT_ATOMIC, 1u32),
        (&spec.developer_address, DEVELOPER_VAULT_ATOMIC, 2u32),
        (&spec.marketing_address, MARKETING_VAULT_ATOMIC, 3u32),
    ];

    // Ensure all 4 vault addresses are valid Base58Check 'E...' addresses and distinct
    let mut hashes = Vec::with_capacity(4);
    for (addr, _, _) in &allocations {
        let h160 = decode_and_verify_address(addr)
            .map_err(|_| format!("Invalid Base58Check EQX address: {}", addr))?;
        if hashes.contains(&h160) {
            return Err("All 4 mainnet genesis vaults must use distinct addresses".to_string());
        }
        hashes.push(h160);
    }

    // Deterministic Genesis TXID & Block #0 Hash
    let mut tx_hasher = Sha256::new();
    tx_hasher.update(b"EQX_MAINNET_GENESIS_TX_V1");
    tx_hasher.update(&CHAIN_ID_MAINNET.to_le_bytes());
    tx_hasher.update(&spec.timestamp_utc.to_le_bytes());
    for (idx, (_, amount, _)) in allocations.iter().enumerate() {
        tx_hasher.update(&hashes[idx]);
        tx_hasher.update(&amount.to_le_bytes());
    }
    let genesis_txid: [u8; 32] = tx_hasher.finalize().into();

    let mut blk_hasher = Sha256::new();
    blk_hasher.update(b"EQX_MAINNET_BLOCK_0_V1");
    blk_hasher.update(&CHAIN_ID_MAINNET.to_le_bytes());
    blk_hasher.update(&spec.timestamp_utc.to_le_bytes());
    blk_hasher.update(&genesis_txid);
    let block_hash: [u8; 32] = blk_hasher.finalize().into();

    let mut creates = Vec::with_capacity(4);
    for (idx, (_, amount, vout)) in allocations.iter().enumerate() {
        creates.push((
            OutPoint {
                txid: genesis_txid,
                vout: *vout,
            },
            UtxoEntry {
                value_atomic: *amount,
                script_hash160: hashes[idx],
                height: 0,
                is_coinbase: true,
            },
        ));
    }

    Ok(GenesisAllocationResult {
        block_hash,
        write_batch: WriteBatch {
            height: 0,
            block_hash,
            spends: Vec::new(),
            creates,
        },
        total_premine_atomic: total,
    })
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim().strip_prefix("0x").unwrap_or(hex.trim());
    if clean.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|_| "Invalid UTF-8 hex".to_string())?;
        let val = u8::from_str_radix(pair, 16).map_err(|_| "Invalid hex character".to_string())?;
        out.push(val);
        i += 2;
    }
    Ok(out)
}