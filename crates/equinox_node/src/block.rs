#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

use crate::tx::SignedTransaction;

pub const MAX_BLOCK_TXS: usize = 500;
pub const MAX_SINGLE_TX_BYTES: usize = 60_000;

/// Computes deterministic Double-SHA256 PoW header hash shared by Miner and P2P Sync Verifier.
pub fn compute_header_pow_hash(
    height: u64,
    prev_hash: &[u8; 32],
    state_root: &[u8; 32],
    miner_h160: &[u8; 20],
    timestamp: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut h1 = Sha256::new();
    h1.update(b"EQX_POW_HDR_V1");
    h1.update(&height.to_le_bytes());
    h1.update(prev_hash);
    h1.update(state_root);
    h1.update(miner_h160);
    h1.update(&timestamp.to_le_bytes());
    h1.update(&nonce.to_le_bytes());
    let first = h1.finalize();

    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullBlock {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub miner_h160: [u8; 20],
    pub timestamp: u64,
    pub nonce: u64,
    pub txs: Vec<SignedTransaction>,
}

impl FullBlock {
    pub fn pow_hash(&self) -> [u8; 32] {
        compute_header_pow_hash(
            self.height,
            &self.prev_hash,
            &self.state_root,
            &self.miner_h160,
            self.timestamp,
            self.nonce,
        )
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(110 + self.txs.len() * 220);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.prev_hash);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.miner_h160);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&(self.txs.len() as u16).to_le_bytes());
        for tx in &self.txs {
            let raw = tx.encode_bytes();
            buf.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            buf.extend_from_slice(&raw);
        }
        buf
    }

    pub fn decode_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 110 {
            return Err("Block payload too short".to_string());
        }
        let height = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let prev_hash: [u8; 32] = raw[8..40].try_into().unwrap();
        let state_root: [u8; 32] = raw[40..72].try_into().unwrap();
        let miner_h160: [u8; 20] = raw[72..92].try_into().unwrap();
        let timestamp = u64::from_le_bytes(raw[92..100].try_into().unwrap());
        let nonce = u64::from_le_bytes(raw[100..108].try_into().unwrap());
        let tx_count = u16::from_le_bytes([raw[108], raw[109]]) as usize;
        if tx_count > MAX_BLOCK_TXS {
            return Err("Block transaction count exceeds limit".to_string());
        }

        let mut offset = 110usize;
        let mut txs = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            if raw.len() < offset + 4 {
                return Err("Truncated block transaction length".to_string());
            }
            let tx_len = u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if tx_len == 0 || tx_len > MAX_SINGLE_TX_BYTES || raw.len() < offset + tx_len {
                return Err("Invalid or truncated block transaction bytes".to_string());
            }
            let tx = SignedTransaction::decode_bytes(&raw[offset..offset + tx_len])?;
            txs.push(tx);
            offset += tx_len;
        }
        if offset != raw.len() {
            return Err("Trailing bytes in block payload".to_string());
        }

        Ok(Self {
            height,
            prev_hash,
            state_root,
            miner_h160,
            timestamp,
            nonce,
            txs,
        })
    }
}
