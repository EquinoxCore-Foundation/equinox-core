#![forbid(unsafe_code)]

use equinox_crypto::signer::{verify_canonical, SecretSeed, DOMAIN_TX_MAINNET};
use equinox_storage::types::OutPoint;
use sha2::{Digest, Sha256};

pub const TX_VERSION: u8 = 1;
pub const MAX_TX_IO: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
}

impl TxInput {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.prev_txid,
            vout: self.prev_vout,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value_atomic: u128,
    pub script_hash160: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub version: u8,
    pub chain_id: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

impl SignedTransaction {
    /// Deterministic sighash preimage committing to version, chain_id, input outpoints, and outputs.
    pub fn signing_payload(&self) -> Vec<u8> {
        let cap = 32 + self.inputs.len() * 36 + self.outputs.len() * 36;
        let mut buf = Vec::with_capacity(cap);
        buf.extend_from_slice(b"EQX_SIGHASH_V1");
        buf.push(self.version);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&(self.inputs.len() as u16).to_le_bytes());
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.prev_txid);
            buf.extend_from_slice(&inp.prev_vout.to_le_bytes());
        }
        buf.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for out in &self.outputs {
            buf.extend_from_slice(&out.value_atomic.to_le_bytes());
            buf.extend_from_slice(&out.script_hash160);
        }
        buf
    }

    pub fn sign_transfer(
        seed: &SecretSeed,
        chain_id: u64,
        spend_outpoints: Vec<OutPoint>,
        outputs: Vec<TxOutput>,
    ) -> Result<Self, String> {
        if spend_outpoints.is_empty() || spend_outpoints.len() > MAX_TX_IO {
            return Err("Invalid input count".to_string());
        }
        if outputs.is_empty() || outputs.len() > MAX_TX_IO {
            return Err("Invalid output count".to_string());
        }

        let pubkey = seed.public_key_bytes();
        let inputs = spend_outpoints
            .into_iter()
            .map(|op| TxInput {
                prev_txid: op.txid,
                prev_vout: op.vout,
                pubkey,
                signature: [0u8; 64],
            })
            .collect();

        let mut tx = Self {
            version: TX_VERSION,
            chain_id,
            inputs,
            outputs,
        };
        let sighash_msg = tx.signing_payload();
        let sig = seed.sign_domain(DOMAIN_TX_MAINNET, &sighash_msg);
        for inp in &mut tx.inputs {
            inp.signature = sig;
        }
        Ok(tx)
    }

    pub fn verify_signatures(&self) -> Result<(), String> {
        if self.version != TX_VERSION {
            return Err("Unsupported transaction version".to_string());
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_TX_IO {
            return Err("Invalid transaction input count".to_string());
        }
        if self.outputs.is_empty() || self.outputs.len() > MAX_TX_IO {
            return Err("Invalid transaction output count".to_string());
        }
        let sighash_msg = self.signing_payload();
        for inp in &self.inputs {
            verify_canonical(&inp.pubkey, DOMAIN_TX_MAINNET, &sighash_msg, &inp.signature)
                .map_err(|_| "Invalid canonical Ed25519 input signature".to_string())?;
        }
        Ok(())
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let cap = 13 + self.inputs.len() * 132 + self.outputs.len() * 36;
        let mut buf = Vec::with_capacity(cap);
        buf.push(self.version);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&(self.inputs.len() as u16).to_le_bytes());
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.prev_txid);
            buf.extend_from_slice(&inp.prev_vout.to_le_bytes());
            buf.extend_from_slice(&inp.pubkey);
            buf.extend_from_slice(&inp.signature);
        }
        buf.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for out in &self.outputs {
            buf.extend_from_slice(&out.value_atomic.to_le_bytes());
            buf.extend_from_slice(&out.script_hash160);
        }
        buf
    }

    pub fn decode_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 13 {
            return Err("Transaction payload too short".to_string());
        }
        let version = raw[0];
        if version != TX_VERSION {
            return Err("Unsupported transaction version".to_string());
        }
        let chain_id = u64::from_le_bytes(raw[1..9].try_into().unwrap());
        let in_count = u16::from_le_bytes([raw[9], raw[10]]) as usize;
        if in_count == 0 || in_count > MAX_TX_IO {
            return Err("Invalid input count".to_string());
        }

        let mut offset = 11usize;
        let in_bytes = in_count.saturating_mul(132);
        if raw.len() < offset.saturating_add(in_bytes).saturating_add(2) {
            return Err("Truncated transaction inputs".to_string());
        }

        let mut inputs = Vec::with_capacity(in_count);
        for _ in 0..in_count {
            let prev_txid: [u8; 32] = raw[offset..offset + 32].try_into().unwrap();
            let prev_vout = u32::from_le_bytes(raw[offset + 32..offset + 36].try_into().unwrap());
            let pubkey: [u8; 32] = raw[offset + 36..offset + 68].try_into().unwrap();
            let signature: [u8; 64] = raw[offset + 68..offset + 132].try_into().unwrap();
            inputs.push(TxInput {
                prev_txid,
                prev_vout,
                pubkey,
                signature,
            });
            offset += 132;
        }

        let out_count = u16::from_le_bytes([raw[offset], raw[offset + 1]]) as usize;
        offset += 2;
        if out_count == 0 || out_count > MAX_TX_IO {
            return Err("Invalid output count".to_string());
        }

        let out_bytes = out_count.saturating_mul(36);
        if raw.len() != offset.saturating_add(out_bytes) {
            return Err("Invalid transaction output byte length".to_string());
        }

        let mut outputs = Vec::with_capacity(out_count);
        for _ in 0..out_count {
            let value_atomic = u128::from_le_bytes(raw[offset..offset + 16].try_into().unwrap());
            let script_hash160: [u8; 20] = raw[offset + 16..offset + 36].try_into().unwrap();
            outputs.push(TxOutput {
                value_atomic,
                script_hash160,
            });
            offset += 36;
        }

        Ok(Self {
            version,
            chain_id,
            inputs,
            outputs,
        })
    }

    pub fn txid(&self) -> [u8; 32] {
        let encoded = self.encode_bytes();
        let first = Sha256::digest(&encoded);
        Sha256::digest(first).into()
    }
}
