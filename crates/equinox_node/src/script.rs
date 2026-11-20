#![forbid(unsafe_code)]

use std::collections::HashSet;

use equinox_crypto::address::hash160;
use sha2::{Digest, Sha256};

pub const MAX_MULTISIG_SIGNERS: usize = 7;
pub const MAX_DATA_ANCHOR_BYTES: usize = 128;
pub const MAX_DOC_METADATA_BYTES: usize = 64;
pub const NAME_REGISTRATION_MIN_FEE_ATOMIC: u128 = 100_000; // 0.001 EQX anti-squatting fee
pub const NAME_LEASE_BLOCKS: u64 = 2_102_400; // ~1 year at 15-second block interval

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockCondition {
    /// Standard single-signature address lock (100% compatible with EQX Base58Check addresses)
    P2PKH([u8; 20]),
    /// M-of-N Multi-Signature lock (DAO treasury, business wallets, cooperative escrow)
    MultiSig {
        threshold: u8,
        signers: Vec<[u8; 20]>,
    },
    /// Block-height locked output (Digital inheritance heartbeat, vesting, channel lock)
    Timelock {
        unlock_height: u64,
        recipient: [u8; 20],
    },
    /// M-of-N Escrow with trustless timeout refund fallback if counterparty disappears
    Escrow {
        threshold: u8,
        signers: Vec<[u8; 20]>,
        refund_height: u64,
        refund_recipient: [u8; 20],
    },
}

impl LockCondition {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            LockCondition::P2PKH(_) => Ok(()),
            LockCondition::MultiSig { threshold, signers } => {
                validate_multisig_params(*threshold, signers)
            }
            LockCondition::Timelock { unlock_height, .. } => {
                if *unlock_height == 0 {
                    return Err("Timelock unlock_height must be greater than 0".to_string());
                }
                Ok(())
            }
            LockCondition::Escrow {
                threshold,
                signers,
                refund_height,
                ..
            } => {
                validate_multisig_params(*threshold, signers)?;
                if *refund_height == 0 {
                    return Err("Escrow refund_height must be greater than 0".to_string());
                }
                Ok(())
            }
        }
    }

    /// Returns the deterministic 20-byte UTXO commitment hash stored in UtxoStorageEngine.
    pub fn script_hash160(&self) -> [u8; 20] {
        match self {
            LockCondition::P2PKH(h160) => *h160,
            other => {
                let mut h = Sha256::new();
                h.update(b"EQX_LOCK_SCRIPT_V1");
                h.update(&other.encode_bytes());
                let digest: [u8; 32] = h.finalize().into();
                hash160(&digest)
            }
        }
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        match self {
            LockCondition::P2PKH(h160) => {
                buf.push(0x01);
                buf.extend_from_slice(h160);
            }
            LockCondition::MultiSig { threshold, signers } => {
                buf.push(0x02);
                buf.push(*threshold);
                buf.push(signers.len() as u8);
                for s in signers {
                    buf.extend_from_slice(s);
                }
            }
            LockCondition::Timelock {
                unlock_height,
                recipient,
            } => {
                buf.push(0x03);
                buf.extend_from_slice(&unlock_height.to_le_bytes());
                buf.extend_from_slice(recipient);
            }
            LockCondition::Escrow {
                threshold,
                signers,
                refund_height,
                refund_recipient,
            } => {
                buf.push(0x04);
                buf.push(*threshold);
                buf.push(signers.len() as u8);
                for s in signers {
                    buf.extend_from_slice(s);
                }
                buf.extend_from_slice(&refund_height.to_le_bytes());
                buf.extend_from_slice(refund_recipient);
            }
        }
        buf
    }

    pub fn decode_bytes(raw: &[u8]) -> Result<(Self, usize), String> {
        if raw.is_empty() {
            return Err("Empty LockCondition bytes".to_string());
        }
        match raw[0] {
            0x01 => {
                if raw.len() < 21 {
                    return Err("Truncated P2PKH LockCondition".to_string());
                }
                let h160: [u8; 20] = raw[1..21].try_into().unwrap();
                Ok((LockCondition::P2PKH(h160), 21))
            }
            0x02 => {
                if raw.len() < 3 {
                    return Err("Truncated MultiSig LockCondition".to_string());
                }
                let threshold = raw[1];
                let count = raw[2] as usize;
                if count == 0 || count > MAX_MULTISIG_SIGNERS {
                    return Err("Invalid MultiSig signer count".to_string());
                }
                let total = 3 + count * 20;
                if raw.len() < total {
                    return Err("Truncated MultiSig signers".to_string());
                }
                let mut signers = Vec::with_capacity(count);
                for i in 0..count {
                    let start = 3 + i * 20;
                    signers.push(raw[start..start + 20].try_into().unwrap());
                }
                let cond = LockCondition::MultiSig { threshold, signers };
                cond.validate()?;
                Ok((cond, total))
            }
            0x03 => {
                if raw.len() < 29 {
                    return Err("Truncated Timelock LockCondition".to_string());
                }
                let unlock_height = u64::from_le_bytes(raw[1..9].try_into().unwrap());
                let recipient: [u8; 20] = raw[9..29].try_into().unwrap();
                let cond = LockCondition::Timelock {
                    unlock_height,
                    recipient,
                };
                cond.validate()?;
                Ok((cond, 29))
            }
            0x04 => {
                if raw.len() < 3 {
                    return Err("Truncated Escrow LockCondition".to_string());
                }
                let threshold = raw[1];
                let count = raw[2] as usize;
                if count == 0 || count > MAX_MULTISIG_SIGNERS {
                    return Err("Invalid Escrow signer count".to_string());
                }
                let signers_end = 3 + count * 20;
                let total = signers_end + 28;
                if raw.len() < total {
                    return Err("Truncated Escrow fields".to_string());
                }
                let mut signers = Vec::with_capacity(count);
                for i in 0..count {
                    let start = 3 + i * 20;
                    signers.push(raw[start..start + 20].try_into().unwrap());
                }
                let refund_height =
                    u64::from_le_bytes(raw[signers_end..signers_end + 8].try_into().unwrap());
                let refund_recipient: [u8; 20] =
                    raw[signers_end + 8..signers_end + 28].try_into().unwrap();
                let cond = LockCondition::Escrow {
                    threshold,
                    signers,
                    refund_height,
                    refund_recipient,
                };
                cond.validate()?;
                Ok((cond, total))
            }
            _ => Err("Unknown LockCondition tag".to_string()),
        }
    }
}

fn validate_multisig_params(threshold: u8, signers: &[[u8; 20]]) -> Result<(), String> {
    if threshold == 0 {
        return Err("MultiSig threshold must be at least 1".to_string());
    }
    if signers.is_empty() || signers.len() > MAX_MULTISIG_SIGNERS {
        return Err("MultiSig signers count out of bounds (1..=7)".to_string());
    }
    if (threshold as usize) > signers.len() {
        return Err("MultiSig threshold exceeds signer count".to_string());
    }
    let mut unique = HashSet::with_capacity(signers.len());
    for s in signers {
        if !unique.insert(*s) {
            return Err("Duplicate signer in MultiSig/Escrow condition".to_string());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataAnchor {
    /// Proof-of-Existence / Anti-Deepfake SHA-256 or pHash anchor with short UTF-8 metadata
    DocumentProof {
        doc_hash: [u8; 32],
        metadata: Vec<u8>,
    },
    /// Human-readable identity handle registration (@name.eqx -> owner_h160)
    NameRegister {
        name: String,
        owner_h160: [u8; 20],
    },
    /// General OP_RETURN payload (up to 128 bytes: x402 receipt, software license tag, etc.)
    RawData(Vec<u8>),
}

impl DataAnchor {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            DataAnchor::DocumentProof { metadata, .. } => {
                if metadata.len() > MAX_DOC_METADATA_BYTES {
                    return Err("DocumentProof metadata exceeds 64-byte limit".to_string());
                }
                Ok(())
            }
            DataAnchor::NameRegister { name, .. } => {
                if !is_valid_eqx_name(name) {
                    return Err(
                        "Invalid @name.eqx handle (3-24 lowercase a-z, 0-9, _ ; cannot start/end with _)"
                            .to_string(),
                    );
                }
                Ok(())
            }
            DataAnchor::RawData(bytes) => {
                if bytes.is_empty() || bytes.len() > MAX_DATA_ANCHOR_BYTES {
                    return Err("RawData anchor must be 1..=128 bytes".to_string());
                }
                Ok(())
            }
        }
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        match self {
            DataAnchor::DocumentProof { doc_hash, metadata } => {
                buf.push(0x01);
                buf.extend_from_slice(doc_hash);
                buf.push(metadata.len() as u8);
                buf.extend_from_slice(metadata);
            }
            DataAnchor::NameRegister { name, owner_h160 } => {
                buf.push(0x02);
                let name_bytes = name.as_bytes();
                buf.push(name_bytes.len() as u8);
                buf.extend_from_slice(name_bytes);
                buf.extend_from_slice(owner_h160);
            }
            DataAnchor::RawData(bytes) => {
                buf.push(0x03);
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
            }
        }
        buf
    }

    pub fn decode_bytes(raw: &[u8]) -> Result<(Self, usize), String> {
        if raw.is_empty() {
            return Err("Empty DataAnchor bytes".to_string());
        }
        match raw[0] {
            0x01 => {
                if raw.len() < 34 {
                    return Err("Truncated DocumentProof anchor".to_string());
                }
                let doc_hash: [u8; 32] = raw[1..33].try_into().unwrap();
                let meta_len = raw[33] as usize;
                if meta_len > MAX_DOC_METADATA_BYTES || raw.len() < 34 + meta_len {
                    return Err("Invalid DocumentProof metadata length".to_string());
                }
                let metadata = raw[34..34 + meta_len].to_vec();
                let anchor = DataAnchor::DocumentProof { doc_hash, metadata };
                anchor.validate()?;
                Ok((anchor, 34 + meta_len))
            }
            0x02 => {
                if raw.len() < 2 {
                    return Err("Truncated NameRegister anchor".to_string());
                }
                let name_len = raw[1] as usize;
                let total = 2 + name_len + 20;
                if name_len < 3 || name_len > 24 || raw.len() < total {
                    return Err("Invalid NameRegister anchor length".to_string());
                }
                let name = String::from_utf8(raw[2..2 + name_len].to_vec())
                    .map_err(|_| "NameRegister must be valid UTF-8".to_string())?;
                let owner_h160: [u8; 20] = raw[2 + name_len..total].try_into().unwrap();
                let anchor = DataAnchor::NameRegister { name, owner_h160 };
                anchor.validate()?;
                Ok((anchor, total))
            }
            0x03 => {
                if raw.len() < 2 {
                    return Err("Truncated RawData anchor".to_string());
                }
                let len = raw[1] as usize;
                if len == 0 || len > MAX_DATA_ANCHOR_BYTES || raw.len() < 2 + len {
                    return Err("Invalid RawData anchor length".to_string());
                }
                let bytes = raw[2..2 + len].to_vec();
                Ok((DataAnchor::RawData(bytes), 2 + len))
            }
            _ => Err("Unknown DataAnchor tag".to_string()),
        }
    }
}

pub fn is_valid_eqx_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 24 {
        return false;
    }
    if bytes[0] == b'_' || bytes[bytes.len() - 1] == b'_' {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

pub fn normalize_eqx_name(input: &str) -> Result<String, String> {
    let mut s = input.trim().to_ascii_lowercase();
    if let Some(stripped) = s.strip_prefix('@') {
        s = stripped.to_string();
    }
    if let Some(stripped) = s.strip_suffix(".eqx") {
        s = stripped.to_string();
    }
    if !is_valid_eqx_name(&s) {
        return Err("Invalid @name.eqx handle format".to_string());
    }
    Ok(s)
}

pub fn format_eqx_handle(name: &str) -> String {
    format!("@{}.eqx", name)
}

#[derive(Debug, Clone)]
pub struct NameRecord {
    pub name: String,
    pub owner_h160: [u8; 20],
    pub owner_address: String,
    pub registered_height: u64,
    pub expires_height: u64,
    pub txid_hex: String,
}

#[derive(Debug, Clone)]
pub struct DocumentProofRecord {
    pub doc_hash_hex: String,
    pub metadata_utf8: String,
    pub block_height: u64,
    pub timestamp: u64,
    pub txid_hex: String,
}

