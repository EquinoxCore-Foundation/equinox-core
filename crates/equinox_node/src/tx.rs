#![forbid(unsafe_code)]

use std::collections::HashSet;

use equinox_crypto::address::hash160;
use equinox_crypto::signer::{verify_canonical, SecretSeed, DOMAIN_TX_MAINNET};
use equinox_storage::types::OutPoint;
use sha2::{Digest, Sha256};

use crate::script::{DataAnchor, LockCondition, MAX_MULTISIG_SIGNERS};

pub const TX_VERSION_V2: u8 = 2;
pub const MAX_TX_IO: usize = 64;
pub const MAX_ANCHORS_PER_TX: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockProof {
    P2PKH {
        pubkey: [u8; 32],
        signature: [u8; 64],
    },
    MultiSig {
        condition: LockCondition,
        signatures: Vec<([u8; 32], [u8; 64])>,
    },
    Timelock {
        unlock_height: u64,
        pubkey: [u8; 32],
        signature: [u8; 64],
    },
    EscrowRelease {
        condition: LockCondition,
        signatures: Vec<([u8; 32], [u8; 64])>,
    },
    EscrowRefund {
        condition: LockCondition,
        pubkey: [u8; 32],
        signature: [u8; 64],
    },
}

impl UnlockProof {
    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        match self {
            UnlockProof::P2PKH { pubkey, signature } => {
                buf.push(0x01);
                buf.extend_from_slice(pubkey);
                buf.extend_from_slice(signature);
            }
            UnlockProof::MultiSig {
                condition,
                signatures,
            } => {
                buf.push(0x02);
                buf.extend_from_slice(&condition.encode_bytes());
                buf.push(signatures.len() as u8);
                for (pk, sig) in signatures {
                    buf.extend_from_slice(pk);
                    buf.extend_from_slice(sig);
                }
            }
            UnlockProof::Timelock {
                unlock_height,
                pubkey,
                signature,
            } => {
                buf.push(0x03);
                buf.extend_from_slice(&unlock_height.to_le_bytes());
                buf.extend_from_slice(pubkey);
                buf.extend_from_slice(signature);
            }
            UnlockProof::EscrowRelease {
                condition,
                signatures,
            } => {
                buf.push(0x04);
                buf.extend_from_slice(&condition.encode_bytes());
                buf.push(signatures.len() as u8);
                for (pk, sig) in signatures {
                    buf.extend_from_slice(pk);
                    buf.extend_from_slice(sig);
                }
            }
            UnlockProof::EscrowRefund {
                condition,
                pubkey,
                signature,
            } => {
                buf.push(0x05);
                buf.extend_from_slice(&condition.encode_bytes());
                buf.extend_from_slice(pubkey);
                buf.extend_from_slice(signature);
            }
        }
        buf
    }

    pub fn decode_bytes(raw: &[u8]) -> Result<(Self, usize), String> {
        if raw.is_empty() {
            return Err("Empty UnlockProof bytes".to_string());
        }
        match raw[0] {
            0x01 => {
                if raw.len() < 97 {
                    return Err("Truncated P2PKH UnlockProof".to_string());
                }
                let pubkey: [u8; 32] = raw[1..33].try_into().unwrap();
                let signature: [u8; 64] = raw[33..97].try_into().unwrap();
                Ok((UnlockProof::P2PKH { pubkey, signature }, 97))
            }
            0x02 | 0x04 => {
                let tag = raw[0];
                let (condition, consumed) = LockCondition::decode_bytes(&raw[1..])?;
                let mut offset = 1 + consumed;
                if raw.len() < offset + 1 {
                    return Err("Truncated MultiSig/Escrow sig count".to_string());
                }
                let sig_count = raw[offset] as usize;
                offset += 1;
                if sig_count == 0 || sig_count > MAX_MULTISIG_SIGNERS {
                    return Err("Invalid MultiSig/Escrow signature count".to_string());
                }
                if raw.len() < offset + sig_count * 96 {
                    return Err("Truncated MultiSig/Escrow signatures".to_string());
                }
                let mut signatures = Vec::with_capacity(sig_count);
                for _ in 0..sig_count {
                    let pk: [u8; 32] = raw[offset..offset + 32].try_into().unwrap();
                    let sig: [u8; 64] = raw[offset + 32..offset + 96].try_into().unwrap();
                    signatures.push((pk, sig));
                    offset += 96;
                }
                let proof = if tag == 0x02 {
                    UnlockProof::MultiSig {
                        condition,
                        signatures,
                    }
                } else {
                    UnlockProof::EscrowRelease {
                        condition,
                        signatures,
                    }
                };
                Ok((proof, offset))
            }
            0x03 => {
                if raw.len() < 105 {
                    return Err("Truncated Timelock UnlockProof".to_string());
                }
                let unlock_height = u64::from_le_bytes(raw[1..9].try_into().unwrap());
                let pubkey: [u8; 32] = raw[9..41].try_into().unwrap();
                let signature: [u8; 64] = raw[41..105].try_into().unwrap();
                Ok((
                    UnlockProof::Timelock {
                        unlock_height,
                        pubkey,
                        signature,
                    },
                    105,
                ))
            }
            0x05 => {
                let (condition, consumed) = LockCondition::decode_bytes(&raw[1..])?;
                let offset = 1 + consumed;
                if raw.len() < offset + 96 {
                    return Err("Truncated EscrowRefund UnlockProof".to_string());
                }
                let pubkey: [u8; 32] = raw[offset..offset + 32].try_into().unwrap();
                let signature: [u8; 64] = raw[offset + 32..offset + 96].try_into().unwrap();
                Ok((
                    UnlockProof::EscrowRefund {
                        condition,
                        pubkey,
                        signature,
                    },
                    offset + 96,
                ))
            }
            _ => Err("Unknown UnlockProof tag".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub proof: UnlockProof,
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
pub enum OutputPayload {
    Lock(LockCondition),
    Anchor(DataAnchor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value_atomic: u128,
    pub payload: OutputPayload,
}

impl TxOutput {
    pub fn p2pkh(value_atomic: u128, script_hash160: [u8; 20]) -> Self {
        Self {
            value_atomic,
            payload: OutputPayload::Lock(LockCondition::P2PKH(script_hash160)),
        }
    }

    pub fn locked(value_atomic: u128, condition: LockCondition) -> Self {
        Self {
            value_atomic,
            payload: OutputPayload::Lock(condition),
        }
    }

    pub fn anchor(data: DataAnchor) -> Self {
        Self {
            value_atomic: 0,
            payload: OutputPayload::Anchor(data),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub version: u8,
    pub chain_id: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

fn verify_multisig_signatures(
    threshold: u8,
    authorized_signers: &[[u8; 20]],
    signatures: &[([u8; 32], [u8; 64])],
    sighash: &[u8; 32],
) -> Result<(), String> {
    if signatures.len() < (threshold as usize) {
        return Err(format!(
            "Insufficient signatures: need {}, got {}",
            threshold,
            signatures.len()
        ));
    }
    if signatures.len() > authorized_signers.len() {
        return Err("Too many signatures provided for MultiSig/Escrow".to_string());
    }
    let mut used_signers = HashSet::with_capacity(signatures.len());
    for (pk, sig) in signatures {
        let signer_h160 = hash160(pk);
        if !authorized_signers.contains(&signer_h160) {
            return Err("Signer public key is not authorized for this MultiSig/Escrow".to_string());
        }
        if !used_signers.insert(signer_h160) {
            return Err("Duplicate signature from the same signer rejected".to_string());
        }
        verify_canonical(pk, DOMAIN_TX_MAINNET, sighash, sig)
            .map_err(|_| "Invalid Ed25519 signature in MultiSig/Escrow".to_string())?;
    }
    Ok(())
}

impl SignedTransaction {
    /// Computes deterministic witness-free sighash so multi-party signers sign the exact same digest.
    pub fn sighash_from_parts(
        version: u8,
        chain_id: u64,
        outpoints: &[OutPoint],
        outputs: &[TxOutput],
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"EQX_TX_SIGHASH_V2");
        h.update([version]);
        h.update(&chain_id.to_le_bytes());
        h.update(&(outpoints.len() as u16).to_le_bytes());
        for op in outpoints {
            h.update(&op.txid);
            h.update(&op.vout.to_le_bytes());
        }
        h.update(&(outputs.len() as u16).to_le_bytes());
        for out in outputs {
            h.update(&out.value_atomic.to_le_bytes());
            match &out.payload {
                OutputPayload::Lock(cond) => {
                    h.update([0x01]);
                    h.update(&cond.encode_bytes());
                }
                OutputPayload::Anchor(anchor) => {
                    h.update([0x02]);
                    h.update(&anchor.encode_bytes());
                }
            }
        }
        h.finalize().into()
    }

    pub fn sighash(&self) -> [u8; 32] {
        let ops: Vec<OutPoint> = self.inputs.iter().map(|i| i.outpoint()).collect();
        Self::sighash_from_parts(self.version, self.chain_id, &ops, &self.outputs)
    }

    pub fn txid(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"EQX_TXID_V2");
        h.update(&self.encode_bytes());
        h.finalize().into()
    }

    pub fn sign_transfer(
        seed: &SecretSeed,
        chain_id: u64,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOutput>,
    ) -> Result<Self, String> {
        if inputs.is_empty() || outputs.is_empty() {
            return Err("Transaction requires at least 1 input and 1 output".to_string());
        }
        let sighash = Self::sighash_from_parts(TX_VERSION_V2, chain_id, &inputs, &outputs);
        let pubkey = seed.public_key_bytes();
        let signature = seed.sign_domain(DOMAIN_TX_MAINNET, &sighash);

        let signed_inputs = inputs
            .into_iter()
            .map(|op| TxInput {
                prev_txid: op.txid,
                prev_vout: op.vout,
                proof: UnlockProof::P2PKH { pubkey, signature },
            })
            .collect();

        let tx = Self {
            version: TX_VERSION_V2,
            chain_id,
            inputs: signed_inputs,
            outputs,
        };
        tx.verify_structure_and_outputs()?;
        Ok(tx)
    }

    pub fn sign_multisig_spend(
        seeds: &[&SecretSeed],
        condition: LockCondition,
        chain_id: u64,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOutput>,
    ) -> Result<Self, String> {
        if inputs.is_empty() || outputs.is_empty() {
            return Err("Transaction requires at least 1 input and 1 output".to_string());
        }
        condition.validate()?;
        let is_escrow = matches!(condition, LockCondition::Escrow { .. });
        let is_multisig = matches!(condition, LockCondition::MultiSig { .. });
        if !is_escrow && !is_multisig {
            return Err("Expected MultiSig or Escrow LockCondition".to_string());
        }

        let sighash = Self::sighash_from_parts(TX_VERSION_V2, chain_id, &inputs, &outputs);
        let signatures: Vec<([u8; 32], [u8; 64])> = seeds
            .iter()
            .map(|s| {
                (
                    s.public_key_bytes(),
                    s.sign_domain(DOMAIN_TX_MAINNET, &sighash),
                )
            })
            .collect();

        let signed_inputs = inputs
            .into_iter()
            .map(|op| TxInput {
                prev_txid: op.txid,
                prev_vout: op.vout,
                proof: if is_escrow {
                    UnlockProof::EscrowRelease {
                        condition: condition.clone(),
                        signatures: signatures.clone(),
                    }
                } else {
                    UnlockProof::MultiSig {
                        condition: condition.clone(),
                        signatures: signatures.clone(),
                    }
                },
            })
            .collect();

        let tx = Self {
            version: TX_VERSION_V2,
            chain_id,
            inputs: signed_inputs,
            outputs,
        };
        tx.verify_structure_and_outputs()?;
        Ok(tx)
    }

    pub fn sign_timelock_spend(
        seed: &SecretSeed,
        unlock_height: u64,
        chain_id: u64,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOutput>,
    ) -> Result<Self, String> {
        if inputs.is_empty() || outputs.is_empty() {
            return Err("Transaction requires at least 1 input and 1 output".to_string());
        }
        let sighash = Self::sighash_from_parts(TX_VERSION_V2, chain_id, &inputs, &outputs);
        let pubkey = seed.public_key_bytes();
        let signature = seed.sign_domain(DOMAIN_TX_MAINNET, &sighash);

        let signed_inputs = inputs
            .into_iter()
            .map(|op| TxInput {
                prev_txid: op.txid,
                prev_vout: op.vout,
                proof: UnlockProof::Timelock {
                    unlock_height,
                    pubkey,
                    signature,
                },
            })
            .collect();

        let tx = Self {
            version: TX_VERSION_V2,
            chain_id,
            inputs: signed_inputs,
            outputs,
        };
        tx.verify_structure_and_outputs()?;
        Ok(tx)
    }

    pub fn sign_escrow_refund(
        seed: &SecretSeed,
        condition: LockCondition,
        chain_id: u64,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOutput>,
    ) -> Result<Self, String> {
        if inputs.is_empty() || outputs.is_empty() {
            return Err("Transaction requires at least 1 input and 1 output".to_string());
        }
        if !matches!(condition, LockCondition::Escrow { .. }) {
            return Err("Expected Escrow LockCondition for refund".to_string());
        }
        condition.validate()?;

        let sighash = Self::sighash_from_parts(TX_VERSION_V2, chain_id, &inputs, &outputs);
        let pubkey = seed.public_key_bytes();
        let signature = seed.sign_domain(DOMAIN_TX_MAINNET, &sighash);

        let signed_inputs = inputs
            .into_iter()
            .map(|op| TxInput {
                prev_txid: op.txid,
                prev_vout: op.vout,
                proof: UnlockProof::EscrowRefund {
                    condition: condition.clone(),
                    pubkey,
                    signature,
                },
            })
            .collect();

        let tx = Self {
            version: TX_VERSION_V2,
            chain_id,
            inputs: signed_inputs,
            outputs,
        };
        tx.verify_structure_and_outputs()?;
        Ok(tx)
    }

    pub fn verify_structure_and_outputs(&self) -> Result<(), String> {
        if self.version != TX_VERSION_V2 {
            return Err(format!("Unsupported transaction version {}", self.version));
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_TX_IO {
            return Err("Invalid transaction input count".to_string());
        }
        if self.outputs.is_empty() || self.outputs.len() > MAX_TX_IO {
            return Err("Invalid transaction output count".to_string());
        }

        let mut anchor_count = 0usize;
        for out in &self.outputs {
            match &out.payload {
                OutputPayload::Lock(cond) => {
                    if out.value_atomic == 0 {
                        return Err("Zero-value spendable output rejected".to_string());
                    }
                    cond.validate()?;
                }
                OutputPayload::Anchor(anchor) => {
                    if out.value_atomic != 0 {
                        return Err("DataAnchor (OP_RETURN) output must have 0 value".to_string());
                    }
                    anchor.validate()?;
                    anchor_count += 1;
                    if anchor_count > MAX_ANCHORS_PER_TX {
                        return Err("Exceeded max DataAnchor outputs per transaction".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// Cryptographically verifies an input's UnlockProof against the UTXO commitment & block height.
    pub fn verify_input_proof(
        &self,
        input_idx: usize,
        sighash: &[u8; 32],
        utxo_script_hash160: [u8; 20],
        eval_height: u64,
    ) -> Result<(), String> {
        let inp = self
            .inputs
            .get(input_idx)
            .ok_or_else(|| "Input index out of bounds".to_string())?;

        match &inp.proof {
            UnlockProof::P2PKH { pubkey, signature } => {
                if hash160(pubkey) != utxo_script_hash160 {
                    return Err("Input pubkey does not match P2PKH UTXO owner".to_string());
                }
                verify_canonical(pubkey, DOMAIN_TX_MAINNET, sighash, signature)
                    .map_err(|_| "Invalid P2PKH Ed25519 signature".to_string())
            }
            UnlockProof::MultiSig {
                condition,
                signatures,
            } => {
                condition.validate()?;
                let LockCondition::MultiSig { threshold, signers } = condition else {
                    return Err("MultiSig proof requires MultiSig LockCondition".to_string());
                };
                if condition.script_hash160() != utxo_script_hash160 {
                    return Err("MultiSig condition hash does not match UTXO lock".to_string());
                }
                verify_multisig_signatures(*threshold, signers, signatures, sighash)
            }
            UnlockProof::Timelock {
                unlock_height,
                pubkey,
                signature,
            } => {
                if eval_height < *unlock_height {
                    return Err(format!(
                        "Timelock not yet matured: current height {} < unlock height {}",
                        eval_height, unlock_height
                    ));
                }
                let cond = LockCondition::Timelock {
                    unlock_height: *unlock_height,
                    recipient: hash160(pubkey),
                };
                cond.validate()?;
                if cond.script_hash160() != utxo_script_hash160 {
                    return Err("Timelock condition hash does not match UTXO lock".to_string());
                }
                verify_canonical(pubkey, DOMAIN_TX_MAINNET, sighash, signature)
                    .map_err(|_| "Invalid Timelock Ed25519 signature".to_string())
            }
            UnlockProof::EscrowRelease {
                condition,
                signatures,
            } => {
                condition.validate()?;
                let LockCondition::Escrow {
                    threshold, signers, ..
                } = condition
                else {
                    return Err("EscrowRelease proof requires Escrow LockCondition".to_string());
                };
                if condition.script_hash160() != utxo_script_hash160 {
                    return Err("Escrow condition hash does not match UTXO lock".to_string());
                }
                verify_multisig_signatures(*threshold, signers, signatures, sighash)
            }
            UnlockProof::EscrowRefund {
                condition,
                pubkey,
                signature,
            } => {
                condition.validate()?;
                let LockCondition::Escrow {
                    refund_height,
                    refund_recipient,
                    ..
                } = condition
                else {
                    return Err("EscrowRefund proof requires Escrow LockCondition".to_string());
                };
                if eval_height < *refund_height {
                    return Err(format!(
                        "Escrow refund not yet matured: current height {} < refund height {}",
                        eval_height, refund_height
                    ));
                }
                if condition.script_hash160() != utxo_script_hash160 {
                    return Err("Escrow condition hash does not match UTXO lock".to_string());
                }
                if hash160(pubkey) != *refund_recipient {
                    return Err("Refund signer does not match Escrow refund_recipient".to_string());
                }
                verify_canonical(pubkey, DOMAIN_TX_MAINNET, sighash, signature)
                    .map_err(|_| "Invalid EscrowRefund Ed25519 signature".to_string())
            }
        }
    }

    /// Call only after all inputs have been verified with `verify_input_proof`.
    pub fn has_signer_hash160(&self, target: &[u8; 20]) -> bool {
        for inp in &self.inputs {
            match &inp.proof {
                UnlockProof::P2PKH { pubkey, .. }
                | UnlockProof::Timelock { pubkey, .. }
                | UnlockProof::EscrowRefund { pubkey, .. } => {
                    if &hash160(pubkey) == target {
                        return true;
                    }
                }
                UnlockProof::MultiSig { signatures, .. }
                | UnlockProof::EscrowRelease { signatures, .. } => {
                    if signatures.iter().any(|(pk, _)| &hash160(pk) == target) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(self.version);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&(self.inputs.len() as u16).to_le_bytes());
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.prev_txid);
            buf.extend_from_slice(&inp.prev_vout.to_le_bytes());
            buf.extend_from_slice(&inp.proof.encode_bytes());
        }
        buf.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for out in &self.outputs {
            buf.extend_from_slice(&out.value_atomic.to_le_bytes());
            match &out.payload {
                OutputPayload::Lock(cond) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&cond.encode_bytes());
                }
                OutputPayload::Anchor(anchor) => {
                    buf.push(0x02);
                    buf.extend_from_slice(&anchor.encode_bytes());
                }
            }
        }
        buf
    }

    pub fn decode_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 13 {
            return Err("Transaction payload too short".to_string());
        }
        let version = raw[0];
        if version != TX_VERSION_V2 {
            return Err(format!("Unsupported transaction version {}", version));
        }
        let chain_id = u64::from_le_bytes(raw[1..9].try_into().unwrap());
        let in_count = u16::from_le_bytes([raw[9], raw[10]]) as usize;
        if in_count == 0 || in_count > MAX_TX_IO {
            return Err("Invalid input count in encoded transaction".to_string());
        }

        let mut offset = 11usize;
        let mut inputs = Vec::with_capacity(in_count);
        for _ in 0..in_count {
            if raw.len() < offset + 36 {
                return Err("Truncated transaction input".to_string());
            }
            let prev_txid: [u8; 32] = raw[offset..offset + 32].try_into().unwrap();
            let prev_vout = u32::from_le_bytes(raw[offset + 32..offset + 36].try_into().unwrap());
            offset += 36;
            let (proof, consumed) = UnlockProof::decode_bytes(&raw[offset..])?;
            offset += consumed;
            inputs.push(TxInput {
                prev_txid,
                prev_vout,
                proof,
            });
        }

        if raw.len() < offset + 2 {
            return Err("Truncated transaction output count".to_string());
        }
        let out_count = u16::from_le_bytes([raw[offset], raw[offset + 1]]) as usize;
        offset += 2;
        if out_count == 0 || out_count > MAX_TX_IO {
            return Err("Invalid output count in encoded transaction".to_string());
        }

        let mut outputs = Vec::with_capacity(out_count);
        for _ in 0..out_count {
            if raw.len() < offset + 17 {
                return Err("Truncated transaction output".to_string());
            }
            let value_atomic =
                u128::from_le_bytes(raw[offset..offset + 16].try_into().unwrap());
            let payload_tag = raw[offset + 16];
            offset += 17;
            let payload = match payload_tag {
                0x01 => {
                    let (cond, consumed) = LockCondition::decode_bytes(&raw[offset..])?;
                    offset += consumed;
                    OutputPayload::Lock(cond)
                }
                0x02 => {
                    let (anchor, consumed) = DataAnchor::decode_bytes(&raw[offset..])?;
                    offset += consumed;
                    OutputPayload::Anchor(anchor)
                }
                _ => return Err("Unknown output payload tag".to_string()),
            };
            outputs.push(TxOutput {
                value_atomic,
                payload,
            });
        }

        if offset != raw.len() {
            return Err("Trailing garbage bytes in transaction".to_string());
        }

        let tx = Self {
            version,
            chain_id,
            inputs,
            outputs,
        };
        tx.verify_structure_and_outputs()?;
        Ok(tx)
    }
}
