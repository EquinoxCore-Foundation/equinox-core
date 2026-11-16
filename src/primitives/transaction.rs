// File: src/primitives/transaction.rs
#![forbid(unsafe_code)]

use crate::config::{
    calculate_block_reward, is_timelock_expired, CHAIN_ID, MAX_SUPPLY, MIN_RELAY_TX_FEE,
};
use crate::crypto::hash::{sha256d, sha256d_tagged, Hash256};
use crate::crypto::keys::{
    verify_batch_parallel, verify_signature, KeyPair, PublicKeyBytes, SignatureBytes,
    SignatureVerificationTask,
};
use crate::state::outpoint::OutPoint;
use crate::wallet::address::is_valid_address;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const TX_SIGNING_DOMAIN: &[u8] = b"EQX_MAINNET_TX_SIGNING_V2";
const KEY_IMAGE_DOMAIN: &[u8] = b"EQX_KEY_IMAGE_NULLIFIER_V2";

mod sig64_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut r_part = [0u8; 32];
        let mut s_part = [0u8; 32];
        r_part.copy_from_slice(&sig[0..32]);
        s_part.copy_from_slice(&sig[32..64]);
        (r_part, s_part).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let (r_part, s_part): ([u8; 32], [u8; 32]) = Deserialize::deserialize(deserializer)?;
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&r_part);
        sig[32..64].copy_from_slice(&s_part);
        Ok(sig)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_out: OutPoint,
    pub public_key: PublicKeyBytes,
    #[serde(with = "sig64_serde")]
    pub signature: SignatureBytes,
}

impl TxInput {
    #[inline]
    pub const fn new(prev_out: OutPoint, public_key: PublicKeyBytes) -> Self {
        Self {
            prev_out,
            public_key,
            signature: [0u8; 64],
        }
    }

    pub fn key_image(&self) -> Hash256 {
        let mut buf = Vec::with_capacity(68);
        buf.extend_from_slice(&self.prev_out.txid);
        buf.extend_from_slice(&self.prev_out.vout.to_le_bytes());
        buf.extend_from_slice(&self.public_key);
        sha256d_tagged(KEY_IMAGE_DOMAIN, &buf)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub amount: u64,
    pub recipient_address: String,
    pub unlock_height: u64,
}

impl TxOutput {
    #[inline]
    pub const fn new(amount: u64, recipient_address: String) -> Self {
        Self {
            amount,
            recipient_address,
            unlock_height: 0,
        }
    }

    #[inline]
    pub const fn new_timelocked(
        amount: u64,
        recipient_address: String,
        unlock_height: u64,
    ) -> Self {
        Self {
            amount,
            recipient_address,
            unlock_height,
        }
    }

    #[inline]
    pub fn is_spendable_at(&self, current_block_height: u64) -> bool {
        is_timelock_expired(self.unlock_height, current_block_height)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub timestamp: u64,
    pub fee: u64,
}

impl Transaction {
    pub fn new(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        timestamp: u64,
        fee: u64,
    ) -> Self {
        Self {
            version: 1,
            inputs,
            outputs,
            timestamp,
            fee,
        }
    }

    pub fn new_coinbase(
        block_height: u64,
        miner_address: String,
        collected_fees: u64,
        timestamp: u64,
    ) -> Self {
        let base_reward = calculate_block_reward(block_height);
        let total_reward = base_reward
            .checked_add(collected_fees)
            .unwrap_or(MAX_SUPPLY)
            .min(MAX_SUPPLY);

        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: vec![TxOutput::new(total_reward, miner_address)],
            timestamp,
            fee: 0,
        }
    }

    #[inline]
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// CHAIN_ID এবং দৈর্ঘ্য-প্রিফিক্সসহ ক্যানোনিকাল সাইনিং মেসেজ (Replay ও Boundary Shifting প্রতিরোধী)
    pub fn signing_message(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(280);
        buf.extend_from_slice(TX_SIGNING_DOMAIN);
        buf.extend_from_slice(&CHAIN_ID.to_le_bytes());
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.fee.to_le_bytes());

        buf.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.prev_out.txid);
            buf.extend_from_slice(&inp.prev_out.vout.to_le_bytes());
            buf.extend_from_slice(&inp.public_key);
        }

        buf.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for out in &self.outputs {
            buf.extend_from_slice(&out.amount.to_le_bytes());
            buf.extend_from_slice(&out.unlock_height.to_le_bytes());
            let addr_bytes = out.recipient_address.as_bytes();
            buf.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(addr_bytes);
        }

        buf
    }

    pub fn txid(&self) -> Hash256 {
        let mut buf = self.signing_message();
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.signature);
        }
        sha256d(&buf)
    }

    pub fn sign_input(&mut self, input_index: usize, keypair: &KeyPair) -> Result<(), String> {
        if input_index >= self.inputs.len() {
            return Err(format!("Input index #{} out of bounds", input_index));
        }
        self.inputs[input_index].public_key = keypair.public_key();
        let msg = self.signing_message();
        let sig = keypair.sign(&msg);
        self.inputs[input_index].signature = sig;
        Ok(())
    }

    pub fn verify_signatures(&self) -> bool {
        if self.is_coinbase() {
            return true;
        }
        // Reject duplicate OutPoints or Key-Images inside the same transaction
        let mut seen_outpoints = HashSet::with_capacity(self.inputs.len());
        let mut seen_key_images = HashSet::with_capacity(self.inputs.len());
        for inp in &self.inputs {
            if inp.prev_out.is_null()
                || !seen_outpoints.insert(inp.prev_out.clone())
                || !seen_key_images.insert(inp.key_image())
            {
                return false;
            }
        }

        let msg = self.signing_message();
        if self.inputs.len() == 1 {
            let inp = &self.inputs[0];
            return verify_signature(&inp.public_key, &msg, &inp.signature);
        }

        let tasks: Vec<SignatureVerificationTask> = self
            .inputs
            .iter()
            .map(|inp| SignatureVerificationTask {
                public_key: inp.public_key,
                message: msg.clone(),
                signature: inp.signature,
            })
            .collect();

        verify_batch_parallel(&tasks)
    }

    pub fn total_output_amount(&self) -> Result<u64, String> {
        if self.outputs.is_empty() {
            return Err("Transaction must contain at least 1 output".to_string());
        }

        let mut total: u64 = 0;
        for out in &self.outputs {
            if out.amount == 0 || out.amount > MAX_SUPPLY {
                return Err(format!("Invalid output amount: {}", out.amount));
            }
            if !is_valid_address(&out.recipient_address) {
                return Err(format!(
                    "Invalid recipient wallet address: {}",
                    out.recipient_address
                ));
            }
            total = total
                .checked_add(out.amount)
                .ok_or_else(|| "Output amount addition overflow".to_string())?;
        }

        if total > MAX_SUPPLY {
            return Err("Total output sum exceeds 21M MAX_SUPPLY cap".to_string());
        }

        if !self.is_coinbase() && self.fee < MIN_RELAY_TX_FEE {
            return Err(format!(
                "Transaction fee ({}) is below MIN_RELAY_TX_FEE ({})",
                self.fee, MIN_RELAY_TX_FEE
            ));
        }

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_transaction_chain_id_signing_and_duplicate_input_rejection() {
        let kp = KeyPair::generate();
        let recipient = pubkey_to_address(&kp.public_key());
        let op = OutPoint::new([0x55u8; 32], 0);

        let mut tx = Transaction::new(
            vec![TxInput::new(op.clone(), kp.public_key())],
            vec![TxOutput::new(10 * COIN, recipient.clone())],
            1_729_468_815,
            10_000,
        );

        assert!(!tx.verify_signatures());
        tx.sign_input(0, &kp).unwrap();
        assert!(tx.verify_signatures());

        // Duplicate input inside same transaction must fail signature verification
        let mut dup_tx = Transaction::new(
            vec![
                TxInput::new(op.clone(), kp.public_key()),
                TxInput::new(op, kp.public_key()),
            ],
            vec![TxOutput::new(10 * COIN, recipient)],
            1_729_468_815,
            10_000,
        );
        dup_tx.sign_input(0, &kp).unwrap();
        dup_tx.sign_input(1, &kp).unwrap();
        assert!(!dup_tx.verify_signatures());
    }
}