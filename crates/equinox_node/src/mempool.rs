#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use equinox_crypto::address::hash160;
use equinox_storage::engine::UtxoStorageEngine;
use equinox_storage::types::OutPoint;

use crate::tx::SignedTransaction;

pub const DEFAULT_MIN_FEE_ATOMIC: u128 = 1_000; // 0.00001 EQX anti-spam fee floor
pub const DEFAULT_MAX_MEMPOOL_TXS: usize = 5_000;

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub txid: [u8; 32],
    pub tx: SignedTransaction,
    pub fee_atomic: u128,
    pub spends: Vec<OutPoint>,
}

pub struct Mempool {
    max_txs: usize,
    min_fee_atomic: u128,
    pending: HashMap<[u8; 32], MempoolEntry>,
    spent_outpoints: HashSet<OutPoint>,
}

impl Mempool {
    pub fn new(max_txs: usize, min_fee_atomic: u128) -> Self {
        Self {
            max_txs,
            min_fee_atomic,
            pending: HashMap::new(),
            spent_outpoints: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn min_fee_atomic(&self) -> u128 {
        self.min_fee_atomic
    }

    pub fn validate_and_insert(
        &mut self,
        tx: SignedTransaction,
        storage: &mut UtxoStorageEngine,
        expected_chain_id: u64,
    ) -> Result<([u8; 32], u128), String> {
        if self.pending.len() >= self.max_txs {
            return Err("Mempool is full".to_string());
        }
        if tx.chain_id != expected_chain_id {
            return Err(format!(
                "Chain ID mismatch: expected {}, got {}",
                expected_chain_id, tx.chain_id
            ));
        }

        // 1. Canonical Ed25519 signature verification
        tx.verify_signatures()?;

        let txid = tx.txid();
        if self.pending.contains_key(&txid) {
            return Err("Transaction already in mempool".to_string());
        }

        // 2. Verify every input exists in UTXO set, matches owner hash160, and has no double-spend
        let mut seen_in_tx = HashSet::with_capacity(tx.inputs.len());
        let mut total_in: u128 = 0;
        let mut spends = Vec::with_capacity(tx.inputs.len());

        for inp in &tx.inputs {
            let op = inp.outpoint();
            if !seen_in_tx.insert(op) {
                return Err("Duplicate input inside transaction".to_string());
            }
            if self.spent_outpoints.contains(&op) {
                return Err("Double-spend detected in mempool".to_string());
            }

            let utxo = storage
                .get_utxo(&op)
                .ok_or_else(|| "Referenced UTXO does not exist or already spent".to_string())?;

            let signer_h160 = hash160(&inp.pubkey);
            if signer_h160 != utxo.script_hash160 {
                return Err("Input pubkey does not match UTXO owner".to_string());
            }

            total_in = total_in
                .checked_add(utxo.value_atomic)
                .ok_or_else(|| "Input value overflow".to_string())?;
            spends.push(op);
        }

        // 3. Verify outputs are non-zero and strictly bounded by total_in - min_fee
        let mut total_out: u128 = 0;
        for out in &tx.outputs {
            if out.value_atomic == 0 {
                return Err("Zero-value output rejected".to_string());
            }
            total_out = total_out
                .checked_add(out.value_atomic)
                .ok_or_else(|| "Output value overflow".to_string())?;
        }

        if total_in < total_out {
            return Err("Insufficient input funds (outputs exceed inputs)".to_string());
        }
        let fee_atomic = total_in - total_out;
        if fee_atomic < self.min_fee_atomic {
            return Err(format!(
                "Transaction fee {} below minimum {}",
                fee_atomic, self.min_fee_atomic
            ));
        }

        for &op in &spends {
            self.spent_outpoints.insert(op);
        }
        self.pending.insert(
            txid,
            MempoolEntry {
                txid,
                tx,
                fee_atomic,
                spends,
            },
        );
        Ok((txid, fee_atomic))
    }

    /// Selects highest-fee valid transactions for inclusion in the next mined block.
    pub fn select_for_block(&self, max_count: usize) -> Vec<MempoolEntry> {
        let mut list: Vec<MempoolEntry> = self.pending.values().cloned().collect();
        list.sort_by(|a, b| b.fee_atomic.cmp(&a.fee_atomic).then_with(|| a.txid.cmp(&b.txid)));
        list.truncate(max_count);
        list
    }

    pub fn remove_confirmed(&mut self, confirmed_txids: &[[u8; 32]]) {
        for txid in confirmed_txids {
            if let Some(entry) = self.pending.remove(txid) {
                for op in entry.spends {
                    self.spent_outpoints.remove(&op);
                }
            }
        }
    }
}
