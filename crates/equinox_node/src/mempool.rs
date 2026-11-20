#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use equinox_storage::engine::UtxoStorageEngine;
use equinox_storage::types::OutPoint;

use crate::script::{DataAnchor, NameRecord, NAME_REGISTRATION_MIN_FEE_ATOMIC};
use crate::tx::{OutputPayload, SignedTransaction};

pub const DEFAULT_MIN_FEE_ATOMIC: u128 = 1_000; // 0.00001 EQX anti-spam fee floor
pub const DEFAULT_MAX_MEMPOOL_TXS: usize = 5_000;

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub txid: [u8; 32],
    pub tx: SignedTransaction,
    pub fee_atomic: u128,
    pub spends: Vec<OutPoint>,
    pub registered_names: Vec<String>,
}

pub struct Mempool {
    max_txs: usize,
    min_fee_atomic: u128,
    pending: HashMap<[u8; 32], MempoolEntry>,
    spent_outpoints: HashSet<OutPoint>,
    pending_names: HashSet<String>,
}

impl Mempool {
    pub fn new(max_txs: usize, min_fee_atomic: u128) -> Self {
        Self {
            max_txs,
            min_fee_atomic,
            pending: HashMap::new(),
            spent_outpoints: HashSet::new(),
            pending_names: HashSet::new(),
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
        next_height: u64,
        active_names: &HashMap<String, NameRecord>,
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

        tx.verify_structure_and_outputs()?;

        let txid = tx.txid();
        if self.pending.contains_key(&txid) {
            return Err("Transaction already in mempool".to_string());
        }

        let sighash = tx.sighash();
        let mut seen_in_tx = HashSet::with_capacity(tx.inputs.len());
        let mut total_in: u128 = 0;
        let mut spends = Vec::with_capacity(tx.inputs.len());

        for (idx, inp) in tx.inputs.iter().enumerate() {
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

            tx.verify_input_proof(idx, &sighash, utxo.script_hash160, next_height)?;

            total_in = total_in
                .checked_add(utxo.value_atomic)
                .ok_or_else(|| "Input value overflow".to_string())?;
            spends.push(op);
        }

        let mut total_out: u128 = 0;
        let mut required_fee = self.min_fee_atomic;
        let mut registered_names = Vec::new();
        let mut seen_names_in_tx = HashSet::new();

        for out in &tx.outputs {
            match &out.payload {
                OutputPayload::Lock(_) => {
                    total_out = total_out
                        .checked_add(out.value_atomic)
                        .ok_or_else(|| "Output value overflow".to_string())?;
                }
                OutputPayload::Anchor(anchor) => {
                    if let DataAnchor::NameRegister { name, owner_h160 } = anchor {
                        if !seen_names_in_tx.insert(name.clone()) {
                            return Err("Duplicate @name.eqx registration in transaction".to_string());
                        }
                        if self.pending_names.contains(name) {
                            return Err(format!(
                                "Name @{}.eqx already pending in mempool",
                                name
                            ));
                        }
                        if let Some(existing) = active_names.get(name) {
                            if existing.expires_height > next_height {
                                let is_owner_renewal = existing.owner_h160 == *owner_h160
                                    && tx.has_signer_hash160(&existing.owner_h160);
                                if !is_owner_renewal {
                                    return Err(format!(
                                        "Name @{}.eqx is already registered and active",
                                        name
                                    ));
                                }
                            }
                        }
                        required_fee = required_fee.max(NAME_REGISTRATION_MIN_FEE_ATOMIC);
                        registered_names.push(name.clone());
                    }
                }
            }
        }

        if total_in < total_out {
            return Err("Insufficient input funds (outputs exceed inputs)".to_string());
        }
        let fee_atomic = total_in - total_out;
        if fee_atomic < required_fee {
            return Err(format!(
                "Transaction fee {} below minimum {}",
                fee_atomic, required_fee
            ));
        }

        for &op in &spends {
            self.spent_outpoints.insert(op);
        }
        for name in &registered_names {
            self.pending_names.insert(name.clone());
        }
        self.pending.insert(
            txid,
            MempoolEntry {
                txid,
                tx,
                fee_atomic,
                spends,
                registered_names,
            },
        );
        Ok((txid, fee_atomic))
    }

    pub fn select_for_block(&self, max_count: usize) -> Vec<MempoolEntry> {
        let mut list: Vec<MempoolEntry> = self.pending.values().cloned().collect();
        list.sort_by(|a, b| b.fee_atomic.cmp(&a.fee_atomic).then_with(|| a.txid.cmp(&b.txid)));
        list.truncate(max_count);
        list
    }

    pub fn all_transactions(&self, max_count: usize) -> Vec<SignedTransaction> {
        self.select_for_block(max_count)
            .into_iter()
            .map(|e| e.tx)
            .collect()
    }

    pub fn remove_confirmed(&mut self, confirmed_txids: &[[u8; 32]]) {
        for txid in confirmed_txids {
            if let Some(entry) = self.pending.remove(txid) {
                for op in entry.spends {
                    self.spent_outpoints.remove(&op);
                }
                for name in entry.registered_names {
                    self.pending_names.remove(&name);
                }
            }
        }
    }

    pub fn prune_spent_outpoints(&mut self, newly_spent: &[OutPoint]) {
        if newly_spent.is_empty() {
            return;
        }
        let spent_set: HashSet<OutPoint> = newly_spent.iter().copied().collect();
        let to_remove: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, entry)| entry.spends.iter().any(|op| spent_set.contains(op)))
            .map(|(txid, _)| *txid)
            .collect();
        self.remove_confirmed(&to_remove);
    }

    pub fn prune_registered_names(&mut self, newly_registered: &[String]) {
        if newly_registered.is_empty() {
            return;
        }
        let name_set: HashSet<&str> = newly_registered.iter().map(|s| s.as_str()).collect();
        let to_remove: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, entry)| {
                entry
                    .registered_names
                    .iter()
                    .any(|n| name_set.contains(n.as_str()))
            })
            .map(|(txid, _)| *txid)
            .collect();
        self.remove_confirmed(&to_remove);
    }
}
