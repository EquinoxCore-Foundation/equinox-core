#![allow(dead_code)]
// src/mempool/anti_double_spend.rs
// Equinox (EQX) L1 — Audit-Grade Mempool Double-Spend Firewall (OutPoint + Key-Image Nullifier)
// Features: Intra-Transaction Duplicate Input Detection, Live Conflict Proof Generation & Atomic Release.

use crate::crypto::hash::Hash256;
use crate::primitives::transaction::Transaction;
use crate::state::outpoint::OutPoint;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// ডাবল-স্পেন্ড ধরা পড়লে কোন ট্রানজ্যাকশনের সাথে সংঘর্ষ হয়েছে তার প্রমাণ
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoubleSpendConflict {
    pub incoming_txid: Hash256,
    pub existing_txid: Hash256,
    pub conflicted_outpoint: OutPoint,
    pub conflicted_key_image: Hash256,
}

/// মেমপুল ডাবল-স্পেন্ড গার্ড ইঞ্জিন
#[derive(Clone, Debug, Default)]
pub struct AntiDoubleSpendGuard {
    /// OutPoint -> TxID
    locked_outpoints: HashMap<OutPoint, Hash256>,
    /// KeyImage -> TxID
    locked_key_images: HashMap<Hash256, Hash256>,
}

impl AntiDoubleSpendGuard {
    pub fn new() -> Self {
        Self {
            locked_outpoints: HashMap::new(),
            locked_key_images: HashMap::new(),
        }
    }

    /// নতুন ট্রানজ্যাকশন মেমপুলে ঢোকার আগে তার কোনো ইনপুট বা কী-ইমেজ আগে থেকেই লক করা আছে কি না তা পরীক্ষা করে
    pub fn check_and_lock(&mut self, tx: &Transaction) -> Result<(), String> {
        if tx.is_coinbase() {
            return Err("কয়েনবেস ট্রানজ্যাকশন মেমপুল গার্ডে লক করা যাবে না".to_string());
        }

        let txid = tx.txid();
        let mut seen_outpoints = HashSet::with_capacity(tx.inputs.len());
        let mut seen_key_images = HashSet::with_capacity(tx.inputs.len());

        // ১. প্রথমে সব ইনপুট যাচাই করা (যাতে মাঝপথে এরর হলে আংশিক লক না হয়)
        for inp in &tx.inputs {
            if inp.prev_out.is_null() {
                return Err("সাধারণ ট্রানজ্যাকশনে নাল (Null) OutPoint অবৈধ".to_string());
            }

            if !seen_outpoints.insert(inp.prev_out.clone()) {
                return Err("একই ট্রানজ্যাকশনের ভেতরে ডুপ্লিকেট OutPoint পাওয়া গেছে".to_string());
            }

            if let Some(existing_tx) = self.locked_outpoints.get(&inp.prev_out) {
                if *existing_tx != txid {
                    return Err(format!(
                        "ডাবল-স্পেন্ড শনাক্ত: UTXO {:?} ইতোমধ্যে ট্রানজ্যাকশন {}-এ লক করা আছে",
                        inp.prev_out,
                        hex::encode(existing_tx)
                    ));
                }
            }

            let ki = inp.key_image();
            if !seen_key_images.insert(ki) {
                return Err("একই ট্রানজ্যাকশনের ভেতরে ডুপ্লিকেট Key-Image পাওয়া গেছে".to_string());
            }

            if let Some(existing_tx) = self.locked_key_images.get(&ki) {
                if *existing_tx != txid {
                    return Err(format!(
                        "ডাবল-স্পেন্ড শনাক্ত: Key-Image নাল্লিফায়ার ইতোমধ্যে ট্রানজ্যাকশন {}-এ ব্যবহৃত হয়েছে",
                        hex::encode(existing_tx)
                    ));
                }
            }
        }

        // ২. সব চেক পাস করলে অ্যাটমিকভাবে লক করা
        for inp in &tx.inputs {
            self.locked_outpoints.insert(inp.prev_out.clone(), txid);
            self.locked_key_images.insert(inp.key_image(), txid);
        }

        Ok(())
    }

    /// ট্রানজ্যাকশন মেমপুল থেকে সরে গেলে বা কনফার্ম হলে তার লক মুক্ত করে
    pub fn release_transaction_locks(&mut self, tx: &Transaction) {
        for inp in &tx.inputs {
            self.locked_outpoints.remove(&inp.prev_out);
            self.locked_key_images.remove(&inp.key_image());
        }
    }

    #[inline]
    pub fn locked_utxo_count(&self) -> usize {
        self.locked_outpoints.len()
    }
}
