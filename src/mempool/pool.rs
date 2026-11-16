#![allow(dead_code)]
// src/mempool/pool.rs
// Equinox (EQX) L1 — Audit-Grade Transaction Mempool, Dual Double-Spend Guard (OutPoint + Key-Image),
// Anti-DoS Fee-Priority Eviction & Collision-Safe Compact Block Reconstruction Engine.

use crate::config::{MAX_BLOCK_SIZE_BYTES, MAX_SUPPLY, MIN_RELAY_TX_FEE};
use crate::crypto::hash::{compute_short_txid, Hash256, ShortTxId};
use crate::primitives::block::{Block, CompactBlock};
use crate::primitives::transaction::Transaction;
use crate::state::outpoint::OutPoint;
use crate::state::utxo_set::UtxoSet;
use std::collections::{HashMap, HashSet};

/// মেমপুলে সর্বোচ্চ অনুমোদিত আনকনফার্মড ট্রানজ্যাকশন সংখ্যা (RAM DoS প্রতিরোধে)
pub const MAX_MEMPOOL_TXS: usize = 5_000;

/// একটি একক ট্রানজ্যাকশনের সর্বোচ্চ অনুমোদিত বাইনারি আকার (১০০ কিলোবাইট)
pub const MAX_SINGLE_TX_BYTES: usize = 100 * 1024;

/// আনকনফার্মড ট্রানজ্যাকশন পুল ও কম্প্যাক্ট ব্লক রিকনস্ট্রাকশন ইঞ্জিন
#[derive(Clone, Debug, Default)]
pub struct Mempool {
    /// TxID -> Transaction
    transactions: HashMap<Hash256, Transaction>,
    /// বর্তমানে মেমপুলের ট্রানজ্যাকশনগুলো যেসব OutPoint খরচ করতে চাইছে তার লক সেট (OutPoint -> TxID)
    spent_outpoints: HashMap<OutPoint, Hash256>,
    /// বর্তমানে মেমপুলে ব্যবহৃত ক্রিপ্টোগ্রাফিক Key-Image নাল্লিফায়ার সেট (KeyImage -> TxID)
    spent_key_images: HashMap<Hash256, Hash256>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            spent_outpoints: HashMap::new(),
            spent_key_images: HashMap::new(),
        }
    }

    /// ট্রানজ্যাকশনের কাঠামোগত বৈধতা, সিগনেচার, ন্যূনতম ফি এবং ডাবল-স্পেন্ড পরীক্ষা করে মেমপুলে যুক্ত করে
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<Hash256, String> {
        // ১. কয়েনবেস ট্রানজ্যাকশন মেমপুলে আসতে পারবে না
        if tx.is_coinbase() {
            return Err("কয়েনবেস ট্রানজ্যাকশন মেমপুলে গ্রহণ করা হয় না".to_string());
        }

        // ২. ন্যূনতম রিলে ফি এবং আউটপুট বাউন্ডারি যাচাই
        if tx.fee < MIN_RELAY_TX_FEE {
            return Err(format!(
                "ট্রানজ্যাকশন ফি ন্যূনতম সীমার ({}) কম",
                MIN_RELAY_TX_FEE
            ));
        }
        let _total_out = tx.total_output_amount()?;

        // ৩. বাইনারি সাইজ বাউন্ডারি চেক (OOM স্প্যাম প্রতিরোধ)
        let encoded_size = bincode::serialize(&tx)
            .map_err(|e| format!("ট্রানজ্যাকশন সিরিয়ালাইজেশন ত্রুটি: {}", e))?
            .len();
        if encoded_size == 0 || encoded_size > MAX_SINGLE_TX_BYTES {
            return Err(format!(
                "ট্রানজ্যাকশনের আকার ({} বাইট) অনুমোদিত সীমার বাইরে",
                encoded_size
            ));
        }

        let txid = tx.txid();
        if self.transactions.contains_key(&txid) {
            return Ok(txid);
        }

        // ৪. ইন্ট্রা-ট্রানজ্যাকশন ও মেমপুল ডাবল-স্পেন্ড পরীক্ষা (OutPoint + Key-Image)
        let mut local_outpoints = HashSet::with_capacity(tx.inputs.len());
        let mut local_key_images = HashSet::with_capacity(tx.inputs.len());

        for inp in &tx.inputs {
            if inp.prev_out.is_null() {
                return Err("সাধারণ ট্রানজ্যাকশনে নাল (Null) OutPoint অবৈধ".to_string());
            }
            if !local_outpoints.insert(inp.prev_out.clone()) {
                return Err("একই ট্রানজ্যাকশনের ভেতরে ডুপ্লিকেট OutPoint ইনপুট পাওয়া গেছে".to_string());
            }
            if self.spent_outpoints.contains_key(&inp.prev_out) {
                return Err("ডাবল-স্পেন্ড প্রতিরোধ: এই UTXO-টি ইতোমধ্যে মেমপুলের অন্য ট্রানজ্যাকশনে ব্যবহৃত হয়েছে".to_string());
            }

            let ki = inp.key_image();
            if !local_key_images.insert(ki) {
                return Err("একই ট্রানজ্যাকশনের ভেতরে ডুপ্লিকেট Key-Image পাওয়া গেছে".to_string());
            }
            if self.spent_key_images.contains_key(&ki) {
                return Err("ডাবল-স্পেন্ড প্রতিরোধ: এই Key-Image নাল্লিফায়ারটি ইতোমধ্যে মেমপুলে সক্রিয়".to_string());
            }
        }

        // ৫. Ed25519 ক্রিপ্টোগ্রাফিক সিগনেচার যাচাই
        if !tx.verify_signatures() {
            return Err("ট্রানজ্যাকশনের ডিজিটাল সিগনেচার যাচাই ব্যর্থ হয়েছে!".to_string());
        }

        // ৬. মেমপুল পূর্ণ থাকলে সবচেয়ে কম ফি-এর ট্রানজ্যাকশন সরিয়ে জায়গা তৈরি করা (Fee-Priority Eviction)
        if self.transactions.len() >= MAX_MEMPOOL_TXS {
            if let Some((lowest_txid, lowest_fee)) = self
                .transactions
                .iter()
                .map(|(id, t)| (*id, t.fee))
                .min_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
            {
                if tx.fee <= lowest_fee {
                    return Err("মেমপুল পূর্ণ: ট্রানজ্যাকশন ফি বর্তমান সর্বনিম্ন সীমার চেয়ে বেশি হতে হবে".to_string());
                }
                self.remove_transaction(&lowest_txid);
            }
        }

        // ৭. সব চেক পাস করলে অ্যাটমিকভাবে ইনডেক্স ও মেমপুলে যুক্ত করা
        for inp in &tx.inputs {
            self.spent_outpoints.insert(inp.prev_out.clone(), txid);
            self.spent_key_images.insert(inp.key_image(), txid);
        }
        self.transactions.insert(txid, tx);

        Ok(txid)
    }

    /// লাইভ `UtxoSet`-এর বিপরীতে ইনপুটগুলোর মালিকানা, টাইম-লক এবং ইনপুট-আউটপুট ব্যালেন্স সমীকরণ যাচাই করে মেমপুলে যুক্ত করে
    pub fn add_transaction_verified(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_block_height: u64,
    ) -> Result<Hash256, String> {
        if tx.is_coinbase() {
            return Err("কয়েনবেস ট্রানজ্যাকশন মেমপুলে গ্রহণ করা হয় না".to_string());
        }

        let mut total_in: u128 = 0;
        for inp in &tx.inputs {
            let utxo = utxo_set.verify_utxo_spendable(
                &inp.prev_out,
                &inp.public_key,
                current_block_height,
            )?;
            total_in = total_in
                .checked_add(utxo.amount as u128)
                .ok_or_else(|| "ইনপুট যোগফলে গাণিতিক ওভারফ্লো".to_string())?;
        }

        let total_out = tx.total_output_amount()? as u128;
        let required_in = total_out
            .checked_add(tx.fee as u128)
            .ok_or_else(|| "আউটপুট ও ফি যোগফলে ওভারফ্লো".to_string())?;

        if total_in < required_in || total_in > (MAX_SUPPLY as u128) {
            return Err(format!(
                "ইনপুট ব্যালেন্স অপর্যাপ্ত: ইনপুট {}, কিন্তু আউটপুট + ফি {}",
                total_in, required_in
            ));
        }

        self.add_transaction(tx)
    }

    /// নির্দিষ্ট `TxID` মেমপুল থেকে মুছে ফেলে এবং তার লক করা `OutPoint` ও `Key-Image` মুক্ত করে
    pub fn remove_transaction(&mut self, txid: &Hash256) -> Option<Transaction> {
        if let Some(removed_tx) = self.transactions.remove(txid) {
            for inp in &removed_tx.inputs {
                self.spent_outpoints.remove(&inp.prev_out);
                self.spent_key_images.remove(&inp.key_image());
            }
            return Some(removed_tx);
        }
        None
    }

    /// নতুন ব্লক কনফার্ম হওয়ার পর ওই ব্লকে থাকা ট্রানজ্যাকশন এবং কনফ্লিক্টিং ইনপুটগুলো মেমপুল থেকে পরিষ্কার করে
    pub fn remove_confirmed_block_transactions(&mut self, block: &Block) {
        for tx in &block.transactions {
            let txid = tx.txid();
            self.remove_transaction(&txid);

            for inp in &tx.inputs {
                if let Some(conflicting_txid) = self.spent_outpoints.get(&inp.prev_out).copied() {
                    self.remove_transaction(&conflicting_txid);
                }
                let ki = inp.key_image();
                if let Some(conflicting_txid) = self.spent_key_images.get(&ki).copied() {
                    self.remove_transaction(&conflicting_txid);
                }
            }
        }
    }

    /// কম্প্যাক্ট ব্লক (`CompactBlock`)-এর ৬-বাইট শর্ট আইডিগুলোর সাথে মেমপুলের ট্রানজ্যাকশন মিলিয়ে পূর্ণাঙ্গ `Block` তৈরি করে।
    /// কোনো ট্রানজ্যাকশন মেমপুলে না থাকলে বা শর্ট-আইডি কলিশন হলে সেই ইনডেক্সগুলোর তালিকা `Err(missing_indices)` হিসেবে রিটার্ন করে।
    pub fn reconstruct_from_compact_block(
        &self,
        compact: &CompactBlock,
    ) -> Result<Block, Vec<usize>> {
        let nonce = compact.header.nonce;

        // মেমপুলের প্রতিটি ট্রানজ্যাকশনের ৬-বাইট শর্ট আইডি ম্যাপ তৈরি (কলিশন ডিটেকশনসহ)
        let mut short_id_map: HashMap<ShortTxId, Option<&Transaction>> =
            HashMap::with_capacity(self.transactions.len());

        for (txid, tx) in &self.transactions {
            let sid = compute_short_txid(txid, nonce);
            match short_id_map.get_mut(&sid) {
                Some(entry) => {
                    // যদি দুটি ভিন্ন ট্রানজ্যাকশন একই ৬-বাইট শর্ট আইডি তৈরি করে (Collision),
                    // তবে ভুল ট্রানজ্যাকশন না বসিয়ে সেটিকে অ্যাম্বিগুয়াস (None) করা হয় যাতে ফুল ট্রানজ্যাকশন চেয়ে নেওয়া হয়।
                    *entry = None;
                }
                None => {
                    short_id_map.insert(sid, Some(tx));
                }
            }
        }

        let mut missing_indices = Vec::new();
        let mut matched_txs = Vec::with_capacity(compact.short_txids.len());

        for (idx, target_sid) in compact.short_txids.iter().enumerate() {
            match short_id_map.get(target_sid) {
                Some(Some(tx)) => {
                    matched_txs.push((*tx).clone());
                }
                _ => {
                    missing_indices.push(idx);
                }
            }
        }

        if !missing_indices.is_empty() {
            return Err(missing_indices);
        }

        let mut full_transactions =
            Vec::with_capacity(matched_txs.len() + usize::from(compact.coinbase_tx.is_some()));
        if let Some(cb) = &compact.coinbase_tx {
            full_transactions.push(cb.clone());
        }
        full_transactions.extend(matched_txs);

        Ok(Block {
            header: compact.header.clone(),
            transactions: full_transactions,
        })
    }

    /// নতুন ব্লক মাইনিংয়ের জন্য সর্বোচ্চ ফি প্রদানকারী ট্রানজ্যাকশনগুলোকে ডিটারমিনিস্টিক ক্রমে বাছাই করে
    pub fn select_transactions_for_block(&self, max_count: usize) -> Vec<Transaction> {
        let mut candidates: Vec<(&Hash256, &Transaction)> = self.transactions.iter().collect();

        // সর্বোচ্চ ফি আগে আসবে; ফি সমান হলে TxID দিয়ে ডিটারমিনিস্টিক টাই-ব্রেক
        candidates.sort_by(|a, b| {
            b.1.fee
                .cmp(&a.1.fee)
                .then_with(|| a.0.cmp(b.0))
        });

        let mut selected = Vec::new();
        let mut current_bytes = 1024usize; // ব্লক হেডার ও কয়েনবেসের জন্য সংরক্ষিত জায়গা

        for (_, tx) in candidates.into_iter().take(max_count) {
            if let Ok(encoded) = bincode::serialize(tx) {
                if current_bytes + encoded.len() <= MAX_BLOCK_SIZE_BYTES {
                    current_bytes += encoded.len();
                    selected.push(tx.clone());
                }
            }
        }

        selected
    }

    #[inline]
    pub fn get_transaction(&self, txid: &Hash256) -> Option<&Transaction> {
        self.transactions.get(txid)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::primitives::transaction::{TxInput, TxOutput};
    use crate::wallet::address::pubkey_to_address;

    fn create_signed_user_tx(kp: &KeyPair, prev_txid: Hash256, vout: u32, fee: u64) -> Transaction {
        let recipient = pubkey_to_address(&kp.public_key());
        let mut tx = Transaction::new(
            vec![TxInput::new(OutPoint::new(prev_txid, vout), kp.public_key())],
            vec![TxOutput::new(10 * COIN, recipient)],
            1_729_468_815,
            fee,
        );
        tx.sign_input(0, kp).unwrap();
        tx
    }

    #[test]
    fn test_mempool_add_and_double_spend_rejection() {
        let mut mempool = Mempool::new();
        let kp = KeyPair::generate();

        let tx1 = create_signed_user_tx(&kp, [0x11u8; 32], 0, 20_000);
        let tx_double_spend = create_signed_user_tx(&kp, [0x11u8; 32], 0, 50_000);

        assert!(mempool.add_transaction(tx1).is_ok());
        assert_eq!(mempool.len(), 1);

        // একই OutPoint ([0x11; 32], 0) দিয়ে দ্বিতীয় ট্রানজ্যাকশন পাঠালে ডাবল-স্পেন্ড গার্ড তা আটকে দেবে
        assert!(mempool.add_transaction(tx_double_spend).is_err());
    }

    #[test]
    fn test_compact_block_full_reconstruction_from_mempool() {
        let mut mempool = Mempool::new();
        let kp = KeyPair::generate();
        let miner_addr = pubkey_to_address(&kp.public_key());

        let tx1 = create_signed_user_tx(&kp, [0xAAu8; 32], 0, 15_000);
        let tx2 = create_signed_user_tx(&kp, [0xBBu8; 32], 1, 30_000);

        mempool.add_transaction(tx1.clone()).unwrap();
        mempool.add_transaction(tx2.clone()).unwrap();

        let coinbase = Transaction::new_coinbase(1, miner_addr, 45_000, 1_729_468_815);
        let mut original_block = Block::new(
            1,
            [0u8; 32],
            vec![coinbase, tx1, tx2],
            2,
            1_729_468_815,
        );
        original_block.mine(Some(20_000));

        let compact = original_block.to_compact_block();
        let reconstructed = mempool.reconstruct_from_compact_block(&compact).unwrap();

        assert_eq!(reconstructed, original_block);
    }
}
