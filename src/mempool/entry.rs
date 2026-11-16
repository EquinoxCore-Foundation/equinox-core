#![allow(dead_code)]
// src/mempool/entry.rs
// Equinox (EQX) L1 — Audit-Grade Mempool Transaction Entry & Integer Fee-Per-Byte Priority Ordering
// Features: Zero-Floating-Point Satoshi/Byte Fee-Rate Calculation, Age Tracking & Deterministic Ord.

use crate::crypto::hash::Hash256;
use crate::primitives::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// মেমপুলে অবস্থানরত প্রতিটি আনকনফার্মড ট্রানজ্যাকশনের পূর্ণাঙ্গ মেটাডেটা ও প্রাইওরিটি র‍্যাপার
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolEntry {
    pub txid: Hash256,
    pub transaction: Transaction,
    pub serialized_size_bytes: usize,
    pub fee_atomic: u64,
    /// প্রতি বাইটে কত অ্যাটমিক ইউনিট ফি দেওয়া হয়েছে (Integer Fee-Rate = fee_atomic / size)
    pub fee_per_byte_atomic: u64,
    pub added_timestamp: u64,
}

impl MempoolEntry {
    /// ট্রানজ্যাকশন থেকে বাইনারি আকার ও প্রতি বাইটের ফি-রেট হিসাব করে নতুন `MempoolEntry` তৈরি করে
    pub fn new(transaction: Transaction, added_timestamp: u64) -> Result<Self, String> {
        let encoded = bincode::serialize(&transaction)
            .map_err(|e| format!("MempoolEntry সিরিয়ালাইজেশন ব্যর্থ: {}", e))?;

        let size_bytes = encoded.len().max(1);
        let fee_atomic = transaction.fee;
        let fee_per_byte_atomic = fee_atomic / (size_bytes as u64);
        let txid = transaction.txid();

        Ok(Self {
            txid,
            transaction,
            serialized_size_bytes: size_bytes,
            fee_atomic,
            fee_per_byte_atomic,
            added_timestamp,
        })
    }

    /// নির্দিষ্ট কাস্টম টাইমস্ট্যাম্পে এন্ট্রিটি মেমপুলে কত সেকেন্ড ধরে অপেক্ষা করছে তা হিসাব করে
    #[inline]
    pub fn age_seconds(&self, current_timestamp: u64) -> u64 {
        current_timestamp.saturating_sub(self.added_timestamp)
    }
}

/// মাইনার যাতে সর্বোচ্চ লাভজনক ট্রানজ্যাকশন আগে পায় সেজন্য ডিটারমিনিস্টিক অর্ডারিং (`Ord`)
impl PartialOrd for MempoolEntry {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // ১. যার প্রতি বাইটে ফি বেশি, সে আগে যাবে
        self.fee_per_byte_atomic
            .cmp(&other.fee_per_byte_atomic)
            // ২. ফি-রেট সমান হলে যার মোট ফি বেশি, সে আগে যাবে
            .then_with(|| self.fee_atomic.cmp(&other.fee_atomic))
            // ৩. মোট ফি-ও সমান হলে যে আগে এসেছে (কম টাইমস্ট্যাম্প), সে অগ্রাধিকার পাবে
            .then_with(|| other.added_timestamp.cmp(&self.added_timestamp))
            // ৪. চূড়ান্ত টাই-ব্রেকার: ক্রিপ্টোগ্রাফিক TxID
            .then_with(|| self.txid.cmp(&other.txid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::primitives::transaction::{TxInput, TxOutput};
    use crate::state::outpoint::OutPoint;
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_mempool_entry_fee_rate_priority_ordering() {
        let kp = KeyPair::generate();
        let addr = pubkey_to_address(&kp.public_key());

        let tx_low = Transaction::new(
            vec![TxInput::new(OutPoint::new([0x11u8; 32], 0), kp.public_key())],
            vec![TxOutput::new(10 * COIN, addr.clone())],
            1000,
            10_000,
        );
        let tx_high = Transaction::new(
            vec![TxInput::new(OutPoint::new([0x22u8; 32], 0), kp.public_key())],
            vec![TxOutput::new(10 * COIN, addr)],
            1000,
            50_000,
        );

        let entry_low = MempoolEntry::new(tx_low, 1000).unwrap();
        let entry_high = MempoolEntry::new(tx_high, 1005).unwrap();

        assert!(entry_high > entry_low);
    }
}
