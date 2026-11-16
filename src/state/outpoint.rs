#![allow(dead_code)]
// src/state/outpoint.rs
// Equinox (EQX) L1 — Cryptographic UTXO Reference Point & Deterministic Sorting Engine

use crate::crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

/// একটি নির্দিষ্ট ট্রানজ্যাকশনের সুনির্দিষ্ট আউটপুট সূচক (TxID + Vout)
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Hash256,
    pub vout: u32,
}

impl OutPoint {
    #[inline]
    pub const fn new(txid: Hash256, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// জেনেসিস বা কয়েনবেস বিশেষ নাল আউটপয়েন্ট কি না তা পরীক্ষা করে
    #[inline]
    pub fn is_null(&self) -> bool {
        self.txid.iter().all(|&b| b == 0) && self.vout == u32::MAX
    }
}

/// কনসেনসাস স্তরে UTXOs সাজানোর জন্য কঠোর ডিটারমিনিস্টিক লেক্সিকোগ্রাফিক সর্টিং (`Ord`)
impl PartialOrd for OutPoint {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OutPoint {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.txid.cmp(&other.txid) {
            std::cmp::Ordering::Equal => self.vout.cmp(&other.vout),
            other_ord => other_ord,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outpoint_deterministic_ordering() {
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];

        let op1 = OutPoint::new(h1, 0);
        let op2 = OutPoint::new(h1, 1);
        let op3 = OutPoint::new(h2, 0);

        assert!(op1 < op2);
        assert!(op2 < op3);
    }
}
