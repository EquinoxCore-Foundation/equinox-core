#![allow(dead_code)]
// src/state/utxo_set.rs
// Equinox (EQX) L1 — Audit-Grade In-Memory UTXO Ledger, Deterministic State Merkle Root,
// 21M Hard-Cap Supply Auditor & Cryptographic Ownership Spend Guard.

use crate::config::MAX_SUPPLY;
use crate::crypto::hash::{sha256d, Hash256, ZERO_HASH};
use crate::crypto::keys::PublicKeyBytes;
use crate::crypto::merkle::compute_merkle_root;
use crate::primitives::transaction::TxOutput;
use crate::state::outpoint::OutPoint;
use crate::wallet::address::{is_valid_address, verify_address_ownership};
use std::collections::HashMap;

/// স্টেট লিফ হ্যাশ ডোমেইন সেপারেটর
const UTXO_STATE_LEAF_DOMAIN: &[u8] = b"EQX_UTXO_STATE_LEAF_V2";

/// ইন-মেমোরি UTXO সেট ম্যানেজার
#[derive(Clone, Debug, Default)]
pub struct UtxoSet {
    pub utxos: HashMap<OutPoint, TxOutput>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
        }
    }

    /// নতুন UTXO লেজারে যুক্ত করে
    #[inline]
    pub fn add_utxo(&mut self, outpoint: OutPoint, output: TxOutput) {
        self.utxos.insert(outpoint, output);
    }

    /// সুনির্দিষ্ট ভ্যালিডেশনসহ নতুন UTXO যুক্ত করে (শূন্য অ্যামাউন্ট বা অবৈধ অ্যাড্রেস ব্লক করে)
    pub fn add_utxo_checked(&mut self, outpoint: OutPoint, output: TxOutput) -> Result<(), String> {
        if outpoint.is_null() {
            return Err("নাল (Null) OutPoint লেজারে যুক্ত করা যাবে না".to_string());
        }
        if output.amount == 0 || output.amount > MAX_SUPPLY {
            return Err(format!(
                "অবৈধ UTXO কয়েন পরিমাণ: {} (সীমা: 1..={})",
                output.amount, MAX_SUPPLY
            ));
        }
        if !is_valid_address(&output.recipient_address) {
            return Err(format!(
                "অবৈধ প্রাপকের ওয়ালেট অ্যাড্রেস: {}",
                output.recipient_address
            ));
        }
        self.utxos.insert(outpoint, output);
        Ok(())
    }

    /// খরচ হওয়া UTXO লেজার থেকে মুছে ফেলে এবং রিটার্ন করে
    #[inline]
    pub fn remove_utxo(&mut self, outpoint: &OutPoint) -> Option<TxOutput> {
        self.utxos.remove(outpoint)
    }

    /// নির্দিষ্ট OutPoint থেকে আউটপুট রেফারেন্স রিটার্ন করে
    #[inline]
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<&TxOutput> {
        self.utxos.get(outpoint)
    }

    /// কোনো UTXO খরচ করার আগে তার অস্তিত্ব, টাইম-লক মেয়াদ এবং পাবলিক কি-এর মালিকানা কঠোরভাবে যাচাই করে
    pub fn verify_utxo_spendable(
        &self,
        outpoint: &OutPoint,
        spender_pubkey: &PublicKeyBytes,
        current_block_height: u64,
    ) -> Result<&TxOutput, String> {
        let utxo = self
            .utxos
            .get(outpoint)
            .ok_or_else(|| "UTXO খুঁজে পাওয়া যায়নি অথবা ইতোমধ্যে খরচ (Spent) হয়ে গেছে".to_string())?;

        if !utxo.is_spendable_at(current_block_height) {
            return Err(format!(
                "টাইম-লক সক্রিয়: এই কয়েনটি ব্লক #{} না আসা পর্যন্ত খরচ করা যাবে না (বর্তমান ব্লক: #{})",
                utxo.unlock_height, current_block_height
            ));
        }

        if !verify_address_ownership(&utxo.recipient_address, spender_pubkey).unwrap_or(false) {
    return Err("UTXO ক্রিপ্টোগ্রাফিক মালিকানা যাচাই ব্যর্থ!".to_string());
}

        Ok(utxo)
    }

    /// নির্দিষ্ট অ্যাড্রেসের বর্তমান মোট ব্যালেন্স হিসাব করে `(spendable, locked)`
    pub fn get_balance(&self, address: &str, current_block_height: u64) -> (u64, u64) {
        let mut spendable = 0u64;
        let mut locked = 0u64;

        for output in self.utxos.values() {
            if output.recipient_address == address {
                if output.is_spendable_at(current_block_height) {
                    spendable = spendable.saturating_add(output.amount);
                } else {
                    locked = locked.saturating_add(output.amount);
                }
            }
        }
        (spendable, locked)
    }

    /// নির্দিষ্ট অ্যাড্রেসের ব্যালেন্স এবং মোট UTXO নোটের সংখ্যা একসাথে রিটার্ন করে `(spendable, locked, note_count)`
    pub fn get_balance_with_count(
        &self,
        address: &str,
        current_block_height: u64,
    ) -> (u64, u64, usize) {
        let mut spendable = 0u64;
        let mut locked = 0u64;
        let mut count = 0usize;

        for output in self.utxos.values() {
            if output.recipient_address == address {
                count += 1;
                if output.is_spendable_at(current_block_height) {
                    spendable = spendable.saturating_add(output.amount);
                } else {
                    locked = locked.saturating_add(output.amount);
                }
            }
        }
        (spendable, locked, count)
    }

    /// পুরো UTXO সেটে থাকা মোট কয়েনের পরিমাণ হিসাব করে এবং ২১ মিলিয়ন হার্ড-ক্যাপ অতিক্রম করেছে কি না তা যাচাই করে
    pub fn verify_supply_invariant(&self) -> Result<u64, String> {
        let mut total_atomic: u128 = 0;

        for output in self.utxos.values() {
            if output.amount == 0 {
                return Err("লেজারে শূন্য (0) অ্যামাউন্টের অবৈধ UTXO পাওয়া গেছে".to_string());
            }
            total_atomic = total_atomic
                .checked_add(output.amount as u128)
                .ok_or_else(|| "UTXO সাপ্লাই যোগফলে গাণিতিক ওভারফ্লো".to_string())?;
        }

        if total_atomic > (MAX_SUPPLY as u128) {
            return Err(format!(
                "২১ মিলিয়ন হার্ড-ক্যাপ লঙ্ঘন: UTXO সেটের মোট সাপ্লাই ({}) সর্বোচ্চ সীমা ({}) অতিক্রম করেছে!",
                total_atomic, MAX_SUPPLY
            ));
        }

        Ok(total_atomic as u64)
    }

    /// পুরো UTXO লেজারকে ডিটারমিনিস্টিক ক্রমানুসারে সাজিয়ে ৩২-বাইট ক্রিপ্টোগ্রাফিক State Merkle Root তৈরি করে
    pub fn compute_state_root(&self) -> Hash256 {
        if self.utxos.is_empty() {
            return ZERO_HASH;
        }

        let mut sorted_entries: Vec<(&OutPoint, &TxOutput)> = self.utxos.iter().collect();
        sorted_entries.sort_by(|a, b| a.0.cmp(b.0));

        let leaf_hashes: Vec<Hash256> = sorted_entries
            .into_iter()
            .map(|(op, out)| {
                let mut buf = Vec::with_capacity(96);
                buf.extend_from_slice(UTXO_STATE_LEAF_DOMAIN);
                buf.extend_from_slice(&op.txid);
                buf.extend_from_slice(&op.vout.to_le_bytes());
                buf.extend_from_slice(&out.amount.to_le_bytes());
                buf.extend_from_slice(&out.unlock_height.to_le_bytes());
                buf.extend_from_slice(out.recipient_address.as_bytes());
                sha256d(&buf)
            })
            .collect();

        compute_merkle_root(&leaf_hashes)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_utxo_ownership_timelock_and_deterministic_state_root() {
        let kp_owner = KeyPair::generate();
        let kp_hacker = KeyPair::generate();
        let owner_addr = pubkey_to_address(&kp_owner.public_key());

        let mut set_a = UtxoSet::new();
        let mut set_b = UtxoSet::new();

        let op1 = OutPoint::new([0x11u8; 32], 0);
        let op2 = OutPoint::new([0x22u8; 32], 1);

        let out1 = TxOutput::new_timelocked(100 * COIN, owner_addr.clone(), 50);
        let out2 = TxOutput::new(250 * COIN, owner_addr.clone());

        // ভিন্ন ক্রমে ইনসার্ট করা হলেও স্টেট মার্কেল রুট হুবহু এক হতে হবে
        set_a.add_utxo_checked(op1.clone(), out1.clone()).unwrap();
        set_a.add_utxo_checked(op2.clone(), out2.clone()).unwrap();

        set_b.add_utxo_checked(op2.clone(), out2).unwrap();
        set_b.add_utxo_checked(op1.clone(), out1).unwrap();

        assert_eq!(set_a.compute_state_root(), set_b.compute_state_root());
        assert_eq!(set_a.verify_supply_invariant().unwrap(), 350 * COIN);

        // ব্লক #১০-এ op1 লকড এবং op2 আনলকড থাকবে
        let (spendable, locked, count) = set_a.get_balance_with_count(&owner_addr, 10);
        assert_eq!(spendable, 250 * COIN);
        assert_eq!(locked, 100 * COIN);
        assert_eq!(count, 2);

        // হ্যাকারের পাবলিক কি দিয়ে op2 খরচ করার চেষ্টা করলে ব্লক হবে
        assert!(set_a
            .verify_utxo_spendable(&op2, &kp_hacker.public_key(), 10)
            .is_err());

        // আসল মালিক ব্লক #১০-এ টাইম-লকড op1 খরচ করতে গেলে ব্লক হবে, কিন্তু ব্লক #৫০-এ সফল হবে
        assert!(set_a
            .verify_utxo_spendable(&op1, &kp_owner.public_key(), 10)
            .is_err());
        assert!(set_a
            .verify_utxo_spendable(&op1, &kp_owner.public_key(), 50)
            .is_ok());
    }
}
