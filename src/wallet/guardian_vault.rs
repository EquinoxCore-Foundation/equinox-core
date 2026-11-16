#![allow(dead_code)]
// src/wallet/guardian_vault.rs
// Equinox (EQX) L1 — World's First Anti-Hack Reversible Quarantine Vault & Dead-Man's Inheritance Switch
// Integrated with Automated Protocol Owner Royalty (0.20% Default Annual Protection Fee).

use crate::config::{BLOCKS_PER_DAY, BLOCKS_PER_YEAR, MAX_SUPPLY};
use crate::consensus::royalty::{ProtocolRoyaltyEngine, DEFAULT_ANNUAL_ROYALTY_BPS};
use crate::crypto::hash::{sha256d_tagged, Hash256};
use crate::crypto::keys::{verify_signature, PublicKeyBytes, SignatureBytes};
use crate::wallet::address::is_valid_address;
use serde::{Deserialize, Serialize};

/// ২৪ ঘণ্টার অ্যান্টি-হ্যাক কোয়ারেন্টাইন উইন্ডো (১৫ সেকেন্ড ব্লক টাইমে ৫,৭৬০ ব্লক)
pub const VAULT_QUARANTINE_BLOCKS: u64 = BLOCKS_PER_DAY;

/// ৩ বছরের নিষ্ক্রিয়তা সীমা (Dead-Man's Inheritance Switch: ৬,৩০৭,২০০ ব্লক)
pub const INHERITANCE_INACTIVITY_BLOCKS: u64 = BLOCKS_PER_YEAR * 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    PendingQuarantine,
    FinalizedAndReleased,
    ClawedBackByGuardian,
}

/// কোয়ারেন্টাইনে থাকা পেন্ডিং হাই-সিকিউরিটি ট্রানজ্যাকশন
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedTransfer {
    pub transfer_id: Hash256,
    pub vault_address: String,
    pub destination_address: String,
    pub net_amount_atomic: u64,
    pub owner_royalty_atomic: u64,
    pub initiated_at_height: u64,
    pub release_at_height: u64,
    pub status: QuarantineStatus,
}

/// অ্যান্টি-হ্যাক গার্ডিয়ান ভল্ট এবং উত্তরাধিকার (Inheritance) কন্ট্রোলার
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianVault {
    pub primary_owner_address: String,
    /// হ্যাকার প্রাইভেট কি চুরি করলেও এই অফলাইন প্যানিক পাবলিক কি দিয়ে ২৪ ঘণ্টার মধ্যে ট্রানজ্যাকশন বাতিল করা যাবে
    pub guardian_panic_pubkey: PublicKeyBytes,
    /// জরুরি অবস্থায় কয়েন যে নিরাপদ কোল্ড-স্টোরেজ অ্যাড্রেসে ফিরে যাবে
    pub emergency_recovery_address: String,
    /// মালিকের অবর্তমানে (৩ বছর নিষ্ক্রিয় থাকলে) পরিবারের যে নমিনি অ্যাড্রেস কয়েন পাবে
    pub nominee_inheritance_address: String,
    /// প্রটোকল ওনার রয়্যালটি ওয়ালেট অ্যাড্রেস
    pub protocol_royalty_address: String,
    /// বার্ষিক সার্ভিস রয়্যালটি রেট (ডিফল্ট ০.২০% বা ২০ BPS)
    pub annual_royalty_bps: u16,
    pub vault_created_at_height: u64,
    /// সর্বশেষ যে ব্লকে মালিক ওয়ালেটে সক্রিয় (Heartbeat) ছিলেন
    pub last_owner_heartbeat_height: u64,
    pub pending_transfers: Vec<QuarantinedTransfer>,
}

impl GuardianVault {
    pub fn new(
        primary_owner_address: String,
        guardian_panic_pubkey: PublicKeyBytes,
        emergency_recovery_address: String,
        nominee_inheritance_address: String,
        protocol_royalty_address: String,
        current_height: u64,
    ) -> Result<Self, String> {
        if !is_valid_address(&primary_owner_address)
            || !is_valid_address(&emergency_recovery_address)
            || !is_valid_address(&nominee_inheritance_address)
            || !is_valid_address(&protocol_royalty_address)
        {
            return Err("গার্ডিয়ান ভল্টের ওয়ালেট অ্যাড্রেস বৈধ নয়".to_string());
        }

        Ok(Self {
            primary_owner_address,
            guardian_panic_pubkey,
            emergency_recovery_address,
            nominee_inheritance_address,
            protocol_royalty_address,
            annual_royalty_bps: DEFAULT_ANNUAL_ROYALTY_BPS,
            vault_created_at_height: current_height,
            last_owner_heartbeat_height: current_height,
            pending_transfers: Vec::new(),
        })
    }

    /// মালিক সক্রিয় থাকলে হার্টবিট আপডেট করে (যাতে ৩ বছরের Dead-Man's Switch রিসেট হয়)
    pub fn record_owner_heartbeat(&mut self, current_height: u64) {
        if current_height > self.last_owner_heartbeat_height {
            self.last_owner_heartbeat_height = current_height;
        }
    }

    /// ভল্ট থেকে কয়েন পাঠালে বার্ষিক ০.২% রয়্যালটি স্বয়ংক্রিয়ভাবে হিসাব হয়ে ২৪ ঘণ্টার কোয়ারেন্টাইনে জমা হয়
    pub fn initiate_guarded_transfer(
        &mut self,
        destination_address: String,
        gross_amount_atomic: u64,
        current_height: u64,
    ) -> Result<QuarantinedTransfer, String> {
        if !is_valid_address(&destination_address) {
            return Err("প্রাপকের অ্যাড্রেস বৈধ নয়".to_string());
        }
        if gross_amount_atomic == 0 || gross_amount_atomic > MAX_SUPPLY {
            return Err("অবৈধ ট্রান্সফার অ্যামাউন্ট".to_string());
        }

        let elapsed_blocks = current_height
            .saturating_sub(self.vault_created_at_height)
            .max(1);

        let royalty_engine = ProtocolRoyaltyEngine::new(
            self.protocol_royalty_address.clone(),
            self.annual_royalty_bps,
        )?;

        let royalty_cut =
            royalty_engine.calculate_annualized_vault_royalty(gross_amount_atomic, elapsed_blocks);
        let net_amount = gross_amount_atomic.saturating_sub(royalty_cut);

        if net_amount == 0 {
            return Err("রয়্যালটি কাটার পর নিট ট্রান্সফার অ্যামাউন্ট শূন্য হতে পারে না".to_string());
        }

        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(self.primary_owner_address.as_bytes());
        buf.extend_from_slice(destination_address.as_bytes());
        buf.extend_from_slice(&gross_amount_atomic.to_le_bytes());
        buf.extend_from_slice(&current_height.to_le_bytes());

        let transfer_id = sha256d_tagged(b"EQX_GUARDIAN_VAULT_TX_V1", &buf);
        let release_at_height = current_height.saturating_add(VAULT_QUARANTINE_BLOCKS);

        let record = QuarantinedTransfer {
            transfer_id,
            vault_address: self.primary_owner_address.clone(),
            destination_address,
            net_amount_atomic: net_amount,
            owner_royalty_atomic: royalty_cut,
            initiated_at_height: current_height,
            release_at_height,
            status: QuarantineStatus::PendingQuarantine,
        };

        self.pending_transfers.push(record.clone());
        Ok(record)
    }

    /// অ্যান্টি-হ্যাক প্যানিক সুইচ: হ্যাকার কয়েন সরানোর চেষ্টা করলে ২৪ ঘণ্টার মধ্যে এটি কল করলেই চুরি বাতিল হয়ে যাবে!
    pub fn trigger_panic_clawback(
        &mut self,
        transfer_id: &Hash256,
        current_height: u64,
        panic_signature: &SignatureBytes,
    ) -> Result<String, String> {
        let mut sign_msg = Vec::with_capacity(53);
        sign_msg.extend_from_slice(b"EQX_PANIC_CLAWBACK_V1");
        sign_msg.extend_from_slice(transfer_id);

        if !verify_signature(&self.guardian_panic_pubkey, &sign_msg, panic_signature) {
            return Err("অবৈধ প্যানিক সিগনেচার! ক্ল-ব্যাক অনুমোদিত নয়।".to_string());
        }

        for item in &mut self.pending_transfers {
            if &item.transfer_id == transfer_id {
                if item.status != QuarantineStatus::PendingQuarantine {
                    return Err("ট্রানজ্যাকশনটি ইতিমধ্যে নিষ্পত্তি হয়ে গেছে".to_string());
                }
                if current_height >= item.release_at_height {
                    return Err("২৪ ঘণ্টার কোয়ারেন্টাইন সময় পার হয়ে গেছে".to_string());
                }

                item.status = QuarantineStatus::ClawedBackByGuardian;
                return Ok(self.emergency_recovery_address.clone());
            }
        }

        Err("পেন্ডিং ট্রানজ্যাকশন আইডি খুঁজে পাওয়া যায়নি".to_string())
    }

    /// মালিক যদি ৩ বছর (৬,৩০৭,২০০ ব্লক) নিষ্ক্রিয় থাকেন, তবে পরিবারের নমিনি অ্যাড্রেস ভল্ট আনলক করতে পারবে
    pub fn check_inheritance_unlock(&self, current_height: u64) -> Option<String> {
        let inactive_blocks = current_height.saturating_sub(self.last_owner_heartbeat_height);
        if inactive_blocks >= INHERITANCE_INACTIVITY_BLOCKS {
            Some(self.nominee_inheritance_address.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::wallet::address::{derive_deterministic_genesis_address, pubkey_to_address};

    #[test]
    fn test_anti_hack_vault_clawback_royalty_and_inheritance() {
        let owner_kp = KeyPair::generate();
        let panic_kp = KeyPair::generate();
        let recovery_kp = KeyPair::generate();
        let nominee_kp = KeyPair::generate();
        let hacker_kp = KeyPair::generate();

        let owner_addr = pubkey_to_address(&owner_kp.public_key());
        let recovery_addr = pubkey_to_address(&recovery_kp.public_key());
        let nominee_addr = pubkey_to_address(&nominee_kp.public_key());
        let hacker_addr = pubkey_to_address(&hacker_kp.public_key());
        let protocol_owner = derive_deterministic_genesis_address("EQX_MAINNET_OWNER_VAULT");

        let mut vault = GuardianVault::new(
            owner_addr,
            panic_kp.public_key(),
            recovery_addr.clone(),
            nominee_addr.clone(),
            protocol_owner,
            0,
        )
        .unwrap();

        // ১ বছর (BLOCKS_PER_YEAR) পর ১০,০০০ EQX ট্রান্সফার করলে ০.২% (২০ EQX) রয়্যালটি স্বয়ংক্রিয়ভাবে কাটবে
        let transfer = vault
            .initiate_guarded_transfer(hacker_addr, 10_000 * COIN, BLOCKS_PER_YEAR)
            .unwrap();
        assert_eq!(transfer.owner_royalty_atomic, 20 * COIN);
        assert_eq!(transfer.net_amount_atomic, 9_980 * COIN);

        // আসল মালিক ২৪ ঘণ্টার মধ্যে প্যানিক সিগনেচার দিয়ে হ্যাকারের ট্রানজ্যাকশনটি বাতিল করলেন!
        let mut msg = Vec::new();
        msg.extend_from_slice(b"EQX_PANIC_CLAWBACK_V1");
        msg.extend_from_slice(&transfer.transfer_id);
        let sig = panic_kp.sign(&msg);

        let rescued_to = vault
            .trigger_panic_clawback(&transfer.transfer_id, BLOCKS_PER_YEAR + 10, &sig)
            .unwrap();
        assert_eq!(rescued_to, recovery_addr);

        // ৩ বছর নিষ্ক্রিয় থাকলে নমিনি অ্যাড্রেস স্বয়ংক্রিয়ভাবে ভল্টের মালিকানা পাবে
        let unlocked_nominee = vault
            .check_inheritance_unlock(INHERITANCE_INACTIVITY_BLOCKS + 10)
            .unwrap();
        assert_eq!(unlocked_nominee, nominee_addr);
    }
}