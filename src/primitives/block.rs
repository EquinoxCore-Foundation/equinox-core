#![allow(dead_code)]
// src/primitives/block.rs
// Equinox (EQX) L1 — Audit-Grade Block Header, 2M Time-Locked Genesis Block,
// Bit-Level PoW Target Verifier & 6-Byte Short-ID Compact Block Relay Engine.

use crate::config::{
    MAX_BLOCK_SIZE_BYTES, OWNER_TIER1_UNLOCKED_AMOUNT, OWNER_TIER1_UNLOCK_HEIGHT,
    OWNER_TIER2_LOCKED_AMOUNT, OWNER_TIER2_UNLOCK_HEIGHT, OWNER_TIER3_YEAR4_AMOUNT,
    OWNER_TIER3_YEAR4_UNLOCK_HEIGHT, OWNER_TIER3_YEAR5_AMOUNT, OWNER_TIER3_YEAR5_UNLOCK_HEIGHT,
    PREMINE_ECOSYSTEM_RESERVE, PREMINE_EXCHANGE_LIQUIDITY, PREMINE_MARKETING_AND_DEV,
    PREMINE_SUPPLY,
};
use crate::crypto::hash::{
    compute_short_txid, constant_time_eq, sha256d, Hash256, ShortTxId, ZERO_HASH,
};
use crate::crypto::merkle::{compute_merkle_root, has_duplicate_transactions};
use crate::primitives::transaction::{Transaction, TxOutput};
use serde::{Deserialize, Serialize};

/// জেনেসিস ব্লকের নির্ধারিত ইউনিক্স টাইমস্ট্যাম্প
pub const GENESIS_TIMESTAMP: u64 = 1_729_468_800;

/// প্রুফ-অফ-ওয়ার্ক ডিফিকাল্টি টার্গেটের সর্বোচ্চ সীমা (২৫৬ বিট)
pub const MAX_DIFFICULTY_BITS: u32 = 256;

/// ব্লক হেডার স্ট্রাকচার (৮০+ বাইট ডিটারমিনিস্টিক কমিটমেন্ট)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub prev_block_hash: Hash256,
    pub merkle_root: Hash256,
    pub timestamp: u64,
    pub difficulty_target: u32,
    pub nonce: u64,
}

impl BlockHeader {
    /// ব্লক হেডারের ক্যানোনিকাল বাইট থেকে ডাবল SHA-256 (`sha256d`) হ্যাশ তৈরি করে
    pub fn hash(&self) -> Hash256 {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.prev_block_hash);
        buf.extend_from_slice(&self.merkle_root);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.difficulty_target.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        sha256d(&buf)
    }

    /// ব্লক হ্যাশটি নির্ধারিত প্রুফ-অফ-ওয়ার্ক ডিফিকাল্টি (Leading Zero Bits) পূরণ করেছে কি না তা যাচাই করে
    pub fn meets_difficulty(&self) -> bool {
        if self.difficulty_target == 0 {
            return true;
        }
        if self.difficulty_target > MAX_DIFFICULTY_BITS {
            return false;
        }

        let hash = self.hash();
        let mut zero_bits_counted = 0u32;

        for &byte in hash.iter() {
            if byte == 0 {
                zero_bits_counted += 8;
                if zero_bits_counted >= self.difficulty_target {
                    return true;
                }
            } else {
                zero_bits_counted += byte.leading_zeros();
                return zero_bits_counted >= self.difficulty_target;
            }
        }

        zero_bits_counted >= self.difficulty_target
    }
}

/// ৯৫% ব্যান্ডউইথ সাশ্রয়ী কম্প্যাক্ট ব্লক স্ট্রাকচার (BIP-152 স্ট্যান্ডার্ড)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactBlock {
    pub header: BlockHeader,
    pub coinbase_tx: Option<Transaction>,
    pub short_txids: Vec<ShortTxId>,
}

/// পূর্ণাঙ্গ লেয়ার-১ ব্লক স্ট্রাকচার
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// নতুন ব্লক তৈরি করে এবং ট্রানজ্যাকশনগুলোর ক্রিপ্টোগ্রাফিক Merkle Root স্বয়ংক্রিয়ভাবে সেট করে
    pub fn new(
        height: u64,
        prev_block_hash: Hash256,
        transactions: Vec<Transaction>,
        difficulty_target: u32,
        timestamp: u64,
    ) -> Self {
        let tx_hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();
        let merkle_root = compute_merkle_root(&tx_hashes);

        let header = BlockHeader {
            version: 1,
            height,
            prev_block_hash,
            merkle_root,
            timestamp,
            difficulty_target,
            nonce: 0,
        };

        Self {
            header,
            transactions,
        }
    }

    /// Equinox (EQX) মেইননেটের জেনেসিস ব্লক (`Height #0`) তৈরি করে।
    /// এতে মোট ২০ লক্ষ EQX প্রি-মাইন কয়েন এবং ওনারের ১২ লক্ষ কয়েনের ৫ বছরের টাইম-লক শিডিউল সেট করা থাকে।
    pub fn genesis(
        owner_address: &str,
        liquidity_address: &str,
        marketing_address: &str,
        reserve_address: &str,
    ) -> Self {
        let outputs = vec![
            // ১. এক্সচেঞ্জ লিকুইডিটি ফান্ড: ৩,০০,০০০ EQX
            TxOutput::new_timelocked(
                PREMINE_EXCHANGE_LIQUIDITY,
                liquidity_address.trim().to_string(),
                0,
            ),
            // ২. মার্কেটিং, এয়ারড্রপ ও ডেভেলপমেন্ট ফান্ড: ৩,০০,০০০ EQX
            TxOutput::new_timelocked(
                PREMINE_MARKETING_AND_DEV,
                marketing_address.trim().to_string(),
                0,
            ),
            // ৩. ইকোসিস্টেম ও কমিউনিটি রিজার্ভ ফান্ড: ২,০০,০০০ EQX
            TxOutput::new_timelocked(
                PREMINE_ECOSYSTEM_RESERVE,
                reserve_address.trim().to_string(),
                0,
            ),
            // ৪. ওনার বরাদ্দ — ধাপ ১ (জেনেসিসে আনলকড): ২,০০,০০০ EQX
            TxOutput::new_timelocked(
                OWNER_TIER1_UNLOCKED_AMOUNT,
                owner_address.trim().to_string(),
                OWNER_TIER1_UNLOCK_HEIGHT,
            ),
            // ৫. ওনার বরাদ্দ — ধাপ ২ (২ বছর টাইম-লকড): ৫,০০,০০০ EQX
            TxOutput::new_timelocked(
                OWNER_TIER2_LOCKED_AMOUNT,
                owner_address.trim().to_string(),
                OWNER_TIER2_UNLOCK_HEIGHT,
            ),
            // ৬. ওনার বরাদ্দ — ধাপ ৩ ক (৪ বছর টাইম-লকড): ২,৫০,০০০ EQX
            TxOutput::new_timelocked(
                OWNER_TIER3_YEAR4_AMOUNT,
                owner_address.trim().to_string(),
                OWNER_TIER3_YEAR4_UNLOCK_HEIGHT,
            ),
            // ৭. ওনার বরাদ্দ — ধাপ ৩ খ (৫ বছর টাইম-লকড): ২,৫০,০০০ EQX
            TxOutput::new_timelocked(
                OWNER_TIER3_YEAR5_AMOUNT,
                owner_address.trim().to_string(),
                OWNER_TIER3_YEAR5_UNLOCK_HEIGHT,
            ),
        ];

        let total_genesis_out: u64 = outputs.iter().map(|o| o.amount).sum();
        debug_assert_eq!(total_genesis_out, PREMINE_SUPPLY);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: Vec::new(),
            outputs,
            timestamp: GENESIS_TIMESTAMP,
            fee: 0,
        };

        Self::new(0, ZERO_HASH, vec![genesis_coinbase], 4, GENESIS_TIMESTAMP)
    }

    /// ব্লকের ৩২-বাইট হ্যাশ রিটার্ন করে
    #[inline]
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    /// ব্লকের বর্তমান ট্রানজ্যাকশন তালিকা থেকে Merkle Root গণনা করে
    pub fn calculate_merkle_root(&self) -> Hash256 {
        let tx_hashes: Vec<Hash256> = self.transactions.iter().map(|tx| tx.txid()).collect();
        compute_merkle_root(&tx_hashes)
    }

    /// প্রুফ-অফ-ওয়ার্ক (PoW) মাইনিং ইঞ্জিন: ডিফিকাল্টি টার্গেট পূরণ না হওয়া পর্যন্ত ননস বৃদ্ধি করে।
    /// `max_iterations` দেওয়া থাকলে নির্দিষ্ট সংখ্যক চেষ্টার পর থেমে যাবে (ইউনিট টেস্টের জন্য নিরাপদ)।
    pub fn mine(&mut self, max_iterations: Option<u64>) -> bool {
        self.header.merkle_root = self.calculate_merkle_root();
        let limit = max_iterations.unwrap_or(u64::MAX);

        for _ in 0..limit {
            if self.header.meets_difficulty() {
                return true;
            }
            self.header.nonce = self.header.nonce.wrapping_add(1);
        }

        self.header.meets_difficulty()
    }

    /// পূর্ণাঙ্গ ব্লক থেকে ৯৫% হালকা `CompactBlock` তৈরি করে (P2P ব্রডকাস্টের জন্য)
    pub fn to_compact_block(&self) -> CompactBlock {
        let coinbase_tx = self.transactions.first().cloned();
        let nonce = self.header.nonce;

        let short_txids: Vec<ShortTxId> = self
            .transactions
            .iter()
            .skip(1)
            .map(|tx| compute_short_txid(&tx.txid(), nonce))
            .collect();

        CompactBlock {
            header: self.header.clone(),
            coinbase_tx,
            short_txids,
        }
    }

    /// ব্লকের কাঠামোগত অখণ্ডতা, সাইজ লিমিট, কয়েনবেস পজিশন, মার্কেল রুট এবং PoW কঠোরভাবে যাচাই করে
    pub fn verify_structural_integrity(&self) -> Result<(), String> {
        if self.transactions.is_empty() {
            return Err("ব্লকে অন্তত ১টি কয়েনবেস ট্রানজ্যাকশন থাকতে হবে".to_string());
        }

        // ১. প্রথম ট্রানজ্যাকশনটি অবশ্যই কয়েনবেস হতে হবে এবং পরের কোনোটিই কয়েনবেস হতে পারবে না
        if !self.transactions[0].is_coinbase() {
            return Err("ব্লকের প্রথম ট্রানজ্যাকশনটি কয়েনবেস নয়".to_string());
        }
        for (idx, tx) in self.transactions.iter().enumerate().skip(1) {
            if tx.is_coinbase() {
                return Err(format!(
                    "ব্লকের ইনডেক্স #{}-এ অবৈধ অতিরিক্ত কয়েনবেস ট্রানজ্যাকশন পাওয়া গেছে",
                    idx
                ));
            }
        }

        // ২. ডুপ্লিকেট ট্রানজ্যাকশন চেক (CVE-2012-2459 প্রতিরোধ)
        let tx_hashes: Vec<Hash256> = self.transactions.iter().map(|tx| tx.txid()).collect();
        if has_duplicate_transactions(&tx_hashes) {
            return Err("ব্লকের ভেতরে ডুপ্লিকেট ট্রানজ্যাকশন (CVE-2012-2459) পাওয়া গেছে".to_string());
        }

        // ৩. কনস্ট্যান্ট-টাইমে Merkle Root যাচাই
        let expected_merkle = compute_merkle_root(&tx_hashes);
        if constant_time_eq(&expected_merkle, &ZERO_HASH)
            || !constant_time_eq(&expected_merkle, &self.header.merkle_root)
        {
            return Err("ব্লক হেডারের Merkle Root ট্রানজ্যাকশন তালিকার সাথে মেলেনি!".to_string());
        }

        // ৪. প্রুফ-অফ-ওয়ার্ক ডিফিকাল্টি যাচাই
        if !self.header.meets_difficulty() {
            return Err("ব্লক হেডার প্রুফ-অফ-ওয়ার্ক (PoW) ডিফিকাল্টি টার্গেট পূরণ করেনি".to_string());
        }

        // ৫. ব্লকের সর্বোচ্চ ২ মেগাবাইট সাইজ লিমিট যাচাই
        let encoded_len = bincode::serialize(self)
            .map_err(|e| format!("ব্লক সিরিয়ালাইজেশন ত্রুটি: {}", e))?
            .len();
        if encoded_len > MAX_BLOCK_SIZE_BYTES {
            return Err(format!(
                "ব্লকের আকার ({} বাইট) সর্বোচ্চ অনুমোদিত সীমা ({} বাইট) অতিক্রম করেছে",
                encoded_len, MAX_BLOCK_SIZE_BYTES
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use crate::primitives::transaction::TxInput;
    use crate::state::outpoint::OutPoint;
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_genesis_2m_premine_and_pow_mining() {
        let mut genesis = Block::genesis(
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
        );

        assert!(genesis.mine(Some(50_000)));
        assert!(genesis.verify_structural_integrity().is_ok());

        let total_premine: u64 = genesis.transactions[0]
            .outputs
            .iter()
            .map(|o| o.amount)
            .sum();
        assert_eq!(total_premine, PREMINE_SUPPLY);
    }

    #[test]
    fn test_compact_block_conversion() {
        let kp = KeyPair::generate();
        let addr = pubkey_to_address(&kp.public_key());

        let cb = Transaction::new_coinbase(1, addr.clone(), 0, 1_729_468_815);
        let mut user_tx = Transaction::new(
            vec![TxInput {
                prev_out: OutPoint::new([0x11u8; 32], 0),
                public_key: kp.public_key(),
                signature: [0u8; 64],
            }],
            vec![TxOutput::new(50_000_000, addr)],
            1_729_468_815,
            10_000,
        );
        user_tx.sign_input(0, &kp).unwrap();

        let mut blk = Block::new(1, [0xAAu8; 32], vec![cb, user_tx], 4, 1_729_468_815);
        assert!(blk.mine(Some(50_000)));

        let compact = blk.to_compact_block();
        assert!(compact.coinbase_tx.is_some());
        assert_eq!(compact.short_txids.len(), 1);
    }
}

