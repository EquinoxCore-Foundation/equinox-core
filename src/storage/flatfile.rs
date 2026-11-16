#![allow(dead_code)]
// src/storage/flatfile.rs
// Equinox (EQX) L1 — Audit-Grade Flat-File Binary Block Storage ('blk00000.dat')
// Features: OOM Payload Size Guard, Power-Failure Self-Healing Tail Truncation,
// Constant-Time SHA-256d Checksum, Post-Read Block Hash Verification & O(1) Seek Index.

use crate::config::{MAX_BLOCK_SIZE_BYTES, NETWORK_MAGIC};
use crate::crypto::hash::{constant_time_eq, sha256d, Hash256};
use crate::primitives::block::Block;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// প্রতিটি ফ্ল্যাট-ফাইলের (`blkXXXXX.dat`) ডিফল্ট সর্বোচ্চ আকার: ১২৮ মেগাবাইট (Bitcoin Core স্ট্যান্ডার্ড)
pub const DEFAULT_MAX_BLK_FILE_SIZE: u64 = 128 * 1024 * 1024;

/// ডিস্কে প্রতিটি ব্লক রেকর্ডের শুরুতে ১২ বাইটের ফ্রেম হেডার থাকে:
/// [Magic Bytes (4B)] + [Payload Length u32 (4B)] + [Checksum (4B)]
const RECORD_HEADER_SIZE: u64 = 12;

/// সিরিয়ালাইজেশন ওভারহেডসহ একটি ব্লক রেকর্ডের সর্বোচ্চ অনুমোদিত ডিস্ক আকার (৪ মেগাবাইট)
pub const MAX_RECORD_PAYLOAD_BYTES: u32 = (MAX_BLOCK_SIZE_BYTES as u32) * 2;

/// ডিস্ক স্টোরেজ সংক্রান্ত এরর টাইপ
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("ডিস্ক I/O ত্রুটি: {0}")]
    IoError(#[from] std::io::Error),

    #[error("বাইনারি সিরিয়ালাইজেশন/ডিসিরিয়ালাইজেশন ত্রুটি: {0}")]
    SerializationError(String),

    #[error("ডিস্কে অবৈধ ম্যাজিক বাইটস পাওয়া গেছে (ফাইল করাপশন বা ভুল নেটওয়ার্ক ডেটা)")]
    InvalidMagicBytes,

    #[error("ডিস্ক চেকসাম মেলেনি! ব্লক ডেটা ক্ষতিগ্রস্ত (Corrupted) হয়েছে")]
    ChecksumMismatch,

    #[error("নির্দিষ্ট ব্লকটি ডিস্ক ইনডেক্সে খুঁজে পাওয়া যায়নি")]
    BlockNotFound,
}

/// ডিস্কের কোন ফাইলের (`blk00000.dat`) কত নম্বর বাইটে ব্লকটি আছে তার নিখুঁত ঠিকানা
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDiskLocation {
    /// ফাইলের ক্রমিক নম্বর (যেমন: 0 মানে `blk00000.dat`, 1 মানে `blk00001.dat`)
    pub file_index: u32,
    /// ফাইলের শুরু থেকে কত বাইট পরে ব্লক রেকর্ডটি শুরু হয়েছে
    pub byte_offset: u64,
    /// সিরিয়ালাইজড ব্লকের মোট বাইট আকার
    pub payload_size: u32,
    /// ব্লকের হাইট
    pub height: u64,
    /// ব্লকের ৩২-বাইট হ্যাশ
    pub block_hash: Hash256,
}

/// ডেটাবেস-মুক্ত ফ্ল্যাট-ফাইল ব্লক স্টোরেজ ইঞ্জিন
pub struct FlatFileStorage {
    data_dir: PathBuf,
    current_file_index: u32,
    current_file_size: u64,
    max_file_size: u64,
    /// ব্লক হ্যাশ থেকে ডিস্কের অবস্থান খোঁজার O(1) ইন-মেমোরি ইনডেক্স
    hash_index: HashMap<Hash256, BlockDiskLocation>,
    /// ব্লক হাইট থেকে ডিস্কের অবস্থান খোঁজার O(1) ইন-মেমোরি ইনডেক্স
    height_index: HashMap<u64, BlockDiskLocation>,
}

impl FlatFileStorage {
    /// স্টোরেজ ডিরেক্টরি খুলে দেয় এবং ডিস্কে থাকা `blk*.dat` ফাইলগুলো স্ক্যান করে ইনডেক্স তৈরি করে
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self, StorageError> {
        let dir_path = data_dir.as_ref().to_path_buf();
        if !dir_path.exists() {
            fs::create_dir_all(&dir_path)?;
        }

        let mut storage = Self {
            data_dir: dir_path,
            current_file_index: 0,
            current_file_size: 0,
            max_file_size: DEFAULT_MAX_BLK_FILE_SIZE,
            hash_index: HashMap::new(),
            height_index: HashMap::new(),
        };

        // ডিস্কে আগে থেকে কোনো ব্লক ফাইল থাকলে সেগুলো স্ক্যান ও সেলফ-হিল করে ইনডেক্স রিবিল্ড করা হয়
        storage.rebuild_index_from_disk()?;
        Ok(storage)
    }

    /// কাস্টম ফাইল সাইজ লিমিট সেট করার মেথড (ইউনিট টেস্ট বা কাস্টম নোডের জন্য)
    pub fn with_max_file_size(mut self, max_bytes: u64) -> Self {
        self.max_file_size = max_bytes.max(4096);
        self
    }

    /// ফাইল নম্বর অনুযায়ী ফাইলের নাম তৈরি করে (যেমন: `0` -> `blk00000.dat`)
    #[inline]
    pub fn blk_file_path(&self, file_index: u32) -> PathBuf {
        self.data_dir.join(format!("blk{:05}.dat", file_index))
    }

    /// পেলোড সাইজ নিরাপদ সীমার ভেতরে আছে কি না তা পরীক্ষা করে (OOM Crash Guard)
    #[inline]
    fn validate_payload_size(size: u32) -> Result<(), StorageError> {
        if size == 0 || size > MAX_RECORD_PAYLOAD_BYTES {
            return Err(StorageError::SerializationError(format!(
                "অবৈধ ব্লক পেলোড সাইজ: {} বাইট (অনুমোদিত সীমা: 1..={})",
                size, MAX_RECORD_PAYLOAD_BYTES
            )));
        }
        Ok(())
    }

    /// নতুন ব্লক ডিস্কের ফ্ল্যাট-ফাইলে সেভ করে এবং ইনডেক্সে তার অবস্থান যুক্ত করে
    pub fn append_block(&mut self, block: &Block) -> Result<BlockDiskLocation, StorageError> {
        let block_hash = block.hash();

        // ব্লকটি আগে থেকেই সেভ করা থাকলে সরাসরি সেই লোকেশন রিটার্ন করবে (Idempotent)
        if let Some(existing_loc) = self.hash_index.get(&block_hash) {
            return Ok(existing_loc.clone());
        }

        let payload = bincode::serialize(block)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        if payload.len() > (u32::MAX as usize) {
            return Err(StorageError::SerializationError(
                "ব্লক পেলোড u32 সীমার বাইরে".to_string(),
            ));
        }

        let payload_size = payload.len() as u32;
        Self::validate_payload_size(payload_size)?;

        let total_record_bytes = RECORD_HEADER_SIZE + (payload_size as u64);

        // যদি বর্তমান ফাইলটি ১২৮ মেগাবাইট (বা নির্ধারিত সীমা) ছাড়িয়ে যায়, তবে নতুন ফাইলে (`blk00001.dat`) যাবে
        if self.current_file_size > 0
            && self.current_file_size.saturating_add(total_record_bytes) > self.max_file_size
        {
            self.current_file_index = self.current_file_index.saturating_add(1);
            self.current_file_size = 0;
        }

        let target_path = self.blk_file_path(self.current_file_index);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&target_path)?;

        let byte_offset = self.current_file_size;
        file.seek(SeekFrom::Start(byte_offset))?;

        // ৪-বাইট ডিস্ক চেকসাম হিসাব (SHA-256d এর প্রথম ৪ বাইট)
        let checksum_full = sha256d(&payload);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&checksum_full[..4]);

        // ১২-বাইট রেকর্ড হেডার + ব্লক পেলোড একসাথে বাফারে সাজানো
        let mut record_buffer = Vec::with_capacity(total_record_bytes as usize);
        record_buffer.extend_from_slice(&NETWORK_MAGIC);
        record_buffer.extend_from_slice(&payload_size.to_le_bytes());
        record_buffer.extend_from_slice(&checksum);
        record_buffer.extend_from_slice(&payload);

        // ডিস্কে রাইট ও ফুল হার্ডওয়্যার ফ্লাশ করা
        file.write_all(&record_buffer)?;
        file.sync_all()?;

        self.current_file_size = byte_offset + total_record_bytes;

        let location = BlockDiskLocation {
            file_index: self.current_file_index,
            byte_offset,
            payload_size,
            height: block.header.height,
            block_hash,
        };

        self.hash_index.insert(block_hash, location.clone());
        self.height_index
            .insert(block.header.height, location.clone());

        Ok(location)
    }

    /// ডিস্কের নির্দিষ্ট লোকেশন (`BlockDiskLocation`) থেকে সরাসরি সিক করে ব্লক রিড ও যাচাই করে
    pub fn read_block_at(&self, loc: &BlockDiskLocation) -> Result<Block, StorageError> {
        Self::validate_payload_size(loc.payload_size)?;

        let file_path = self.blk_file_path(loc.file_index);
        let mut file = File::open(file_path)?;

        // পুরো ফাইল না পড়ে সরাসরি কাঙ্ক্ষিত বাইট অফসেটে চলে যায় (O(1) Seek)
        file.seek(SeekFrom::Start(loc.byte_offset))?;

        let mut header_buf = [0u8; RECORD_HEADER_SIZE as usize];
        file.read_exact(&mut header_buf)?;

        // ১. কনস্ট্যান্ট-টাইমে নেটওয়ার্ক ম্যাজিক বাইটস যাচাই
        if !constant_time_eq(&header_buf[0..4], &NETWORK_MAGIC) {
            return Err(StorageError::InvalidMagicBytes);
        }

        // ২. পেলোড সাইজ বাউন্ডারি ও ইনডেক্স সামঞ্জস্যতা যাচাই (OOM প্রতিরোধ)
        let mut size_bytes = [0u8; 4];
        size_bytes.copy_from_slice(&header_buf[4..8]);
        let recorded_size = u32::from_le_bytes(size_bytes);
        Self::validate_payload_size(recorded_size)?;

        if recorded_size != loc.payload_size {
            return Err(StorageError::SerializationError(
                "ডিস্ক হেডারের সাইজের সাথে ইনডেক্সের পেলোড সাইজ মেলেনি".to_string(),
            ));
        }

        let mut expected_checksum = [0u8; 4];
        expected_checksum.copy_from_slice(&header_buf[8..12]);

        // ৩. ব্লক পেলোড রিড করা
        let mut payload = vec![0u8; recorded_size as usize];
        file.read_exact(&mut payload)?;

        // ৪. কনস্ট্যান্ট-টাইমে চেকসাম মিলিয়ে ডিস্ক করাপশন পরীক্ষা করা
        let actual_checksum = sha256d(&payload);
        if !constant_time_eq(&actual_checksum[..4], &expected_checksum) {
            return Err(StorageError::ChecksumMismatch);
        }

        let block: Block = bincode::deserialize(&payload)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        // ৫. পোস্ট-ডিসিরিয়ালাইজেশন ব্লক হ্যাশ ও হাইট যাচাই
        if !constant_time_eq(&block.hash(), &loc.block_hash) || block.header.height != loc.height {
            return Err(StorageError::ChecksumMismatch);
        }

        Ok(block)
    }

    /// ব্লক হাইট দিয়ে ডিস্ক থেকে ব্লক খুঁজে বের করে
    pub fn read_block_by_height(&self, height: u64) -> Result<Block, StorageError> {
        let loc = self
            .height_index
            .get(&height)
            .ok_or(StorageError::BlockNotFound)?;
        self.read_block_at(loc)
    }

    /// ব্লক হ্যাশ দিয়ে ডিস্ক থেকে ব্লক খুঁজে বের করে
    pub fn read_block_by_hash(&self, block_hash: &Hash256) -> Result<Block, StorageError> {
        let loc = self
            .hash_index
            .get(block_hash)
            .ok_or(StorageError::BlockNotFound)?;
        self.read_block_at(loc)
    }

    /// নোড রিস্টার্ট হলে ডিস্কে থাকা সব `blk00000.dat`, `blk00001.dat`... ফাইল স্ক্যান করে ইনডেক্স পুনর্গঠন করে।
    /// পাওয়ার ফেইলরের কারণে শেষের কোনো ব্লক আংশিক লেখা হয়ে থাকলে তা স্বয়ংক্রিয়ভাবে ট্রাঙ্কেট করে ঠিক করে দেয়।
    pub fn rebuild_index_from_disk(&mut self) -> Result<usize, StorageError> {
        self.hash_index.clear();
        self.height_index.clear();

        let mut file_idx = 0u32;
        let mut total_indexed_blocks = 0usize;

        loop {
            let path = self.blk_file_path(file_idx);
            if !path.exists() {
                break;
            }

            let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
            let file_len = file.metadata()?.len();
            let mut offset = 0u64;

            while offset < file_len {
                // পাওয়ার ফেইলর গার্ড ১: ফাইলের শেষে ১২ বাইটের কম অসম্পূর্ণ হেডার থাকলে ট্রাঙ্কেট করে হিল করা
                if offset + RECORD_HEADER_SIZE > file_len {
                    file.set_len(offset)?;
                    file.sync_all()?;
                    break;
                }

                file.seek(SeekFrom::Start(offset))?;

                let mut header_buf = [0u8; RECORD_HEADER_SIZE as usize];
                file.read_exact(&mut header_buf)?;

                if !constant_time_eq(&header_buf[0..4], &NETWORK_MAGIC) {
                    return Err(StorageError::InvalidMagicBytes);
                }

                let mut size_bytes = [0u8; 4];
                size_bytes.copy_from_slice(&header_buf[4..8]);
                let payload_size = u32::from_le_bytes(size_bytes);

                // OOM গার্ড: পেলোড সাইজ সীমার বাইরে হলে এরর রিটার্ন করবে
                Self::validate_payload_size(payload_size)?;

                let record_end = offset + RECORD_HEADER_SIZE + (payload_size as u64);

                // পাওয়ার ফেইলর গার্ড ২: ব্লক লেখার মাঝপথে পিসি বন্ধ হয়ে পেলোড অসম্পূর্ণ থাকলে ট্রাঙ্কেট করে হিল করা
                if record_end > file_len {
                    file.set_len(offset)?;
                    file.sync_all()?;
                    break;
                }

                let mut expected_checksum = [0u8; 4];
                expected_checksum.copy_from_slice(&header_buf[8..12]);

                let mut payload = vec![0u8; payload_size as usize];
                file.read_exact(&mut payload)?;

                let actual_checksum = sha256d(&payload);
                if !constant_time_eq(&actual_checksum[..4], &expected_checksum) {
                    return Err(StorageError::ChecksumMismatch);
                }

                let block: Block = bincode::deserialize(&payload)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                let block_hash = block.hash();
                let loc = BlockDiskLocation {
                    file_index: file_idx,
                    byte_offset: offset,
                    payload_size,
                    height: block.header.height,
                    block_hash,
                };

                self.hash_index.insert(block_hash, loc.clone());
                self.height_index.insert(block.header.height, loc);

                offset = record_end;
                total_indexed_blocks += 1;
            }

            self.current_file_index = file_idx;
            self.current_file_size = offset;
            file_idx += 1;
        }

        Ok(total_indexed_blocks)
    }

    /// ডিস্কে বর্তমানে মোট কতটি ব্লক সংরক্ষিত আছে
    #[inline]
    pub fn total_stored_blocks(&self) -> usize {
        self.hash_index.len()
    }

    /// ডিস্কে সংরক্ষিত সর্বশেষ ব্লকের হাইট রিটার্ন করে
    pub fn latest_stored_height(&self) -> Option<u64> {
        self.height_index.keys().max().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::transaction::Transaction;
    use std::env;

    fn create_temp_storage_dir(test_name: &str) -> PathBuf {
        let mut dir = env::temp_dir();
        dir.push(format!("equinox_storage_test_{}", test_name));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_flatfile_write_read_and_self_healing_tail_recovery() {
        let dir = create_temp_storage_dir("basic_rw_and_heal");
        let mut storage = FlatFileStorage::open(&dir).unwrap();

        let mut genesis = Block::genesis(
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
        );
        genesis.mine(Some(50_000));
        let gen_hash = genesis.hash();

        let loc0 = storage.append_block(&genesis).unwrap();
        assert_eq!(loc0.file_index, 0);
        assert_eq!(loc0.byte_offset, 0);

        let cb1 = Transaction::new_coinbase(
            1,
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP".to_string(),
            0,
            1_729_468_815,
        );
        let mut block1 = Block::new(1, gen_hash, vec![cb1], 4, 1_729_468_815);
        block1.mine(Some(50_000));
        let b1_hash = block1.hash();

        storage.append_block(&block1).unwrap();
        assert_eq!(storage.total_stored_blocks(), 2);

        // পাওয়ার-ফেইলর সিমুলেশন: blk00000.dat ফাইলের শেষে ৫ বাইট অর্ধ-সমাপ্ত গার্বেজ ডেটা যোগ করা হলো
        let blk0_path = storage.blk_file_path(0);
        {
            let mut f = OpenOptions::new().append(true).open(&blk0_path).unwrap();
            f.write_all(&[0x45, 0x51, 0x58, 0x01, 0xFF]).unwrap();
        }

        // নোড রিস্টার্ট করলে সেলফ-হিলিং ইঞ্জিন ভাঙা ৫ বাইট কেটে ফেলে আগের ২টি বৈধ ব্লক নিখুঁতভাবে লোড করবে!
        let reopened_storage = FlatFileStorage::open(&dir).unwrap();
        assert_eq!(reopened_storage.total_stored_blocks(), 2);
        assert_eq!(
            reopened_storage.read_block_by_height(1).unwrap().hash(),
            b1_hash
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_automatic_blk_file_rotation() {
        let dir = create_temp_storage_dir("rotation");
        let mut storage = FlatFileStorage::open(&dir)
            .unwrap()
            .with_max_file_size(4096);

        let mut prev_hash = [0u8; 32];
        for h in 0..15 {
            let cb = Transaction::new_coinbase(
                h,
                "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP".to_string(),
                0,
                1_729_468_800 + (h * 15),
            );
            let mut blk = Block::new(h, prev_hash, vec![cb], 2, 1_729_468_800 + (h * 15));
            blk.mine(Some(10_000));
            prev_hash = blk.hash();
            storage.append_block(&blk).unwrap();
        }

        assert!(storage.blk_file_path(0).exists());
        assert_eq!(storage.total_stored_blocks(), 15);

        let _ = fs::remove_dir_all(&dir);
    }
}

