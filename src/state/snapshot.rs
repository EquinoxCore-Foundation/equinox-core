#![allow(dead_code)]
// src/state/snapshot.rs
// Equinox (EQX) L1 — Audit-Grade Atomic UTXO & Key-Image Chainstate Snapshot Engine ('chainstate.dat')
// Features: Instant O(1) Fast-Boot without Genesis Replay, Spent Key-Image Nullifier Persistence,
// Canonical Sorting, State Merkle Root Binding, SHA-256d Checksum & .bak Crash Recovery.

use crate::config::MAX_SUPPLY;
use crate::crypto::hash::{constant_time_eq, sha256d, Hash256};
use crate::primitives::transaction::TxOutput;
use crate::state::outpoint::OutPoint;
use crate::state::utxo_set::UtxoSet;
use crate::wallet::address::is_valid_address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// স্ন্যাপশট ফাইলের ম্যাজিক বাইটস ("EQXS" = Equinox Snapshot) ও ফরম্যাট ভার্সন
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"EQXS";
pub const SNAPSHOT_VERSION: u8 = 0x03;

/// মেমোরি নিঃশেষ (OOM DoS) প্রতিরোধে স্ন্যাপশট ফাইলের সর্বোচ্চ অনুমোদিত আকার (২৫৬ মেগাবাইট)
pub const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// একটি একক স্ন্যাপশটে সর্বোচ্চ অনুমোদিত UTXO এন্ট্রি সংখ্যা
pub const MAX_SNAPSHOT_ENTRIES: usize = 5_000_000;

/// পেলোডের ভেতরে থাকা ক্যানোনিকাল স্টেট ডেটা (UTXO তালিকা + খরচ হওয়া Key-Image তালিকা)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SnapshotInnerPayload {
    pub sorted_utxos: Vec<(OutPoint, TxOutput)>,
    pub sorted_key_images: Vec<Hash256>,
}

/// ডিস্কে সংরক্ষিত ক্রিপ্টোগ্রাফিক স্ন্যাপশট এনভেলপ
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotEnvelope {
    pub magic: [u8; 4],
    pub version: u8,
    pub block_height: u64,
    pub utxo_count: u64,
    pub key_image_count: u64,
    pub total_supply_atomic: u64,
    pub state_merkle_root: Hash256,
    pub payload_checksum: Hash256,
    pub payload_bytes: Vec<u8>,
}

pub struct ChainstateSnapshot;

impl ChainstateSnapshot {
    fn temp_path_for(base_path: &Path) -> PathBuf {
        let mut p = base_path.as_os_str().to_os_string();
        p.push(".tmp");
        PathBuf::from(p)
    }

    fn backup_path_for(base_path: &Path) -> PathBuf {
        let mut p = base_path.as_os_str().to_os_string();
        p.push(".bak");
        PathBuf::from(p)
    }

    /// ইন-মেমোরি UTXO লেজার বাইনারি ফাইলে (`chainstate.dat`) সেভ করে (Backward Compatible)
    pub fn save<P: AsRef<Path>>(
        file_path: P,
        ledger: &HashMap<OutPoint, TxOutput>,
    ) -> Result<(), String> {
        let empty_ki = HashSet::new();
        Self::save_full_state(file_path, ledger, &empty_ki, 0)
    }

    /// নির্দিষ্ট ব্লক হাইটসহ UTXO লেজার ডিস্কে সেভ করে (Backward Compatible)
    pub fn save_with_height<P: AsRef<Path>>(
        file_path: P,
        ledger: &HashMap<OutPoint, TxOutput>,
        block_height: u64,
    ) -> Result<(), String> {
        let empty_ki = HashSet::new();
        Self::save_full_state(file_path, ledger, &empty_ki, block_height)
    }

    /// পূর্ণাঙ্গ মেইননেট ফাস্ট-বুট স্ন্যাপশট: UTXO লেজার, খরচ হওয়া `spent_key_images` এবং ব্লক হাইট একসাথে ডিস্কে অ্যাটমিকভাবে সেভ করে
    pub fn save_full_state<P: AsRef<Path>>(
        file_path: P,
        ledger: &HashMap<OutPoint, TxOutput>,
        spent_key_images: &HashSet<Hash256>,
        block_height: u64,
    ) -> Result<(), String> {
        let target_path = file_path.as_ref();

        if ledger.len() > MAX_SNAPSHOT_ENTRIES || spent_key_images.len() > MAX_SNAPSHOT_ENTRIES {
            return Err(format!(
                "স্ন্যাপশটে এন্ট্রি সংখ্যা অনুমোদিত সীমার ({}) বাইরে",
                MAX_SNAPSHOT_ENTRIES
            ));
        }

        // ১. ২১ মিলিয়ন সাপ্লাই ইনভ্যারিয়েন্ট ও স্টেট মার্কেল রুট যাচাই
        let utxo_set = UtxoSet {
            utxos: ledger.clone(),
        };
        let total_supply_atomic = utxo_set.verify_supply_invariant()?;
        let state_merkle_root = utxo_set.compute_state_root();

        // ২. ১০০% ডিটারমিনিস্টিক ক্যানোনিকাল সর্টিং
        let mut sorted_utxos: Vec<(OutPoint, TxOutput)> = ledger
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        sorted_utxos.sort_by(|a, b| a.0.cmp(&b.0));

        let mut sorted_key_images: Vec<Hash256> = spent_key_images.iter().copied().collect();
        sorted_key_images.sort_unstable();

        let inner_payload = SnapshotInnerPayload {
            sorted_utxos,
            sorted_key_images,
        };

        let payload_bytes = bincode::serialize(&inner_payload)
            .map_err(|e| format!("স্ন্যাপশট পেলোড সিরিয়ালাইজেশন ব্যর্থ: {}", e))?;

        let payload_checksum = sha256d(&payload_bytes);

        let envelope = SnapshotEnvelope {
            magic: SNAPSHOT_MAGIC,
            version: SNAPSHOT_VERSION,
            block_height,
            utxo_count: inner_payload.sorted_utxos.len() as u64,
            key_image_count: inner_payload.sorted_key_images.len() as u64,
            total_supply_atomic,
            state_merkle_root,
            payload_checksum,
            payload_bytes,
        };

        let encoded_envelope = bincode::serialize(&envelope)
            .map_err(|e| format!("স্ন্যাপশট এনভেলপ সিরিয়ালাইজেশন ব্যর্থ: {}", e))?;

        if let Some(parent) = target_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("স্ন্যাপশট ডিরেক্টরি তৈরি ব্যর্থ: {}", e))?;
            }
        }

        let tmp_path = Self::temp_path_for(target_path);
        let bak_path = Self::backup_path_for(target_path);

        // ৩. অস্থায়ী `.tmp` ফাইলে রাইট এবং হার্ডওয়্যার ডিস্ক ফ্লাশ (`sync_all`)
        {
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| format!("অস্থায়ী স্ন্যাপশট ফাইল তৈরি ব্যর্থ: {}", e))?;

            tmp_file
                .write_all(&encoded_envelope)
                .map_err(|e| format!("স্ন্যাপশট ডিস্কে রাইট ব্যর্থ: {}", e))?;

            tmp_file
                .sync_all()
                .map_err(|e| format!("স্ন্যাপশট ডিস্ক ফ্লাশ (fsync) ব্যর্থ: {}", e))?;
        }

        // ৪. রিড-ব্যাক ইন্টিগ্রিটি যাচাই
        let written_bytes = fs::read(&tmp_path)
            .map_err(|e| format!("স্ন্যাপশট রিড-ব্যাক যাচাই ব্যর্থ: {}", e))?;

        if !constant_time_eq(&written_bytes, &encoded_envelope) {
            let _ = fs::remove_file(&tmp_path);
            return Err("স্ন্যাপশট ডিস্ক রাইট ইন্টিগ্রিটি ত্রুটি: ডেটা মেলেনি!".to_string());
        }

        // ৫. আগের বৈধ `chainstate.dat` ফাইলটিকে `.bak` হিসেবে ব্যাকআপ রাখা এবং অ্যাটমিক রিনেম করা
        if target_path.exists() {
            let _ = fs::copy(target_path, &bak_path);
        }

        fs::rename(&tmp_path, target_path)
            .map_err(|e| format!("স্ন্যাপশট অ্যাটমিক রিনেম ব্যর্থ: {}", e))?;

        Ok(())
    }

    /// ডিস্কের বাইনারি ফাইল (`chainstate.dat`) থেকে চেকসাম ও স্টেট রুট যাচাই করে UTXO লেজার লোড করে
    pub fn load<P: AsRef<Path>>(file_path: P) -> Result<HashMap<OutPoint, TxOutput>, String> {
        let (ledger, _ki, _height) = Self::load_full_state(file_path)?;
        Ok(ledger)
    }

    /// ডিস্ক থেকে UTXO লেজার এবং স্ন্যাপশটের ব্লক হাইট একসাথে লোড করে `(ledger, block_height)`
    pub fn load_with_height<P: AsRef<Path>>(
        file_path: P,
    ) -> Result<(HashMap<OutPoint, TxOutput>, u64), String> {
        let (ledger, _ki, height) = Self::load_full_state(file_path)?;
        Ok((ledger, height))
    }

    /// জেনেসিস রিপ্লে ছাড়াই সরাসরি ডিস্ক থেকে `(ledger, spent_key_images, block_height)` লোড ও ক্রিপ্টোগ্রাফিক্যালি যাচাই করে
    pub fn load_full_state<P: AsRef<Path>>(
        file_path: P,
    ) -> Result<(HashMap<OutPoint, TxOutput>, HashSet<Hash256>, u64), String> {
        let target_path = file_path.as_ref();
        let bak_path = Self::backup_path_for(target_path);

        let active_path = if target_path.exists() {
            target_path.to_path_buf()
        } else if bak_path.exists() {
            bak_path.clone()
        } else {
            return Err("chainstate.dat স্ন্যাপশট ফাইল পাওয়া যায়নি".to_string());
        };

        let primary_res = Self::decode_and_verify_snapshot_file(&active_path);
        if primary_res.is_ok() {
            return primary_res;
        }

        // মূল ফাইলটি ক্ষতিগ্রস্ত হলে স্বয়ংক্রিয়ভাবে `.bak` ফাইল থেকে উদ্ধারের চেষ্টা
        if active_path == target_path && bak_path.exists() {
            if let Ok(recovered) = Self::decode_and_verify_snapshot_file(&bak_path) {
                let _ = fs::copy(&bak_path, target_path);
                return Ok(recovered);
            }
        }

        primary_res
    }

    fn decode_and_verify_snapshot_file(
        path: &Path,
    ) -> Result<(HashMap<OutPoint, TxOutput>, HashSet<Hash256>, u64), String> {
        let metadata = fs::metadata(path)
            .map_err(|e| format!("স্ন্যাপশট ফাইল মেটাডেটা রিড ব্যর্থ: {}", e))?;

        if metadata.len() == 0 || metadata.len() > MAX_SNAPSHOT_FILE_BYTES {
            return Err(format!(
                "স্ন্যাপশট ফাইলের আকার অবৈধ ({} বাইট)",
                metadata.len()
            ));
        }

        let bytes = fs::read(path).map_err(|e| format!("স্ন্যাপশট ফাইল রিড ব্যর্থ: {}", e))?;

        let envelope: SnapshotEnvelope = bincode::deserialize(&bytes)
            .map_err(|e| format!("স্ন্যাপশট এনভেলপ ডিসিরিয়ালাইজেশন ব্যর্থ: {}", e))?;

        if !constant_time_eq(&envelope.magic, &SNAPSHOT_MAGIC) {
            return Err("অবৈধ স্ন্যাপশট ম্যাজিক হেডার".to_string());
        }
        if envelope.version != SNAPSHOT_VERSION {
            return Err(format!(
                "অসমর্থিত স্ন্যাপশট ফরম্যাট ভার্সন: {}",
                envelope.version
            ));
        }
        if (envelope.utxo_count as usize) > MAX_SNAPSHOT_ENTRIES
            || (envelope.key_image_count as usize) > MAX_SNAPSHOT_ENTRIES
        {
            return Err("স্ন্যাপশটে এন্ট্রি সংখ্যা অনুমোদিত সীমার বাইরে".to_string());
        }

        let actual_checksum = sha256d(&envelope.payload_bytes);
        if !constant_time_eq(&actual_checksum, &envelope.payload_checksum) {
            return Err("স্ন্যাপশট চেকসাম মেলেনি! ফাইলটি ক্ষতিগ্রস্ত বা টেম্পারড হয়েছে".to_string());
        }

        let inner: SnapshotInnerPayload = bincode::deserialize(&envelope.payload_bytes)
            .map_err(|e| format!("স্ন্যাপশট পেলোড ডিকোড ব্যর্থ: {}", e))?;

        if (inner.sorted_utxos.len() as u64) != envelope.utxo_count
            || (inner.sorted_key_images.len() as u64) != envelope.key_image_count
        {
            return Err("স্ন্যাপশটের হেডার সংখ্যার সাথে প্রকৃত এন্ট্রি সংখ্যার মিল নেই".to_string());
        }

        let mut ledger = HashMap::with_capacity(inner.sorted_utxos.len());
        let mut calculated_supply: u128 = 0;

        for (op, out) in inner.sorted_utxos {
            if op.is_null() {
                return Err("স্ন্যাপশটে অবৈধ নাল (Null) OutPoint পাওয়া গেছে".to_string());
            }
            if out.amount == 0 || out.amount > MAX_SUPPLY {
                return Err(format!("স্ন্যাপশটে অবৈধ UTXO অ্যামাউন্ট: {}", out.amount));
            }
            if !is_valid_address(&out.recipient_address) {
                return Err(format!(
                    "স্ন্যাপশটে অবৈধ ওয়ালেট অ্যাড্রেস পাওয়া গেছে: {}",
                    out.recipient_address
                ));
            }

            calculated_supply = calculated_supply
                .checked_add(out.amount as u128)
                .ok_or_else(|| "স্ন্যাপশট সাপ্লাই যোগফলে ওভারফ্লো".to_string())?;

            if ledger.insert(op, out).is_some() {
                return Err("স্ন্যাপশটে ডুপ্লিকেট OutPoint ধরা পড়েছে!".to_string());
            }
        }

        if calculated_supply > (MAX_SUPPLY as u128)
            || (calculated_supply as u64) != envelope.total_supply_atomic
        {
            return Err("স্ন্যাপশটের মোট সাপ্লাই হিসাব মেলেনি বা ২১ মিলিয়ন ক্যাপ লঙ্ঘিত হয়েছে".to_string());
        }

        let mut key_images = HashSet::with_capacity(inner.sorted_key_images.len());
        for ki in inner.sorted_key_images {
            if !key_images.insert(ki) {
                return Err("স্ন্যাপশটে ডুপ্লিকেট Key-Image ধরা পড়েছে!".to_string());
            }
        }

        let reconstructed_set = UtxoSet {
            utxos: ledger.clone(),
        };
        let actual_state_root = reconstructed_set.compute_state_root();
        if !constant_time_eq(&actual_state_root, &envelope.state_merkle_root) {
            return Err("স্ন্যাপশটের State Merkle Root মেলেনি!".to_string());
        }

        Ok((ledger, key_images, envelope.block_height))
    }
}
