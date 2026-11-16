#![allow(dead_code)]
// src/wallet/keystore.rs
// Equinox (EQX) L1 — Audit-Grade Atomic Keystore Disk Engine ('wallet.dat')
// Features: Atomic Write-Flush-Rename (.tmp), Read-Back Disk Verification,
// Automatic Fail-Safe Backup (.bak) Recovery, DoS Size Bounds & RAM Zeroization.

use crate::crypto::hash::constant_time_eq;
use crate::wallet::cipher::{decrypt_data, encrypt_data};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const MIN_KEYSTORE_FILE_BYTES: u64 = 40;
pub const MAX_KEYSTORE_FILE_BYTES: u64 = 64 * 1024;

pub struct WalletKeystore;

impl WalletKeystore {
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

    pub fn save_to_file<P: AsRef<Path>>(
        file_path: P,
        seed_bytes: &[u8],
        password: &str,
    ) -> Result<(), String> {
        let target_path = file_path.as_ref();

        if seed_bytes.is_empty() || seed_bytes.iter().all(|&b| b == 0) {
            return Err("কি-স্টোরে শূন্য বা খালি সিড সেভ করা অনুমোদিত নয়".to_string());
        }

        if let Some(parent) = target_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("ওয়ালেট ডিরেক্টরি তৈরি ব্যর্থ: {}", e))?;
            }
        }

        let mut encrypted = encrypt_data(seed_bytes, password)?;

        let tmp_path = Self::temp_path_for(target_path);
        let bak_path = Self::backup_path_for(target_path);

        {
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| format!("অস্থায়ী ওয়ালেট ফাইল তৈরি ব্যর্থ: {}", e))?;

            tmp_file
                .write_all(&encrypted)
                .map_err(|e| format!("ওয়ালেট ফাইল রাইট ব্যর্থ: {}", e))?;

            tmp_file
                .sync_all()
                .map_err(|e| format!("ডিস্ক হার্ডওয়্যার সিঙ্ক (fsync) ব্যর্থ: {}", e))?;
        }

        let mut written_bytes = fs::read(&tmp_path)
            .map_err(|e| format!("ওয়ালেট ফাইল রিড-ব্যাক যাচাই ব্যর্থ: {}", e))?;

        let integrity_ok = constant_time_eq(&written_bytes, &encrypted);
        written_bytes.zeroize();
        encrypted.zeroize();

        if !integrity_ok {
            let _ = fs::remove_file(&tmp_path);
            return Err("ডিস্ক রাইট ইন্টিগ্রিটি ত্রুটি: লেখা ডেটা মূল সাইফারের সাথে মেলেনি!".to_string());
        }

        if target_path.exists() {
            let _ = fs::copy(target_path, &bak_path);
        }

        fs::rename(&tmp_path, target_path)
            .map_err(|e| format!("ওয়ালেট ফাইল অ্যাটমিক রিনেম ব্যর্থ: {}", e))?;

        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(
        file_path: P,
        password: &str,
    ) -> Result<Vec<u8>, String> {
        let target_path = file_path.as_ref();
        let bak_path = Self::backup_path_for(target_path);

        let active_path = if target_path.exists() {
            target_path.to_path_buf()
        } else if bak_path.exists() {
            bak_path.clone()
        } else {
            return Err("ওয়ালেট ফাইল পাওয়া যায়নি (wallet.dat অনুপস্থিত)".to_string());
        } ;

        let metadata = fs::metadata(&active_path)
            .map_err(|e| format!("ওয়ালেট ফাইল মেটাডেটা রিড ব্যর্থ: {}", e))?;

        let file_len = metadata.len();
        if file_len < MIN_KEYSTORE_FILE_BYTES || file_len > MAX_KEYSTORE_FILE_BYTES {
            return Err(format!("ওয়ালেট ফাইলের আকার অবৈধ ({} বাইট)", file_len));
        }

        let mut encrypted_bytes =
            fs::read(&active_path).map_err(|e| format!("ওয়ালেট ফাইল রিড ব্যর্থ: {}", e))?;

        let primary_res = decrypt_data(&encrypted_bytes, password);
        encrypted_bytes.zeroize();

        if primary_res.is_ok() {
            return primary_res;
        }

        if active_path == target_path && bak_path.exists() {
            if let Ok(mut bak_bytes) = fs::read(&bak_path) {
                let bak_res = decrypt_data(&bak_bytes, password);
                bak_bytes.zeroize();
                if bak_res.is_ok() {
                    let _ = fs::copy(&bak_path, target_path);
                    return bak_res;
                }
            }
        }

        primary_res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_wallet_path(test_name: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("eqx_keystore_test_{}.dat", test_name));
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(WalletKeystore::temp_path_for(&p));
        let _ = fs::remove_file(WalletKeystore::backup_path_for(&p));
        p
    }

    #[test]
    fn test_atomic_save_and_load_roundtrip() {
        let path = temp_wallet_path("atomic_rw");
        let seed = [0x55u8; 64];
        let pass = "Equinox#Keystore$Pass2026";

        WalletKeystore::save_to_file(&path, &seed, pass).expect("Save should succeed");
        assert!(path.exists());
        assert!(!WalletKeystore::temp_path_for(&path).exists());

        let loaded = WalletKeystore::load_from_file(&path, pass).expect("Load should succeed");
        assert_eq!(loaded, seed);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_backup_creation_and_automatic_crash_recovery() {
        let path = temp_wallet_path("backup_recovery");
        let seed_v1 = [0x11u8; 64];
        let seed_v2 = [0x22u8; 64];
        let pass = "BackupVaultPass!99";

        WalletKeystore::save_to_file(&path, &seed_v1, pass).unwrap();
        WalletKeystore::save_to_file(&path, &seed_v2, pass).unwrap();

        let bak_path = WalletKeystore::backup_path_for(&path);
        assert!(bak_path.exists());

        let _ = fs::remove_file(&path);
        let recovered = WalletKeystore::load_from_file(&path, pass).unwrap();
        assert_eq!(recovered, seed_v1);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&bak_path);
    }

    #[test]
    fn test_zero_seed_rejected() {
        let path = temp_wallet_path("zero_seed");
        let zero_seed = [0u8; 64];
        assert!(WalletKeystore::save_to_file(&path, &zero_seed, "Pass1234").is_err());
    }
}
