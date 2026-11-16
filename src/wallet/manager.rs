#![allow(dead_code)]
// src/wallet/manager.rs
// Equinox (EQX) L1 — Audit-Grade Wallet Controller & Key Lifecycle Manager
// Features: 12/24-Word Creation, Atomic Keystore Persistence, BIP-44 External/Change Address
// Derivation, Strict Password Policy Enforcement & Automatic RAM Zeroization (ZeroizeOnDrop).

use crate::crypto::keys::KeyPair;
use crate::wallet::address::{pubkey_to_address, verify_address_ownership};
use crate::wallet::hd_derivation::HDWallet;
use crate::wallet::keystore::WalletKeystore;
use crate::wallet::mnemonic::{
    generate_mnemonic, generate_mnemonic_24, mnemonic_to_seed, validate_mnemonic,
};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ওয়ালেট এনক্রিপশন পাসওয়ার্ডের সর্বনিম্ন দৈর্ঘ্য (৮ অক্ষর)
pub const MIN_WALLET_PASSWORD_LEN: usize = 8;

/// পাসওয়ার্ডের সর্বোচ্চ অনুমোদিত দৈর্ঘ্য (DoS প্রতিরোধে ১২৮ বাইট)
pub const MAX_WALLET_PASSWORD_LEN: usize = 128;

/// মাস্টার সিডের বাধ্যতামূলক আকার (৬৪ বাইট / ৫১২ বিট)
pub const MASTER_SEED_LEN: usize = 64;

/// র‍্যাম-সুরক্ষিত (`ZeroizeOnDrop`) ওয়ালেট কন্ট্রোলার
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WalletManager {
    hd_wallet: HDWallet,
    mnemonic_phrase: String,
}

impl WalletManager {
    /// ওয়ালেট পাসওয়ার্ডের নিরাপত্তা ও দৈর্ঘ্য যাচাই করে
    pub fn validate_password_policy(password: &str) -> Result<(), String> {
        let trimmed = password.trim();
        if trimmed.len() < MIN_WALLET_PASSWORD_LEN {
            return Err(format!(
                "নিরাপত্তার স্বার্থে ওয়ালেট পাসওয়ার্ড কমপক্ষে {} অক্ষরের হতে হবে",
                MIN_WALLET_PASSWORD_LEN
            ));
        }
        if password.len() > MAX_WALLET_PASSWORD_LEN {
            return Err("পাসওয়ার্ডের দৈর্ঘ্য অনুমোদিত সীমার (১২৮ বাইট) বাইরে".to_string());
        }
        Ok(())
    }

    /// সম্পূর্ণ নতুন ১২-শব্দের (১২৮-বিট এনট্রপি) ওয়ালেট তৈরি করে এবং ডিস্কে এনক্রিপ্ট করে সেভ করে
    pub fn create_new<P: AsRef<Path>>(
        wallet_file_path: P,
        password: &str,
    ) -> Result<(Self, String), String> {
        Self::validate_password_policy(password)?;

        let mnemonic_phrase = generate_mnemonic()?;
        let mut seed = mnemonic_to_seed(&mnemonic_phrase, None)?;

        let save_res = WalletKeystore::save_to_file(wallet_file_path, &seed, password);
        if let Err(e) = save_res {
            seed.zeroize();
            return Err(e);
        }

        let hd_res = HDWallet::from_seed(&seed);
        seed.zeroize();
        let hd_wallet = hd_res?;

        Ok((
            Self {
                hd_wallet,
                mnemonic_phrase: mnemonic_phrase.clone(),
            },
            mnemonic_phrase,
        ))
    }

    /// আলট্রা-সিকিউর ২৪-শব্দের (২৫৬-বিট এনট্রপি) ওয়ালেট তৈরি করে এবং ডিস্কে সেভ করে
    pub fn create_new_24_words<P: AsRef<Path>>(
        wallet_file_path: P,
        password: &str,
    ) -> Result<(Self, String), String> {
        Self::validate_password_policy(password)?;

        let mnemonic_phrase = generate_mnemonic_24()?;
        let mut seed = mnemonic_to_seed(&mnemonic_phrase, None)?;

        let save_res = WalletKeystore::save_to_file(wallet_file_path, &seed, password);
        if let Err(e) = save_res {
            seed.zeroize();
            return Err(e);
        }

        let hd_res = HDWallet::from_seed(&seed);
        seed.zeroize();
        let hd_wallet = hd_res?;

        Ok((
            Self {
                hd_wallet,
                mnemonic_phrase: mnemonic_phrase.clone(),
            },
            mnemonic_phrase,
        ))
    }

    /// পূর্বে তৈরি করা `wallet.dat` ফাইল থেকে পাসওয়ার্ড দিয়ে ওয়ালেট লোড করে
    pub fn load_from_file<P: AsRef<Path>>(
        wallet_file_path: P,
        password: &str,
    ) -> Result<Self, String> {
        if password.trim().is_empty() {
            return Err("ওয়ালেট আনলক করতে পাসওয়ার্ড প্রদান করুন".to_string());
        }

        let mut seed_vec = WalletKeystore::load_from_file(wallet_file_path, password)?;
        if seed_vec.len() != MASTER_SEED_LEN {
            seed_vec.zeroize();
            return Err(format!(
                "অবৈধ মাস্টার সিড দৈর্ঘ্য: পাওয়া গেছে {} বাইট, হতে হবে ৬৪ বাইট",
                seed_vec.len()
            ));
        }

        let mut seed = [0u8; MASTER_SEED_LEN];
        seed.copy_from_slice(&seed_vec);
        seed_vec.zeroize();

        let hd_res = HDWallet::from_seed(&seed);
        seed.zeroize();
        let hd_wallet = hd_res?;

        Ok(Self {
            hd_wallet,
            // নিরাপত্তা নিশ্চিত করতে ডিস্ক থেকে লোড করার সময় ফ্রেজ র‍্যামে রাখা হয় না
            mnemonic_phrase: String::new(),
        })
    }

    /// ১২ বা ২৪ শব্দের রিকভারি ফ্রেজ ব্যবহার করে ওয়ালেট রিকভার বা রিস্টোর করে
    pub fn recover_from_mnemonic<P: AsRef<Path>>(
        mnemonic_phrase: &str,
        wallet_file_path: P,
        password: &str,
    ) -> Result<Self, String> {
        Self::validate_password_policy(password)?;
        validate_mnemonic(mnemonic_phrase)?;

        let canonical_phrase = mnemonic_phrase
            .split_whitespace()
            .map(|w| w.trim().to_ascii_lowercase())
            .collect::<Vec<String>>()
            .join(" ");

        let mut seed = mnemonic_to_seed(&canonical_phrase, None)?;

        let save_res = WalletKeystore::save_to_file(wallet_file_path, &seed, password);
        if let Err(e) = save_res {
            seed.zeroize();
            return Err(e);
        }

        let hd_res = HDWallet::from_seed(&seed);
        seed.zeroize();
        let hd_wallet = hd_res?;

        Ok(Self {
            hd_wallet,
            mnemonic_phrase: canonical_phrase,
        })
    }

    /// নির্দিষ্ট অ্যাকাউন্ট ও এক্সটার্নাল ইনডেক্সের (`change = 0`) কি-পেয়ার রিটার্ন করে
    #[inline]
    pub fn get_keypair(&self, account: u32, index: u32) -> Result<KeyPair, String> {
        self.hd_wallet.derive_keypair(account, index)
    }

    /// পূর্ণাঙ্গ BIP-44 পাথ (`account`, `change`, `index`) থেকে কি-পেয়ার রিটার্ন করে
    #[inline]
    pub fn get_keypair_full(
        &self,
        account: u32,
        change: u32,
        index: u32,
    ) -> Result<KeyPair, String> {
        self.hd_wallet.derive_keypair_full(account, change, index)
    }

    /// নির্দিষ্ট অ্যাকাউন্ট ও ইনডেক্সের রিসিভিং ওয়ালেট অ্যাড্রেস (`change = 0`) রিটার্ন করে
    pub fn get_address(&self, account: u32, index: u32) -> Result<String, String> {
        let kp = self.get_keypair(account, index)?;
        Ok(pubkey_to_address(&kp.public_key()))
    }

    /// নির্দিষ্ট অ্যাকাউন্ট ও ইনডেক্সের ইন্টারনাল ভাংতি/চেঞ্জ অ্যাড্রেস (`change = 1`) রিটার্ন করে
    pub fn get_change_address(&self, account: u32, index: u32) -> Result<String, String> {
        let kp = self.get_keypair_full(account, 1, index)?;
        Ok(pubkey_to_address(&kp.public_key()))
    }

    /// প্রদত্ত ওয়ালেট অ্যাড্রেসটি নির্দিষ্ট `(account, index)` কি-পেয়ারের মালিকানাধীন কি না তা যাচাই করে
    pub fn owns_address(&self, account: u32, index: u32, address: &str) -> bool {
    if let Ok(kp) = self.get_keypair(account, index) {
        verify_address_ownership(address, &kp.public_key()).unwrap_or(false)
    } else {
        false
    }
}

    /// ১২ বা ২৪ শব্দের ম্নিমোনিক ফ্রেজ রিটার্ন করে (যদি সেশনে উপস্থিত থাকে)
    #[inline]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic_phrase
    }

    /// ইউজার সিড ফ্রেজ কাগজে লিখে রাখার পর র‍্যাম (RAM) থেকে তাৎক্ষণিক মুছে ফেলার মেথড
    pub fn scrub_mnemonic_from_ram(&mut self) {
        self.mnemonic_phrase.zeroize();
        self.mnemonic_phrase.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    fn temp_manager_wallet_path(name: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("eqx_manager_test_{}.dat", name));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn test_wallet_manager_creation_load_and_recovery() {
        let test_path = temp_manager_wallet_path("create_recover");
        let recover_path = temp_manager_wallet_path("recovered_clone");
        let password = "StrongPassword999*";

        // ১. নতুন ওয়ালেট তৈরি
        let (mut manager, phrase) = WalletManager::create_new(&test_path, password).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);

        // ২. অ্যাড্রেস ও কি-পেয়ার ডেরাইভেশন চেক
        let addr_0 = manager.get_address(0, 0).unwrap();
        let change_addr_0 = manager.get_change_address(0, 0).unwrap();
        assert!(addr_0.starts_with('E'));
        assert_ne!(addr_0, change_addr_0);
        assert!(manager.owns_address(0, 0, &addr_0));

        // ৩. র‍্যাম থেকে ম্নিমোনিক স্ক্রাব টেস্ট
        manager.scrub_mnemonic_from_ram();
        assert!(manager.mnemonic().is_empty());

        // ৪. ডিস্ক থেকে লোড টেস্ট
        let loaded_manager = WalletManager::load_from_file(&test_path, password).unwrap();
        assert_eq!(loaded_manager.get_address(0, 0).unwrap(), addr_0);

        // ৫. ১২ শব্দের ফ্রেজ দিয়ে রিকভারি টেস্ট
        let recovered_manager =
            WalletManager::recover_from_mnemonic(&phrase, &recover_path, password).unwrap();
        assert_eq!(recovered_manager.get_address(0, 0).unwrap(), addr_0);

        let _ = fs::remove_file(&test_path);
        let _ = fs::remove_file(&recover_path);
    }

    #[test]
    fn test_weak_password_and_wrong_password_rejected() {
        let test_path = temp_manager_wallet_path("weak_pass");
        assert!(WalletManager::create_new(&test_path, "123").is_err());

        let _ = WalletManager::create_new(&test_path, "ValidVaultPassword#1").unwrap();
        assert!(WalletManager::load_from_file(&test_path, "WrongVaultPassword#1").is_err());

        let _ = fs::remove_file(&test_path);
    }
}
