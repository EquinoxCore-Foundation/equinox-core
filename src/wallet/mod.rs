#![allow(dead_code)]
// src/wallet/mod.rs
// Equinox (EQX) L1 — এইচডি ওয়ালেট, ম্নিমোনিক, কি-স্টোর এবং অফলাইন ট্রানজ্যাকশন সাইনার মডিউল।

pub mod address;
pub mod cipher;
pub mod hd_derivation;
pub mod keystore;
pub mod manager;
pub mod mnemonic;
pub mod signer;

pub use address::{
    hash160_to_address, is_valid_address, pubkey_to_address, validate_address_strict,
    verify_address_ownership,
};
pub use cipher::{decrypt_data, encrypt_data};
pub use hd_derivation::{DerivationPath, HDWallet, BIP44_PURPOSE, EQUINOX_COIN_TYPE, HARDENED_BIT};
pub use keystore::WalletKeystore;
pub use manager::WalletManager;
pub use signer::OfflineSigner;
