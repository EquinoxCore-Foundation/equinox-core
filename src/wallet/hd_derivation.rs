#![allow(dead_code)]
// src/wallet/hd_derivation.rs
// Equinox (EQX) L1 — SLIP-0010 / BIP-44 Hierarchical Deterministic (HD) Key Derivation Engine

use crate::crypto::keys::KeyPair;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha512 = Hmac<Sha512>;

pub const HARDENED_BIT: u32 = 0x8000_0000;
pub const BIP44_PURPOSE: u32 = 44;
pub const EQUINOX_COIN_TYPE: u32 = 9333;
const SLIP10_ED25519_DOMAIN: &[u8] = b"ed25519 seed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationPath {
    pub account: u32,
    pub change: u32,
    pub address_index: u32,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HDWallet {
    master_private_key: [u8; 32],
    master_chain_code: [u8; 32],
}

impl HDWallet {
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, String> {
        if seed.iter().all(|&b| b == 0) {
            return Err("মাস্টার সিড শূন্য (All-Zero) হতে পারবে না".to_string());
        }

        let mut mac = HmacSha512::new_from_slice(SLIP10_ED25519_DOMAIN)
            .map_err(|e| format!("HMAC ইনিশিয়ালাইজেশন ত্রুটি: {}", e))?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut master_private_key = [0u8; 32];
        let mut master_chain_code = [0u8; 32];
        master_private_key.copy_from_slice(&result[0..32]);
        master_chain_code.copy_from_slice(&result[32..64]);

        Ok(Self {
            master_private_key,
            master_chain_code,
        })
    }

    fn ckd_priv_hardened(
        parent_key: &[u8; 32],
        parent_chain_code: &[u8; 32],
        index: u32,
    ) -> Result<([u8; 32], [u8; 32]), String> {
        let hardened_idx = index | HARDENED_BIT;
        let mut data = [0u8; 37];
        data[0] = 0x00;
        data[1..33].copy_from_slice(parent_key);
        data[33..37].copy_from_slice(&hardened_idx.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(parent_chain_code)
            .map_err(|e| format!("CKD HMAC ত্রুটি: {}", e))?;
        mac.update(&data);
        data.zeroize();

        let out = mac.finalize().into_bytes();
        let mut child_key = [0u8; 32];
        let mut child_chain = [0u8; 32];
        child_key.copy_from_slice(&out[0..32]);
        child_chain.copy_from_slice(&out[32..64]);

        Ok((child_key, child_chain))
    }

    /// স্ট্যান্ডার্ড রিসিভিং কি-পেয়ার (`m/44'/9333'/account'/0'/index'`) ডেরাইভ করে
    pub fn derive_keypair(&self, account: u32, index: u32) -> Result<KeyPair, String> {
        self.derive_keypair_full(account, 0, index)
    }

    /// পূর্ণাঙ্গ BIP-44 পাথ (`m/44'/9333'/account'/change'/index'`) থেকে কি-পেয়ার ডেরাইভ করে
    pub fn derive_keypair_full(
        &self,
        account: u32,
        change: u32,
        index: u32,
    ) -> Result<KeyPair, String> {
        if change > 1 {
            return Err("BIP-44 change মান শুধুমাত্র 0 (External) বা 1 (Internal) হতে পারে".to_string());
        }

        let steps = [BIP44_PURPOSE, EQUINOX_COIN_TYPE, account, change, index];
        let mut current_key = self.master_private_key;
        let mut current_chain = self.master_chain_code;

        for &step in &steps {
            let (next_k, next_c) = Self::ckd_priv_hardened(&current_key, &current_chain, step)?;
            current_key.zeroize();
            current_chain.zeroize();
            current_key = next_k;
            current_chain = next_c;
        }

        let kp = KeyPair::from_secret_bytes(current_key);
        current_key.zeroize();
        current_chain.zeroize();
        Ok(kp)
    }
}
