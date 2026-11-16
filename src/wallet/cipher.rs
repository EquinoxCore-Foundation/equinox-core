#![allow(dead_code)]
// src/wallet/cipher.rs
// Equinox (EQX) L1 — Audit-Grade AES-256-GCM AEAD & PBKDF2-HMAC-SHA256 (600,000 Rounds) Cipher Engine
// Features: AAD Header Binding, CSPRNG Fault Guard, DoS Payload Bounds & Automatic RAM Zeroization.

use crate::crypto::hash::constant_time_eq;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// ক্রিপ্টোগ্রাফিক সল্টের আকার: ১৬ বাইট (১২৮ বিট)
pub const SALT_SIZE: usize = 16;

/// AES-256-GCM স্ট্যান্ডার্ড ননসের আকার: ১২ বাইট (৯৬ বিট)
pub const NONCE_SIZE: usize = 12;

/// AES-256-GCM পলি১৩০৫/জিহ্যাশ অথেনটিকেশন ট্যাগের আকার: ১৬ বাইট (১২৮ বিট)
pub const GCM_TAG_SIZE: usize = 16;

/// OWASP মানদণ্ড অনুযায়ী PBKDF2-HMAC-SHA256 রাউন্ড সংখ্যা: ৬,০০,০০০
pub const PBKDF2_ROUNDS: u32 = 600_000;

/// এনক্রিপ্টেড এনভেলপ ম্যাজিক বাইটস ("EQXV") ও ফরম্যাট ভার্সন (0x02)
pub const CIPHER_MAGIC: [u8; 4] = *b"EQXV";
pub const CIPHER_VERSION: u8 = 0x02;
pub const HEADER_SIZE: usize = 5; // 4B Magic + 1B Version

/// মেমোরি নিঃশেষ (OOM DoS) আক্রমণ প্রতিরোধে সর্বোচ্চ অনুমোদিত পেলোড আকার (১৬ মেগাবাইট)
pub const MAX_CIPHER_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// ডোমেইন-সেপারেটেড সল্ট ও ৬,০০,০০০ রাউন্ড PBKDF2-HMAC-SHA256 ব্যবহার করে পাসওয়ার্ড থেকে ২৫৬-বিট কি তৈরি করে
fn derive_key_from_password(password: &str, salt: &[u8; SALT_SIZE]) -> [u8; 32] {
    let mut domain_salt_hasher = Sha256::new();
    domain_salt_hasher.update(b"EQX_AES256GCM_KDF_DOMAIN_V2");
    domain_salt_hasher.update(salt);
    let mut domain_salt: [u8; 32] = domain_salt_hasher.finalize().into();

    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        &domain_salt,
        PBKDF2_ROUNDS,
        &mut derived_key,
    );

    domain_salt.zeroize();
    derived_key
}

/// CSPRNG (`OsRng`) কোনো কারণে শূন্য-বাইট তৈরি করেছে কি না তা পরীক্ষা করে
#[inline]
fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// সংবেদনশীল ডেটা পাসওয়ার্ড দিয়ে `AES-256-GCM` (AAD Header Bound) পদ্ধতিতে এনক্রিপ্ট করে।
/// আউটপুট ফরম্যাট: `[Magic (4B)] + [Version (1B)] + [Salt (16B)] + [Nonce (12B)] + [Ciphertext + 16B GCM Tag]`
pub fn encrypt_data(plain_data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if password.trim().is_empty() {
        return Err("এনক্রিপশন পাসওয়ার্ড খালি রাখা যাবে না".to_string());
    }
    if plain_data.is_empty() {
        return Err("এনক্রিপ্ট করার জন্য ডেটা খালি হতে পারবে না".to_string());
    }
    if plain_data.len() > MAX_CIPHER_PAYLOAD_BYTES {
        return Err("ডেটার আকার অনুমোদিত সীমার (১৬ মেগাবাইট) বাইরে".to_string());
    }

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    if is_all_zero(&salt) || is_all_zero(&nonce_bytes) {
        return Err("হার্ডওয়্যার র‍্যান্ডম জেনারেটর (CSPRNG) ত্রুটি ধরা পড়েছে".to_string());
    }

    // ১. মেটাডেটা প্রিফিক্স তৈরি যা AAD (Authenticated Associated Data) হিসেবে লক থাকবে
    let mut prefix_aad = Vec::with_capacity(HEADER_SIZE + SALT_SIZE + NONCE_SIZE);
    prefix_aad.extend_from_slice(&CIPHER_MAGIC);
    prefix_aad.push(CIPHER_VERSION);
    prefix_aad.extend_from_slice(&salt);
    prefix_aad.extend_from_slice(&nonce_bytes);

    // ২. পাসওয়ার্ড থেকে ২৫৬-বিট এনক্রিপশন কি ডেরাইভ করা
    let mut derived_key = derive_key_from_password(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // ৩. AAD বাইন্ডিংসহ এইএডি (AEAD) এনক্রিপশন সম্পাদন
    let encrypt_res = cipher.encrypt(
        nonce,
        Payload {
            msg: plain_data,
            aad: &prefix_aad,
        },
    );

    // ৪. কাজ শেষ হওয়া মাত্রই র‍্যাম থেকে ২৫৬-বিট ডেরাইভড কি মুছে ফেলা
    derived_key.zeroize();
    salt.zeroize();
    nonce_bytes.zeroize();

    let ciphertext = encrypt_res.map_err(|e| format!("এনক্রিপশন ব্যর্থ: {}", e))?;

    let mut output = Vec::with_capacity(prefix_aad.len() + ciphertext.len());
    output.extend_from_slice(&prefix_aad);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// এনক্রিপ্টেড বাইনারি ডেটা থেকে AAD হেডার ও ট্যাগ যাচাই করে পাসওয়ার্ডের মাধ্যমে আসল ডেটা উদ্ধার করে
pub fn decrypt_data(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if password.trim().is_empty() {
        return Err("ডিক্রিপশন পাসওয়ার্ড খালি রাখা যাবে না".to_string());
    }

    let min_v2_len = HEADER_SIZE + SALT_SIZE + NONCE_SIZE + GCM_TAG_SIZE + 1;
    let min_legacy_len = SALT_SIZE + NONCE_SIZE + GCM_TAG_SIZE + 1;

    if encrypted_data.len() < min_legacy_len || encrypted_data.len() > MAX_CIPHER_PAYLOAD_BYTES {
        return Err("এনক্রিপ্টেড ডেটার সাইজ অবৈধ বা ফাইলটি ক্ষতিগ্রস্ত".to_string());
    }

    // নতুন V2 ফরম্যাট ("EQXV" + 0x02) কি না তা কনস্ট্যান্ট-টাইমে পরীক্ষা করা
    if encrypted_data.len() >= min_v2_len
        && constant_time_eq(&encrypted_data[..4], &CIPHER_MAGIC)
    {
        let version = encrypted_data[4];
        if version != CIPHER_VERSION {
            return Err(format!("অসমর্থিত সাইফার ফরম্যাট ভার্সন: {}", version));
        }

        let aad_end = HEADER_SIZE + SALT_SIZE + NONCE_SIZE;
        let prefix_aad = &encrypted_data[..aad_end];
        let salt_slice = &encrypted_data[HEADER_SIZE..HEADER_SIZE + SALT_SIZE];
        let nonce_slice = &encrypted_data[HEADER_SIZE + SALT_SIZE..aad_end];
        let ciphertext = &encrypted_data[aad_end..];

        let mut salt = [0u8; SALT_SIZE];
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        salt.copy_from_slice(salt_slice);
        nonce_bytes.copy_from_slice(nonce_slice);

        let mut derived_key = derive_key_from_password(password, &salt);
        let key = Key::<Aes256Gcm>::from_slice(&derived_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypt_res = cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: prefix_aad,
            },
        );

        derived_key.zeroize();
        salt.zeroize();
        nonce_bytes.zeroize();

        return decrypt_res
            .map_err(|_| "ভুল পাসওয়ার্ড অথবা ক্ষতিগ্রস্ত ওয়ালেট ফাইল".to_string());
    }

    Err("অবৈধ ওয়ালেট সাইফার হেডার অথবা ক্ষতিগ্রস্ত ডেটা".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_v2_encrypt_decrypt_roundtrip() {
        let secret_seed = [0x7Au8; 64];
        let password = "Equinox#Mainnet$UltraPassword2026";

        let encrypted = encrypt_data(&secret_seed, password).expect("Encryption should succeed");
        assert_eq!(&encrypted[..4], &CIPHER_MAGIC);
        assert_eq!(encrypted[4], CIPHER_VERSION);

        let decrypted = decrypt_data(&encrypted, password).expect("Decryption should succeed");
        assert_eq!(decrypted, secret_seed);
    }

    #[test]
    fn test_wrong_password_and_empty_password_rejected() {
        let data = b"Equinox Master Private Seed Bytes";
        assert!(encrypt_data(data, "").is_err());
        assert!(encrypt_data(data, "   ").is_err());

        let encrypted = encrypt_data(data, "CorrectHorseBatteryStaple").unwrap();
        assert!(decrypt_data(&encrypted, "WrongPassword123").is_err());
    }

    #[test]
    fn test_aad_header_or_ciphertext_tampering_rejected() {
        let data = b"64-byte master seed payload for Equinox HD wallet";
        let password = "VaultPassword#999";
        let encrypted = encrypt_data(data, password).unwrap();

        // ১. সাইফারটেক্সটের শেষ বাইট টেম্পার করলে GCM ট্যাগ তা আটকে দেবে
        let mut tampered_ct = encrypted.clone();
        let last_idx = tampered_ct.len() - 1;
        tampered_ct[last_idx] ^= 0x01;
        assert!(decrypt_data(&tampered_ct, password).is_err());

        // ২. সল্ট বা AAD হেডারের ১ বিটও টেম্পার করলে সাথে সাথে রিজেক্ট হবে
        let mut tampered_aad = encrypted.clone();
        tampered_aad[HEADER_SIZE + 2] ^= 0x01;
        assert!(decrypt_data(&tampered_aad, password).is_err());
    }
}
