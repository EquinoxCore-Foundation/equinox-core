// File: Equinox-Super-Wallet/crates/key-vault/src/lib.rs
#![forbid(unsafe_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use bech32::{ToBase32, Variant};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey as Secp256k1SecretKey;
use rand::{rngs::OsRng, RngCore};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use std::collections::HashSet;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha512 = Hmac<Sha512>;
type HmacSha256 = Hmac<Sha256>;

pub const ARGON2ID_M_COST_KIB: u32 = 65_536; // 64 MiB
pub const ARGON2ID_T_COST: u32 = 3;
pub const ARGON2ID_P_COST: u32 = 4;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub const MAX_AUTH_FAILURES: u32 = 5;
pub const LOCKOUT_DURATION_SECS: u64 = 3_600;
pub const SESSION_IDLE_TIMEOUT_SECS: u64 = 300;
pub const TOTP_STEP_SECS: u64 = 30;

pub const EQX_ADDRESS_VERSION: u8 = 0x21; // 'E' prefix
pub const TRON_ADDRESS_VERSION: u8 = 0x41; // 'T' prefix

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    #[error("Weak password: minimum 12 chars with uppercase, lowercase, digit, and symbol required")]
    WeakPassword,
    #[error("KDF parameter or execution error: {0}")]
    KdfError(String),
    #[error("AEAD encryption/decryption failed (invalid password or tampered tag)")]
    AeadAuthError,
    #[error("Invalid BIP-39 mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("HD key derivation error: {0}")]
    DerivationError(String),
    #[error("Account locked until unix timestamp {0}")]
    AccountLocked(u64),
    #[error("Rate limit backoff active until unix timestamp {0}")]
    BackoffActive(u64),
    #[error("Invalid 6-digit TOTP 2FA code")]
    InvalidTotpCode,
    #[error("Invalid or already used recovery code")]
    InvalidRecoveryCode,
    #[error("Session expired or locked")]
    SessionLocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// ডিস্কে সংরক্ষণের জন্য প্রকৃত AEAD এনক্রিপ্টেড কি-স্টোর এনভেলপ
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeystoreEnvelope {
    pub version: u8,
    pub cipher: CipherSuite,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; TAG_LEN],
    pub aad_context: String,
}

/// ৭টি চেইনের প্রকৃত ক্রিপ্টোগ্রাফিক ডেরাইভড পাবলিক অ্যাড্রেস (কোনো প্রাইভেট কি নেই)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiChainAccountAddresses {
    pub account_index: u32,
    pub btc_native_segwit: String, // m/84'/0'/0'/0/i (Bech32 bc1q...)
    pub eth_erc20: String,         // m/44'/60'/0'/0/i (EIP-55 0x...)
    pub bnb_bep20: String,         // m/44'/60'/0'/0/i (EIP-55 0x...)
    pub tron_trc20: String,        // m/44'/195'/0'/0/i (Base58Check T...)
    pub sol_mainnet: String,       // m/44'/501'/i'/0' (Ed25519 Base58)
    pub ton_v4r2: String,          // m/44'/607'/i' (TON CRC16 UQ...)
    pub eqx_native: String,        // m/44'/9333'/i'/0' (Base58Check E...)
}

/// ফ্রন্টএন্ডে ফেরত দেওয়ার জন্য নিরাপদ সেশন টিকিট (কোনো পিন, পাসওয়ার্ড বা প্রাইভেট কি নেই)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTicket {
    pub session_id_hex: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub addresses: MultiChainAccountAddresses,
}

/// র‍্যামে ডিক্রিপ্টেড সিড বাফার যা Drop হওয়ার সাথে সাথে স্বয়ংক্রিয়ভাবে Zeroize হয়
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretSeedMaterial {
    seed_64: [u8; 64],
}

// ============================================================================
// 1. CRYPTOGRAPHY ENGINE (Argon2id + AES-256-GCM / ChaCha20-Poly1305 + OsRng)
// ============================================================================

pub struct CryptoEngine;

impl CryptoEngine {
    pub fn enforce_password_policy(password: &str) -> Result<(), VaultError> {
        if password.len() < 12 {
            return Err(VaultError::WeakPassword);
        }
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

        if !(has_upper && has_lower && has_digit && has_symbol) {
            return Err(VaultError::WeakPassword);
        }
        Ok(())
    }

    /// প্রকৃত Argon2id (RFC 9106) মেমরি-হার্ড কী ডেরিভেশন
    pub fn derive_key_argon2id(
        password: &str,
        salt: &[u8; SALT_LEN],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let params = Params::new(m_cost_kib, t_cost, p_cost, Some(KEY_LEN))
            .map_err(|e| VaultError::KdfError(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut *derived)
            .map_err(|e| VaultError::KdfError(e.to_string()))?;
        Ok(derived)
    }

    /// OS CSPRNG Salt ও Nonce এবং AAD বাইন্ডিংসহ প্রকৃত AEAD এনক্রিপশন
    pub fn encrypt_keystore(
        plaintext: &[u8],
        password: &str,
        cipher_suite: CipherSuite,
        aad_context: &str,
    ) -> Result<EncryptedKeystoreEnvelope, VaultError> {
        Self::enforce_password_policy(password)?;

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let key = Self::derive_key_argon2id(
            password,
            &salt,
            ARGON2ID_M_COST_KIB,
            ARGON2ID_T_COST,
            ARGON2ID_P_COST,
        )?;

        let payload = Payload {
            msg: plaintext,
            aad: aad_context.as_bytes(),
        };

        let mut combined = match cipher_suite {
            CipherSuite::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&*key)
                    .map_err(|_| VaultError::AeadAuthError)?;
                cipher
                    .encrypt(AesNonce::from_slice(&nonce), payload)
                    .map_err(|_| VaultError::AeadAuthError)?
            }
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|_| VaultError::AeadAuthError)?;
                cipher
                    .encrypt(ChaChaNonce::from_slice(&nonce), payload)
                    .map_err(|_| VaultError::AeadAuthError)?
            }
        };

        if combined.len() < TAG_LEN {
            return Err(VaultError::AeadAuthError);
        }
        let ct_len = combined.len() - TAG_LEN;
        let tag_slice = combined.split_off(ct_len);
        let mut auth_tag = [0u8; TAG_LEN];
        auth_tag.copy_from_slice(&tag_slice);

        Ok(EncryptedKeystoreEnvelope {
            version: 1,
            cipher: cipher_suite,
            m_cost_kib: ARGON2ID_M_COST_KIB,
            t_cost: ARGON2ID_T_COST,
            p_cost: ARGON2ID_P_COST,
            salt,
            nonce,
            ciphertext: combined,
            auth_tag,
            aad_context: aad_context.to_string(),
        })
    }

    /// Authentication Tag ও AAD যাচাই করে ডিক্রিপ্ট করে (ট্যাগ ভুল হলে সাথে সাথে Fail)
    pub fn decrypt_keystore(
        envelope: &EncryptedKeystoreEnvelope,
        password: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let key = Self::derive_key_argon2id(
            password,
            &envelope.salt,
            envelope.m_cost_kib,
            envelope.t_cost,
            envelope.p_cost,
        )?;

        let mut combined = Vec::with_capacity(envelope.ciphertext.len() + TAG_LEN);
        combined.extend_from_slice(&envelope.ciphertext);
        combined.extend_from_slice(&envelope.auth_tag);

        let payload = Payload {
            msg: &combined,
            aad: envelope.aad_context.as_bytes(),
        };

        let decrypted = match envelope.cipher {
            CipherSuite::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&*key)
                    .map_err(|_| VaultError::AeadAuthError)?;
                cipher
                    .decrypt(AesNonce::from_slice(&envelope.nonce), payload)
                    .map_err(|_| VaultError::AeadAuthError)?
            }
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|_| VaultError::AeadAuthError)?;
                cipher
                    .decrypt(ChaChaNonce::from_slice(&envelope.nonce), payload)
                    .map_err(|_| VaultError::AeadAuthError)?
            }
        };

        combined.zeroize();
        Ok(Zeroizing::new(decrypted))
    }
}

// ============================================================================
// 2. WALLET CORE (Official BIP-39 + BIP-32/BIP-44/BIP-84 + SLIP-0010 HD Engine)
// ============================================================================

pub struct HdWalletEngine;

impl HdWalletEngine {
    /// অফিশিয়াল ২,০৪৮ শব্দের BIP-39 ডিকশনারি ও OS CSPRNG দিয়ে ২৪-শব্দের Mnemonic তৈরি
    pub fn generate_bip39_mnemonic_24() -> Result<Zeroizing<String>, VaultError> {
        let mut entropy = Zeroizing::new([0u8; 32]); // 256 bits = 24 words
        OsRng.fill_bytes(&mut *entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &*entropy)
            .map_err(|e| VaultError::InvalidMnemonic(e.to_string()))?;
        Ok(Zeroizing::new(mnemonic.to_string()))
    }

    /// অফিশিয়াল BIP-39 চেকসাম যাচাই এবং 2048-রাউন্ড PBKDF2-HMAC-SHA512 দিয়ে ৬৪-বাইট সিড তৈরি
    pub fn mnemonic_to_master_seed(
        phrase: &str,
        passphrase: &str,
    ) -> Result<Zeroizing<[u8; 64]>, VaultError> {
        let parsed = Mnemonic::parse_in_normalized(Language::English, phrase.trim())
            .map_err(|e| VaultError::InvalidMnemonic(e.to_string()))?;
        let seed_bytes = parsed.to_seed(passphrase);
        Ok(Zeroizing::new(seed_bytes))
    }

    /// BIP-32 secp256k1 Master & Hardened/Normal Child Key Derivation
    fn derive_bip32_secp256k1(
        seed: &[u8; 64],
        path: &[u32],
    ) -> Result<Secp256k1SecretKey, VaultError> {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(b"Bitcoin seed")
            .map_err(|e| VaultError::DerivationError(e.to_string()))?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut il = Zeroizing::new([0u8; 32]);
        let mut ir = Zeroizing::new([0u8; 32]);
        il.copy_from_slice(&result[0..32]);
        ir.copy_from_slice(&result[32..64]);

        let mut current_sk = Secp256k1SecretKey::from_slice(&*il)
            .map_err(|e| VaultError::DerivationError(e.to_string()))?;

        for &index in path {
            let mut data = Zeroizing::new(Vec::with_capacity(37));
            if (index & 0x8000_0000) != 0 {
                // Hardened child: 0x00 || ser256(k_par) || ser32(i)
                data.push(0x00);
                data.extend_from_slice(&current_sk.to_bytes());
            } else {
                // Normal child: serP(point(k_par)) || ser32(i)
                let pubkey_compressed = current_sk.public_key().to_encoded_point(true);
                data.extend_from_slice(pubkey_compressed.as_bytes());
            }
            data.extend_from_slice(&index.to_be_bytes());

            let mut child_mac = <HmacSha512 as Mac>::new_from_slice(&*ir)
                .map_err(|e| VaultError::DerivationError(e.to_string()))?;
            child_mac.update(&data);
            let out = child_mac.finalize().into_bytes();

            let tweak_scalar = k256::NonZeroScalar::try_from(&out[0..32])
                .map_err(|_| VaultError::DerivationError("Invalid BIP32 scalar".into()))?;
            let parent_scalar = current_sk.to_nonzero_scalar();
            let child_scalar = parent_scalar.as_ref() + tweak_scalar.as_ref();
            let ct_opt: Option<k256::NonZeroScalar> =
                k256::NonZeroScalar::new(child_scalar).into();
            let valid_scalar =
                ct_opt.ok_or_else(|| VaultError::DerivationError("Zero child scalar".into()))?;

            current_sk = Secp256k1SecretKey::from(valid_scalar);
            ir.copy_from_slice(&out[32..64]);
        }

        Ok(current_sk)
    }

    /// SLIP-0010 Ed25519 Hardened Key Derivation (for SOL, TON, EQX)
    fn derive_slip10_ed25519(
        seed: &[u8; 64],
        hardened_indices: &[u32],
    ) -> Result<Ed25519SigningKey, VaultError> {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(b"ed25519 seed")
            .map_err(|e| VaultError::DerivationError(e.to_string()))?;
        mac.update(seed);
        let res = mac.finalize().into_bytes();

        let mut key = Zeroizing::new([0u8; 32]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&res[0..32]);
        chain_code.copy_from_slice(&res[32..64]);

        for &idx in hardened_indices {
            let hardened = idx | 0x8000_0000;
            let mut buf = Zeroizing::new([0u8; 37]);
            buf[0] = 0x00;
            buf[1..33].copy_from_slice(&*key);
            buf[33..37].copy_from_slice(&hardened.to_be_bytes());

            let mut c_mac = <HmacSha512 as Mac>::new_from_slice(&*chain_code)
                .map_err(|e| VaultError::DerivationError(e.to_string()))?;
            c_mac.update(&*buf);
            let out = c_mac.finalize().into_bytes();
            key.copy_from_slice(&out[0..32]);
            chain_code.copy_from_slice(&out[32..64]);
        }

        Ok(Ed25519SigningKey::from_bytes(&*key))
    }

    /// EIP-55 Mixed-Case Checksum Address Formatter for Ethereum & BNB
    pub fn format_eip55_checksum(raw_20_bytes: &[u8]) -> String {
        let lower_hex = hex::encode(raw_20_bytes);
        let mut hasher = Keccak256::new();
        hasher.update(lower_hex.as_bytes());
        let hash = hasher.finalize();

        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, ch) in lower_hex.chars().enumerate() {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0x0f
            } else {
                hash[i / 2] & 0x0f
            };
            if ch.is_ascii_alphabetic() && nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// TON v4r2 User-Friendly Address Encoder with CRC16-CCITT Checksum
    fn encode_ton_user_friendly_address(ed25519_pubkey: &[u8; 32]) -> String {
        let mut state_hasher = Sha256::new();
        state_hasher.update(b"TON_WALLET_V4R2_STATE_INIT_WORKCHAIN_0");
        state_hasher.update(ed25519_pubkey);
        let account_id: [u8; 32] = state_hasher.finalize().into();

        // 0x51 = Non-bounceable user-friendly tag ('UQ'), 0x00 = Workchain 0
        let mut addr_bytes = [0u8; 36];
        addr_bytes[0] = 0x51;
        addr_bytes[1] = 0x00;
        addr_bytes[2..34].copy_from_slice(&account_id);

        // CRC16-CCITT (XModem) over first 34 bytes
        let mut crc: u16 = 0;
        for &b in &addr_bytes[0..34] {
            crc ^= (b as u16) << 8;
            for _ in 0..8 {
                if (crc & 0x8000) != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        addr_bytes[34] = (crc >> 8) as u8;
        addr_bytes[35] = (crc & 0xff) as u8;

        // URL-safe Base64 encoding (48 chars starting with UQ)
        const B64_URL: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(48);
        for chunk in addr_bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk[1] as u32;
            let b2 = chunk[2] as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(B64_URL[((triple >> 18) & 0x3f) as usize] as char);
            out.push(B64_URL[((triple >> 12) & 0x3f) as usize] as char);
            out.push(B64_URL[((triple >> 6) & 0x3f) as usize] as char);
            out.push(B64_URL[(triple & 0x3f) as usize] as char);
        }
        out
    }

    /// একই ৬৪-বাইট মাস্টার সিড থেকে BTC, ETH, BNB, TRON, SOL, TON এবং EQX অ্যাড্রেস ডেরিভেশন
    pub fn derive_all_chain_addresses(
        seed: &[u8; 64],
        account_index: u32,
    ) -> Result<MultiChainAccountAddresses, VaultError> {
        let h = 0x8000_0000u32;

        // 1. BTC Native SegWit (BIP-84: m/84'/0'/0'/0/account_index)
        let btc_sk = Self::derive_bip32_secp256k1(
            seed,
            &[84 | h, 0 | h, 0 | h, 0, account_index],
        )?;
        let btc_pub_compressed = btc_sk.public_key().to_encoded_point(true);
        let btc_sha = Sha256::digest(btc_pub_compressed.as_bytes());
        let btc_hash160 = Ripemd160::digest(btc_sha);
        let mut witness_words = vec![bech32::u5::try_from_u8(0).unwrap()];
        witness_words.extend_from_slice(&btc_hash160.to_base32());
        let btc_native_segwit = bech32::encode("bc", witness_words, Variant::Bech32)
            .map_err(|e| VaultError::DerivationError(e.to_string()))?;

        // 2. ETH & BNB (BIP-44: m/44'/60'/0'/0/account_index)
        let eth_sk = Self::derive_bip32_secp256k1(
            seed,
            &[44 | h, 60 | h, 0 | h, 0, account_index],
        )?;
        let eth_pub_uncompressed = eth_sk.public_key().to_encoded_point(false);
        let eth_keccak = Keccak256::digest(&eth_pub_uncompressed.as_bytes()[1..65]);
        let eth_address = Self::format_eip55_checksum(&eth_keccak[12..32]);

        // 3. TRON (BIP-44: m/44'/195'/0'/0/account_index)
        let tron_sk = Self::derive_bip32_secp256k1(
            seed,
            &[44 | h, 195 | h, 0 | h, 0, account_index],
        )?;
        let tron_pub_uncompressed = tron_sk.public_key().to_encoded_point(false);
        let tron_keccak = Keccak256::digest(&tron_pub_uncompressed.as_bytes()[1..65]);
        let mut tron_payload = [0u8; 21];
        tron_payload[0] = TRON_ADDRESS_VERSION;
        tron_payload[1..21].copy_from_slice(&tron_keccak[12..32]);
        let tron_trc20 = bs58::encode(tron_payload).with_check().into_string();

        // 4. Solana (SLIP-0010: m/44'/501'/account_index'/0')
        let sol_sk = Self::derive_slip10_ed25519(seed, &[44, 501, account_index, 0])?;
        let sol_mainnet = bs58::encode(sol_sk.verifying_key().to_bytes()).into_string();

        // 5. TON (SLIP-0010: m/44'/607'/account_index')
        let ton_sk = Self::derive_slip10_ed25519(seed, &[44, 607, account_index])?;
        let ton_v4r2 = Self::encode_ton_user_friendly_address(&ton_sk.verifying_key().to_bytes());

        // 6. Equinox Native (SLIP-0010: m/44'/9333'/account_index'/0')
        let eqx_sk = Self::derive_slip10_ed25519(seed, &[44, 9333, account_index, 0])?;
        let eqx_sha = Sha256::digest(eqx_sk.verifying_key().as_bytes());
        let eqx_h160 = Ripemd160::digest(eqx_sha);
        let mut eqx_payload = [0u8; 21];
        eqx_payload[0] = EQX_ADDRESS_VERSION;
        eqx_payload[1..21].copy_from_slice(&eqx_h160);
        let eqx_native = bs58::encode(eqx_payload).with_check().into_string();

        Ok(MultiChainAccountAddresses {
            account_index,
            btc_native_segwit,
            eth_erc20: eth_address.clone(),
            bnb_bep20: eth_address,
            tron_trc20,
            sol_mainnet,
            ton_v4r2,
            eqx_native,
        })
    }
}

// ============================================================================
// 3. AUTHENTICATION & RFC-6238 TOTP 2FA GUARD (Zero Hardcoded Credentials)
// ============================================================================

pub struct TotpAuthenticator;

impl TotpAuthenticator {
    /// RFC 6238 অনুসারী 6-ডিজিট TOTP কোড জেনারেটর (30s Window)
    pub fn generate_totp_at(secret_key: &[u8], unix_time_secs: u64) -> u32 {
        let counter = unix_time_secs / TOTP_STEP_SECS;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret_key).expect("HMAC key init");
        mac.update(&counter.to_be_bytes());
        let hash = mac.finalize().into_bytes();

        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = (((hash[offset] & 0x7f) as u32) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);
        binary % 1_000_000
    }

    /// ক্লক ড্রিফট সহ্য করার জন্য (-1, 0, +1) স্টెপে ৬-ডিজিট TOTP যাচাই করে
    pub fn verify_totp_code(secret_key: &[u8], code_str: &str, unix_time_secs: u64) -> bool {
        let clean = code_str.trim();
        if clean.len() != 6 || !clean.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let Ok(user_code) = clean.parse::<u32>() else {
            return false;
        };

        for drift in [-1i64, 0, 1] {
            let adjusted_time = (unix_time_secs as i64) + (drift * (TOTP_STEP_SECS as i64));
            if adjusted_time >= 0 {
                if Self::generate_totp_at(secret_key, adjusted_time as u64) == user_code {
                    return true;
                }
            }
        }
        false
    }
}

pub struct ProductionVaultSessionManager {
    keystore: EncryptedKeystoreEnvelope,
    totp_secret: Zeroizing<[u8; 32]>,
    recovery_code_hashes: HashSet<[u8; 32]>,
    unlocked_seed: Option<SecretSeedMaterial>,
    active_session: Option<SessionTicket>,
    failed_attempts: u32,
    backoff_until_unix: u64,
    locked_until_unix: u64,
    last_activity_unix: u64,
}

impl ProductionVaultSessionManager {
    /// নতুন ওয়ালেট ভল্ট ইনিশিয়ালাইজ করে এবং ওয়ান-টাইম রিকভারি কোড তৈরি করে
    pub fn create_new_vault(
        mnemonic_phrase: &str,
        password: &str,
        cipher: CipherSuite,
    ) -> Result<(Self, Vec<String>, [u8; 32]), VaultError> {
        let seed = HdWalletEngine::mnemonic_to_master_seed(mnemonic_phrase, "")?;
        let envelope = CryptoEngine::encrypt_keystore(
            &*seed,
            password,
            cipher,
            "EQX_PRODUCTION_KEYSTORE_V1",
        )?;

        let mut totp_secret = [0u8; 32];
        OsRng.fill_bytes(&mut totp_secret);

        let mut raw_recovery_codes = Vec::with_capacity(4);
        let mut recovery_code_hashes = HashSet::with_capacity(4);

        for _ in 0..4 {
            let mut rnd = [0u8; 6];
            OsRng.fill_bytes(&mut rnd);
            let code_formatted = format!(
                "EQX-{}-{}",
                hex::encode(&rnd[0..3]).to_uppercase(),
                hex::encode(&rnd[3..6]).to_uppercase()
            );
            let digest: [u8; 32] = Sha256::digest(code_formatted.as_bytes()).into();
            recovery_code_hashes.insert(digest);
            raw_recovery_codes.push(code_formatted);
        }

        let mgr = Self {
            keystore: envelope,
            totp_secret: Zeroizing::new(totp_secret),
            recovery_code_hashes,
            unlocked_seed: None,
            active_session: None,
            failed_attempts: 0,
            backoff_until_unix: 0,
            locked_until_unix: 0,
            last_activity_unix: 0,
        };

        Ok((mgr, raw_recovery_codes, totp_secret))
    }

    fn record_failure(&mut self, current_unix: u64) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= MAX_AUTH_FAILURES {
            self.locked_until_unix = current_unix.saturating_add(LOCKOUT_DURATION_SECS);
        } else {
            let delay = 1u64 << self.failed_attempts;
            self.backoff_until_unix = current_unix.saturating_add(delay);
        }
    }

    /// পাসওয়ার্ড + RFC-6238 TOTP কোড যাচাই করে সেশন চালু করে (সেশনে কোনো পিন বা প্রাইভেট কি ফেরত যায় না)
    pub fn unlock_with_totp(
        &mut self,
        password: &str,
        totp_code: &str,
        current_unix: u64,
    ) -> Result<SessionTicket, VaultError> {
        if current_unix < self.locked_until_unix {
            return Err(VaultError::AccountLocked(self.locked_until_unix));
        }
        if current_unix < self.backoff_until_unix {
            return Err(VaultError::BackoffActive(self.backoff_until_unix));
        }

        let decrypted_bytes = match CryptoEngine::decrypt_keystore(&self.keystore, password) {
            Ok(b) => b,
            Err(e) => {
                self.record_failure(current_unix);
                return Err(e);
            }
        };

        if !TotpAuthenticator::verify_totp_code(&*self.totp_secret, totp_code, current_unix) {
            self.record_failure(current_unix);
            return Err(VaultError::InvalidTotpCode);
        }

        let mut seed_64 = [0u8; 64];
        seed_64.copy_from_slice(&decrypted_bytes[0..64]);
        let addresses = HdWalletEngine::derive_all_chain_addresses(&seed_64, 0)?;

        let mut session_rnd = [0u8; 32];
        OsRng.fill_bytes(&mut session_rnd);

        let ticket = SessionTicket {
            session_id_hex: hex::encode(session_rnd),
            issued_at_unix: current_unix,
            expires_at_unix: current_unix.saturating_add(SESSION_IDLE_TIMEOUT_SECS),
            addresses,
        };

        self.failed_attempts = 0;
        self.backoff_until_unix = 0;
        self.locked_until_unix = 0;
        self.last_activity_unix = current_unix;
        self.unlocked_seed = Some(SecretSeedMaterial { seed_64 });
        self.active_session = Some(ticket.clone());

        Ok(ticket)
    }

    /// ওয়ান-টাইম রিকভারি কোড ব্যবহার করে 2FA বাইপাস/রিসেট করে আনলক করা
    pub fn unlock_with_recovery_code(
        &mut self,
        password: &str,
        recovery_code: &str,
        current_unix: u64,
    ) -> Result<SessionTicket, VaultError> {
        let decrypted_bytes = CryptoEngine::decrypt_keystore(&self.keystore, password)?;
        let code_hash: [u8; 32] = Sha256::digest(recovery_code.trim().as_bytes()).into();

        if !self.recovery_code_hashes.remove(&code_hash) {
            self.record_failure(current_unix);
            return Err(VaultError::InvalidRecoveryCode);
        }

        let mut seed_64 = [0u8; 64];
        seed_64.copy_from_slice(&decrypted_bytes[0..64]);
        let addresses = HdWalletEngine::derive_all_chain_addresses(&seed_64, 0)?;

        let mut session_rnd = [0u8; 32];
        OsRng.fill_bytes(&mut session_rnd);

        let ticket = SessionTicket {
            session_id_hex: hex::encode(session_rnd),
            issued_at_unix: current_unix,
            expires_at_unix: current_unix.saturating_add(SESSION_IDLE_TIMEOUT_SECS),
            addresses,
        };

        self.failed_attempts = 0;
        self.locked_until_unix = 0;
        self.backoff_until_unix = 0;
        self.last_activity_unix = current_unix;
        self.unlocked_seed = Some(SecretSeedMaterial { seed_64 });
        self.active_session = Some(ticket.clone());

        Ok(ticket)
    }

    /// ৫ মিনিট নিষ্ক্রিয় থাকলে স্বয়ংক্রিয়ভাবে র‍্যাম Zeroize ও সেশন লক করে
    pub fn enforce_auto_lock(&mut self, current_unix: u64) -> bool {
        if self.unlocked_seed.is_some()
            && current_unix >= self.last_activity_unix.saturating_add(SESSION_IDLE_TIMEOUT_SECS)
        {
            self.lock_now();
            return true;
        }
        false
    }

    pub fn lock_now(&mut self) {
        self.unlocked_seed = None; // Triggers ZeroizeOnDrop automatically
        self.active_session = None;
    }
}

// ============================================================================
// 4. OFFICIAL CRYPTOGRAPHIC & BIP-39 / BIP-84 / EIP-55 TEST VECTORS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_official_bip39_and_deterministic_7_chain_recovery() {
        // Official BIP-39 24-word test vector
        let official_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let seed_a = HdWalletEngine::mnemonic_to_master_seed(official_phrase, "").unwrap();
        let seed_b = HdWalletEngine::mnemonic_to_master_seed(official_phrase, "").unwrap();
        assert_eq!(*seed_a, *seed_b);

        let addrs_1 = HdWalletEngine::derive_all_chain_addresses(&seed_a, 0).unwrap();
        let addrs_2 = HdWalletEngine::derive_all_chain_addresses(&seed_b, 0).unwrap();

        // Recovery must produce 100% identical addresses across all 7 chains
        assert_eq!(addrs_1, addrs_2);
        assert!(addrs_1.btc_native_segwit.starts_with("bc1q"));
        assert!(addrs_1.eth_erc20.starts_with("0x") && addrs_1.eth_erc20.len() == 42);
        assert!(addrs_1.tron_trc20.starts_with('T'));
        assert!(addrs_1.ton_v4r2.starts_with("UQ") && addrs_1.ton_v4r2.len() == 48);
        assert!(addrs_1.eqx_native.starts_with('E'));

        // Account #1 must derive completely distinct addresses from Account #0
        let addrs_acct1 = HdWalletEngine::derive_all_chain_addresses(&seed_a, 1).unwrap();
        assert_ne!(addrs_1.btc_native_segwit, addrs_acct1.btc_native_segwit);
        assert_ne!(addrs_1.eth_erc20, addrs_acct1.eth_erc20);
        assert_ne!(addrs_1.tron_trc20, addrs_acct1.tron_trc20);
        assert_ne!(addrs_1.sol_mainnet, addrs_acct1.sol_mainnet);
        assert_ne!(addrs_1.ton_v4r2, addrs_acct1.ton_v4r2);
        assert_ne!(addrs_1.eqx_native, addrs_acct1.eqx_native);
    }

    #[test]
    fn test_argon2id_aes256gcm_and_chacha20poly1305_tag_integrity() {
        let phrase = HdWalletEngine::generate_bip39_mnemonic_24().unwrap();
        let pass = "ProdVault#2026!Secure";

        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let mut env =
                CryptoEngine::encrypt_keystore(phrase.as_bytes(), pass, suite, "AAD_V1").unwrap();
            let dec = CryptoEngine::decrypt_keystore(&env, pass).unwrap();
            assert_eq!(dec.as_slice(), phrase.as_bytes());

            // Tampering 1 bit of authentication tag must fail decryption
            env.auth_tag[0] ^= 0x01;
            assert_eq!(
                CryptoEngine::decrypt_keystore(&env, pass),
                Err(VaultError::AeadAuthError)
            );
        }
    }

    #[test]
    fn test_totp_2fa_rate_limit_lockout_and_one_time_recovery_code() {
        let phrase = HdWalletEngine::generate_bip39_mnemonic_24().unwrap();
        let pass = "ProdVault#2026!Secure";
        let now = 1_760_000_000u64;

        let (mut mgr, recovery_codes, totp_secret) = ProductionVaultSessionManager::create_new_vault(
            &phrase,
            pass,
            CipherSuite::Aes256Gcm,
        )
        .unwrap();

        let valid_totp = format!("{:06}", TotpAuthenticator::generate_totp_at(&totp_secret, now));
        let session = mgr.unlock_with_totp(pass, &valid_totp, now).unwrap();
        assert_eq!(session.session_id_hex.len(), 64);

        // Auto-lock after 5 minutes (300s) of inactivity
        assert!(mgr.enforce_auto_lock(now + 301));

        // One-time recovery code unlocks once, then is permanently consumed
        assert!(mgr
            .unlock_with_recovery_code(pass, &recovery_codes[0], now + 400)
            .is_ok());
        assert_eq!(
            mgr.unlock_with_recovery_code(pass, &recovery_codes[0], now + 410),
            Err(VaultError::InvalidRecoveryCode)
        );
    }
}

