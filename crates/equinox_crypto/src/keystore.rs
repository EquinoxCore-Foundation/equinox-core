#![forbid(unsafe_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::CryptoError;

pub const KEYSTORE_VERSION: u8 = 1;
pub const MIN_PASSWORD_LEN: usize = 10;

#[derive(Debug, Clone, Copy)]
pub struct KdfConfig {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfConfig {
    /// Production Argon2id settings: 64 MiB memory, 3 iterations, 1 lane.
    pub fn mainnet_default() -> Self {
        Self {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// Lightweight settings strictly for fast unit test execution.
    pub fn fast_test() -> Self {
        Self {
            m_cost_kib: 1_024,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKeystore {
    pub version: u8,
    pub chain_id: u64,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedKeystore {
    fn build_aad(
        version: u8,
        chain_id: u64,
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
        salt: &[u8; 32],
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(b"EQX_KEYSTORE_AAD");
        aad.push(version);
        aad.extend_from_slice(&chain_id.to_le_bytes());
        aad.extend_from_slice(&m_cost_kib.to_le_bytes());
        aad.extend_from_slice(&t_cost.to_le_bytes());
        aad.extend_from_slice(&p_cost.to_le_bytes());
        aad.extend_from_slice(salt);
        aad
    }

    fn derive_key(
        password: &[u8],
        salt: &[u8; 32],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
            .map_err(|_| CryptoError::KdfFailure)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, salt, &mut *key)
            .map_err(|_| CryptoError::KdfFailure)?;
        Ok(key)
    }

    pub fn encrypt(
        secret_bytes: &[u8],
        password: &[u8],
        chain_id: u64,
        cfg: KdfConfig,
    ) -> Result<Self, CryptoError> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(CryptoError::WeakPassword);
        }

        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = Self::derive_key(password, &salt, cfg.m_cost_kib, cfg.t_cost, cfg.p_cost)?;
        let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| CryptoError::EncryptionFailed)?;
        let aad = Self::build_aad(
            KEYSTORE_VERSION,
            chain_id,
            cfg.m_cost_kib,
            cfg.t_cost,
            cfg.p_cost,
            &salt,
        );

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: secret_bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(Self {
            version: KEYSTORE_VERSION,
            chain_id,
            m_cost_kib: cfg.m_cost_kib,
            t_cost: cfg.t_cost,
            p_cost: cfg.p_cost,
            salt,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = Self::derive_key(
            password,
            &self.salt,
            self.m_cost_kib,
            self.t_cost,
            self.p_cost,
        )?;
        let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| CryptoError::DecryptionFailed)?;
        let aad = Self::build_aad(
            self.version,
            self.chain_id,
            self.m_cost_kib,
            self.t_cost,
            self.p_cost,
            &self.salt,
        );

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(Zeroizing::new(plaintext))
    }
}
