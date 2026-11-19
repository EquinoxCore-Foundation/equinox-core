#![forbid(unsafe_code)]

use equinox_crypto::address::encode_mainnet_address;
use equinox_crypto::signer::SecretSeed;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::WalletError;

type HmacSha512 = Hmac<Sha512>;

pub const HARDENED_OFFSET: u32 = 0x8000_0000;
pub const BIP44_PURPOSE: u32 = 44;
pub const EQUINOX_COIN_TYPE: u32 = 9333;

/// SLIP-0010 Ed25519 extended private key (intentionally no Debug to avoid key leakage).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Slip10Key {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl Slip10Key {
    pub fn derive_master(seed: &[u8]) -> Result<Self, WalletError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(WalletError::InvalidSeedLength);
        }
        let mut mac =
            HmacSha512::new_from_slice(b"ed25519 seed").map_err(|_| WalletError::DerivationError)?;
        mac.update(seed);
        let mut raw = [0u8; 64];
        raw.copy_from_slice(&mac.finalize().into_bytes());

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&raw[0..32]);
        chain_code.copy_from_slice(&raw[32..64]);
        raw.zeroize();
        Ok(Self { key, chain_code })
    }

    pub fn derive_child_hardened(&self, index: u32) -> Result<Self, WalletError> {
        if index < HARDENED_OFFSET {
            return Err(WalletError::NonHardenedPathUnsupported);
        }
        let mut data = [0u8; 37];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&self.key);
        data[33..37].copy_from_slice(&index.to_be_bytes());

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).map_err(|_| WalletError::DerivationError)?;
        mac.update(&data);
        data.zeroize();

        let mut raw = [0u8; 64];
        raw.copy_from_slice(&mac.finalize().into_bytes());

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&raw[0..32]);
        chain_code.copy_from_slice(&raw[32..64]);
        raw.zeroize();
        Ok(Self { key, chain_code })
    }

    pub fn derive_path(seed: &[u8], path: &[u32]) -> Result<Self, WalletError> {
        let mut current = Self::derive_master(seed)?;
        for &segment in path {
            current = current.derive_child_hardened(segment)?;
        }
        Ok(current)
    }

    pub fn to_secret_seed(&self) -> SecretSeed {
        SecretSeed::from_bytes(self.key)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.to_secret_seed().public_key_bytes()
    }

    pub fn mainnet_address(&self) -> String {
        encode_mainnet_address(&self.public_key_bytes())
    }
}

pub fn equinox_hd_path(
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<[u32; 5], WalletError> {
    if account >= HARDENED_OFFSET
        || change >= HARDENED_OFFSET
        || address_index >= HARDENED_OFFSET
    {
        return Err(WalletError::InvalidPathComponent);
    }
    Ok([
        BIP44_PURPOSE | HARDENED_OFFSET,
        EQUINOX_COIN_TYPE | HARDENED_OFFSET,
        account | HARDENED_OFFSET,
        change | HARDENED_OFFSET,
        address_index | HARDENED_OFFSET,
    ])
}
