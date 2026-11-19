#![forbid(unsafe_code)]

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::CryptoError;

/// Version byte 0x21 (33) mathematically guarantees every 25-byte Base58Check address starts with 'E' (34 chars).
pub const ADDRESS_VERSION_MAINNET: u8 = 0x21;

pub fn hash160(pubkey: &[u8; 32]) -> [u8; 20] {
    let sha = Sha256::digest(pubkey);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn double_sha256_checksum(data: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

pub fn encode_mainnet_address(pubkey: &[u8; 32]) -> String {
    let h160 = hash160(pubkey);
    encode_from_hash160(&h160)
}

pub fn encode_from_hash160(h160: &[u8; 20]) -> String {
    let mut payload = [0u8; 25];
    payload[0] = ADDRESS_VERSION_MAINNET;
    payload[1..21].copy_from_slice(h160);
    let checksum = double_sha256_checksum(&payload[..21]);
    payload[21..25].copy_from_slice(&checksum);
    bs58::encode(payload).into_string()
}

pub fn decode_and_verify_address(address: &str) -> Result<[u8; 20], CryptoError> {
    let raw = bs58::decode(address)
        .into_vec()
        .map_err(|_| CryptoError::InvalidAddressEncoding)?;

    if raw.len() != 25 || raw[0] != ADDRESS_VERSION_MAINNET {
        return Err(CryptoError::InvalidAddressVersionOrLength);
    }

    let expected = double_sha256_checksum(&raw[..21]);
    let provided = &raw[21..25];
    if !bool::from(provided.ct_eq(&expected)) {
        return Err(CryptoError::InvalidAddressChecksum);
    }

    let mut h160 = [0u8; 20];
    h160.copy_from_slice(&raw[1..21]);
    Ok(h160)
}
