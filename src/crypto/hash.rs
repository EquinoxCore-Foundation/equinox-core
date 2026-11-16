#![allow(dead_code)]
// src/crypto/hash.rs
// Equinox (EQX) L1 — Cryptographic Hashing Engine (SHA-256, SHA-256d, Tagged SHA-256d, Hash160 & ShortTxId)

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub type Hash256 = [u8; 32];
pub type Hash160 = [u8; 20];
pub type ShortTxId = [u8; 6];

pub const ZERO_HASH: Hash256 = [0u8; 32];

#[inline]
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[inline]
pub fn sha256d(data: &[u8]) -> Hash256 {
    let first = sha256(data);
    sha256(&first)
}

pub fn sha256d_tagged(tag: &[u8], data: &[u8]) -> Hash256 {
    let tag_hash = sha256(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    let first: Hash256 = hasher.finalize().into();
    sha256(&first)
}

pub fn hash160(data: &[u8]) -> Hash160 {
    let sha_out = sha256(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha_out);
    ripemd.finalize().into()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn compute_short_txid(txid: &Hash256, block_nonce: u64) -> ShortTxId {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(txid);
    buf[32..40].copy_from_slice(&block_nonce.to_le_bytes());
    let digest = sha256d_tagged(b"EQX_COMPACT_SHORT_ID_V2", &buf);
    let mut short_id = [0u8; 6];
    short_id.copy_from_slice(&digest[..6]);
    short_id
}
