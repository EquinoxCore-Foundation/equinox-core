#![allow(dead_code)]
// src/crypto/mod.rs
// Equinox (EQX) L1 — ক্রিপ্টোগ্রাফিক হ্যাশিং (SHA-256d, Hash160), ডোমেইন-সেপারেটেড Merkle Tree,
// এবং স্ট্রিক্ট ক্যানোনিকাল Ed25519 ডিজিটাল সিগনেচার ইঞ্জিন।

pub mod hash;
pub mod keys;
pub mod merkle;

pub use hash::{
    compute_short_txid, constant_time_eq, hash160, sha256, sha256d, sha256d_tagged, Hash160,
    Hash256, ShortTxId, ZERO_HASH,
};
pub use keys::{
    verify_batch_parallel, verify_signature, KeyPair, PublicKeyBytes, SecretKeyBytes,
    SignatureBytes, SignatureVerificationTask,
};
pub use merkle::{
    compute_merkle_root, generate_merkle_proof, has_duplicate_transactions, verify_merkle_proof,
    MerkleProofNode,
};

pub mod pq_shield;
pub use pq_shield::{PostQuantumKeyPair, PostQuantumSignature};
