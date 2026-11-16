#![allow(dead_code)]
// src/crypto/pq_shield.rs
// Equinox (EQX) L1 — Immortal-Grade Post-Quantum Hash-Based Signature & Vault Commitment Shield
// Architecture: Pure SHA-256d Lamport-Merkle 256-Bit Bitwise Hash Trapdoor (Shor's Algorithm Immune).
// Features: Zero Elliptic-Curve Dependency, Constant-Time Verification & Automatic RAM Zeroization.

use crate::crypto::hash::{constant_time_eq, sha256d, sha256d_tagged, Hash256};
use crate::crypto::merkle::compute_merkle_root;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// পোস্ট-কোয়ান্টাম সিক্রেট সিড ডেরিভেশন ট্যাগ
const PQ_SECRET_SCALAR_TAG: &[u8] = b"EQX_PQ_LAMPORT_SECRET_SCALAR_V1";

/// পোস্ট-কোয়ান্টাম পাবলিক কমিটমেন্ট লিফ ট্যাগ
const PQ_PUBLIC_LEAF_TAG: &[u8] = b"EQX_PQ_LAMPORT_PUBLIC_LEAF_V1";

/// পোস্ট-কোয়ান্টাম মেসেজ ডাইজেস্ট বাইন্ডিং ট্যাগ
const PQ_MESSAGE_BIND_TAG: &[u8] = b"EQX_PQ_LAMPORT_MSG_DIGEST_V1";

/// কোয়ান্টাম-প্রতিরোধী প্রাইভেট কি (RAM-এ কাজ শেষে স্বয়ংক্রিয়ভাবে মুছে যাবে)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PostQuantumKeyPair {
    master_seed: Hash256,
    pub public_root: Hash256,
}

/// ২৫৬-বিট মেসেজের জন্য কোয়ান্টাম-প্রতিরোধী হ্যাশ সিগনেচার ও পাবলিক পেয়ার প্রুফ
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostQuantumSignature {
    /// মেসেজের প্রতিটি বিটের (`0` বা `1`) জন্য উদ্ঘাটিত ২৫৬টি প্রি-ইমেজ হ্যাশ
    pub revealed_preimages: Vec<Hash256>,
    /// অপর বিটের ২৫৬টি পাবলিক হ্যাশ (যাতে ভেরিফায়ার সম্পূর্ণ Merkle Root পুনর্গঠন করতে পারে)
    pub sibling_public_hashes: Vec<Hash256>,
}

impl PostQuantumKeyPair {
    /// ৩২-বাইট মাস্টার সিড থেকে ডিটারমিনিস্টিক পোস্ট-কোয়ান্টাম কি-পেয়ার ও Merkle Root পাবলিক কি তৈরি করে
    pub fn from_seed(seed: Hash256) -> Result<Self, String> {
        if seed.iter().all(|&b| b == 0) {
            return Err("পোস্ট-কোয়ান্টাম সিড শূন্য (All-Zero) হতে পারবে না".to_string());
        }

        let mut leaf_commitments = Vec::with_capacity(256);
        for bit_idx in 0..256u16 {
            let mut sk0 = Self::derive_secret_preimage(&seed, bit_idx, 0);
            let mut sk1 = Self::derive_secret_preimage(&seed, bit_idx, 1);

            let pk0 = sha256d_tagged(PQ_PUBLIC_LEAF_TAG, &sk0);
            let pk1 = sha256d_tagged(PQ_PUBLIC_LEAF_TAG, &sk1);

            sk0.zeroize();
            sk1.zeroize();

            leaf_commitments.push(Self::combine_bit_pair_hash(&pk0, &pk1, bit_idx));
        }

        let public_root = compute_merkle_root(&leaf_commitments);
        Ok(Self {
            master_seed: seed,
            public_root,
        })
    }

    #[inline]
    fn derive_secret_preimage(seed: &Hash256, bit_index: u16, branch: u8) -> Hash256 {
        let mut buf = [0u8; 35];
        buf[..32].copy_from_slice(seed);
        buf[32..34].copy_from_slice(&bit_index.to_le_bytes());
        buf[34] = branch;
        sha256d_tagged(PQ_SECRET_SCALAR_TAG, &buf)
    }

    #[inline]
    fn combine_bit_pair_hash(pk0: &Hash256, pk1: &Hash256, bit_index: u16) -> Hash256 {
        let mut buf = [0u8; 66];
        buf[..32].copy_from_slice(pk0);
        buf[32..64].copy_from_slice(pk1);
        buf[64..66].copy_from_slice(&bit_index.to_le_bytes());
        sha256d(&buf)
    }

    /// যেকোনো মেসেজকে কোয়ান্টাম-প্রতিরোধী `SHA-256d` ট্র্যাপডোর দিয়ে সাইন করে
    pub fn sign_quantum_safe(&self, message: &[u8]) -> PostQuantumSignature {
        let msg_digest = sha256d_tagged(PQ_MESSAGE_BIND_TAG, message);

        let mut revealed_preimages = Vec::with_capacity(256);
        let mut sibling_public_hashes = Vec::with_capacity(256);

        for bit_idx in 0..256u16 {
            let byte_pos = (bit_idx / 8) as usize;
            let bit_offset = (bit_idx % 8) as u8;
            let bit_val = (msg_digest[byte_pos] >> bit_offset) & 1;

            let mut sk0 = Self::derive_secret_preimage(&self.master_seed, bit_idx, 0);
            let mut sk1 = Self::derive_secret_preimage(&self.master_seed, bit_idx, 1);

            if bit_val == 0 {
                let pk1 = sha256d_tagged(PQ_PUBLIC_LEAF_TAG, &sk1);
                revealed_preimages.push(sk0);
                sibling_public_hashes.push(pk1);
            } else {
                let pk0 = sha256d_tagged(PQ_PUBLIC_LEAF_TAG, &sk0);
                revealed_preimages.push(sk1);
                sibling_public_hashes.push(pk0);
            }

            sk0.zeroize();
            sk1.zeroize();
        }

        PostQuantumSignature {
            revealed_preimages,
            sibling_public_hashes,
        }
    }

    /// কোয়ান্টাম-প্রতিরোধী সিগনেচার কনস্ট্যান্ট-টাইমে যাচাই করে (১০০% ইলিপটিক-কার্ভমুক্ত)
    pub fn verify_quantum_safe(
        expected_public_root: &Hash256,
        message: &[u8],
        signature: &PostQuantumSignature,
    ) -> bool {
        if signature.revealed_preimages.len() != 256
            || signature.sibling_public_hashes.len() != 256
        {
            return false;
        }

        let msg_digest = sha256d_tagged(PQ_MESSAGE_BIND_TAG, message);
        let mut reconstructed_leaves = Vec::with_capacity(256);

        for bit_idx in 0..256u16 {
            let idx = bit_idx as usize;
            let byte_pos = (bit_idx / 8) as usize;
            let bit_offset = (bit_idx % 8) as u8;
            let bit_val = (msg_digest[byte_pos] >> bit_offset) & 1;

            let hashed_revealed =
                sha256d_tagged(PQ_PUBLIC_LEAF_TAG, &signature.revealed_preimages[idx]);
            let sibling_pub = &signature.sibling_public_hashes[idx];

            let leaf = if bit_val == 0 {
                Self::combine_bit_pair_hash(&hashed_revealed, sibling_pub, bit_idx)
            } else {
                Self::combine_bit_pair_hash(sibling_pub, &hashed_revealed, bit_idx)
            };

            reconstructed_leaves.push(leaf);
        }

        let actual_root = compute_merkle_root(&reconstructed_leaves);
        constant_time_eq(&actual_root, expected_public_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_quantum_lamport_merkle_signature_roundtrip() {
        let seed = [0x77u8; 32];
        let pq_kp = PostQuantumKeyPair::from_seed(seed).unwrap();
        let message = b"Equinox L1 Immortal Genesis Vault Transfer 100000 EQX";

        let sig = pq_kp.sign_quantum_safe(message);
        assert!(PostQuantumKeyPair::verify_quantum_safe(
            &pq_kp.public_root,
            message,
            &sig
        ));

        // মেসেজের ১টি অক্ষর বদলালেও সিগনেচার সাথে সাথে ব্যর্থ হবে
        let tampered_msg = b"Equinox L1 Immortal Genesis Vault Transfer 900000 EQX";
        assert!(!PostQuantumKeyPair::verify_quantum_safe(
            &pq_kp.public_root,
            tampered_msg,
            &sig
        ));
    }
}
