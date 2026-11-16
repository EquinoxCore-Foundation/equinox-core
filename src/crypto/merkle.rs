#![allow(dead_code)]
// src/crypto/merkle.rs
// CVE-2012-2459 প্রতিরোধী ডোমেইন-সেপারেটেড Merkle Tree রুট ক্যালকুলেটর (মাল্টি-কোর সাপোর্টসহ) এবং SPV Merkle Proof ভেরিফায়ার।

use crate::crypto::hash::{constant_time_eq, sha256d, Hash256, ZERO_HASH};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// ইন্টারনাল মার্কেল পেয়ার ডোমেইন প্রিফিক্স (Second-Preimage আক্রমণ প্রতিরোধের জন্য)
const MERKLE_INTERNAL_NODE_TAG: u8 = 0x01;

/// লাইট ওয়ালেট বা ব্রিজ ভেরিফিকেশনের জন্য Merkle Proof নোড
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofNode {
    pub hash: Hash256,
    pub is_left_sibling: bool,
}

/// দুটি চাইল্ড হ্যাশ ডোমেইন-সেপারেটেডভাবে জোড়া লাগিয়ে প্যারেন্ট হ্যাশ তৈরি করে
#[inline]
fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut combined = [0u8; 65];
    combined[0] = MERKLE_INTERNAL_NODE_TAG;
    combined[1..33].copy_from_slice(left);
    combined[33..65].copy_from_slice(right);
    sha256d(&combined)
}

/// ব্লকের ভেতরে ডুপ্লিকেট ট্রানজ্যাকশন হ্যাশ আছে কি না তা পরীক্ষা করে (CVE-2012-2459 সুরক্ষা)
pub fn has_duplicate_transactions(tx_hashes: &[Hash256]) -> bool {
    let mut seen = HashSet::with_capacity(tx_hashes.len());
    for h in tx_hashes {
        if !seen.insert(*h) {
            return true;
        }
    }
    false
}

/// ব্লকের সব ট্রানজ্যাকশন হ্যাশ থেকে Merkle Root হিসাব করে।
/// ডুপ্লিকেট ট্রানজ্যাকশন থাকলে `ZERO_HASH` রিটার্ন করে যাতে অবৈধ ব্লক কনসেনসাসে সাথে সাথে বাতিল হয়।
pub fn compute_merkle_root(tx_hashes: &[Hash256]) -> Hash256 {
    if tx_hashes.is_empty() || has_duplicate_transactions(tx_hashes) {
        return ZERO_HASH;
    }
    if tx_hashes.len() == 1 {
        return tx_hashes[0];
    }

    let mut current_level: Vec<Hash256> = tx_hashes.to_vec();

    while current_level.len() > 1 {
        if current_level.len() % 2 != 0 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        current_level = if current_level.len() >= 64 {
            current_level
                .par_chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect()
        } else {
            current_level
                .chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect()
        };
    }

    current_level[0]
}

/// নির্দিষ্ট কোনো ট্রানজ্যাকশন ব্লকে আছে কি না তা প্রমাণ করার জন্য Merkle Proof তৈরি করে
pub fn generate_merkle_proof(
    tx_hashes: &[Hash256],
    target_index: usize,
) -> Option<Vec<MerkleProofNode>> {
    if tx_hashes.is_empty()
        || target_index >= tx_hashes.len()
        || has_duplicate_transactions(tx_hashes)
    {
        return None;
    }

    let mut proof = Vec::new();
    let mut current_level = tx_hashes.to_vec();
    let mut idx = target_index;

    while current_level.len() > 1 {
        if current_level.len() % 2 != 0 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let is_left_sibling = idx % 2 == 1;

        proof.push(MerkleProofNode {
            hash: current_level[sibling_idx],
            is_left_sibling,
        });

        current_level = current_level
            .chunks(2)
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();

        idx /= 2;
    }

    Some(proof)
}

/// Merkle Proof যাচাই করে দেখে ট্রানজ্যাকশনটি আসলেই ওই Merkle Root-এর অংশ কি না
pub fn verify_merkle_proof(
    tx_hash: &Hash256,
    proof: &[MerkleProofNode],
    expected_root: &Hash256,
) -> bool {
    if constant_time_eq(expected_root, &ZERO_HASH) {
        return false;
    }

    let mut current_hash = *tx_hash;

    for node in proof {
        current_hash = if node.is_left_sibling {
            hash_pair(&node.hash, &current_hash)
        } else {
            hash_pair(&current_hash, &node.hash)
        };
    }

    constant_time_eq(&current_hash, expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_proof_and_cve_2012_2459_defense() {
        let txs: Vec<Hash256> = (0..5)
            .map(|i| sha256d(format!("tx_{}", i).as_bytes()))
            .collect();

        let root = compute_merkle_root(&txs);
        assert_ne!(root, ZERO_HASH);

        let proof = generate_merkle_proof(&txs, 2).expect("Proof should be generated");
        assert!(verify_merkle_proof(&txs[2], &proof, &root));

        let fake_tx = sha256d(b"fake_tx");
        assert!(!verify_merkle_proof(&fake_tx, &proof, &root));

        // CVE-2012-2459 Attack Test: Duplicating the last odd leaf must be rejected!
        let mut mutated_txs = txs.clone();
        mutated_txs.push(*txs.last().unwrap());
        assert_eq!(compute_merkle_root(&mutated_txs), ZERO_HASH);
    }
}
