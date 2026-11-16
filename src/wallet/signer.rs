#![allow(dead_code)]
// src/wallet/signer.rs
// Equinox (EQX) L1 — Audit-Grade Offline Transaction Signing Engine
// Features: Unconditional RAM Zeroization on All Exit Paths, Weak-Key Rejection,
// Duplicate/Out-of-Bounds Index Guard & Post-Signature Cryptographic Verification.

use crate::crypto::keys::{verify_signature, KeyPair};
use crate::primitives::transaction::Transaction;
use std::collections::HashSet;
use zeroize::Zeroize;

pub struct OfflineSigner;

impl OfflineSigner {
    /// নির্দিষ্ট ইনপুটগুলোর জন্য ওয়ালেটের প্রাইভেট কি ব্যবহার করে ট্রানজ্যাকশন সাইন করে।
    /// সাইনিং সফল হোক বা মাঝপথে এরর হোক—উভয় ক্ষেত্রেই র‍্যাম থেকে প্রাইভেট কি তাৎক্ষণিক মুছে ফেলা হয়।
    pub fn sign_transaction(
        tx: &mut Transaction,
        input_indices: &[usize],
        secret_key_bytes: &[u8; 32],
    ) -> Result<(), String> {
        // ১. প্রাথমিক ইনপুট ও সিক্রেট কি যাচাই
        if input_indices.is_empty() {
            return Err("সাইন করার জন্য কোনো ইনপুট ইনডেক্স প্রদান করা হয়নি".to_string());
        }
        if tx.inputs.is_empty() {
            return Err("কয়েনবেস বা ইনপুটবিহীন ট্রানজ্যাকশন সাইন করা যাবে না".to_string());
        }
        if secret_key_bytes.iter().all(|&b| b == 0) {
            return Err("অবৈধ অল-জিরো (All-Zero) প্রাইভেট কি দিয়ে সাইন করা নিষিদ্ধ".to_string());
        }

        // ২. ইনপুট ইনডেক্স বাউন্ডারি এবং ডুপ্লিকেট ইনডেক্স পরীক্ষা
        let mut seen_indices = HashSet::with_capacity(input_indices.len());
        for &idx in input_indices {
            if idx >= tx.inputs.len() {
                return Err(format!(
                    "ইনপুট ইনডেক্স #{} সীমার বাইরে (মোট ইনপুট: {})",
                    idx,
                    tx.inputs.len()
                ));
            }
            if !seen_indices.insert(idx) {
                return Err(format!(
                    "ডুপ্লিকেট ইনপুট ইনডেক্স #{} প্রদান করা হয়েছে",
                    idx
                ));
            }
        }

        // ৩. লোকাল স্ট্যাক কপি ও কি-পেয়ার তৈরি
        let mut local_secret = *secret_key_bytes;
        let mut keypair = KeyPair::from_secret_bytes(local_secret);
        local_secret.zeroize();

        // ৪. ক্লোজারের ভেতরে সাইনিং ও পোস্ট-ভেরিফিকেশন চালানো যাতে মাঝপথে এরর হলেও নিচে zeroize() বাদ না পড়ে
        let signing_result = (|| -> Result<(), String> {
            let expected_pubkey = keypair.public_key();
            if expected_pubkey.iter().all(|&b| b == 0) {
                return Err("উৎপন্ন পাবলিক কি অবৈধ (Degenerate Key)".to_string());
            }

            for &idx in input_indices {
                tx.sign_input(idx, &keypair)?;
            }

            // ৫. ফল্ট-ইনজেকশন সুরক্ষা: উৎপন্ন প্রতিটি সিগনেচার আসলেই বৈধ হয়েছে কি না তা তাৎক্ষণিক মিলিয়ে দেখা
            let signing_message = tx.signing_message();
            for &idx in input_indices {
                let inp = &tx.inputs[idx];
                if inp.public_key != expected_pubkey
                    || !verify_signature(&inp.public_key, &signing_message, &inp.signature)
                {
                    return Err(format!(
                        "ইনপুট #{}-এর পোস্ট-সাইনিং ক্রিপ্টোগ্রাফিক ভেরিফিকেশন ব্যর্থ হয়েছে!",
                        idx
                    ));
                }
            }

            Ok(())
        })();

        // ৬. ফলাফল যা-ই হোক না কেন, র‍্যাম থেকে প্রাইভেট কি-পেয়ার সম্পূর্ণ মুছে ফেলা বাধ্যতামূলক
        keypair.zeroize();

        signing_result
    }

    /// ট্রানজ্যাকশনের সব ইনপুট একই প্রাইভেট কি দিয়ে এক কমান্ডে সাইন করার হেল্পার মেথড
    pub fn sign_all_inputs(
        tx: &mut Transaction,
        secret_key_bytes: &[u8; 32],
    ) -> Result<(), String> {
        let all_indices: Vec<usize> = (0..tx.inputs.len()).collect();
        Self::sign_transaction(tx, &all_indices, secret_key_bytes)
    }
}
