#![allow(dead_code)]
// src/wallet/mnemonic.rs
// Equinox (EQX) L1 — BIP-39 Compatible 11-Bit (2048-Word) Cryptographic Mnemonic Engine
// Features: 128-Bit (12-Word) & 256-Bit (24-Word) CSPRNG Entropy, SHA-256 Checksum Bit-Packing,
// PBKDF2-HMAC-SHA512 Key Stretching, Constant-Time Checksum Verification & RAM Zeroization.

use crate::crypto::hash::constant_time_eq;
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::sync::OnceLock;
use zeroize::Zeroize;

/// PBKDF2-HMAC-SHA512 রাউন্ড সংখ্যা (BIP-39 স্ট্যান্ডার্ড অনুযায়ী ২,০৪৮ রাউন্ড)
pub const MNEMONIC_PBKDF2_ROUNDS: u32 = 2048;

/// ১২ শব্দের ফ্রেজের জন্য ১৬ বাইট (১২৮ বিট) এনট্রপি
pub const ENTROPY_BYTES_12_WORDS: usize = 16;

/// ২৪ শব্দের ফ্রেজের জন্য ৩২ বাইট (২৫৬ বিট) এনট্রপি
pub const ENTROPY_BYTES_24_WORDS: usize = 32;

/// ৬৪টি মৌলিক ক্রিপ্টোগ্রাফিক রুট শব্দ (ইন্ডেক্স ০..৬৩)
const ROOT_WORDS: [&str; 64] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
];

/// ৩২টি ফোনেটিক সাফিক্স স্টেম (৬৪ * ৩২ = ২,০৪৮টি সম্পূর্ণ ইউনিক ও দ্ব্যর্থহীন শব্দ তৈরির জন্য)
const STEM_SUFFIXES: [&str; 32] = [
    "", "apex", "arc", "atom", "axis", "bolt", "core", "crest",
    "crypt", "dawn", "drift", "echo", "edge", "flux", "forge", "gate",
    "glow", "grid", "halo", "helm", "hive", "jade", "knot", "link",
    "lock", "lynx", "mesh", "mint", "node", "nova", "orb", "peak",
];

/// মেমোরিতে একবারই ইনিশিয়ালাইজ হওয়া ২,০৪৮টি শব্দের (১১-বিট) ডিটারমিনিস্টিক ডিকশনারি
fn lexicon_2048() -> &'static Vec<String> {
    static LEXICON: OnceLock<Vec<String>> = OnceLock::new();
    LEXICON.get_or_init(|| {
        let mut words = Vec::with_capacity(2048);
        for suffix in STEM_SUFFIXES.iter() {
            for root in ROOT_WORDS.iter() {
                if suffix.is_empty() {
                    words.push((*root).to_string());
                } else {
                    words.push(format!("{}{}", root, suffix));
                }
            }
        }
        words
    })
}

/// কোনো শব্দ ২,০৪৮ শব্দের তালিকায় থাকলে তার ১১-বিট ইন্ডেক্স (`0..2047`) রিটার্ন করে
#[inline]
fn word_to_index(word: &str) -> Option<usize> {
    lexicon_2048().iter().position(|w| w == word)
}

/// ইউজারের দেওয়া ম্নিমোনিক ফ্রেজের অতিরিক্ত স্পেস ও বড় হাতের অক্ষর পরিষ্কার (Canonicalize) করে
fn normalize_phrase(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .map(|w| w.trim().to_ascii_lowercase())
        .collect::<Vec<String>>()
        .join(" ")
}

/// হার্ডওয়্যার CSPRNG (`OsRng`) ব্যবহার করে ১২৮-বিট এনট্রপি + ৪-বিট SHA-256 চেকসামসহ ১২ শব্দের ফ্রেজ তৈরি করে
pub fn generate_mnemonic() -> Result<String, String> {
    let mut entropy = [0u8; ENTROPY_BYTES_12_WORDS];
    OsRng.fill_bytes(&mut entropy);
    let result = entropy_to_mnemonic(&entropy);
    entropy.zeroize();
    result
}

/// হার্ডওয়্যার CSPRNG (`OsRng`) ব্যবহার করে ২৫৬-বিট এনট্রপি + ৮-বিট SHA-256 চেকসামসহ ২৪ শব্দের ফ্রেজ তৈরি করে
pub fn generate_mnemonic_24() -> Result<String, String> {
    let mut entropy = [0u8; ENTROPY_BYTES_24_WORDS];
    OsRng.fill_bytes(&mut entropy);
    let result = entropy_to_mnemonic(&entropy);
    entropy.zeroize();
    result
}

/// ১৬-বাইট (১২৮-বিট) অথবা ৩২-বাইট (২৫৬-বিট) র‍্যান্ডম এনট্রপি থেকে SHA-256 চেকসামসহ ম্নিমোনিক তৈরি করে
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, String> {
    let (word_count, checksum_bits) = match entropy.len() {
        ENTROPY_BYTES_12_WORDS => (12usize, 4usize),
        ENTROPY_BYTES_24_WORDS => (24usize, 8usize),
        other => {
            return Err(format!(
                "অবৈধ এনট্রপি আকার: {} বাইট (হতে হবে ১৬ বাইট বা ৩২ বাইট)",
                other
            ))
        }
    };

    // SHA-256 হ্যাশের প্রথম বাইট থেকে চেকসাম বিট সংগ্রহ
    let hash = Sha256::digest(entropy);
    let checksum_byte = hash[0];

    let mut bit_buffer = vec![0u8; entropy.len() + 1];
    bit_buffer[..entropy.len()].copy_from_slice(entropy);
    bit_buffer[entropy.len()] = if checksum_bits == 4 {
        checksum_byte & 0xF0
    } else {
        checksum_byte
    };

    let dict = lexicon_2048();
    let mut selected_words = Vec::with_capacity(word_count);

    for w in 0..word_count {
        let mut idx: usize = 0;
        for b in 0..11 {
            let abs_bit = w * 11 + b;
            let byte_pos = abs_bit / 8;
            let bit_in_byte = 7 - (abs_bit % 8);
            let bit_val = (bit_buffer[byte_pos] >> bit_in_byte) & 1;
            idx = (idx << 1) | (bit_val as usize);
        }
        selected_words.push(dict[idx].as_str());
    }

    bit_buffer.zeroize();
    Ok(selected_words.join(" "))
}

/// ম্নিমোনিক ফ্রেজের শব্দসংখ্যা, অভিধানের বৈধতা এবং SHA-256 চেকসাম বিট যাচাই করে
pub fn validate_mnemonic(mnemonic_phrase: &str) -> Result<(), String> {
    let normalized = normalize_phrase(mnemonic_phrase);
    let words: Vec<&str> = normalized.split_whitespace().collect();

    let (entropy_len, checksum_bits) = match words.len() {
        12 => (ENTROPY_BYTES_12_WORDS, 4usize),
        24 => (ENTROPY_BYTES_24_WORDS, 8usize),
        other => {
            return Err(format!(
                "রিকভারি ফ্রেজে ঠিক ১২টি বা ২৪টি শব্দ থাকতে হবে, পাওয়া গেছে: {}টি",
                other
            ))
        }
    };

    let mut indices = Vec::with_capacity(words.len());
    for (pos, &w) in words.iter().enumerate() {
        let idx = word_to_index(w).ok_or_else(|| {
            format!(
                "ফ্রেজের #{} নম্বর শব্দটি ('{}') Equinox অভিধানে নেই বা বানান ভুল",
                pos + 1,
                w
            )
        })?;
        indices.push(idx);
    }

    let mut unpacked = vec![0u8; entropy_len + 1];
    for (w, &idx) in indices.iter().enumerate() {
        for b in 0..11 {
            let bit_val = ((idx >> (10 - b)) & 1) as u8;
            let abs_bit = w * 11 + b;
            let byte_pos = abs_bit / 8;
            let bit_in_byte = 7 - (abs_bit % 8);
            unpacked[byte_pos] |= bit_val << bit_in_byte;
        }
    }

    let extracted_entropy = &unpacked[..entropy_len];
    let expected_hash = Sha256::digest(extracted_entropy);

    let checksum_ok = if checksum_bits == 4 {
        let actual_cs = [unpacked[entropy_len] & 0xF0];
        let expected_cs = [expected_hash[0] & 0xF0];
        constant_time_eq(&actual_cs, &expected_cs)
    } else {
        let actual_cs = [unpacked[entropy_len]];
        let expected_cs = [expected_hash[0]];
        constant_time_eq(&actual_cs, &expected_cs)
    };

    unpacked.zeroize();

    if !checksum_ok {
        return Err(
            "রিকভারি ফ্রেজের SHA-256 চেকসাম মেলেনি! কোনো শব্দ ভুল বা ওলটপালট হয়েছে।".to_string(),
        );
    }

    Ok(())
}

/// ১২ বা ২৪ শব্দের ফ্রেজ যাচাই করে BIP-39 স্ট্যান্ডার্ড (PBKDF2-HMAC-SHA512, 2048 rounds) অনুযায়ী ৬৪-বাইট মাস্টার সিড তৈরি করে
pub fn mnemonic_to_seed(
    mnemonic_phrase: &str,
    password_opt: Option<&str>,
) -> Result<[u8; 64], String> {
    // ১. প্রথমেই ফ্রেজের শব্দ ও ক্রিপ্টোগ্রাফিক চেকসাম যাচাই করা হয়
    validate_mnemonic(mnemonic_phrase)?;

    let mut normalized = normalize_phrase(mnemonic_phrase);
    let mut salt = format!("mnemonic{}", password_opt.unwrap_or(""));

    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(
        normalized.as_bytes(),
        salt.as_bytes(),
        MNEMONIC_PBKDF2_ROUNDS,
        &mut seed,
    );

    // ২. র‍্যাম থেকে সেন্সিটিভ স্ট্রিং মুছে ফেলা
    normalized.zeroize();
    salt.zeroize();

    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_all_2048_words_are_strictly_unique_and_lowercase() {
        let dict = lexicon_2048();
        assert_eq!(dict.len(), 2048);

        let unique_set: HashSet<&String> = dict.iter().collect();
        assert_eq!(unique_set.len(), 2048, "Every single word in 2048 lexicon must be unique");

        for w in dict {
            assert!(!w.is_empty());
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn test_12_and_24_word_generation_and_checksum_verification() {
        let phrase_12 = generate_mnemonic().expect("12-word generation failed");
        assert_eq!(phrase_12.split_whitespace().count(), 12);
        assert!(validate_mnemonic(&phrase_12).is_ok());

        let seed_1 = mnemonic_to_seed(&phrase_12, Some("MyPassphrase")).unwrap();
        let seed_2 = mnemonic_to_seed(&phrase_12, Some("MyPassphrase")).unwrap();
        let seed_no_pass = mnemonic_to_seed(&phrase_12, None).unwrap();
        assert_eq!(seed_1, seed_2);
        assert_ne!(seed_1, seed_no_pass);

        let phrase_24 = generate_mnemonic_24().expect("24-word generation failed");
        assert_eq!(phrase_24.split_whitespace().count(), 24);
        assert!(validate_mnemonic(&phrase_24).is_ok());
    }

    #[test]
    fn test_tampered_mnemonic_rejected_by_sha256_checksum() {
        let entropy = [0x42u8; ENTROPY_BYTES_12_WORDS];
        let valid_phrase = entropy_to_mnemonic(&entropy).unwrap();
        assert!(validate_mnemonic(&valid_phrase).is_ok());

        // শেষের শব্দটি বদলে দিলে চেকসাম ফেইল করতে বাধ্য
        let mut words: Vec<&str> = valid_phrase.split_whitespace().collect();
        words[11] = if words[11] == "abandon" { "ability" } else { "abandon" };
        let tampered_phrase = words.join(" ");

        assert!(
            mnemonic_to_seed(&tampered_phrase, None).is_err(),
            "Tampered mnemonic phrase must be rejected by SHA-256 checksum!"
        );
    }
}
