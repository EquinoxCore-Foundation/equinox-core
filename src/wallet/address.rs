#![allow(dead_code)]
// src/wallet/address.rs
// Equinox (EQX) L1 — Audit-Grade Base58Check Address Generator, Strict 25-Byte Payload Validator,
// Deterministic Genesis Vault Address Generator & Public-Key Ownership Verifier.

use crate::config::ADDRESS_VERSION_BYTE;
use crate::crypto::hash::{constant_time_eq, hash160, sha256d, sha256d_tagged, Hash160};
use crate::crypto::keys::{KeyPair, PublicKeyBytes};

/// পাবলিক কি থেকে Base58Check এনকোডেড Equinox ওয়ালেট অ্যাড্রেস তৈরি করে (সর্বদা 'E' দিয়ে শুরু হবে)
pub fn pubkey_to_address(pubkey: &PublicKeyBytes) -> String {
    let pub_hash: Hash160 = hash160(pubkey);
    hash160_to_address(&pub_hash)
}

/// ২০-বাইট Hash160 পেলোড থেকে Base58Check অ্যাড্রেস তৈরি করে
pub fn hash160_to_address(pub_hash: &Hash160) -> String {
    let mut payload = [0u8; 21];
    payload[0] = ADDRESS_VERSION_BYTE;
    payload[1..21].copy_from_slice(pub_hash);

    let checksum = sha256d(&payload);
    let mut full_bytes = [0u8; 25];
    full_bytes[0..21].copy_from_slice(&payload);
    full_bytes[21..25].copy_from_slice(&checksum[..4]);

    bs58::encode(full_bytes).into_string()
}

/// কোনো হার্ডকোডেড স্ট্রিং ছাড়াই প্রটোকলের জেনেসিস ভল্টের জন্য ১০০% বৈধ ক্রিপ্টোগ্রাফিক অ্যাড্রেস তৈরি করে
pub fn derive_deterministic_genesis_address(vault_role_tag: &str) -> String {
    let seed = sha256d_tagged(b"EQX_OFFICIAL_GENESIS_VAULT_KEY_V1", vault_role_tag.as_bytes());
    let kp = KeyPair::from_secret_bytes(seed);
    pubkey_to_address(&kp.public_key())
}

/// ওয়ালেট অ্যাড্রেস ফরম্যাট, ভার্সন বাইট (0x21) ও ৪-বাইট চেকসাম কঠোরভাবে যাচাই করে
pub fn is_valid_address(address: &str) -> bool {
    let trimmed = address.trim();
    if trimmed.is_empty() || trimmed.len() < 26 || trimmed.len() > 35 {
        return false;
    }

    let Ok(decoded) = bs58::decode(trimmed).into_vec() else {
        return false;
    };

    if decoded.len() != 25 || decoded[0] != ADDRESS_VERSION_BYTE {
        return false;
    }

    let payload = &decoded[0..21];
    let expected_checksum = &decoded[21..25];
    let actual_checksum = sha256d(payload);

    constant_time_eq(&actual_checksum[..4], expected_checksum)
}

/// কঠোর স্ট্রিং অ্যাড্রেস ভ্যালিডেশন
pub fn validate_address_strict(address: &str) -> Result<(), String> {
    if !is_valid_address(address) {
        return Err(format!("অবৈধ Equinox ওয়ালেট অ্যাড্রেস: {}", address));
    }
    Ok(())
}

/// ক্রিপ্টোগ্রাফিক মালিকানা যাচাই: প্রদত্ত পাবলিক কি আসলেই এই ওয়ালেট অ্যাড্রেসের মালিক কি না তা পরীক্ষা করে
pub fn verify_address_ownership(address: &str, pubkey: &PublicKeyBytes) -> Result<bool, String> {
    if !is_valid_address(address) {
        return Err(format!("অবৈধ অ্যাড্রেস: {}", address));
    }
    let expected_addr = pubkey_to_address(pubkey);
    Ok(constant_time_eq(expected_addr.as_bytes(), address.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_generation_and_strict_validation() {
        let kp = KeyPair::generate();
        let addr = pubkey_to_address(&kp.public_key());

        assert!(addr.starts_with('E'));
        assert!(is_valid_address(&addr));
        assert!(validate_address_strict(&addr).is_ok());
        assert!(verify_address_ownership(&addr, &kp.public_key()).unwrap());
        assert!(!is_valid_address("EQXInvalidAddressStringWithBadChecksum"));
    }

    #[test]
    fn test_genesis_addresses_and_tamper_rejection() {
        let genesis_owner = derive_deterministic_genesis_address("OWNER_TIMELOCK_VAULT");
        let genesis_liquidity = derive_deterministic_genesis_address("EXCHANGE_LIQUIDITY_VAULT");

        assert!(genesis_owner.starts_with('E'));
        assert!(is_valid_address(&genesis_owner));
        assert!(is_valid_address(&genesis_liquidity));
        assert_ne!(genesis_owner, genesis_liquidity);

        // ১টি অক্ষর পরিবর্তন করলেই চেকসাম গার্ড তা ধরে ফেলবে
        let mut tampered = genesis_owner.clone();
        tampered.pop();
        tampered.push(if genesis_owner.ends_with('1') { '2' } else { '1' });
        assert!(!is_valid_address(&tampered));
    }
}
