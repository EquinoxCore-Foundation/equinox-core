#![forbid(unsafe_code)]

pub mod address;
pub mod keystore;
pub mod signer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidPublicKey,
    InvalidSignature,
    InvalidAddressEncoding,
    InvalidAddressVersionOrLength,
    InvalidAddressChecksum,
    WeakPassword,
    KdfFailure,
    EncryptionFailed,
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{decode_and_verify_address, encode_from_hash160, encode_mainnet_address};
    use crate::keystore::{EncryptedKeystore, KdfConfig};
    use crate::signer::{verify_canonical, SecretSeed, DOMAIN_BFT_VOTE_MAINNET, DOMAIN_TX_MAINNET};

    #[test]
    fn test_canonical_ed25519_sign_and_domain_isolation() {
        let seed = SecretSeed::generate();
        let pubkey = seed.public_key_bytes();
        let tx = b"send:100_EQX:chain_9333";

        let sig = seed.sign_domain(DOMAIN_TX_MAINNET, tx);
        assert!(verify_canonical(&pubkey, DOMAIN_TX_MAINNET, tx, &sig).is_ok());

        // Cross-domain replay must fail
        assert_eq!(
            verify_canonical(&pubkey, DOMAIN_BFT_VOTE_MAINNET, tx, &sig),
            Err(CryptoError::InvalidSignature)
        );

        // Single bit flip in signature must fail
        let mut tampered = sig;
        tampered[0] ^= 0x01;
        assert_eq!(
            verify_canonical(&pubkey, DOMAIN_TX_MAINNET, tx, &tampered),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn test_address_prefix_e_bounds_and_checksum() {
        // Test mathematical extremes: all-zeros and all-0xFF hash160
        let min_addr = encode_from_hash160(&[0x00u8; 20]);
        let max_addr = encode_from_hash160(&[0xFFu8; 20]);
        assert!(min_addr.starts_with('E') && min_addr.len() == 34);
        assert!(max_addr.starts_with('E') && max_addr.len() == 34);

        // Random generated keypair roundtrip
        let seed = SecretSeed::generate();
        let pubkey = seed.public_key_bytes();
        let addr = encode_mainnet_address(&pubkey);
        assert!(addr.starts_with('E') && addr.len() == 34);
        let decoded = decode_and_verify_address(&addr).unwrap();
        assert_eq!(decoded, address::hash160(&pubkey));

        // Corrupt last char -> checksum mismatch
        let mut bad = addr.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            decode_and_verify_address(&bad),
            Err(CryptoError::InvalidAddressChecksum)
        );
    }

    #[test]
    fn test_keystore_argon2id_aes_gcm_and_aad_tamper_resistance() {
        let seed = SecretSeed::generate();
        let pass = b"Equinox#SovereignVault2026!";

        // Weak password rejected
        assert_eq!(
            EncryptedKeystore::encrypt(seed.as_bytes(), b"short123", 9333, KdfConfig::fast_test()),
            Err(CryptoError::WeakPassword)
        );

        // Valid encrypt/decrypt roundtrip
        let mut ks =
            EncryptedKeystore::encrypt(seed.as_bytes(), pass, 9333, KdfConfig::fast_test())
                .unwrap();
        let recovered = ks.decrypt(pass).unwrap();
        assert_eq!(&recovered[..], seed.as_bytes());

        // Wrong password rejected
        assert_eq!(
            ks.decrypt(b"WrongPassword12345"),
            Err(CryptoError::DecryptionFailed)
        );

        // Tampering with Chain ID metadata must break AAD authentication
        ks.chain_id = 1;
        assert_eq!(ks.decrypt(pass), Err(CryptoError::DecryptionFailed));
    }
}
