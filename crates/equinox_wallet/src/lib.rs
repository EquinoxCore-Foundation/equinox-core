#![forbid(unsafe_code)]

pub mod hardware;
pub mod mnemonic;
pub mod slip10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletError {
    InvalidMnemonicLength,
    InvalidMnemonicFormat,
    InvalidSeedLength,
    NonHardenedPathUnsupported,
    InvalidPathComponent,
    DerivationError,
    ApduPayloadTooLarge,
    MalformedApdu,
    EmptyTransactionPayload,
    HardwareUserRejected,
    HardwareWrongApp,
    HardwareUnsupportedInstruction,
    HardwareDeviceError(u16),
}

#[cfg(test)]
mod tests {
    use super::WalletError;
    use crate::hardware::{
        build_get_public_key_apdu, build_sign_tx_apdus, parse_apdu_response, ApduCommand,
        P1_FIRST_CHUNK, P1_LAST_CHUNK, P1_MORE_CHUNK,
    };
    use crate::mnemonic::mnemonic_to_seed;
    use crate::slip10::{equinox_hd_path, Slip10Key};
    use equinox_crypto::address::decode_and_verify_address;
    use equinox_crypto::signer::{verify_canonical, DOMAIN_TX_MAINNET};

    #[test]
    fn test_bip39_seed_and_slip10_mainnet_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed_plain = mnemonic_to_seed(phrase, "").unwrap();
        let seed_pass = mnemonic_to_seed(phrase, "EquinoxVault2026").unwrap();
        assert_ne!(&seed_plain[..], &seed_pass[..]);

        let path0 = equinox_hd_path(0, 0, 0).unwrap();
        let path1 = equinox_hd_path(0, 0, 1).unwrap();

        let key0 = Slip10Key::derive_path(&*seed_plain, &path0).unwrap();
        let key1 = Slip10Key::derive_path(&*seed_plain, &path1).unwrap();

        let addr0 = key0.mainnet_address();
        let addr1 = key1.mainnet_address();
        assert!(addr0.starts_with('E') && addr0.len() == 34);
        assert!(addr1.starts_with('E') && addr1.len() == 34);
        assert_ne!(addr0, addr1);
        assert!(decode_and_verify_address(&addr0).is_ok());

        let tx = b"utxo_transfer:50_EQX";
        let sig = key0.to_secret_seed().sign_domain(DOMAIN_TX_MAINNET, tx);
        assert!(verify_canonical(&key0.public_key_bytes(), DOMAIN_TX_MAINNET, tx, &sig).is_ok());
    }

    #[test]
    fn test_slip10_rejects_non_hardened_ed25519_path() {
        let seed = [0x42u8; 32];
        let master = Slip10Key::derive_master(&seed).unwrap();
        assert_eq!(
            master.derive_child_hardened(0).err(),
            Some(WalletError::NonHardenedPathUnsupported)
        );
    }

    #[test]
    fn test_hardware_wallet_apdu_chunking_and_status_words() {
        let path = equinox_hd_path(0, 0, 0).unwrap();

        let pub_apdu = build_get_public_key_apdu(&path, true).unwrap();
        let wire = pub_apdu.encode().unwrap();
        assert_eq!(ApduCommand::decode(&wire).unwrap(), pub_apdu);

        let large_tx = vec![0xABu8; 600];
        let packets = build_sign_tx_apdus(&path, &large_tx).unwrap();
        assert_eq!(packets.len(), 4);
        assert_eq!(packets[0].p1, P1_FIRST_CHUNK);
        assert_eq!(packets[1].p1, P1_MORE_CHUNK);
        assert_eq!(packets[2].p1, P1_MORE_CHUNK);
        assert_eq!(packets[3].p1, P1_LAST_CHUNK);

        let reassembled: Vec<u8> = packets[1..].iter().flat_map(|c| c.data.clone()).collect();
        assert_eq!(reassembled, large_tx);

        assert_eq!(parse_apdu_response(&[0x01, 0x02, 0x90, 0x00]).unwrap(), vec![0x01, 0x02]);
        assert_eq!(parse_apdu_response(&[0x69, 0x85]), Err(WalletError::HardwareUserRejected));
        assert_eq!(parse_apdu_response(&[0x6E, 0x00]), Err(WalletError::HardwareWrongApp));
    }
}
