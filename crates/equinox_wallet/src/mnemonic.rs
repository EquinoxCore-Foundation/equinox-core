#![forbid(unsafe_code)]

use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::WalletError;

pub const BIP39_PBKDF2_ROUNDS: u32 = 2_048;

/// Validates word count (12/15/18/21/24) and ASCII-lowercase characters of a mnemonic phrase.
pub fn validate_mnemonic_format(phrase: &str) -> Result<Vec<&str>, WalletError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(WalletError::InvalidMnemonicLength);
    }
    for w in &words {
        if w.is_empty() || !w.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(WalletError::InvalidMnemonicFormat);
        }
    }
    Ok(words)
}

/// Standard BIP-39 PBKDF2-HMAC-SHA512 seed derivation (64-byte zeroizing seed).
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, WalletError> {
    let words = validate_mnemonic_format(phrase)?;
    let normalized = Zeroizing::new(words.join(" "));
    let salt = Zeroizing::new(format!("mnemonic{}", passphrase));

    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2_hmac::<Sha512>(
        normalized.as_bytes(),
        salt.as_bytes(),
        BIP39_PBKDF2_ROUNDS,
        &mut *seed,
    );
    Ok(seed)
}
