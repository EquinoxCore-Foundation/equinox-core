#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

pub const DOMAIN_TX_MAINNET: &[u8] = b"EQX_MAINNET_9333_TX_V1";
pub const DOMAIN_BFT_VOTE_MAINNET: &[u8] = b"EQX_MAINNET_9333_BFT_V1";

/// Double-SHA256 with explicit domain tag and length prefix to block cross-chain replay attacks.
pub fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h1 = Sha256::new();
    h1.update(domain);
    h1.update(&(payload.len() as u64).to_le_bytes());
    h1.update(payload);
    let first = h1.finalize();

    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().into()
}

/// 32-byte Ed25519 secret seed automatically wiped from RAM on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretSeed([u8; 32]);

impl SecretSeed {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        let sk = SigningKey::from_bytes(&self.0);
        sk.verifying_key().to_bytes()
    }

    pub fn sign_domain(&self, domain: &[u8], payload: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.0);
        let digest = domain_hash(domain, payload);
        sk.sign(&digest).to_bytes()
    }
}

/// Strict canonical Ed25519 verification rejecting malleable signatures and small-order points.
pub fn verify_canonical(
    public_key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature_bytes);
    let digest = domain_hash(domain, payload);
    vk.verify_strict(&digest, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}
