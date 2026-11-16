#![allow(dead_code)]
// src/crypto/keys.rs
// Equinox (EQX) L1 — Strict Canonical Ed25519 KeyPair, Signature Verifier & Parallel Batch Engine

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rayon::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type PublicKeyBytes = [u8; 32];
pub type SecretKeyBytes = [u8; 32];
pub type SignatureBytes = [u8; 64];

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    secret: SecretKeyBytes,
    #[zeroize(skip)]
    public: PublicKeyBytes,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let secret = signing_key.to_bytes();
        let public = signing_key.verifying_key().to_bytes();
        Self { secret, public }
    }

    pub fn from_secret_bytes(secret: SecretKeyBytes) -> Self {
        let signing_key = SigningKey::from_bytes(&secret);
        let public = signing_key.verifying_key().to_bytes();
        Self { secret, public }
    }

    #[inline]
    pub fn public_key(&self) -> PublicKeyBytes {
        self.public
    }

    #[inline]
    pub fn secret_bytes(&self) -> SecretKeyBytes {
        self.secret
    }

    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        let signing_key = SigningKey::from_bytes(&self.secret);
        let sig: Signature = signing_key.sign(message);
        sig.to_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct SignatureVerificationTask {
    pub public_key: PublicKeyBytes,
    pub message: Vec<u8>,
    pub signature: SignatureBytes,
}

pub fn verify_signature(
    public_key: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> bool {
    if public_key.iter().all(|&b| b == 0) {
        return false;
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    if verifying_key.is_weak() {
        return false;
    }
    let sig = Signature::from_bytes(signature);
    verifying_key.verify_strict(message, &sig).is_ok()
}

pub fn verify_batch_parallel(tasks: &[SignatureVerificationTask]) -> bool {
    if tasks.is_empty() {
        return true;
    }
    tasks
        .par_iter()
        .all(|t| verify_signature(&t.public_key, &t.message, &t.signature))
}
