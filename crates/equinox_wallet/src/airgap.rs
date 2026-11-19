#![forbid(unsafe_code)]

use equinox_crypto::address::hash160;
use equinox_crypto::signer::{verify_canonical, SecretSeed, DOMAIN_TX_MAINNET};

use crate::WalletError;

pub const AIRGAP_MAGIC: [u8; 4] = *b"EQXA";
pub const AIRGAP_VERSION: u8 = 1;
pub const CHAIN_ID_MAINNET: u64 = 9333;

/// Deterministic unsigned payload passed from an online watch-only wallet to an offline signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedAirGapTx {
    pub chain_id: u64,
    pub from_hash160: [u8; 20],
    pub to_hash160: [u8; 20],
    pub amount_atomic: u128,
    pub fee_atomic: u128,
    pub nonce: u64,
}

impl UnsignedAirGapTx {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(93);
        out.extend_from_slice(&AIRGAP_MAGIC);
        out.push(AIRGAP_VERSION);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.from_hash160);
        out.extend_from_slice(&self.to_hash160);
        out.extend_from_slice(&self.amount_atomic.to_le_bytes());
        out.extend_from_slice(&self.fee_atomic.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WalletError> {
        if raw.len() != 93 || raw[0..4] != AIRGAP_MAGIC || raw[4] != AIRGAP_VERSION {
            return Err(WalletError::InvalidAirGapPacket);
        }
        let chain_id = u64::from_le_bytes(raw[5..13].try_into().unwrap());
        let mut from_hash160 = [0u8; 20];
        from_hash160.copy_from_slice(&raw[13..33]);
        let mut to_hash160 = [0u8; 20];
        to_hash160.copy_from_slice(&raw[33..53]);
        let amount_atomic = u128::from_le_bytes(raw[53..69].try_into().unwrap());
        let fee_atomic = u128::from_le_bytes(raw[69..85].try_into().unwrap());
        let nonce = u64::from_le_bytes(raw[85..93].try_into().unwrap());
        Ok(Self {
            chain_id,
            from_hash160,
            to_hash160,
            amount_atomic,
            fee_atomic,
            nonce,
        })
    }

    pub fn sign_offline(&self, secret: &SecretSeed) -> Result<SignedAirGapTx, WalletError> {
        let pubkey = secret.public_key_bytes();
        if hash160(&pubkey) != self.from_hash160 {
            return Err(WalletError::SignerAddressMismatch);
        }
        let payload = self.encode();
        let signature = secret.sign_domain(DOMAIN_TX_MAINNET, &payload);
        Ok(SignedAirGapTx {
            tx: self.clone(),
            pubkey,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAirGapTx {
    pub tx: UnsignedAirGapTx,
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedAirGapTx {
    pub fn verify_for_broadcast(&self) -> Result<(), WalletError> {
        if self.tx.chain_id != CHAIN_ID_MAINNET || self.tx.amount_atomic == 0 {
            return Err(WalletError::InvalidAirGapPacket);
        }
        if hash160(&self.pubkey) != self.tx.from_hash160 {
            return Err(WalletError::SignerAddressMismatch);
        }
        let payload = self.tx.encode();
        verify_canonical(&self.pubkey, DOMAIN_TX_MAINNET, &payload, &self.signature)
            .map_err(|_| WalletError::InvalidSignature)
    }
}
