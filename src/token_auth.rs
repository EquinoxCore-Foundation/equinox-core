use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const DOMAIN_SEP: &[u8] = b"EQUINOX_TOKEN_TX_V1:";

/// Builds a deterministic signing message for native token operations.
pub fn build_transfer_message(asset_id: &str, from: &str, to: &str, amount: u128, nonce: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(DOMAIN_SEP);
    msg.extend_from_slice(b"TRANSFER:");
    msg.extend_from_slice(asset_id.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(from.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(to.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(&amount.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg
}

/// Verifies an Ed25519 signature against a 32-byte public key and message.
pub fn verify_ed25519_signature(
    pubkey_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<(), String> {
    let pk_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes".to_string())?;

    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| "Invalid Ed25519 signature".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_ed25519_token_signature_verification() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let msg = build_transfer_message("eqx_asset_abc", "eqx1alice", "eqx1bob", 500, 1);
        let sig = signing_key.sign(&msg).to_bytes();

        // Valid signature must pass
        assert!(verify_ed25519_signature(&pubkey, &msg, &sig).is_ok());

        // Tampered amount must fail
        let tampered = build_transfer_message("eqx_asset_abc", "eqx1alice", "eqx1bob", 999, 1);
        assert!(verify_ed25519_signature(&pubkey, &tampered, &sig).is_err());
    }
}