#![forbid(unsafe_code)]

use snow::{Builder, HandshakeState, TransportState};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::NetworkError;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const MAINNET_PROLOGUE: &[u8] = b"EQX_MAINNET_9333_NOISE_XX_V1";
pub const MAX_NOISE_PACKET_BYTES: usize = 65_535;
pub const MAX_PLAINTEXT_FRAME_BYTES: usize = MAX_NOISE_PACKET_BYTES - 16;

/// Static X25519 node identity keypair with automatic RAM zeroization on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NodeStaticKey {
    private: [u8; 32],
    #[zeroize(skip)]
    public: [u8; 32],
}

impl NodeStaticKey {
    pub fn generate() -> Result<Self, NetworkError> {
        let params: snow::params::NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|_| NetworkError::NoiseFailure)?;
        let kp = Builder::new(params)
            .generate_keypair()
            .map_err(|_| NetworkError::NoiseFailure)?;
        let private: [u8; 32] = kp
            .private
            .try_into()
            .map_err(|_| NetworkError::NoiseFailure)?;
        let public: [u8; 32] = kp
            .public
            .try_into()
            .map_err(|_| NetworkError::NoiseFailure)?;
        Ok(Self { private, public })
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }
}

pub struct NoiseHandshake {
    state: HandshakeState,
}

impl NoiseHandshake {
    pub fn new_initiator(key: &NodeStaticKey, prologue: &[u8]) -> Result<Self, NetworkError> {
        let params: snow::params::NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|_| NetworkError::NoiseFailure)?;
        let state = Builder::new(params)
            .local_private_key(&key.private)
            .prologue(prologue)
            .build_initiator()
            .map_err(|_| NetworkError::NoiseFailure)?;
        Ok(Self { state })
    }

    pub fn new_responder(key: &NodeStaticKey, prologue: &[u8]) -> Result<Self, NetworkError> {
        let params: snow::params::NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|_| NetworkError::NoiseFailure)?;
        let state = Builder::new(params)
            .local_private_key(&key.private)
            .prologue(prologue)
            .build_responder()
            .map_err(|_| NetworkError::NoiseFailure)?;
        Ok(Self { state })
    }

    pub fn write_step(&mut self, payload: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if payload.len() > MAX_PLAINTEXT_FRAME_BYTES {
            return Err(NetworkError::FrameTooLarge);
        }
        let mut out = vec![0u8; MAX_NOISE_PACKET_BYTES];
        let len = self
            .state
            .write_message(payload, &mut out)
            .map_err(|_| NetworkError::NoiseFailure)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn read_step(&mut self, message: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if message.len() > MAX_NOISE_PACKET_BYTES {
            return Err(NetworkError::FrameTooLarge);
        }
        let mut out = vec![0u8; MAX_NOISE_PACKET_BYTES];
        let len = self
            .state
            .read_message(message, &mut out)
            .map_err(|_| NetworkError::NoiseFailure)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_transport(self) -> Result<EncryptedChannel, NetworkError> {
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| NetworkError::NoiseFailure)?;
        Ok(EncryptedChannel { transport })
    }
}

pub struct EncryptedChannel {
    transport: TransportState,
}

impl EncryptedChannel {
    pub fn remote_public_key(&self) -> Option<[u8; 32]> {
        let slice = self.transport.get_remote_static()?;
        slice.try_into().ok()
    }

    pub fn encrypt_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if plaintext.len() > MAX_PLAINTEXT_FRAME_BYTES {
            return Err(NetworkError::FrameTooLarge);
        }
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|_| NetworkError::NoiseFailure)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn decrypt_frame(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if ciphertext.len() < 16 || ciphertext.len() > MAX_NOISE_PACKET_BYTES {
            return Err(NetworkError::InvalidCiphertext);
        }
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|_| NetworkError::InvalidCiphertext)?;
        buf.truncate(len);
        Ok(buf)
    }
}
