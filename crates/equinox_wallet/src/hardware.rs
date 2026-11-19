#![forbid(unsafe_code)]

use crate::slip10::HARDENED_OFFSET;
use crate::WalletError;

pub const APDU_CLA_EQUINOX: u8 = 0xE0;
pub const INS_GET_APP_CONFIG: u8 = 0x01;
pub const INS_GET_PUBLIC_KEY: u8 = 0x02;
pub const INS_SIGN_TRANSACTION: u8 = 0x04;

pub const P1_FIRST_CHUNK: u8 = 0x00;
pub const P1_MORE_CHUNK: u8 = 0x01;
pub const P1_LAST_CHUNK: u8 = 0x80;

pub const SW_OK: u16 = 0x9000;
pub const SW_USER_REJECTED: u16 = 0x6985;
pub const SW_WRONG_CLA: u16 = 0x6E00;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

pub const MAX_APDU_DATA_BYTES: usize = 255;
pub const MAX_BIP32_DEPTH: usize = 10;

/// Standard ISO-7816 APDU command packet for Ledger / Trezor hardware wallets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl ApduCommand {
    pub fn encode(&self) -> Result<Vec<u8>, WalletError> {
        if self.data.len() > MAX_APDU_DATA_BYTES {
            return Err(WalletError::ApduPayloadTooLarge);
        }
        let mut out = Vec::with_capacity(5 + self.data.len());
        out.push(self.cla);
        out.push(self.ins);
        out.push(self.p1);
        out.push(self.p2);
        out.push(self.data.len() as u8);
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WalletError> {
        if raw.len() < 5 {
            return Err(WalletError::MalformedApdu);
        }
        let lc = raw[4] as usize;
        if raw.len() != 5 + lc {
            return Err(WalletError::MalformedApdu);
        }
        Ok(Self {
            cla: raw[0],
            ins: raw[1],
            p1: raw[2],
            p2: raw[3],
            data: raw[5..].to_vec(),
        })
    }
}

pub fn encode_hardened_path(path: &[u32]) -> Result<Vec<u8>, WalletError> {
    if path.is_empty() || path.len() > MAX_BIP32_DEPTH {
        return Err(WalletError::InvalidPathComponent);
    }
    let mut buf = Vec::with_capacity(1 + path.len() * 4);
    buf.push(path.len() as u8);
    for &seg in path {
        if seg < HARDENED_OFFSET {
            return Err(WalletError::NonHardenedPathUnsupported);
        }
        buf.extend_from_slice(&seg.to_be_bytes());
    }
    Ok(buf)
}

pub fn build_get_public_key_apdu(
    path: &[u32],
    confirm_on_screen: bool,
) -> Result<ApduCommand, WalletError> {
    let data = encode_hardened_path(path)?;
    Ok(ApduCommand {
        cla: APDU_CLA_EQUINOX,
        ins: INS_GET_PUBLIC_KEY,
        p1: if confirm_on_screen { 0x01 } else { 0x00 },
        p2: 0x00,
        data,
    })
}

/// Streams an arbitrary-length unsigned UTXO transaction across <=255-byte APDU chunks.
pub fn build_sign_tx_apdus(
    path: &[u32],
    tx_payload: &[u8],
) -> Result<Vec<ApduCommand>, WalletError> {
    if tx_payload.is_empty() {
        return Err(WalletError::EmptyTransactionPayload);
    }
    let mut cmds = Vec::new();
    cmds.push(ApduCommand {
        cla: APDU_CLA_EQUINOX,
        ins: INS_SIGN_TRANSACTION,
        p1: P1_FIRST_CHUNK,
        p2: 0x00,
        data: encode_hardened_path(path)?,
    });

    let chunks: Vec<&[u8]> = tx_payload.chunks(MAX_APDU_DATA_BYTES).collect();
    for (idx, chunk) in chunks.iter().enumerate() {
        let is_last = idx + 1 == chunks.len();
        cmds.push(ApduCommand {
            cla: APDU_CLA_EQUINOX,
            ins: INS_SIGN_TRANSACTION,
            p1: if is_last { P1_LAST_CHUNK } else { P1_MORE_CHUNK },
            p2: 0x00,
            data: chunk.to_vec(),
        });
    }
    Ok(cmds)
}

pub fn parse_apdu_response(raw: &[u8]) -> Result<Vec<u8>, WalletError> {
    if raw.len() < 2 {
        return Err(WalletError::MalformedApdu);
    }
    let split = raw.len() - 2;
    let sw = u16::from_be_bytes([raw[split], raw[split + 1]]);
    match sw {
        SW_OK => Ok(raw[..split].to_vec()),
        SW_USER_REJECTED => Err(WalletError::HardwareUserRejected),
        SW_WRONG_CLA => Err(WalletError::HardwareWrongApp),
        SW_INS_NOT_SUPPORTED => Err(WalletError::HardwareUnsupportedInstruction),
        other => Err(WalletError::HardwareDeviceError(other)),
    }
}
