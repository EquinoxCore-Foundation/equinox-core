#![forbid(unsafe_code)]

use crate::NetworkError;

pub const WIRE_MAGIC: [u8; 4] = *b"EQXP";
pub const CHAIN_ID_MAINNET: u64 = 9333;
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_WIRE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SYNC_PAYLOAD_BYTES: usize = 60_000; // Fits safely inside 65,519-byte Noise frame

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireMessage {
    Version {
        protocol_version: u32,
        chain_id: u64,
        best_height: u64,
        nonce: u64,
    },
    VerAck,
    Ping(u64),
    Pong(u64),
    GetPeers,
    InvBlock([u8; 32]),
    InvTx([u8; 32]),
    GetBlocks {
        from_height: u64,
        max_count: u16,
    },
    BlockData(Vec<u8>),
    GetMempool,
    TxData(Vec<u8>),
}

impl WireMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(64);
        match self {
            WireMessage::Version {
                protocol_version,
                chain_id,
                best_height,
                nonce,
            } => {
                body.push(0x01);
                body.extend_from_slice(&protocol_version.to_le_bytes());
                body.extend_from_slice(&chain_id.to_le_bytes());
                body.extend_from_slice(&best_height.to_le_bytes());
                body.extend_from_slice(&nonce.to_le_bytes());
            }
            WireMessage::VerAck => body.push(0x02),
            WireMessage::Ping(n) => {
                body.push(0x03);
                body.extend_from_slice(&n.to_le_bytes());
            }
            WireMessage::Pong(n) => {
                body.push(0x04);
                body.extend_from_slice(&n.to_le_bytes());
            }
            WireMessage::GetPeers => body.push(0x05),
            WireMessage::InvBlock(hash) => {
                body.push(0x10);
                body.extend_from_slice(hash);
            }
            WireMessage::InvTx(hash) => {
                body.push(0x11);
                body.extend_from_slice(hash);
            }
            WireMessage::GetBlocks {
                from_height,
                max_count,
            } => {
                body.push(0x12);
                body.extend_from_slice(&from_height.to_le_bytes());
                body.extend_from_slice(&max_count.to_le_bytes());
            }
            WireMessage::BlockData(raw) => {
                body.push(0x13);
                body.extend_from_slice(raw);
            }
            WireMessage::GetMempool => body.push(0x14),
            WireMessage::TxData(raw) => {
                body.push(0x15);
                body.extend_from_slice(raw);
            }
        }

        let mut frame = Vec::with_capacity(8 + body.len());
        frame.extend_from_slice(&WIRE_MAGIC);
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    pub fn decode(frame: &[u8]) -> Result<Self, NetworkError> {
        if frame.len() < 9 || frame[0..4] != WIRE_MAGIC {
            return Err(NetworkError::MalformedWireFrame);
        }
        let len = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
        if len == 0 || len > MAX_WIRE_PAYLOAD_BYTES || frame.len() != 8 + len {
            return Err(NetworkError::MalformedWireFrame);
        }
        let body = &frame[8..];
        match body[0] {
            0x01 => {
                if body.len() != 29 {
                    return Err(NetworkError::MalformedWireFrame);
                }
                let protocol_version = u32::from_le_bytes([body[1], body[2], body[3], body[4]]);
                let chain_id = u64::from_le_bytes(body[5..13].try_into().unwrap());
                let best_height = u64::from_le_bytes(body[13..21].try_into().unwrap());
                let nonce = u64::from_le_bytes(body[21..29].try_into().unwrap());
                Ok(WireMessage::Version {
                    protocol_version,
                    chain_id,
                    best_height,
                    nonce,
                })
            }
            0x02 if body.len() == 1 => Ok(WireMessage::VerAck),
            0x03 if body.len() == 9 => Ok(WireMessage::Ping(u64::from_le_bytes(
                body[1..9].try_into().unwrap(),
            ))),
            0x04 if body.len() == 9 => Ok(WireMessage::Pong(u64::from_le_bytes(
                body[1..9].try_into().unwrap(),
            ))),
            0x05 if body.len() == 1 => Ok(WireMessage::GetPeers),
            0x10 if body.len() == 33 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&body[1..33]);
                Ok(WireMessage::InvBlock(h))
            }
            0x11 if body.len() == 33 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&body[1..33]);
                Ok(WireMessage::InvTx(h))
            }
            0x12 if body.len() == 11 => {
                let from_height = u64::from_le_bytes(body[1..9].try_into().unwrap());
                let max_count = u16::from_le_bytes([body[9], body[10]]);
                Ok(WireMessage::GetBlocks {
                    from_height,
                    max_count,
                })
            }
            0x13 if body.len() > 1 && body.len() - 1 <= MAX_SYNC_PAYLOAD_BYTES => {
                Ok(WireMessage::BlockData(body[1..].to_vec()))
            }
            0x14 if body.len() == 1 => Ok(WireMessage::GetMempool),
            0x15 if body.len() > 1 && body.len() - 1 <= MAX_SYNC_PAYLOAD_BYTES => {
                Ok(WireMessage::TxData(body[1..].to_vec()))
            }
            _ => Err(NetworkError::MalformedWireFrame),
        }
    }
}
