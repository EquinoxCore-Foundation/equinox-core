#![forbid(unsafe_code)]

use crate::StorageError;

pub const MAX_BATCH_OPS: usize = 500_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.vout.to_le_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), StorageError> {
        if input.len() < 36 {
            return Err(StorageError::CorruptEncoding);
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&input[0..32]);
        let vout = u32::from_le_bytes([input[32], input[33], input[34], input[35]]);
        Ok((Self { txid, vout }, &input[36..]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtxoEntry {
    pub value_atomic: u128,
    pub script_hash160: [u8; 20],
    pub height: u64,
    pub is_coinbase: bool,
}

impl UtxoEntry {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.value_atomic.to_le_bytes());
        buf.extend_from_slice(&self.script_hash160);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.push(if self.is_coinbase { 1 } else { 0 });
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), StorageError> {
        if input.len() < 45 {
            return Err(StorageError::CorruptEncoding);
        }
        let mut val_b = [0u8; 16];
        val_b.copy_from_slice(&input[0..16]);
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(&input[16..36]);
        let mut h_b = [0u8; 8];
        h_b.copy_from_slice(&input[36..44]);
        let flag = input[44];
        if flag > 1 {
            return Err(StorageError::CorruptEncoding);
        }
        Ok((
            Self {
                value_atomic: u128::from_le_bytes(val_b),
                script_hash160: h160,
                height: u64::from_le_bytes(h_b),
                is_coinbase: flag == 1,
            },
            &input[45..],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBatch {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub spends: Vec<OutPoint>,
    pub creates: Vec<(OutPoint, UtxoEntry)>,
}

impl WriteBatch {
    pub fn encode(&self) -> Vec<u8> {
        let cap = 48 + (self.spends.len() * 36) + (self.creates.len() * 81);
        let mut buf = Vec::with_capacity(cap);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&(self.spends.len() as u32).to_le_bytes());
        for sp in &self.spends {
            sp.encode(&mut buf);
        }
        buf.extend_from_slice(&(self.creates.len() as u32).to_le_bytes());
        for (op, entry) in &self.creates {
            op.encode(&mut buf);
            entry.encode(&mut buf);
        }
        buf
    }

    pub fn decode(input: &[u8]) -> Result<Self, StorageError> {
        if input.len() < 48 {
            return Err(StorageError::CorruptEncoding);
        }
        let mut h_b = [0u8; 8];
        h_b.copy_from_slice(&input[0..8]);
        let height = u64::from_le_bytes(h_b);

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&input[8..40]);

        let spend_count =
            u32::from_le_bytes([input[40], input[41], input[42], input[43]]) as usize;
        if spend_count > MAX_BATCH_OPS {
            return Err(StorageError::CorruptEncoding);
        }

        let mut rest = &input[44..];
        if rest.len() < spend_count.saturating_mul(36) + 4 {
            return Err(StorageError::CorruptEncoding);
        }
        let mut spends = Vec::with_capacity(spend_count);
        for _ in 0..spend_count {
            let (op, next) = OutPoint::decode(rest)?;
            spends.push(op);
            rest = next;
        }

        let create_count = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if create_count > MAX_BATCH_OPS {
            return Err(StorageError::CorruptEncoding);
        }
        rest = &rest[4..];
        if rest.len() != create_count.saturating_mul(81) {
            return Err(StorageError::CorruptEncoding);
        }

        let mut creates = Vec::with_capacity(create_count);
        for _ in 0..create_count {
            let (op, next1) = OutPoint::decode(rest)?;
            let (entry, next2) = UtxoEntry::decode(next1)?;
            creates.push((op, entry));
            rest = next2;
        }

        Ok(Self {
            height,
            block_hash,
            spends,
            creates,
        })
    }
}
