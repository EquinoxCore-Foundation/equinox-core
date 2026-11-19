#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::cache::BoundedUtxoCache;
use crate::types::{OutPoint, UtxoEntry, WriteBatch};
use crate::wal::WalFile;
use crate::StorageError;

pub const SNAPSHOT_MAGIC: [u8; 4] = *b"EQXS";

pub struct UtxoStorageEngine {
    wal: WalFile,
    utxo_set: HashMap<OutPoint, UtxoEntry>,
    hot_cache: BoundedUtxoCache,
    tip_height: u64,
    tip_hash: [u8; 32],
    next_expected_height: u64,
    sync_on_commit: bool,
    healed_tail_on_open: bool,
}

impl UtxoStorageEngine {
    pub fn open(
        wal_path: impl AsRef<Path>,
        cache_capacity: usize,
        sync_on_commit: bool,
    ) -> Result<Self, StorageError> {
        let (wal, recovered_batches, healed) = WalFile::open(wal_path)?;
        let mut engine = Self {
            wal,
            utxo_set: HashMap::new(),
            hot_cache: BoundedUtxoCache::new(cache_capacity),
            tip_height: 0,
            tip_hash: [0u8; 32],
            next_expected_height: 0,
            sync_on_commit,
            healed_tail_on_open: healed,
        };

        for batch in recovered_batches {
            engine.apply_validated_in_memory(&batch);
        }
        Ok(engine)
    }

    pub fn wal_path(&self) -> &Path {
        self.wal.path()
    }

    pub fn healed_tail_on_open(&self) -> bool {
        self.healed_tail_on_open
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn utxo_count(&self) -> usize {
        self.utxo_set.len()
    }

    pub fn cache_len(&self) -> usize {
        self.hot_cache.len()
    }

    pub fn get_utxo(&mut self, op: &OutPoint) -> Option<UtxoEntry> {
        if let Some(hit) = self.hot_cache.get(op) {
            return Some(hit);
        }
        if let Some(entry) = self.utxo_set.get(op).copied() {
            self.hot_cache.put(*op, entry);
            return Some(entry);
        }
        None
    }

    /// All-or-nothing atomic UTXO commit: validates entire block before writing WAL or mutating RAM.
    pub fn apply_block_batch(&mut self, batch: &WriteBatch) -> Result<(), StorageError> {
        if batch.height != self.next_expected_height {
            return Err(StorageError::HeightMismatch {
                expected: self.next_expected_height,
                got: batch.height,
            });
        }

        // Phase 1: Strict pre-validation (zero mutation on failure)
        let mut seen_spends = HashSet::with_capacity(batch.spends.len());
        for sp in &batch.spends {
            if !seen_spends.insert(*sp) {
                return Err(StorageError::DoubleSpendInBlock(*sp));
            }
            if !self.utxo_set.contains_key(sp) {
                return Err(StorageError::MissingUtxo(*sp));
            }
        }

        let mut seen_creates = HashSet::with_capacity(batch.creates.len());
        for (op, _) in &batch.creates {
            if !seen_creates.insert(*op) {
                return Err(StorageError::DuplicateOutput(*op));
            }
            if self.utxo_set.contains_key(op) && !seen_spends.contains(op) {
                return Err(StorageError::DuplicateOutput(*op));
            }
        }

        // Phase 2: Durable WAL commit first
        self.wal.append_batch(batch, self.sync_on_commit)?;

        // Phase 3: Commit in-memory state + bounded LRU cache
        self.apply_validated_in_memory(batch);
        Ok(())
    }

    fn apply_validated_in_memory(&mut self, batch: &WriteBatch) {
        for sp in &batch.spends {
            self.utxo_set.remove(sp);
            self.hot_cache.remove(sp);
        }
        for (op, entry) in &batch.creates {
            self.utxo_set.insert(*op, *entry);
            self.hot_cache.put(*op, *entry);
        }
        self.tip_height = batch.height;
        self.tip_hash = batch.block_hash;
        self.next_expected_height = batch.height.saturating_add(1);
    }

    /// Deterministic SHA-256 commitment over the complete sorted UTXO set for fast-sync snapshots.
    pub fn compute_state_root(&self) -> [u8; 32] {
        let mut items: Vec<(OutPoint, UtxoEntry)> =
            self.utxo_set.iter().map(|(k, v)| (*k, *v)).collect();
        items.sort_unstable_by_key(|(op, _)| *op);

        let mut hasher = Sha256::new();
        hasher.update(b"EQX_UTXO_STATE_ROOT_V1");
        hasher.update(&self.tip_height.to_le_bytes());
        hasher.update(&self.tip_hash);
        hasher.update(&(items.len() as u64).to_le_bytes());

        let mut scratch = Vec::with_capacity(81);
        for (op, entry) in items {
            scratch.clear();
            op.encode(&mut scratch);
            entry.encode(&mut scratch);
            hasher.update(&scratch);
        }
        hasher.finalize().into()
    }

    /// Exports an atomic, checksum-verified UTXO snapshot file for new mainnet nodes.
    pub fn export_snapshot(&self, snapshot_path: impl AsRef<Path>) -> Result<[u8; 32], StorageError> {
        let state_root = self.compute_state_root();
        let mut items: Vec<(OutPoint, UtxoEntry)> =
            self.utxo_set.iter().map(|(k, v)| (*k, *v)).collect();
        items.sort_unstable_by_key(|(op, _)| *op);

        let mut payload = Vec::with_capacity(84 + items.len() * 81);
        payload.extend_from_slice(&SNAPSHOT_MAGIC);
        payload.extend_from_slice(&self.tip_height.to_le_bytes());
        payload.extend_from_slice(&self.tip_hash);
        payload.extend_from_slice(&state_root);
        payload.extend_from_slice(&(items.len() as u64).to_le_bytes());
        for (op, entry) in items {
            op.encode(&mut payload);
            entry.encode(&mut payload);
        }

        let crc = crc32fast::hash(&payload);
        let tmp_path = snapshot_path.as_ref().with_extension("tmp");
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(&payload)?;
            f.write_all(&crc.to_le_bytes())?;
            f.sync_data()?;
        }
        fs::rename(tmp_path, snapshot_path)?;
        Ok(state_root)
    }

    /// Verifies a snapshot file's CRC32 and recomputes its SHA-256 state root independently.
    pub fn verify_snapshot(snapshot_path: impl AsRef<Path>) -> Result<([u8; 32], u64, usize), StorageError> {
        let raw = fs::read(snapshot_path)?;
        if raw.len() < 88 {
            return Err(StorageError::CorruptSnapshot);
        }
        let body = &raw[..raw.len() - 4];
        let stored_crc = u32::from_le_bytes([
            raw[raw.len() - 4],
            raw[raw.len() - 3],
            raw[raw.len() - 2],
            raw[raw.len() - 1],
        ]);
        if crc32fast::hash(body) != stored_crc || body[0..4] != SNAPSHOT_MAGIC {
            return Err(StorageError::CorruptSnapshot);
        }

        let mut h_b = [0u8; 8];
        h_b.copy_from_slice(&body[4..12]);
        let tip_height = u64::from_le_bytes(h_b);

        let mut tip_hash = [0u8; 32];
        tip_hash.copy_from_slice(&body[12..44]);

        let mut claimed_root = [0u8; 32];
        claimed_root.copy_from_slice(&body[44..76]);

        let mut count_b = [0u8; 8];
        count_b.copy_from_slice(&body[76..84]);
        let count = u64::from_le_bytes(count_b) as usize;

        let mut rest = &body[84..];
        if rest.len() != count.saturating_mul(81) {
            return Err(StorageError::CorruptSnapshot);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"EQX_UTXO_STATE_ROOT_V1");
        hasher.update(&tip_height.to_le_bytes());
        hasher.update(&tip_hash);
        hasher.update(&(count as u64).to_le_bytes());
        hasher.update(rest);

        // Validate every single record decodes cleanly
        for _ in 0..count {
            let (_, n1) = OutPoint::decode(rest)?;
            let (_, n2) = UtxoEntry::decode(n1)?;
            rest = n2;
        }

        let recomputed: [u8; 32] = hasher.finalize().into();
        if recomputed != claimed_root {
            return Err(StorageError::CorruptSnapshot);
        }
        Ok((recomputed, tip_height, count))
    }
}
