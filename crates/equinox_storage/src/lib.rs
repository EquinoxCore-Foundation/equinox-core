#![forbid(unsafe_code)]

pub mod cache;
pub mod engine;
pub mod types;
pub mod wal;

use std::io;
use crate::types::OutPoint;

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    CorruptEncoding,
    FrameTooLarge,
    CorruptSnapshot,
    HeightMismatch { expected: u64, got: u64 },
    MissingUtxo(OutPoint),
    DoubleSpendInBlock(OutPoint),
    DuplicateOutput(OutPoint),
}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::UtxoStorageEngine;
    use crate::types::{OutPoint, UtxoEntry, WriteBatch};
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("eqx_storage_{}_{}.dat", tag, nanos))
    }

    fn make_op(id: u32) -> OutPoint {
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&id.to_le_bytes());
        OutPoint { txid, vout: 0 }
    }

    fn make_entry(val: u128, height: u64) -> UtxoEntry {
        UtxoEntry {
            value_atomic: val,
            script_hash160: [0x21u8; 20],
            height,
            is_coinbase: height == 0,
        }
    }

    #[test]
    fn test_atomic_rollback_on_double_spend() {
        let wal = temp_path("atomic");
        let mut eng = UtxoStorageEngine::open(&wal, 64, true).unwrap();

        let op1 = make_op(1);
        let op2 = make_op(2);
        let genesis = WriteBatch {
            height: 0,
            block_hash: [1u8; 32],
            spends: vec![],
            creates: vec![(op1, make_entry(500, 0)), (op2, make_entry(500, 0))],
        };
        eng.apply_block_batch(&genesis).unwrap();

        // Malicious block tries to double-spend op1 in the same block
        let bad_block = WriteBatch {
            height: 1,
            block_hash: [2u8; 32],
            spends: vec![op1, op1],
            creates: vec![(make_op(99), make_entry(1000, 1))],
        };
        assert!(matches!(
            eng.apply_block_batch(&bad_block),
            Err(StorageError::DoubleSpendInBlock(_))
        ));

        // State must remain completely untouched at height 0
        assert_eq!(eng.tip_height(), 0);
        assert_eq!(eng.utxo_count(), 2);
        assert!(eng.get_utxo(&op1).is_some());
        assert!(eng.get_utxo(&make_op(99)).is_none());

        let _ = fs::remove_file(wal);
    }

    #[test]
    fn test_wal_power_cut_crash_recovery_and_truncation() {
        let wal = temp_path("crash");
        {
            let mut eng = UtxoStorageEngine::open(&wal, 64, true).unwrap();
            eng.apply_block_batch(&WriteBatch {
                height: 0,
                block_hash: [10u8; 32],
                spends: vec![],
                creates: vec![(make_op(1), make_entry(1_000_000, 0))],
            })
            .unwrap();
            eng.apply_block_batch(&WriteBatch {
                height: 1,
                block_hash: [11u8; 32],
                spends: vec![make_op(1)],
                creates: vec![(make_op(2), make_entry(999_000, 1))],
            })
            .unwrap();
        }

        // Simulate power loss corrupting trailing bytes at EOF
        {
            let mut f = OpenOptions::new().append(true).open(&wal).unwrap();
            f.write_all(b"EQXW\x99\x00\x00\x00CORRUPTED_PARTIAL_WRITE").unwrap();
            f.sync_data().unwrap();
        }

        // Re-open engine: must auto-heal tail and recover exact height 1 state
        let mut recovered = UtxoStorageEngine::open(&wal, 64, true).unwrap();
        assert!(recovered.healed_tail_on_open());
        assert_eq!(recovered.tip_height(), 1);
        assert!(recovered.get_utxo(&make_op(1)).is_none());
        assert_eq!(recovered.get_utxo(&make_op(2)).unwrap().value_atomic, 999_000);

        let _ = fs::remove_file(wal);
    }

    #[test]
    fn test_bounded_lru_cache_prevents_ram_leak() {
        let wal = temp_path("lru");
        let mut eng = UtxoStorageEngine::open(&wal, 50, false).unwrap();

        let creates: Vec<_> = (0..500u32)
            .map(|i| (make_op(i), make_entry(100 + i as u128, 0)))
            .collect();
        eng.apply_block_batch(&WriteBatch {
            height: 0,
            block_hash: [3u8; 32],
            spends: vec![],
            creates,
        })
        .unwrap();

        // Backing store has all 500 UTXOs, but hot LRU cache strictly capped at 50
        assert_eq!(eng.utxo_count(), 500);
        assert_eq!(eng.cache_len(), 50);

        // Fetching evicted item #0 still works cleanly without exceeding cap
        assert_eq!(eng.get_utxo(&make_op(0)).unwrap().value_atomic, 100);
        assert_eq!(eng.cache_len(), 50);

        let _ = fs::remove_file(wal);
    }

    #[test]
    fn test_deterministic_snapshot_export_and_verify() {
        let wal = temp_path("snap_wal");
        let snap = temp_path("snap_file");
        let mut eng = UtxoStorageEngine::open(&wal, 128, false).unwrap();

        eng.apply_block_batch(&WriteBatch {
            height: 0,
            block_hash: [42u8; 32],
            spends: vec![],
            creates: vec![
                (make_op(7), make_entry(700, 0)),
                (make_op(3), make_entry(300, 0)),
            ],
        })
        .unwrap();

        let exported_root = eng.export_snapshot(&snap).unwrap();
        let (verified_root, tip_h, count) = UtxoStorageEngine::verify_snapshot(&snap).unwrap();
        assert_eq!(exported_root, verified_root);
        assert_eq!(tip_h, 0);
        assert_eq!(count, 2);

        let _ = fs::remove_file(wal);
        let _ = fs::remove_file(snap);
    }

    #[test]
    fn test_high_iops_10000_utxo_stress_benchmark() {
        let wal = temp_path("iops");
        let mut eng = UtxoStorageEngine::open(&wal, 2_048, false).unwrap();

        let start = Instant::now();
        let mut next_id = 0u32;
        // 100 blocks x 100 outputs = 10,000 UTXOs created and verified
        for h in 0..100u64 {
            let mut creates = Vec::with_capacity(100);
            for _ in 0..100 {
                creates.push((make_op(next_id), make_entry(1_000, h)));
                next_id += 1;
            }
            eng.apply_block_batch(&WriteBatch {
                height: h,
                block_hash: [h as u8; 32],
                spends: vec![],
                creates,
            })
            .unwrap();
        }
        let elapsed = start.elapsed();
        assert_eq!(eng.utxo_count(), 10_000);
        assert!(eng.cache_len() <= 2_048);
        assert!(elapsed.as_secs() < 5);

        let _ = fs::remove_file(wal);
    }
}
