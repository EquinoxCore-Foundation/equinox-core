#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use equinox_consensus::U256;
use equinox_network::protocol::WireMessage;

use crate::block::{compute_header_pow_hash, FullBlock, POW_MEMORY_KIB};
use crate::runtime::{now_secs, BlockSummary, NodeState, PeerBroadcaster, SharedNode};

/// Mines one valid PoW block using a single worker (preserved for unit tests).
pub fn mine_one_block(
    node: &SharedNode,
    shutdown: &AtomicBool,
) -> Result<Option<(BlockSummary, FullBlock, u64)>, String> {
    mine_one_block_parallel(node, shutdown, 1)
}

/// Mines one valid Argon2id PoW block across `threads` CPU cores and commits it atomically.
pub fn mine_one_block_parallel(
    node: &SharedNode,
    shutdown: &AtomicBool,
    threads: usize,
) -> Result<Option<(BlockSummary, FullBlock, u64)>, String> {
    let worker_count = threads.max(1);
    let (next_height, prev_hash, state_root, miner_h160, target, initial_ts) = {
        let st = node.lock().unwrap();
        let next_h = st.storage.tip_height().saturating_add(1);
        let prev = st.storage.tip_hash();
        let root = st.storage.compute_state_root();
        let t = now_secs().max(st.last_block_timestamp.saturating_add(1));
        (next_h, prev, root, st.miner_h160, st.current_target, t)
    };

    let start = Instant::now();
    if worker_count == 1 {
        let mut nonce = 0u64;
        let mut hashes = 0u64;
        let mut ts = initial_ts;

        loop {
            if shutdown.load(Ordering::Relaxed) {
                return Ok(None);
            }

            let hash = compute_header_pow_hash(
                next_height,
                &prev_hash,
                &state_root,
                &miner_h160,
                ts,
                nonce,
            );
            hashes = hashes.saturating_add(1);

            if U256::meets_target(hash, target) {
                let elapsed_ms = start.elapsed().as_millis().max(1) as u64;
                let hashrate = hashes.saturating_mul(1_000) / elapsed_ms;
                let mut st = node.lock().unwrap();
                let (summary, full_block) =
                    st.commit_mined_block(next_height, prev_hash, state_root, nonce, ts)?;
                return Ok(Some((summary, full_block, hashrate)));
            }

            nonce = nonce.wrapping_add(1);
            if hashes % 16 == 0 {
                ts = now_secs().max(ts);
                if node.lock().unwrap().storage.tip_height() >= next_height {
                    return Err("Stale mining template (tip advanced during mining)".to_string());
                }
            }
        }
    }

    let found = Arc::new(AtomicBool::new(false));
    let stale = Arc::new(AtomicBool::new(false));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let winner: Arc<Mutex<Option<(u64, u64)>>> = Arc::new(Mutex::new(None));

    thread::scope(|scope| {
        for tid in 0..worker_count {
            let node_ref = Arc::clone(node);
            let found_ref = Arc::clone(&found);
            let stale_ref = Arc::clone(&stale);
            let hashes_ref = Arc::clone(&total_hashes);
            let winner_ref = Arc::clone(&winner);

            scope.spawn(move || {
                let stride = worker_count as u64;
                let mut nonce = tid as u64;
                let mut local_hashes = 0u64;
                let mut ts = initial_ts;

                while !shutdown.load(Ordering::Relaxed)
                    && !found_ref.load(Ordering::Relaxed)
                    && !stale_ref.load(Ordering::Relaxed)
                {
                    let hash = compute_header_pow_hash(
                        next_height,
                        &prev_hash,
                        &state_root,
                        &miner_h160,
                        ts,
                        nonce,
                    );
                    local_hashes = local_hashes.saturating_add(1);

                    if U256::meets_target(hash, target) {
                        if !found_ref.swap(true, Ordering::SeqCst) {
                            *winner_ref.lock().unwrap() = Some((nonce, ts));
                        }
                        break;
                    }

                    nonce = nonce.wrapping_add(stride);
                    if local_hashes % 16 == 0 {
                        ts = now_secs().max(ts);
                        if node_ref.lock().unwrap().storage.tip_height() >= next_height {
                            stale_ref.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                hashes_ref.fetch_add(local_hashes, Ordering::Relaxed);
            });
        }
    });

    if shutdown.load(Ordering::Relaxed) {
        return Ok(None);
    }
    if stale.load(Ordering::Relaxed) && !found.load(Ordering::Relaxed) {
        return Err("Stale mining template (tip advanced during mining)".to_string());
    }

    let Some((win_nonce, win_ts)) = *winner.lock().unwrap() else {
        return Ok(None);
    };

    let elapsed_ms = start.elapsed().as_millis().max(1) as u64;
    let hashrate = total_hashes
        .load(Ordering::Relaxed)
        .saturating_mul(1_000)
        / elapsed_ms;
    let mut st = node.lock().unwrap();
    let (summary, full_block) =
        st.commit_mined_block(next_height, prev_hash, state_root, win_nonce, win_ts)?;
    Ok(Some((summary, full_block, hashrate)))
}

/// Spawns continuous multi-thread background Argon2id CPU PoW miner with live P2P broadcast.
pub fn spawn_cpu_miner(
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
    shutdown: Arc<AtomicBool>,
    threads: usize,
) -> thread::JoinHandle<()> {
    let worker_count = threads.max(1);
    thread::spawn(move || {
        println!(
            "[MINER] ASIC-Resistant Argon2id CPU PoW started ({} KiB RAM/hash | {} threads | ASERT3-2d + Live P2P Sync)",
            POW_MEMORY_KIB, worker_count
        );
        while !shutdown.load(Ordering::Relaxed) {
            match mine_one_block_parallel(&node, &shutdown, worker_count) {
                Ok(Some((blk, full_block, hashrate))) => {
                    broadcaster.broadcast(WireMessage::BlockData(full_block.encode_bytes()), None);
                    println!(
                        "[BLOCK #{}] Mined (Argon2id) & Broadcasted! Hash: {}.. | Txs: {} | Miner: +{} EQX | DAO: +{} EQX | Speed: {} H/s ({}T)",
                        blk.height,
                        &blk.hash_hex[..16],
                        blk.tx_count,
                        NodeState::format_eqx(blk.miner_reward_atomic),
                        NodeState::format_eqx(blk.dao_reward_atomic),
                        hashrate,
                        worker_count
                    );
                    thread::sleep(Duration::from_millis(250));
                }
                Ok(None) => break,
                Err(e) => {
                    if !e.contains("Stale mining template") {
                        eprintln!("[MINER ERROR] {}", e);
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::runtime::NetworkMode;

    #[test]
    fn test_multithread_argon2id_miner_mines_valid_block() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let wal = env::temp_dir().join(format!("eqx_argon2_mt_{}.wal", nanos));
        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, None).unwrap();
        let expected_target = state.current_target;
        let node = Arc::new(Mutex::new(state));
        let shutdown = AtomicBool::new(false);

        let (summary, full_block, _hashrate) =
            mine_one_block_parallel(&node, &shutdown, 2).unwrap().unwrap();
        assert_eq!(summary.height, 1);
        assert!(U256::meets_target(full_block.pow_hash(), expected_target));

        let _ = fs::remove_file(&wal);
        let _ = fs::remove_file(wal.with_extension("blocks"));
    }
}