#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use equinox_consensus::U256;
use sha2::{Digest, Sha256};

use crate::runtime::{now_secs, BlockSummary, NodeState, SharedNode};

/// Computes deterministic Double-SHA256 PoW header hash.
pub fn compute_header_pow_hash(
    height: u64,
    prev_hash: &[u8; 32],
    state_root: &[u8; 32],
    miner_h160: &[u8; 20],
    timestamp: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut h1 = Sha256::new();
    h1.update(b"EQX_POW_HDR_V1");
    h1.update(&height.to_le_bytes());
    h1.update(prev_hash);
    h1.update(state_root);
    h1.update(miner_h160);
    h1.update(&timestamp.to_le_bytes());
    h1.update(&nonce.to_le_bytes());
    let first = h1.finalize();

    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().into()
}

/// Mines exactly one valid Proof-of-Work block and commits it atomically into WAL storage.
pub fn mine_one_block(node: &SharedNode, shutdown: &AtomicBool) -> Result<Option<(BlockSummary, u64)>, String> {
    let (next_height, prev_hash, state_root, miner_h160, target, mut ts) = {
        let st = node.lock().unwrap();
        let next_h = st.storage.tip_height().saturating_add(1);
        let prev = st.storage.tip_hash();
        let root = st.storage.compute_state_root();
        let t = now_secs().max(st.last_block_timestamp.saturating_add(1));
        (next_h, prev, root, st.miner_h160, st.current_target, t)
    };

    let start = Instant::now();
    let mut nonce = 0u64;
    let mut hashes = 0u64;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(None);
        }

        let hash = compute_header_pow_hash(next_height, &prev_hash, &state_root, &miner_h160, ts, nonce);
        hashes = hashes.saturating_add(1);

        if U256::meets_target(hash, target) {
            let elapsed_ms = start.elapsed().as_millis().max(1) as u64;
            let hashrate = hashes.saturating_mul(1_000) / elapsed_ms;
            let mut st = node.lock().unwrap();
            let summary = st.commit_mined_block(next_height, hash, nonce, ts)?;
            return Ok(Some((summary, hashrate)));
        }

        nonce = nonce.wrapping_add(1);
        if nonce % 200_000 == 0 {
            ts = now_secs().max(ts);
        }
    }
}

/// Spawns continuous background CPU PoW mining thread respecting clean shutdown.
pub fn spawn_cpu_miner(node: SharedNode, shutdown: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        println!("[MINER] CPU Proof-of-Work engine started (Double-SHA256 + ASERT3-2d)");
        while !shutdown.load(Ordering::Relaxed) {
            match mine_one_block(&node, &shutdown) {
                Ok(Some((blk, hashrate))) => {
                    println!(
                        "[BLOCK #{}] Mined! Hash: {}.. | Nonce: {} | Miner: +{} EQX | DAO: +{} EQX | Speed: {} H/s",
                        blk.height,
                        &blk.hash_hex[..16],
                        blk.nonce,
                        NodeState::format_eqx(blk.miner_reward_atomic),
                        NodeState::format_eqx(blk.dao_reward_atomic),
                        hashrate
                    );
                    // Brief pacing pause so testnet terminal logs stay readable
                    thread::sleep(Duration::from_millis(800));
                }
                Ok(None) => break,
                Err(e) => {
                    eprintln!("[MINER ERROR] {}", e);
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    })
}
