#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use equinox_consensus::U256;
use equinox_network::protocol::WireMessage;

use crate::block::{compute_header_pow_hash, FullBlock};
use crate::runtime::{now_secs, BlockSummary, NodeState, PeerBroadcaster, SharedNode};

/// Mines one valid PoW block and commits it atomically into WAL storage.
pub fn mine_one_block(
    node: &SharedNode,
    shutdown: &AtomicBool,
) -> Result<Option<(BlockSummary, FullBlock, u64)>, String> {
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

        let hash =
            compute_header_pow_hash(next_height, &prev_hash, &state_root, &miner_h160, ts, nonce);
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
        if nonce % 200_000 == 0 {
            ts = now_secs().max(ts);
        }
    }
}

/// Spawns continuous background CPU PoW miner that automatically broadcasts every block to peers.
pub fn spawn_cpu_miner(
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        println!("[MINER] CPU Proof-of-Work engine started (Double-SHA256 + ASERT3-2d + Live P2P Sync)");
        while !shutdown.load(Ordering::Relaxed) {
            match mine_one_block(&node, &shutdown) {
                Ok(Some((blk, full_block, hashrate))) => {
                    broadcaster.broadcast(WireMessage::BlockData(full_block.encode_bytes()), None);
                    println!(
                        "[BLOCK #{}] Mined & Broadcasted! Hash: {}.. | Txs: {} | Miner: +{} EQX | DAO: +{} EQX | Speed: {} H/s",
                        blk.height,
                        &blk.hash_hex[..16],
                        blk.tx_count,
                        NodeState::format_eqx(blk.miner_reward_atomic),
                        NodeState::format_eqx(blk.dao_reward_atomic),
                        hashrate
                    );
                    thread::sleep(Duration::from_millis(800));
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
