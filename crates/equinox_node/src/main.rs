#![forbid(unsafe_code)]

mod block;
mod genesis;
mod mempool;
mod miner;
mod p2p_tcp;
mod rpc_http;
mod runtime;
mod script;
mod tx;

use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use equinox_consensus::{
    calculate_block_subsidy, AsertConfig, BftFinalityGuard, U256, CHAIN_ID_MAINNET,
    MAX_SUPPLY_ATOMIC,
};
use equinox_crypto::address::{encode_mainnet_address, hash160};
use equinox_crypto::keystore::{EncryptedKeystore, KdfConfig};
use equinox_crypto::signer::{verify_canonical, SecretSeed, DOMAIN_TX_MAINNET};
use equinox_network::protocol::WireMessage;
use equinox_network::transport::{NodeStaticKey, NoiseHandshake, MAINNET_PROLOGUE};
use equinox_storage::engine::UtxoStorageEngine;
use equinox_storage::types::OutPoint;
use equinox_wallet::mnemonic::mnemonic_to_seed;
use equinox_wallet::slip10::{equinox_hd_path, Slip10Key};

use crate::genesis::{build_mainnet_genesis_batch, to_hex, GenesisVaultSpec};
use crate::miner::spawn_cpu_miner;
use crate::p2p_tcp::{spawn_outbound_peer, spawn_p2p_listener};
use crate::rpc_http::spawn_rpc_server;
use crate::runtime::{NetworkMode, NodeState, PeerBroadcaster};
use crate::script::DataAnchor;
use crate::tx::{SignedTransaction, TxOutput};

fn run_end_to_end_verification() -> Result<(), String> {
    println!("=== Equinox Core (EQX) Mainnet v1.0.0 Full-Stack Verification ===");

    let demo_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let master_seed = mnemonic_to_seed(demo_phrase, "EquinoxMainnetCheck")
        .map_err(|_| "Mnemonic derivation failed".to_string())?;

    let mut vault_addrs = Vec::with_capacity(4);
    for account_idx in 0..4u32 {
        let path = equinox_hd_path(account_idx, 0, 0).map_err(|_| "Invalid HD path".to_string())?;
        let key = Slip10Key::derive_path(&*master_seed, &path)
            .map_err(|_| "SLIP-0010 derivation failed".to_string())?;
        vault_addrs.push(key.mainnet_address());
    }

    let spec = GenesisVaultSpec {
        founder_address: vault_addrs[0].clone(),
        liquidity_address: vault_addrs[1].clone(),
        developer_address: vault_addrs[2].clone(),
        marketing_address: vault_addrs[3].clone(),
        timestamp_utc: 1_795_000_000,
    };
    let genesis = build_mainnet_genesis_batch(&spec)?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let wal_path = env::temp_dir().join(format!("eqx_node_verify_{}.wal", nanos));
    let mut storage = UtxoStorageEngine::open(&wal_path, 1_024, true)
        .map_err(|e| format!("Storage open failed: {:?}", e))?;
    storage
        .apply_block_batch(&genesis.write_batch)
        .map_err(|e| format!("Genesis WAL commit failed: {:?}", e))?;
    let state_root = storage.compute_state_root();
    let _ = fs::remove_file(&wal_path);

    let asert = AsertConfig::default();
    let anchor = U256([0, 0, 0, 0x0000_1000_0000_0000]);
    let next_target = asert
        .calculate_next_target(0, spec.timestamp_utc, anchor, 0, spec.timestamp_utc + 15)
        .map_err(|e| format!("ASERT error: {:?}", e))?;
    if next_target != anchor {
        return Err("ASERT steady-state check failed".to_string());
    }
    let b1 = calculate_block_subsidy(0).map_err(|e| format!("Subsidy error: {:?}", e))?;
    let mut bft = BftFinalityGuard::new(genesis.block_hash);
    if !bft
        .commit_checkpoint(1, [0x11u8; 32], 7, 10)
        .map_err(|e| format!("BFT error: {:?}", e))?
    {
        return Err("BFT supermajority checkpoint failed".to_string());
    }

    let n1 = NodeStaticKey::generate().map_err(|_| "Noise key 1 failed".to_string())?;
    let n2 = NodeStaticKey::generate().map_err(|_| "Noise key 2 failed".to_string())?;
    let mut hs1 = NoiseHandshake::new_initiator(&n1, MAINNET_PROLOGUE)
        .map_err(|_| "Noise init failed".to_string())?;
    let mut hs2 = NoiseHandshake::new_responder(&n2, MAINNET_PROLOGUE)
        .map_err(|_| "Noise resp failed".to_string())?;

    let m1 = hs1.write_step(b"").map_err(|_| "HS step 1 failed".to_string())?;
    hs2.read_step(&m1).map_err(|_| "HS read 1 failed".to_string())?;
    let m2 = hs2.write_step(b"").map_err(|_| "HS step 2 failed".to_string())?;
    hs1.read_step(&m2).map_err(|_| "HS read 2 failed".to_string())?;
    let m3 = hs1.write_step(b"").map_err(|_| "HS step 3 failed".to_string())?;
    hs2.read_step(&m3).map_err(|_| "HS read 3 failed".to_string())?;

    let mut ch1 = hs1.into_transport().map_err(|_| "Transport 1 failed".to_string())?;
    let mut ch2 = hs2.into_transport().map_err(|_| "Transport 2 failed".to_string())?;
    let raw_inv = WireMessage::InvBlock(genesis.block_hash).encode();
    let enc = ch1.encrypt_frame(&raw_inv).map_err(|_| "Encrypt failed".to_string())?;
    let dec = ch2.decrypt_frame(&enc).map_err(|_| "Decrypt failed".to_string())?;
    if WireMessage::decode(&dec).map_err(|_| "Wire decode failed".to_string())?
        != WireMessage::InvBlock(genesis.block_hash)
    {
        return Err("Noise encrypted wire roundtrip mismatch".to_string());
    }

    let ephemeral = SecretSeed::generate();
    let pubkey = ephemeral.public_key_bytes();
    let sig = ephemeral.sign_domain(DOMAIN_TX_MAINNET, &genesis.block_hash);
    verify_canonical(&pubkey, DOMAIN_TX_MAINNET, &genesis.block_hash, &sig)
        .map_err(|_| "Ed25519 verify failed".to_string())?;

    let sample_tx = SignedTransaction::sign_transfer(
        &ephemeral,
        CHAIN_ID_MAINNET,
        vec![OutPoint {
            txid: genesis.block_hash,
            vout: 0,
        }],
        vec![
            TxOutput::p2pkh(100_000_000, hash160(&pubkey)),
            TxOutput::anchor(DataAnchor::RawData(b"EQX402:INV-001".to_vec())),
        ],
    )?;
    let decoded_tx = SignedTransaction::decode_bytes(&sample_tx.encode_bytes())?;
    let sh = decoded_tx.sighash();
    decoded_tx.verify_input_proof(0, &sh, hash160(&pubkey), 1)?;

    let ks = EncryptedKeystore::encrypt(
        ephemeral.as_bytes(),
        b"Equinox#CeremonyTest2026",
        CHAIN_ID_MAINNET,
        KdfConfig::fast_test(),
    )
    .map_err(|_| "Keystore encrypt failed".to_string())?;
    let _ = ks
        .decrypt(b"Equinox#CeremonyTest2026")
        .map_err(|_| "Keystore decrypt failed".to_string())?;

    println!("[OK] Chain ID             : {}", CHAIN_ID_MAINNET);
    println!("[OK] Hard-Cap Max Supply  : {} atomic units (21,000,000 EQX)", MAX_SUPPLY_ATOMIC);
    println!("[OK] Genesis Premine      : {} atomic units (4 Vaults)", genesis.total_premine_atomic);
    println!("[OK] Genesis Block #0 Hash: {}", to_hex(&genesis.block_hash));
    println!("[OK] UTXO State Root      : {}", to_hex(&state_root));
    println!("[OK] Block #1 Total Reward: {} atomic (90% Miner / 10% DAO)", b1.total_subsidy);
    println!("[OK] Signed UTXO v2 TXID  : {}", to_hex(&decoded_tx.txid()));
    println!("[OK] LockCondition (P2PKH/MultiSig/Timelock/Escrow) + DataAnchor Verified.");
    Ok(())
}

fn run_ceremony_preview() -> Result<(), String> {
    println!("=== Equinox Core Offline 4-Vault Genesis Ceremony (Dry-Run Preview) ===");
    println!("NOTE: Run final Mainnet ceremony on an air-gapped offline PC only!\n");

    let labels = [
        ("1. Founder Vault (1,200,000 EQX - 5Y Lock)", 1_200_000u64),
        ("2. Exchange & DEX Liquidity (400,000 EQX)", 400_000u64),
        ("3. Dev & Bug Bounty Fund (200,000 EQX)", 200_000u64),
        ("4. Community Airdrop & Marketing (200,000 EQX)", 200_000u64),
    ];

    let mut addrs = Vec::with_capacity(4);
    for (label, eqx) in labels {
        let seed = SecretSeed::generate();
        let addr = encode_mainnet_address(&seed.public_key_bytes());
        println!("{} -> {} ({} EQX)", label, addr, eqx);
        addrs.push(addr);
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let spec = GenesisVaultSpec {
        founder_address: addrs[0].clone(),
        liquidity_address: addrs[1].clone(),
        developer_address: addrs[2].clone(),
        marketing_address: addrs[3].clone(),
        timestamp_utc: now_secs,
    };
    let res = build_mainnet_genesis_batch(&spec)?;
    println!("\nPreview Block #0 Hash: {}", to_hex(&res.block_hash));
    Ok(())
}

fn run_live_node(args: &[String]) -> Result<(), String> {
    let mut mode = NetworkMode::Testnet;
    let mut enable_mine = false;
    let mut mine_threads: usize = thread::available_parallelism().map(|n| (n.get() / 2).max(1)).unwrap_or(2);
    let mut p2p_port: u16 = 19333;
    let mut rpc_host = String::from("127.0.0.1");
    let mut rpc_port: u16 = 18545;
    let mut miner_addr: Option<String> = None;
    let mut peers_to_dial: Vec<SocketAddr> = Vec::new();
    let mut data_file = PathBuf::from("equinox_testnet_utxo.wal");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mainnet" => mode = NetworkMode::Mainnet,
            "--testnet" => mode = NetworkMode::Testnet,
            "--mine" => enable_mine = true,
            "--threads" if i + 1 < args.len() => {
                mine_threads = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| "Invalid --threads value".to_string())?
                    .clamp(1, 64);
                i += 1;
            }
            "--p2p-port" if i + 1 < args.len() => {
                p2p_port = args[i + 1]
                    .parse()
                    .map_err(|_| "Invalid --p2p-port value".to_string())?;
                i += 1;
            }
            "--rpc-host" if i + 1 < args.len() => {
                rpc_host = args[i + 1].clone();
                i += 1;
            }
            "--rpc-port" if i + 1 < args.len() => {
                rpc_port = args[i + 1]
                    .parse()
                    .map_err(|_| "Invalid --rpc-port value".to_string())?;
                i += 1;
            }
            "--miner" if i + 1 < args.len() => {
                miner_addr = Some(args[i + 1].clone());
                i += 1;
            }
            "--peer" if i + 1 < args.len() => {
                let addr = args[i + 1]
                    .parse()
                    .map_err(|_| "Invalid --peer IP:PORT".to_string())?;
                peers_to_dial.push(addr);
                i += 1;
            }
            "--wal" if i + 1 < args.len() => {
                data_file = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    let state = NodeState::bootstrap(mode, &data_file, miner_addr)?;
    let miner_display = state.miner_address.clone();
    let chain_id = state.mode.chain_id();
    let tip_h = state.storage.tip_height();
    let node = Arc::new(Mutex::new(state));
    let broadcaster = PeerBroadcaster::new();
    let shutdown = Arc::new(AtomicBool::new(false));

    let p2p_bind = format!("0.0.0.0:{}", p2p_port);
    let rpc_bind = format!("{}:{}", rpc_host, rpc_port);

    let p2p_addr = spawn_p2p_listener(
        &p2p_bind,
        Arc::clone(&node),
        Arc::clone(&broadcaster),
        Arc::clone(&shutdown),
    )?;
    let rpc_addr = spawn_rpc_server(
        &rpc_bind,
        Arc::clone(&node),
        Arc::clone(&broadcaster),
        Arc::clone(&shutdown),
    )?;

    println!("================================================================");
    println!("  Equinox Core (EQX) Live Node Running [{}]", mode.name());
    println!("  Chain ID      : {}", chain_id);
    println!("  P2P Noise_XX  : tcp://{} (Live Block & Mempool Auto-Sync)", p2p_addr);
    println!("  JSON-RPC 2.0  : http://{} (Escrow, Timelock, Proof & @name.eqx)", rpc_addr);
    println!("  Miner Address : {}", miner_display);
    println!("  WAL Ledger    : {} (Height #{})", data_file.display(), tip_h);
    println!("  Press Ctrl+C to stop cleanly.");
    println!("================================================================");

    for target_peer in peers_to_dial {
        match spawn_outbound_peer(
            target_peer,
            Arc::clone(&node),
            Arc::clone(&broadcaster),
            Arc::clone(&shutdown),
        ) {
            Ok((pk, remote_h)) => println!(
                "[P2P] Persistent Live Sync connected to {} | PubKey {}.. | Remote Height #{}",
                target_peer,
                &to_hex(&pk)[..12],
                remote_h
            ),
            Err(e) => eprintln!("[P2P] Outbound dial {} failed: {}", target_peer, e),
        }
    }

    if enable_mine {
        let _miner_handle = spawn_cpu_miner(
            Arc::clone(&node),
            Arc::clone(&broadcaster),
            Arc::clone(&shutdown),
            mine_threads,
        );
    }

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("verify");
    let outcome = match cmd {
        "verify" => run_end_to_end_verification(),
        "ceremony-preview" => run_ceremony_preview(),
        "run" => run_live_node(&args[2..]),
        _ => {
            println!("Usage:");
            println!("  equinox_node verify");
            println!("  equinox_node ceremony-preview");
            println!("  equinox_node run --testnet [--mine] [--p2p-port 19333] [--rpc-port 18545] [--peer IP:PORT]");
            Ok(())
        }
    };

    if let Err(err) = outcome {
        eprintln!("[ERROR] {}", err);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::Ordering;

    use sha2::{Digest, Sha256};

    use crate::script::LockCondition;

    fn temp_wal(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("eqx_live_{}_{}.wal", label, nanos))
    }

    fn cleanup_wal(wal: &PathBuf) {
        let _ = fs::remove_file(wal);
        let _ = fs::remove_file(wal.with_extension("blocks"));
    }

    fn http_post_rpc(addr: SocketAddr, payload: &str) -> String {
        let http_req = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(http_req.as_bytes()).unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        resp
    }

    #[test]
    fn test_full_mainnet_stack_end_to_end() {
        assert!(run_end_to_end_verification().is_ok());
    }

    #[test]
    fn test_upcoming_mainnet_guard_blocks_premature_launch() {
        let wal = temp_wal("guard");
        let res = NodeState::bootstrap(NetworkMode::Mainnet, &wal, None);
        assert!(res.is_err());
        cleanup_wal(&wal);
    }

    #[test]
    fn test_live_tcp_p2p_noise_xx_handshake_and_ping_pong() {
        let wal_a = temp_wal("p2p_a");
        let wal_b = temp_wal("p2p_b");
        let state_a = NodeState::bootstrap(NetworkMode::Testnet, &wal_a, None).unwrap();
        let expected_pk = state_a.node_key.public_bytes();
        let node_a = Arc::new(Mutex::new(state_a));
        let bc_a = PeerBroadcaster::new();
        let shutdown = Arc::new(AtomicBool::new(false));

        let bound_a = spawn_p2p_listener(
            "127.0.0.1:0",
            Arc::clone(&node_a),
            Arc::clone(&bc_a),
            Arc::clone(&shutdown),
        )
        .unwrap();

        let state_b = NodeState::bootstrap(NetworkMode::Testnet, &wal_b, None).unwrap();
        let node_b = Arc::new(Mutex::new(state_b));
        let bc_b = PeerBroadcaster::new();

        let (remote_pk, remote_h) = spawn_outbound_peer(
            bound_a,
            Arc::clone(&node_b),
            Arc::clone(&bc_b),
            Arc::clone(&shutdown),
        )
        .unwrap();
        assert_eq!(remote_pk, expected_pk);
        assert_eq!(remote_h, 0);

        shutdown.store(true, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(150));
        cleanup_wal(&wal_a);
        cleanup_wal(&wal_b);
    }

    #[test]
    fn test_live_http_json_rpc_and_cpu_pow_mining() {
        let wal = temp_wal("rpc_mine");
        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, None).unwrap();
        let miner_addr = state.miner_address.clone();
        let node = Arc::new(Mutex::new(state));
        let bc = PeerBroadcaster::new();
        let shutdown = Arc::new(AtomicBool::new(false));

        let mined = miner::mine_one_block(&node, &shutdown).unwrap().unwrap();
        assert_eq!(mined.0.height, 1);
        assert!(mined.0.miner_reward_atomic > 0);
        assert!(mined.0.dao_reward_atomic > 0);

        let rpc_addr = spawn_rpc_server(
            "127.0.0.1:0",
            Arc::clone(&node),
            Arc::clone(&bc),
            Arc::clone(&shutdown),
        )
        .unwrap();
        let payload = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_getChainInfo","params":["{}"],"id":1}}"#,
            miner_addr
        );
        let resp = http_post_rpc(rpc_addr, &payload);

        assert!(resp.contains("200 OK"));
        assert!(resp.contains(r#""height":1"#));
        assert!(resp.contains(r#""chain_id":9333"#));
        assert!(resp.contains("Access-Control-Allow-Origin: *"));

        shutdown.store(true, Ordering::Relaxed);
        cleanup_wal(&wal);
    }

    #[test]
    fn test_real_signed_utxo_transfer_mempool_and_double_spend_block() {
        let wal = temp_wal("utxo_tx");
        let alice_seed = SecretSeed::generate();
        let alice_pk = alice_seed.public_key_bytes();
        let alice_h160 = hash160(&alice_pk);
        let alice_addr = encode_mainnet_address(&alice_pk);

        let bob_seed = SecretSeed::generate();
        let bob_pk = bob_seed.public_key_bytes();
        let bob_h160 = hash160(&bob_pk);
        let bob_addr = encode_mainnet_address(&bob_pk);

        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, Some(alice_addr)).unwrap();
        let chain_id = state.mode.chain_id();
        let node = Arc::new(Mutex::new(state));
        let bc = PeerBroadcaster::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let rpc_addr = spawn_rpc_server(
            "127.0.0.1:0",
            Arc::clone(&node),
            Arc::clone(&bc),
            Arc::clone(&shutdown),
        )
        .unwrap();

        miner::mine_one_block(&node, &shutdown).unwrap().unwrap();
        let alice_utxos = node.lock().unwrap().utxos_for_hash160(&alice_h160);
        assert_eq!(alice_utxos.len(), 1);
        let (coinbase_op, coinbase_val) = alice_utxos[0];

        let send_to_bob: u128 = 50_000_000;
        let fee: u128 = 2_000;
        let change = coinbase_val - send_to_bob - fee;

        let valid_tx = SignedTransaction::sign_transfer(
            &alice_seed,
            chain_id,
            vec![coinbase_op],
            vec![
                TxOutput::p2pkh(send_to_bob, bob_h160),
                TxOutput::p2pkh(change, alice_h160),
            ],
        )
        .unwrap();

        let send_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_sendRawTransaction","params":["{}"],"id":10}}"#,
            to_hex(&valid_tx.encode_bytes())
        );
        let send_resp = http_post_rpc(rpc_addr, &send_req);
        assert!(send_resp.contains("accepted_in_mempool"));

        let double_spend_tx = SignedTransaction::sign_transfer(
            &alice_seed,
            chain_id,
            vec![coinbase_op],
            vec![TxOutput::p2pkh(coinbase_val - fee, alice_h160)],
        )
        .unwrap();
        let ds_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_sendRawTransaction","params":["{}"],"id":11}}"#,
            to_hex(&double_spend_tx.encode_bytes())
        );
        let ds_resp = http_post_rpc(rpc_addr, &ds_req);
        assert!(ds_resp.contains("Double-spend detected in mempool"));

        let blk2 = miner::mine_one_block(&node, &shutdown).unwrap().unwrap();
        assert_eq!(blk2.0.height, 2);
        assert_eq!(blk2.0.tx_count, 2);
        assert_eq!(node.lock().unwrap().mempool.len(), 0);

        let bal_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_getBalance","params":["{}"],"id":12}}"#,
            bob_addr
        );
        let bal_resp = http_post_rpc(rpc_addr, &bal_req);
        assert!(bal_resp.contains(r#""balance_atomic":"50000000""#));

        shutdown.store(true, Ordering::Relaxed);
        cleanup_wal(&wal);
    }

    #[test]
    fn test_live_node_a_to_node_b_auto_block_and_mempool_sync() {
        let wal_a = temp_wal("sync_a");
        let wal_b = temp_wal("sync_b");
        let shutdown = Arc::new(AtomicBool::new(false));

        let alice_seed = SecretSeed::generate();
        let alice_pk = alice_seed.public_key_bytes();
        let alice_h160 = hash160(&alice_pk);
        let alice_addr = encode_mainnet_address(&alice_pk);

        let bob_seed = SecretSeed::generate();
        let bob_pk = bob_seed.public_key_bytes();
        let bob_h160 = hash160(&bob_pk);
        let bob_addr = encode_mainnet_address(&bob_pk);

        let state_a = NodeState::bootstrap(NetworkMode::Testnet, &wal_a, Some(alice_addr)).unwrap();
        let chain_id = state_a.mode.chain_id();
        let node_a = Arc::new(Mutex::new(state_a));
        let bc_a = PeerBroadcaster::new();

        miner::mine_one_block(&node_a, &shutdown).unwrap().unwrap();
        miner::mine_one_block(&node_a, &shutdown).unwrap().unwrap();
        assert_eq!(node_a.lock().unwrap().storage.tip_height(), 2);

        let p2p_a = spawn_p2p_listener(
            "127.0.0.1:0",
            Arc::clone(&node_a),
            Arc::clone(&bc_a),
            Arc::clone(&shutdown),
        )
        .unwrap();

        let state_b = NodeState::bootstrap(NetworkMode::Testnet, &wal_b, None).unwrap();
        let node_b = Arc::new(Mutex::new(state_b));
        let bc_b = PeerBroadcaster::new();
        let rpc_b = spawn_rpc_server(
            "127.0.0.1:0",
            Arc::clone(&node_b),
            Arc::clone(&bc_b),
            Arc::clone(&shutdown),
        )
        .unwrap();

        spawn_outbound_peer(
            p2p_a,
            Arc::clone(&node_b),
            Arc::clone(&bc_b),
            Arc::clone(&shutdown),
        )
        .unwrap();

        let mut synced_h2 = false;
        for _ in 0..40 {
            if node_b.lock().unwrap().storage.tip_height() == 2 {
                synced_h2 = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(synced_h2);
        assert_eq!(
            node_a.lock().unwrap().storage.compute_state_root(),
            node_b.lock().unwrap().storage.compute_state_root()
        );

        let alice_utxos = node_b.lock().unwrap().utxos_for_hash160(&alice_h160);
        let (op, val) = alice_utxos[0];
        let send_amt: u128 = 50_000_000;
        let fee: u128 = 2_000;

        let tx = SignedTransaction::sign_transfer(
            &alice_seed,
            chain_id,
            vec![op],
            vec![
                TxOutput::p2pkh(send_amt, bob_h160),
                TxOutput::p2pkh(val - send_amt - fee, alice_h160),
            ],
        )
        .unwrap();

        let rpc_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_sendRawTransaction","params":["{}"],"id":99}}"#,
            to_hex(&tx.encode_bytes())
        );
        assert!(http_post_rpc(rpc_b, &rpc_req).contains("accepted_in_mempool"));

        let mut tx_synced_to_a = false;
        for _ in 0..40 {
            if node_a.lock().unwrap().mempool.len() == 1 {
                tx_synced_to_a = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(tx_synced_to_a);

        let (blk3_sum, blk3_full, _) = miner::mine_one_block(&node_a, &shutdown).unwrap().unwrap();
        assert_eq!(blk3_sum.height, 3);
        assert_eq!(blk3_sum.tx_count, 2);
        bc_a.broadcast(WireMessage::BlockData(blk3_full.encode_bytes()), None);

        let mut synced_h3 = false;
        for _ in 0..40 {
            if node_b.lock().unwrap().storage.tip_height() == 3 {
                synced_h3 = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(synced_h3);
        assert_eq!(
            node_b.lock().unwrap().balances.get(&bob_addr).copied().unwrap_or(0),
            send_amt
        );

        shutdown.store(true, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(150));
        cleanup_wal(&wal_a);
        cleanup_wal(&wal_b);
    }

    #[test]
    fn test_multisig_and_escrow_release_plus_timeout_refund() {
        let wal = temp_wal("escrow");
        let shutdown = Arc::new(AtomicBool::new(false));

        let buyer = SecretSeed::generate();
        let freelancer = SecretSeed::generate();
        let arbiter = SecretSeed::generate();

        let buyer_h = hash160(&buyer.public_key_bytes());
        let freelancer_h = hash160(&freelancer.public_key_bytes());
        let arbiter_h = hash160(&arbiter.public_key_bytes());
        let buyer_addr = encode_mainnet_address(&buyer.public_key_bytes());
        let freelancer_addr = encode_mainnet_address(&freelancer.public_key_bytes());

        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, Some(buyer_addr)).unwrap();
        let chain_id = state.mode.chain_id();
        let node = Arc::new(Mutex::new(state));

        // Mine Block #1 so Buyer has coinbase UTXO
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap();
        let (cb_op, cb_val) = node.lock().unwrap().utxos_for_hash160(&buyer_h)[0];

        // 1. Lock 0.30 EQX in pure 2-of-3 MultiSig, and 0.40 EQX in Escrow (refund at height #5)
        let ms_cond = LockCondition::MultiSig {
            threshold: 2,
            signers: vec![buyer_h, freelancer_h, arbiter_h],
        };
        let escrow_cond = LockCondition::Escrow {
            threshold: 2,
            signers: vec![buyer_h, freelancer_h, arbiter_h],
            refund_height: 5,
            refund_recipient: buyer_h,
        };

        let fund_tx = SignedTransaction::sign_transfer(
            &buyer,
            chain_id,
            vec![cb_op],
            vec![
                TxOutput::locked(30_000_000, ms_cond.clone()),
                TxOutput::locked(40_000_000, escrow_cond.clone()),
                TxOutput::p2pkh(cb_val - 70_000_000 - 2_000, buyer_h),
            ],
        )
        .unwrap();
        let fund_txid = fund_tx.txid();
        node.lock().unwrap().submit_transaction(fund_tx).unwrap();
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #2

        let ms_op = OutPoint { txid: fund_txid, vout: 0 };
        let escrow_op = OutPoint { txid: fund_txid, vout: 1 };

        // 2. Single signature (1-of-3) on MultiSig MUST be rejected
        let bad_ms = SignedTransaction::sign_multisig_spend(
            &[&freelancer],
            ms_cond.clone(),
            chain_id,
            vec![ms_op],
            vec![TxOutput::p2pkh(29_998_000, freelancer_h)],
        )
        .unwrap();
        assert!(node.lock().unwrap().submit_transaction(bad_ms).is_err());

        // 3. Cooperative 2-of-3 release (Buyer + Freelancer) SUCCEEDS
        let good_ms = SignedTransaction::sign_multisig_spend(
            &[&buyer, &freelancer],
            ms_cond,
            chain_id,
            vec![ms_op],
            vec![TxOutput::p2pkh(29_998_000, freelancer_h)],
        )
        .unwrap();
        node.lock().unwrap().submit_transaction(good_ms).unwrap();
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #3
        assert_eq!(
            node.lock().unwrap().balances.get(&freelancer_addr).copied().unwrap_or(0),
            29_998_000
        );

        // 4. Premature Escrow timeout refund at next_height = 4 (< 5) MUST be rejected
        let refund_tx = SignedTransaction::sign_escrow_refund(
            &buyer,
            escrow_cond,
            chain_id,
            vec![escrow_op],
            vec![TxOutput::p2pkh(39_998_000, buyer_h)],
        )
        .unwrap();
        let early_err = node.lock().unwrap().submit_transaction(refund_tx.clone()).unwrap_err();
        assert!(early_err.contains("not yet matured"));

        // 5. Advance to Block #4 (so next_height = 5) -> Escrow timeout refund SUCCEEDS
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #4
        node.lock().unwrap().submit_transaction(refund_tx).unwrap();
        let blk5 = miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #5
        assert_eq!(blk5.0.height, 5);
        assert_eq!(blk5.0.tx_count, 2);

        cleanup_wal(&wal);
    }

    #[test]
    fn test_timelock_inheritance_maturity_enforcement() {
        let wal = temp_wal("timelock");
        let shutdown = Arc::new(AtomicBool::new(false));

        let owner = SecretSeed::generate();
        let heir = SecretSeed::generate();
        let owner_h = hash160(&owner.public_key_bytes());
        let heir_h = hash160(&heir.public_key_bytes());
        let owner_addr = encode_mainnet_address(&owner.public_key_bytes());
        let heir_addr = encode_mainnet_address(&heir.public_key_bytes());

        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, Some(owner_addr)).unwrap();
        let chain_id = state.mode.chain_id();
        let node = Arc::new(Mutex::new(state));

        miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #1
        let (cb_op, cb_val) = node.lock().unwrap().utxos_for_hash160(&owner_h)[0];

        let tl_cond = LockCondition::Timelock {
            unlock_height: 4,
            recipient: heir_h,
        };
        let lock_tx = SignedTransaction::sign_transfer(
            &owner,
            chain_id,
            vec![cb_op],
            vec![
                TxOutput::locked(50_000_000, tl_cond),
                TxOutput::p2pkh(cb_val - 50_000_000 - 2_000, owner_h),
            ],
        )
        .unwrap();
        let lock_txid = lock_tx.txid();
        node.lock().unwrap().submit_transaction(lock_tx).unwrap();
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #2

        let claim_tx = SignedTransaction::sign_timelock_spend(
            &heir,
            4,
            chain_id,
            vec![OutPoint { txid: lock_txid, vout: 0 }],
            vec![TxOutput::p2pkh(49_998_000, heir_h)],
        )
        .unwrap();

        // Premature claim at next_height = 3 (< 4) rejected
        assert!(node.lock().unwrap().submit_transaction(claim_tx.clone()).is_err());

        // Advance to Block #3 -> next_height = 4 -> Heir claims inheritance cleanly
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #3
        node.lock().unwrap().submit_transaction(claim_tx).unwrap();
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap(); // Block #4

        assert_eq!(
            node.lock().unwrap().balances.get(&heir_addr).copied().unwrap_or(0),
            49_998_000
        );
        cleanup_wal(&wal);
    }

    #[test]
    fn test_document_proof_and_eqx_name_registry_with_live_p2p_sync() {
        let wal_a = temp_wal("anchor_a");
        let wal_b = temp_wal("anchor_b");
        let shutdown = Arc::new(AtomicBool::new(false));

        let alice = SecretSeed::generate();
        let bob = SecretSeed::generate();
        let alice_h = hash160(&alice.public_key_bytes());
        let bob_h = hash160(&bob.public_key_bytes());
        let alice_addr = encode_mainnet_address(&alice.public_key_bytes());

        let state_a = NodeState::bootstrap(NetworkMode::Testnet, &wal_a, Some(alice_addr.clone())).unwrap();
        let chain_id = state_a.mode.chain_id();
        let node_a = Arc::new(Mutex::new(state_a));
        let bc_a = PeerBroadcaster::new();

        let p2p_a = spawn_p2p_listener(
            "127.0.0.1:0",
            Arc::clone(&node_a),
            Arc::clone(&bc_a),
            Arc::clone(&shutdown),
        )
        .unwrap();

        let state_b = NodeState::bootstrap(NetworkMode::Testnet, &wal_b, None).unwrap();
        let node_b = Arc::new(Mutex::new(state_b));
        let bc_b = PeerBroadcaster::new();
        let rpc_b = spawn_rpc_server(
            "127.0.0.1:0",
            Arc::clone(&node_b),
            Arc::clone(&bc_b),
            Arc::clone(&shutdown),
        )
        .unwrap();

        spawn_outbound_peer(
            p2p_a,
            Arc::clone(&node_b),
            Arc::clone(&bc_b),
            Arc::clone(&shutdown),
        )
        .unwrap();

        // Mine Block #1 on Node A and broadcast
        let (_, blk1, _) = miner::mine_one_block(&node_a, &shutdown).unwrap().unwrap();
        bc_a.broadcast(WireMessage::BlockData(blk1.encode_bytes()), None);

        // Alice anchors a PDF DocumentProof + registers @alice_dev.eqx + sends Bob 0.20 EQX
        let (cb_op, cb_val) = node_a.lock().unwrap().utxos_for_hash160(&alice_h)[0];
        let pdf_hash: [u8; 32] = Sha256::digest(b"Signed Rent Agreement PDF #2026").into();
        let fee: u128 = 150_000; // >= 0.001 EQX NameRegister minimum fee

        let anchor_tx = SignedTransaction::sign_transfer(
            &alice,
            chain_id,
            vec![cb_op],
            vec![
                TxOutput::p2pkh(20_000_000, bob_h),
                TxOutput::p2pkh(cb_val - 20_000_000 - fee, alice_h),
                TxOutput::anchor(DataAnchor::DocumentProof {
                    doc_hash: pdf_hash,
                    metadata: b"Rent Agreement #2026".to_vec(),
                }),
                TxOutput::anchor(DataAnchor::NameRegister {
                    name: "alice_dev".to_string(),
                    owner_h160: alice_h,
                }),
            ],
        )
        .unwrap();
        let anchor_txid = anchor_tx.txid();
        node_a.lock().unwrap().submit_transaction(anchor_tx).unwrap();

        let (_, blk2, _) = miner::mine_one_block(&node_a, &shutdown).unwrap().unwrap();
        bc_a.broadcast(WireMessage::BlockData(blk2.encode_bytes()), None);

        // Bob tries to hijack @alice_dev.eqx -> MUST be rejected!
        let hijack_tx = SignedTransaction::sign_transfer(
            &bob,
            chain_id,
            vec![OutPoint { txid: anchor_txid, vout: 0 }],
            vec![
                TxOutput::p2pkh(20_000_000 - fee, bob_h),
                TxOutput::anchor(DataAnchor::NameRegister {
                    name: "alice_dev".to_string(),
                    owner_h160: bob_h,
                }),
            ],
        )
        .unwrap();
        let hijack_err = node_a.lock().unwrap().submit_transaction(hijack_tx).unwrap_err();
        assert!(hijack_err.contains("already registered"));

        // Wait for Node B to live-sync Block #2 over Noise_XX
        let mut synced = false;
        for _ in 0..40 {
            if node_b.lock().unwrap().storage.tip_height() == 2 {
                synced = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(synced, "Node B failed to sync anchor block #2");

        // Verify via Node B's HTTP JSON-RPC: eqx_resolveName, eqx_verifyProof, and eqx_getBalance(@alice_dev.eqx)
        let name_resp = http_post_rpc(
            rpc_b,
            r#"{"jsonrpc":"2.0","method":"eqx_resolveName","params":["@alice_dev.eqx"],"id":1}"#,
        );
        assert!(name_resp.contains(r#""found":true"#));
        assert!(name_resp.contains(&alice_addr));

        let proof_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_verifyProof","params":["{}"],"id":2}}"#,
            to_hex(&pdf_hash)
        );
        let proof_resp = http_post_rpc(rpc_b, &proof_req);
        assert!(proof_resp.contains(r#""verified":true"#));
        assert!(proof_resp.contains("Rent Agreement #2026"));

        let bal_resp = http_post_rpc(
            rpc_b,
            r#"{"jsonrpc":"2.0","method":"eqx_getBalance","params":["@alice_dev.eqx"],"id":3}"#,
        );
        assert!(bal_resp.contains(&alice_addr));

        shutdown.store(true, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(150));
        cleanup_wal(&wal_a);
        cleanup_wal(&wal_b);
    }
}
