#![forbid(unsafe_code)]

mod genesis;
mod mempool;
mod miner;
mod p2p_tcp;
mod rpc_http;
mod runtime;
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
use crate::p2p_tcp::{dial_and_verify_peer, spawn_p2p_listener};
use crate::rpc_http::spawn_rpc_server;
use crate::runtime::{NetworkMode, NodeState};
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

    // Verify canonical SignedTransaction roundtrip
    let sample_tx = SignedTransaction::sign_transfer(
        &ephemeral,
        CHAIN_ID_MAINNET,
        vec![OutPoint {
            txid: genesis.block_hash,
            vout: 0,
        }],
        vec![TxOutput {
            value_atomic: 100_000_000,
            script_hash160: hash160(&pubkey),
        }],
    )?;
    let decoded_tx = SignedTransaction::decode_bytes(&sample_tx.encode_bytes())?;
    decoded_tx.verify_signatures()?;

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
    println!("[OK] Signed UTXO TXID     : {}", to_hex(&decoded_tx.txid()));
    println!("[OK] Noise_XX E2EE + Ed25519 + Argon2id Keystore Verified.");
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
    let mut p2p_port: u16 = 19333;
    let mut rpc_port: u16 = 18545;
    let mut miner_addr: Option<String> = None;
    let mut peer_to_dial: Option<SocketAddr> = None;
    let mut data_file = PathBuf::from("equinox_testnet_utxo.wal");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mainnet" => mode = NetworkMode::Mainnet,
            "--testnet" => mode = NetworkMode::Testnet,
            "--mine" => enable_mine = true,
            "--p2p-port" if i + 1 < args.len() => {
                p2p_port = args[i + 1]
                    .parse()
                    .map_err(|_| "Invalid --p2p-port value".to_string())?;
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
                peer_to_dial = Some(
                    args[i + 1]
                        .parse()
                        .map_err(|_| "Invalid --peer IP:PORT".to_string())?,
                );
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
    let prologue = state.mode.noise_prologue();
    let chain_id = state.mode.chain_id();
    let tip_h = state.storage.tip_height();
    let node = Arc::new(Mutex::new(state));
    let shutdown = Arc::new(AtomicBool::new(false));

    let p2p_bind = format!("0.0.0.0:{}", p2p_port);
    let rpc_bind = format!("127.0.0.1:{}", rpc_port);

    let p2p_addr = spawn_p2p_listener(&p2p_bind, Arc::clone(&node), Arc::clone(&shutdown))?;
    let rpc_addr = spawn_rpc_server(&rpc_bind, Arc::clone(&node), Arc::clone(&shutdown))?;

    println!("================================================================");
    println!("  Equinox Core (EQX) Live Node Running [{}]", mode.name());
    println!("  Chain ID      : {}", chain_id);
    println!("  P2P Noise_XX  : tcp://{} (E2EE + Rate-Limited)", p2p_addr);
    println!("  JSON-RPC 2.0  : http://{} (Wallet, Mempool & Explorer API)", rpc_addr);
    println!("  Miner Address : {}", miner_display);
    println!("  WAL Ledger    : {} (Height #{})", data_file.display(), tip_h);
    println!("  Press Ctrl+C to stop cleanly.");
    println!("================================================================");

    if let Some(target_peer) = peer_to_dial {
        match dial_and_verify_peer(target_peer, prologue, chain_id, tip_h) {
            Ok((pk, remote_h)) => println!(
                "[P2P] Connected outbound to {} | PubKey {}.. | Height #{}",
                target_peer,
                &to_hex(&pk)[..12],
                remote_h
            ),
            Err(e) => eprintln!("[P2P] Outbound dial {} failed: {}", target_peer, e),
        }
    }

    if enable_mine {
        let _miner_handle = spawn_cpu_miner(Arc::clone(&node), Arc::clone(&shutdown));
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
            println!("  equinox_node run --testnet [--mine] [--p2p-port 19333] [--rpc-port 18545] [--miner E...]");
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

    fn temp_wal(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("eqx_live_{}_{}.wal", label, nanos))
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
        let _ = fs::remove_file(wal);
    }

    #[test]
    fn test_live_tcp_p2p_noise_xx_handshake_and_ping_pong() {
        let wal = temp_wal("p2p");
        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, None).unwrap();
        let expected_pk = state.node_key.public_bytes();
        let prologue = state.mode.noise_prologue();
        let chain_id = state.mode.chain_id();

        let node = Arc::new(Mutex::new(state));
        let shutdown = Arc::new(AtomicBool::new(false));
        let bound = spawn_p2p_listener("127.0.0.1:0", Arc::clone(&node), Arc::clone(&shutdown)).unwrap();

        let (remote_pk, remote_h) = dial_and_verify_peer(bound, prologue, chain_id, 0).unwrap();
        assert_eq!(remote_pk, expected_pk);
        assert_eq!(remote_h, 0);

        shutdown.store(true, Ordering::Relaxed);
        let _ = fs::remove_file(wal);
    }

    #[test]
    fn test_live_http_json_rpc_and_cpu_pow_mining() {
        let wal = temp_wal("rpc_mine");
        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, None).unwrap();
        let miner_addr = state.miner_address.clone();
        let node = Arc::new(Mutex::new(state));
        let shutdown = Arc::new(AtomicBool::new(false));

        let mined = miner::mine_one_block(&node, &shutdown).unwrap().unwrap();
        assert_eq!(mined.0.height, 1);
        assert!(mined.0.miner_reward_atomic > 0);
        assert!(mined.0.dao_reward_atomic > 0);

        let rpc_addr = spawn_rpc_server("127.0.0.1:0", Arc::clone(&node), Arc::clone(&shutdown)).unwrap();
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
        let _ = fs::remove_file(wal);
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

        let state = NodeState::bootstrap(NetworkMode::Testnet, &wal, Some(alice_addr.clone())).unwrap();
        let chain_id = state.mode.chain_id();
        let node = Arc::new(Mutex::new(state));
        let shutdown = Arc::new(AtomicBool::new(false));
        let rpc_addr = spawn_rpc_server("127.0.0.1:0", Arc::clone(&node), Arc::clone(&shutdown)).unwrap();

        // 1. Mine Block #1 so Alice receives a real spendable coinbase UTXO
        miner::mine_one_block(&node, &shutdown).unwrap().unwrap();
        let alice_utxos = node.lock().unwrap().utxos_for_hash160(&alice_h160);
        assert_eq!(alice_utxos.len(), 1);
        let (coinbase_op, coinbase_val) = alice_utxos[0];

        // 2. Alice signs a real UTXO transfer sending 0.50 EQX to Bob + change back to Alice + 2000 atomic fee
        let send_to_bob: u128 = 50_000_000;
        let fee: u128 = 2_000;
        let change = coinbase_val - send_to_bob - fee;

        let valid_tx = SignedTransaction::sign_transfer(
            &alice_seed,
            chain_id,
            vec![coinbase_op],
            vec![
                TxOutput {
                    value_atomic: send_to_bob,
                    script_hash160: bob_h160,
                },
                TxOutput {
                    value_atomic: change,
                    script_hash160: alice_h160,
                },
            ],
        )
        .unwrap();

        // Submit via live HTTP JSON-RPC eqx_sendRawTransaction
        let send_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_sendRawTransaction","params":["{}"],"id":10}}"#,
            to_hex(&valid_tx.encode_bytes())
        );
        let send_resp = http_post_rpc(rpc_addr, &send_req);
        assert!(send_resp.contains("accepted_in_mempool"));

        // 3. Double-spend attempt spending the exact same coinbase_op must be blocked
        let double_spend_tx = SignedTransaction::sign_transfer(
            &alice_seed,
            chain_id,
            vec![coinbase_op],
            vec![TxOutput {
                value_atomic: coinbase_val - fee,
                script_hash160: alice_h160,
            }],
        )
        .unwrap();
        let ds_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eqx_sendRawTransaction","params":["{}"],"id":11}}"#,
            to_hex(&double_spend_tx.encode_bytes())
        );
        let ds_resp = http_post_rpc(rpc_addr, &ds_req);
        assert!(ds_resp.contains("Double-spend detected in mempool"));

        // 4. Unauthorized theft attempt: Bob signing Alice's UTXO must fail ownership check
        let theft_tx = SignedTransaction::sign_transfer(
            &bob_seed,
            chain_id,
            vec![coinbase_op],
            vec![TxOutput {
                value_atomic: coinbase_val - fee,
                script_hash160: bob_h160,
            }],
        )
        .unwrap();
        assert!(node.lock().unwrap().submit_transaction(theft_tx).is_err());

        // 5. Mine Block #2 -> must confirm Alice->Bob tx, clear mempool, and credit Bob's balance
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
        assert!(bal_resp.contains(r#""balance_eqx":"0.50000000""#));

        shutdown.store(true, Ordering::Relaxed);
        let _ = fs::remove_file(wal);
    }
}
