#![allow(dead_code)]
// src/main.rs
// Equinox (EQX) L1 — Audit-Grade Mainnet & Testnet Full Node, Fresh Wallet Generator ('new-wallet'),
// Live P2P TCP Server (Port 9333), Background Sync & Tx Relay Worker, 1.70% Royalty Split & JSON-RPC 2.0.

pub mod config;
pub mod consensus;
pub mod crypto;
pub mod dex;
pub mod gui_wallet;
pub mod mempool;
pub mod network;
pub mod primitives;
pub mod rpc;
pub use rpc::rpc_server;
pub mod state;
pub mod storage;
pub mod wallet;

use crate::config::{
    CHAIN_ID, DAA_AVERAGING_WINDOW, DEFAULT_P2P_PORT, DEFAULT_RPC_PORT, MAX_SUPPLY,
    PROTOCOL_VERSION, SYMBOL, TOKEN_NAME,
};
use crate::consensus::fork_choice::ForkResolver;
use crate::consensus::pow::{ProofOfWorkEngine, DEFAULT_INITIAL_DIFFICULTY_BITS};
use crate::consensus::royalty::ProtocolRoyaltyEngine;
use crate::consensus::tokenomics::TokenomicsEngine;
use crate::consensus::validator::ConsensusValidator;
use crate::crypto::hash::{sha256d, Hash256};
use crate::dex::LiquidityPool;
use crate::gui_wallet::GuiWalletApp;
use crate::mempool::pool::Mempool;
use crate::network::discovery::PeerDiscovery;
use crate::network::peer_manager::{
    P2PMessage, PeerDirection, PeerManager, MAX_P2P_MESSAGE_BYTES, WIRE_HEADER_BYTES,
};
use crate::network::sync::BlockSyncEngine;
use crate::primitives::block::Block;
use crate::primitives::transaction::{Transaction, TxOutput};
use crate::rpc::cli_commands::{CliCommandHandler, NodeCliCommand};
use crate::rpc::rpc_server::{RpcServer, RpcSharedState};
use crate::state::snapshot::ChainstateSnapshot;
use crate::state::utxo_set::UtxoSet;
use crate::storage::flatfile::FlatFileStorage;
use crate::wallet::address::{derive_deterministic_genesis_address, is_valid_address};
use crate::wallet::manager::WalletManager;

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static ACTIVE_P2P_THREADS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONCURRENT_P2P_THREADS: usize = 64;

pub struct EquinoxNodeEngine {
    pub network_mode: String,
    pub data_dir: PathBuf,
    pub chainstate_path: PathBuf,
    pub dex_state_path: PathBuf,
    pub wallet_path: PathBuf,
    pub genesis_owner_address: String,
    pub local_node_id: Hash256,
    pub shared_state: Arc<Mutex<RpcSharedState>>,
    pub fork_resolver: Arc<Mutex<ForkResolver>>,
    pub spent_key_images: Arc<Mutex<HashSet<Hash256>>>,
    pub current_total_supply: u64,
    pub peer_manager: Arc<Mutex<PeerManager>>,
    pub peer_discovery: Arc<Mutex<PeerDiscovery>>,
    pub sync_engine: Arc<Mutex<BlockSyncEngine>>,
    pub gui_controller: GuiWalletApp,
}

impl EquinoxNodeEngine {
    pub fn initialize<P: AsRef<Path>>(data_dir: P) -> Result<Self, String> {
        Self::initialize_with_mode(data_dir, "MAINNET")
    }

    pub fn create_master_wallet_files<P: AsRef<Path>>(
        data_dir: P,
        password: &str,
    ) -> Result<(String, String, String, String), String> {
        let base_dir = data_dir.as_ref().to_path_buf();
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .map_err(|e| format!("ডেটা ডিরেক্টরি তৈরি ব্যর্থ: {}", e))?;
        }

        let wallet_path = base_dir.join("wallet.dat");
        let (mut manager, mnemonic_phrase) =
            WalletManager::create_new_24_words(&wallet_path, password)?;

        let owner_addr = manager.get_address(0, 0)?;
        let liquidity_addr = manager.get_address(0, 1)?;
        let marketing_addr = manager.get_address(0, 2)?;
        let reserve_addr = manager.get_address(0, 3)?;

        manager.scrub_mnemonic_from_ram();

        let addr_file = base_dir.join("genesis_owner_address.txt");
        fs::write(&addr_file, &owner_addr)
            .map_err(|e| format!("ওনার অ্যাড্রেস ফাইল সেভ ব্যর্থ: {}", e))?;

        let vaults_file = base_dir.join("genesis_vault_addresses.txt");
        let vaults_content = format!("{}\n{}\n{}\n", liquidity_addr, marketing_addr, reserve_addr);
        fs::write(&vaults_file, vaults_content)
            .map_err(|e| format!("ভল্ট অ্যাড্রেস ফাইল সেভ ব্যর্থ: {}", e))?;

        println!("\n================================================================");
        println!("   নতুন ২৪-শব্দের মাস্টার ওনার ওয়ালেট সফলভাবে তৈরি হয়েছে!");
        println!("================================================================");
        println!("  [গুরুত্বপূর্ণ] নিচের ২৪টি শব্দ খাতায় লিখে নিরাপদে লকারে রাখুন:");
        println!("  SEED PHRASE : {}\n", mnemonic_phrase);
        println!("  ১. Owner Vault Address (Index 0)     : {}", owner_addr);
        println!("  ২. Liquidity Vault Address (Index 1) : {}", liquidity_addr);
        println!("  ৩. Marketing Vault Address (Index 2) : {}", marketing_addr);
        println!("  ৪. Reserve Vault Address (Index 3)   : {}", reserve_addr);
        println!("  Encrypted Keystore File              : {}", wallet_path.display());
        println!("================================================================\n");

        Ok((owner_addr, liquidity_addr, marketing_addr, reserve_addr))
    }

    fn resolve_genesis_vault_addresses(base_dir: &Path) -> (String, String, String, String) {
        let genesis_addr_file = base_dir.join("genesis_owner_address.txt");
        let vaults_file = base_dir.join("genesis_vault_addresses.txt");

        let owner_addr = if let Ok(custom_addr) = fs::read_to_string(&genesis_addr_file) {
            let trimmed = custom_addr.trim().to_string();
            if is_valid_address(&trimmed) {
                trimmed
            } else {
                derive_deterministic_genesis_address("EQX_MAINNET_OWNER_VAULT")
            }
        } else {
            derive_deterministic_genesis_address("EQX_MAINNET_OWNER_VAULT")
        };

        let mut liquidity_addr =
            derive_deterministic_genesis_address("EQX_EXCHANGE_LIQUIDITY_VAULT");
        let mut marketing_addr =
            derive_deterministic_genesis_address("EQX_MARKETING_AND_DEV_VAULT");
        let mut reserve_addr = derive_deterministic_genesis_address("EQX_ECOSYSTEM_RESERVE_VAULT");

        if let Ok(vaults_raw) = fs::read_to_string(&vaults_file) {
            let lines: Vec<&str> = vaults_raw
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            if lines.len() >= 3
                && is_valid_address(lines[0])
                && is_valid_address(lines[1])
                && is_valid_address(lines[2])
            {
                liquidity_addr = lines[0].to_string();
                marketing_addr = lines[1].to_string();
                reserve_addr = lines[2].to_string();
            }
        }

        (owner_addr, liquidity_addr, marketing_addr, reserve_addr)
    }

    pub fn initialize_with_mode<P: AsRef<Path>>(
        data_dir: P,
        network_mode: &str,
    ) -> Result<Self, String> {
        let base_dir = data_dir.as_ref().to_path_buf();
        let blocks_dir = base_dir.join("blocks");
        let chainstate_path = base_dir.join("chainstate.dat");
        let dex_state_path = base_dir.join("dex_state.dat");
        let wallet_path = base_dir.join("wallet.dat");

        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .map_err(|e| format!("ডেটা ডিরেক্টরি তৈরি ব্যর্থ: {}", e))?;
        }

        let (owner_addr, liquidity_addr, marketing_addr, reserve_addr) =
            Self::resolve_genesis_vault_addresses(&base_dir);

        let mut storage = FlatFileStorage::open(&blocks_dir)
            .map_err(|e| format!("ব্লক স্টোরেজ খুলতে ব্যর্থ: {}", e))?;

        let mut utxo_set = UtxoSet::new();
        let mut spent_key_images: HashSet<Hash256> = HashSet::new();
        let mut current_total_supply = 0u64;
        let fork_resolver: ForkResolver;

        if storage.total_stored_blocks() == 0 {
            let mut genesis_block = Block::genesis(
                &owner_addr,
                &liquidity_addr,
                &marketing_addr,
                &reserve_addr,
            );
            genesis_block.header.difficulty_target = DEFAULT_INITIAL_DIFFICULTY_BITS;

            if !genesis_block.mine(Some(5_000_000)) {
                return Err("জেনেসিস ব্লক প্রুফ-অফ-ওয়ার্ক মাইনিং ব্যর্থ হয়েছে".to_string());
            }

            let outcome = ConsensusValidator::validate_and_apply_block(
                &genesis_block,
                None,
                &mut utxo_set,
                &mut spent_key_images,
                0,
            )?;

            current_total_supply = outcome.new_total_supply_atomic;
            storage
                .append_block(&genesis_block)
                .map_err(|e| format!("জেনেসিস ব্লক ডিস্কে সেভ ব্যর্থ: {}", e))?;

            ChainstateSnapshot::save_full_state(
                &chainstate_path,
                &utxo_set.utxos,
                &spent_key_images,
                0,
            )?;
            fork_resolver = ForkResolver::new(genesis_block.header);
        } else {
            let genesis_block = storage
                .read_block_by_height(0)
                .map_err(|e| format!("ডিস্ক থেকে জেনেসিস ব্লক (#0) রিড ব্যর্থ: {}", e))?;

            let mut resolver = ForkResolver::new(genesis_block.header.clone());
            let latest_height = storage.latest_stored_height().unwrap_or(0);
            let mut snapshot_loaded = false;

            if let Ok((snap_ledger, snap_ki, snap_height)) =
                ChainstateSnapshot::load_full_state(&chainstate_path)
            {
                if snap_height <= latest_height {
                    let mut temp_utxo = UtxoSet { utxos: snap_ledger };
                    let mut temp_ki = snap_ki;

                    if let Ok(mut temp_supply) = temp_utxo.verify_supply_invariant() {
                        if temp_supply > 0 {
                            let mut chain_ok = true;

                            for h in 1..=snap_height {
                                match storage.read_block_by_height(h) {
                                    Ok(blk) => {
                                        if resolver.append_to_main_chain(blk.header).is_err() {
                                            chain_ok = false;
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        chain_ok = false;
                                        break;
                                    }
                                }
                            }

                            if chain_ok {
                                let mut prev_hdr =
                                    resolver.headers_by_height.get(&snap_height).cloned();
                                for h in (snap_height + 1)..=latest_height {
                                    match storage.read_block_by_height(h) {
                                        Ok(blk) => {
                                            match ConsensusValidator::validate_and_apply_block(
                                                &blk,
                                                prev_hdr.as_ref(),
                                                &mut temp_utxo,
                                                &mut temp_ki,
                                                temp_supply,
                                            ) {
                                                Ok(outcome) => {
                                                    temp_supply = outcome.new_total_supply_atomic;
                                                    if resolver
                                                        .append_to_main_chain(blk.header.clone())
                                                        .is_err()
                                                    {
                                                        chain_ok = false;
                                                        break;
                                                    }
                                                    prev_hdr = Some(blk.header);
                                                }
                                                Err(_) => {
                                                    chain_ok = false;
                                                    break;
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            chain_ok = false;
                                            break;
                                        }
                                    }
                                }
                            }

                            if chain_ok {
                                utxo_set = temp_utxo;
                                spent_key_images = temp_ki;
                                current_total_supply = temp_supply;
                                snapshot_loaded = true;
                            }
                        }
                    }
                }
            }

            if !snapshot_loaded {
                utxo_set = UtxoSet::new();
                spent_key_images.clear();
                current_total_supply = 0;
                resolver = ForkResolver::new(genesis_block.header.clone());

                let mut prev_header = None;
                for h in 0..=latest_height {
                    let blk = storage
                        .read_block_by_height(h)
                        .map_err(|e| format!("ব্লক #{} ডিস্ক থেকে রিড ব্যর্থ: {}", h, e))?;

                    let outcome = ConsensusValidator::validate_and_apply_block(
                        &blk,
                        prev_header.as_ref(),
                        &mut utxo_set,
                        &mut spent_key_images,
                        current_total_supply,
                    )?;

                    current_total_supply = outcome.new_total_supply_atomic;
                    if h > 0 {
                        resolver.append_to_main_chain(blk.header.clone())?;
                    }
                    prev_header = Some(blk.header);
                }
            }

            ChainstateSnapshot::save_full_state(
                &chainstate_path,
                &utxo_set.utxos,
                &spent_key_images,
                latest_height,
            )?;
            fork_resolver = resolver;
        }

        let tip_state = fork_resolver.current_state();
        let mut rpc_state = RpcSharedState::new(
            utxo_set,
            Mempool::new(),
            Some(storage),
            tip_state.height,
            tip_state.finalized_height,
            0,
        );

        if let Ok(loaded_dex) = LiquidityPool::load_from_file(&dex_state_path) {
            rpc_state.dex_pool = loaded_dex;
        } else {
            let _ = rpc_state.dex_pool.save_to_file(&dex_state_path);
        }

        let shared_state = Arc::new(Mutex::new(rpc_state));
        let now_ts = Self::current_unix_timestamp();
        let local_node_id = sha256d(base_dir.to_string_lossy().as_bytes());

        let peer_discovery = Arc::new(Mutex::new(PeerDiscovery::new(local_node_id, now_ts)));
        let peer_manager = Arc::new(Mutex::new(PeerManager::new()));
        let sync_engine = Arc::new(Mutex::new(BlockSyncEngine::new()));
        let fork_resolver_arc = Arc::new(Mutex::new(fork_resolver));
        let spent_ki_arc = Arc::new(Mutex::new(spent_key_images));
        let gui_controller = GuiWalletApp::new(&wallet_path, Arc::clone(&shared_state));

        Ok(Self {
            network_mode: network_mode.to_string(),
            data_dir: base_dir,
            chainstate_path,
            dex_state_path,
            wallet_path,
            genesis_owner_address: owner_addr,
            local_node_id,
            shared_state,
            fork_resolver: fork_resolver_arc,
            spent_key_images: spent_ki_arc,
            current_total_supply,
            peer_manager,
            peer_discovery,
            sync_engine,
            gui_controller,
        })
    }

    pub fn generate_fresh_master_wallet(&mut self, password: &str) -> Result<(), String> {
        let (owner_addr, liquidity_addr, marketing_addr, reserve_addr) =
            Self::create_master_wallet_files(&self.data_dir, password)?;
        self.genesis_owner_address = owner_addr.clone();

        let current_height = self
            .fork_resolver
            .lock()
            .map(|fr| fr.current_state().height)
            .unwrap_or(0);

        if current_height == 0 {
            let mut genesis_block = Block::genesis(
                &owner_addr,
                &liquidity_addr,
                &marketing_addr,
                &reserve_addr,
            );
            genesis_block.header.difficulty_target = DEFAULT_INITIAL_DIFFICULTY_BITS;

            if !genesis_block.mine(Some(5_000_000)) {
                return Err("নতুন ওয়ালেটের জন্য জেনেসিস ব্লক মাইনিং ব্যর্থ হয়েছে".to_string());
            }

            let mut new_utxos = UtxoSet::new();
            let mut new_ki: HashSet<Hash256> = HashSet::new();
            let outcome = ConsensusValidator::validate_and_apply_block(
                &genesis_block,
                None,
                &mut new_utxos,
                &mut new_ki,
                0,
            )?;

            let blocks_dir = self.data_dir.join("blocks");
            let mut st = self
                .shared_state
                .lock()
                .map_err(|_| "SharedState লক ত্রুটি".to_string())?;
            let mut fr = self
                .fork_resolver
                .lock()
                .map_err(|_| "ForkResolver লক ত্রুটি".to_string())?;
            let mut ki = self
                .spent_key_images
                .lock()
                .map_err(|_| "KeyImage লক ত্রুটি".to_string())?;

            st.storage = None;
            let _ = fs::remove_dir_all(&blocks_dir);
            let mut fresh_storage = FlatFileStorage::open(&blocks_dir)
                .map_err(|e| format!("স্টোরেজ পুনরায় খুলতে ব্যর্থ: {}", e))?;
            fresh_storage
                .append_block(&genesis_block)
                .map_err(|e| format!("নতুন জেনেসিস ব্লক সেভ ব্যর্থ: {}", e))?;

            ChainstateSnapshot::save_full_state(
                &self.chainstate_path,
                &new_utxos.utxos,
                &new_ki,
                0,
            )?;

            st.utxo_set = new_utxos;
            st.storage = Some(fresh_storage);
            st.best_height = 0;
            st.finalized_height = 0;
            *fr = ForkResolver::new(genesis_block.header);
            *ki = new_ki;
            self.current_total_supply = outcome.new_total_supply_atomic;
        }

        Ok(())
    }

    fn current_unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_729_468_800)
    }

    pub fn start_p2p_server_background(&self, bind_addr: Option<&str>) -> Result<String, String> {
        let addr_str = bind_addr
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("0.0.0.0:{}", DEFAULT_P2P_PORT));

        let listener = TcpListener::bind(&addr_str)
            .map_err(|e| format!("P2P পোর্ট ({}) বাইন্ড ব্যর্থ: {}", addr_str, e))?;

        let bound_addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| addr_str);

        let pm_clone = Arc::clone(&self.peer_manager);
        let pd_clone = Arc::clone(&self.peer_discovery);
        let ss_clone = Arc::clone(&self.shared_state);
        let fr_clone = Arc::clone(&self.fork_resolver);
        let ki_clone = Arc::clone(&self.spent_key_images);
        let sync_clone = Arc::clone(&self.sync_engine);
        let chainstate_path = self.chainstate_path.clone();
        let node_id = self.local_node_id;

        // ১. ইনবাউন্ড P2P লিসেনার থ্রেড
        thread::spawn(move || {
            for stream_res in listener.incoming() {
                if let Ok(stream) = stream_res {
                    let active = ACTIVE_P2P_THREADS.load(Ordering::SeqCst);
                    if active >= MAX_CONCURRENT_P2P_THREADS {
                        drop(stream);
                        continue;
                    }

                    ACTIVE_P2P_THREADS.fetch_add(1, Ordering::SeqCst);
                    let pm = Arc::clone(&pm_clone);
                    let pd = Arc::clone(&pd_clone);
                    let ss = Arc::clone(&ss_clone);
                    let fr = Arc::clone(&fr_clone);
                    let ki = Arc::clone(&ki_clone);
                    let se = Arc::clone(&sync_clone);
                    let cs_path = chainstate_path.clone();

                    thread::spawn(move || {
                        let _ = Self::handle_incoming_p2p_stream(
                            stream, node_id, cs_path, pm, pd, ss, fr, ki, se,
                        );
                        ACTIVE_P2P_THREADS.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            }
        });

        // ২. ব্যাকগ্রাউন্ড RPC-to-P2P রিলে ও অ্যাক্টিভ সিঙ্ক ওয়ার্কার থ্রেড
        let ss_worker = Arc::clone(&self.shared_state);
        let pm_worker = Arc::clone(&self.peer_manager);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(2));
            let pending_txs: Vec<Transaction> = {
                if let Ok(mut st) = ss_worker.lock() {
                    st.pending_p2p_relays.drain(..).collect()
                } else {
                    Vec::new()
                }
            };

            if !pending_txs.is_empty() {
                let targets = pm_worker
                    .lock()
                    .map(|pm| pm.broadcast_targets())
                    .unwrap_or_default();

                for tx in pending_txs {
                    if let Ok(frame) = PeerManager::encode_wire_frame(&P2PMessage::RelayTransaction(tx)) {
                        for addr in &targets {
                            if let Ok(sock) = addr.parse::<SocketAddr>() {
                                if let Ok(mut s) = TcpStream::connect_timeout(&sock, Duration::from_secs(2)) {
                                    let _ = s.write_all(&frame);
                                    let _ = s.flush();
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(bound_addr)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_incoming_p2p_stream(
        mut stream: TcpStream,
        local_node_id: Hash256,
        chainstate_path: PathBuf,
        peer_manager: Arc<Mutex<PeerManager>>,
        peer_discovery: Arc<Mutex<PeerDiscovery>>,
        shared_state: Arc<Mutex<RpcSharedState>>,
        fork_resolver: Arc<Mutex<ForkResolver>>,
        spent_key_images: Arc<Mutex<HashSet<Hash256>>>,
        sync_engine: Arc<Mutex<BlockSyncEngine>>,
    ) -> Result<(), String> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

        let (peer_addr, peer_ip) = match stream.peer_addr() {
            Ok(sock) => (sock.to_string(), sock.ip().to_string()),
            Err(_) => ("0.0.0.0:0".to_string(), "0.0.0.0".to_string()),
        };

        let now = Self::current_unix_timestamp();

        {
            let mut pm = peer_manager.lock().map_err(|_| "PM lock error")?;
            pm.register_peer(&peer_addr, PeerDirection::Inbound, now)
                .map_err(|e| e.to_string())?;
        }

        let mut header_buf = [0u8; WIRE_HEADER_BYTES];
        if stream.read_exact(&mut header_buf).is_err() {
            return Ok(());
        }

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&header_buf[4..8]);
        let payload_len = u32::from_le_bytes(len_bytes) as usize;

        if payload_len == 0 || payload_len > MAX_P2P_MESSAGE_BYTES {
            return Err("P2P পেলোড সাইজ সীমার বাইরে".to_string());
        }

        let mut full_frame = Vec::with_capacity(WIRE_HEADER_BYTES + payload_len);
        full_frame.extend_from_slice(&header_buf);
        let mut payload_buf = vec![0u8; payload_len];
        stream
            .read_exact(&mut payload_buf)
            .map_err(|e| e.to_string())?;
        full_frame.extend_from_slice(&payload_buf);

        let incoming_msg =
            PeerManager::decode_wire_frame(&full_frame).map_err(|e| e.to_string())?;

        let response_opt: Option<P2PMessage> = match incoming_msg {
            P2PMessage::Version {
                best_height,
                finalized_checkpoint,
                listen_port,
                ..
            } => {
                let active_count = {
                    let mut pm = peer_manager.lock().map_err(|_| "PM lock error")?;
                    pm.complete_handshake(&peer_addr, best_height, finalized_checkpoint, now);
                    if listen_port > 0 {
                        let listen_sock = format!("{}:{}", peer_ip, listen_port);
                        if listen_sock != peer_addr {
                            let _ = pm.register_peer(&listen_sock, PeerDirection::Outbound, now);
                            pm.complete_handshake(
                                &listen_sock,
                                best_height,
                                finalized_checkpoint,
                                now,
                            );
                        }
                    }
                    pm.active_peer_count()
                };

                if let Ok(mut st) = shared_state.lock() {
                    st.peer_count = active_count;
                }

                let tip = fork_resolver
                    .lock()
                    .map_err(|_| "ForkResolver lock error")?
                    .current_state();

                Some(P2PMessage::Version {
                    protocol_version: PROTOCOL_VERSION,
                    best_height: tip.height,
                    finalized_checkpoint: tip.finalized_height,
                    node_id: local_node_id,
                    listen_port: DEFAULT_P2P_PORT,
                })
            }
            P2PMessage::Ping(nonce) => Some(P2PMessage::Pong(nonce)),
            P2PMessage::GetPeers => {
                let peers = peer_discovery
                    .lock()
                    .map(|pd| pd.find_closest_peers(&local_node_id, 16))
                    .unwrap_or_default();
                Some(P2PMessage::Peers(peers))
            }
            P2PMessage::GetHeaders {
                start_height,
                max_count,
            } => {
                let fr = fork_resolver.lock().map_err(|_| "FR lock")?;
                let mut headers = Vec::new();
                let limit = (max_count as u64).min(500);
                for h in start_height..start_height.saturating_add(limit) {
                    if let Some(hdr) = fr.headers_by_height.get(&h) {
                        headers.push(hdr.clone());
                    } else {
                        break;
                    }
                }
                Some(P2PMessage::Headers(headers))
            }
            P2PMessage::RelayTransaction(tx) => {
                if let Ok(mut st) = shared_state.lock() {
                    let snapshot = st.utxo_set.clone();
                    let h = st.best_height;
                    let _ = st.mempool.add_transaction_verified(tx, &snapshot, h);
                }
                None
            }
            P2PMessage::NewCompactBlock(compact) => {
                let mut st = shared_state.lock().map_err(|_| "SS lock")?;
                let mut fr = fork_resolver.lock().map_err(|_| "FR lock")?;
                let mut ki = spent_key_images.lock().map_err(|_| "KI lock")?;
                let mut se = sync_engine.lock().map_err(|_| "SE lock")?;
                let mut pm = peer_manager.lock().map_err(|_| "PM lock")?;

                match se.handle_incoming_compact_block(
                    &peer_addr,
                    compact,
                    &st.mempool,
                    &fr,
                    &mut pm,
                    now,
                ) {
                    Ok(Some(reconstructed_block)) => {
                        let parent_h = reconstructed_block.header.height.saturating_sub(1);
                        let parent_hdr = fr.headers_by_height.get(&parent_h).cloned();
                        let mut staged_utxos = st.utxo_set.clone();
                        let mut staged_ki = ki.clone();
                        let current_supply = staged_utxos.verify_supply_invariant().unwrap_or(0);

                        if let Ok(_outcome) = ConsensusValidator::validate_and_apply_block(
                            &reconstructed_block,
                            parent_hdr.as_ref(),
                            &mut staged_utxos,
                            &mut staged_ki,
                            current_supply,
                        ) {
                            let mut disk_ok = true;
                            if let Some(storage) = &mut st.storage {
                                if storage.append_block(&reconstructed_block).is_err() {
                                    disk_ok = false;
                                }
                            }
                            if disk_ok
                                && ChainstateSnapshot::save_full_state(
                                    &chainstate_path,
                                    &staged_utxos.utxos,
                                    &staged_ki,
                                    reconstructed_block.header.height,
                                )
                                .is_ok()
                                && fr
                                    .append_to_main_chain(reconstructed_block.header.clone())
                                    .is_ok()
                            {
                                st.utxo_set = staged_utxos;
                                *ki = staged_ki;
                                st.mempool
                                    .remove_confirmed_block_transactions(&reconstructed_block);
                                let new_tip = fr.current_state();
                                st.best_height = new_tip.height;
                                st.finalized_height = new_tip.finalized_height;
                            }
                        }
                        None
                    }
                    Ok(None) => None,
                    Err(req_missing_msg) => Some(req_missing_msg),
                }
            }
            _ => None,
        };

        if let Some(reply_msg) = response_opt {
            if let Ok(encoded_reply) = PeerManager::encode_wire_frame(&reply_msg) {
                let _ = stream.write_all(&encoded_reply);
                let _ = stream.flush();
            }
        }

        Ok(())
    }

    pub fn broadcast_p2p_message(&self, msg: &P2PMessage) -> usize {
        let Ok(encoded_frame) = PeerManager::encode_wire_frame(msg) else {
            return 0;
        };

        let targets = self
            .peer_manager
            .lock()
            .map(|pm| pm.broadcast_targets())
            .unwrap_or_default();

        let mut sent_count = 0usize;
        for addr in targets {
            let parsed_sock: Option<SocketAddr> = addr
                .parse::<SocketAddr>()
                .ok()
                .or_else(|| format!("{}:{}", addr, DEFAULT_P2P_PORT).parse().ok());

            if let Some(sock_addr) = parsed_sock {
                if let Ok(mut stream) =
                    TcpStream::connect_timeout(&sock_addr, Duration::from_secs(2))
                {
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    if stream.write_all(&encoded_frame).is_ok() {
                        let _ = stream.flush();
                        sent_count += 1;
                    }
                }
            }
        }
        sent_count
    }

    pub fn mine_next_block(&mut self, miner_address: &str) -> Result<Block, String> {
        let clean_miner = miner_address.trim();
        if !is_valid_address(clean_miner) {
            return Err(format!("অবৈধ মাইনার ওয়ালেট অ্যাড্রেস: {}", clean_miner));
        }

        let (tip_state, parent_header, next_difficulty) = {
            let resolver = self
                .fork_resolver
                .lock()
                .map_err(|_| "ফর্ক রিজলভার লক ত্রুটি".to_string())?;
            let tip = resolver.current_state();
            let next_h = tip.height.saturating_add(1);
            let parent = resolver
                .headers_by_height
                .get(&tip.height)
                .cloned()
                .ok_or_else(|| "প্যারেন্ট ব্লক হেডার খুঁজে পাওয়া যায়নি".to_string())?;

            let window_start = if next_h >= DAA_AVERAGING_WINDOW {
                resolver
                    .headers_by_height
                    .get(&(next_h - DAA_AVERAGING_WINDOW))
            } else {
                resolver.headers_by_height.get(&0)
            };

            let diff = ProofOfWorkEngine::calculate_next_difficulty(&parent, window_start);
            (tip, parent, diff)
        };

        let next_height = tip_state.height.saturating_add(1);
        let now_ts =
            Self::current_unix_timestamp().max(parent_header.timestamp.saturating_add(1));

        let (selected_txs, live_supply) = {
            let state = self
                .shared_state
                .lock()
                .map_err(|_| "নোড স্টেট লক ত্রুটি".to_string())?;
            let verified_supply = state
                .utxo_set
                .verify_supply_invariant()
                .unwrap_or(self.current_total_supply);
            (
                state.mempool.select_transactions_for_block(500),
                verified_supply,
            )
        };
        self.current_total_supply = live_supply;

        let user_tx_count = selected_txs.len();
        let total_fees: u64 = selected_txs.iter().map(|tx| tx.fee).sum();

        let allowed_subsidy =
            crate::config::calculate_capped_block_reward(next_height, self.current_total_supply);

        // ১.৭০% মাইনিং রয়্যালটি স্প্লিট (৯৮.৩০% মাইনার + ১.৭০% প্রটোকল ওনার ও ডিভিডেন্ড পুল)
        let split = ProtocolRoyaltyEngine::split_block_subsidy(allowed_subsidy);
        let miner_total = split
            .miner_share_atomic
            .saturating_add(total_fees)
            .min(MAX_SUPPLY);

        let mut coinbase_outputs = Vec::with_capacity(2);
        if miner_total > 0 {
            coinbase_outputs.push(TxOutput::new(miner_total, clean_miner.to_string()));
        }
        if split.total_royalty_atomic > 0 {
            if clean_miner == self.genesis_owner_address && !coinbase_outputs.is_empty() {
                // যদি মাইনার নিজেই জেনেসিস ওনার হন, তবে একক আউটপুটে যোগ করে দেওয়া
                coinbase_outputs[0].amount = coinbase_outputs[0]
                    .amount
                    .saturating_add(split.total_royalty_atomic);
            } else {
                coinbase_outputs.push(TxOutput::new(
                    split.total_royalty_atomic,
                    self.genesis_owner_address.clone(),
                ));
            }
        }
        if coinbase_outputs.is_empty() {
            coinbase_outputs.push(TxOutput::new(1, clean_miner.to_string()));
        }

        let coinbase_tx = Transaction {
            version: 1,
            inputs: Vec::new(),
            outputs: coinbase_outputs,
            timestamp: now_ts,
            fee: 0,
        };

        let mut block_txs = Vec::with_capacity(1 + selected_txs.len());
        block_txs.push(coinbase_tx);
        block_txs.extend(selected_txs);

        let mut candidate_block = Block::new(
            next_height,
            parent_header.hash(),
            block_txs,
            next_difficulty,
            now_ts,
        );

        if !candidate_block.mine(Some(10_000_000)) {
            return Err("নির্ধারিত ইটারেশনের মধ্যে ব্লক মাইনিং সম্পন্ন হয়নি".to_string());
        }

        {
            let mut state = self
                .shared_state
                .lock()
                .map_err(|_| "নোড স্টেট লক ত্রুটি".to_string())?;
            let mut resolver = self
                .fork_resolver
                .lock()
                .map_err(|_| "ফর্ক রিজলভার লক ত্রুটি".to_string())?;
            let mut ki_guard = self
                .spent_key_images
                .lock()
                .map_err(|_| "Key-Image লক ত্রুটি".to_string())?;

            let mut staged_utxos = state.utxo_set.clone();
            let mut staged_ki = ki_guard.clone();

            let outcome = ConsensusValidator::validate_and_apply_block(
                &candidate_block,
                Some(&parent_header),
                &mut staged_utxos,
                &mut staged_ki,
                self.current_total_supply,
            )?;

            if let Some(storage) = &mut state.storage {
                storage
                    .append_block(&candidate_block)
                    .map_err(|e| format!("মাইনকৃত ব্লক ডিস্কে সেভ ব্যর্থ: {}", e))?;
            }

            ChainstateSnapshot::save_full_state(
                &self.chainstate_path,
                &staged_utxos.utxos,
                &staged_ki,
                next_height,
            )?;

            resolver.append_to_main_chain(candidate_block.header.clone())?;

            state.utxo_set = staged_utxos;
            *ki_guard = staged_ki;
            state
                .mempool
                .remove_confirmed_block_transactions(&candidate_block);
            state
                .fee_estimator
                .record_confirmed_block_fees(total_fees, user_tx_count);

            let new_tip = resolver.current_state();
            state.best_height = new_tip.height;
            state.finalized_height = new_tip.finalized_height;
            self.current_total_supply = outcome.new_total_supply_atomic;
        }

        let compact_msg = P2PMessage::NewCompactBlock(candidate_block.to_compact_block());
        let _ = self.broadcast_p2p_message(&compact_msg);

        Ok(candidate_block)
    }

    pub fn print_node_status(&self) {
        let Ok(state) = self.shared_state.lock() else {
            return;
        };
        let ki_len = self.spent_key_images.lock().map(|k| k.len()).unwrap_or(0);
        let peers_known = self
            .peer_discovery
            .lock()
            .map(|d| d.known_peers_count())
            .unwrap_or(0);
        let report = TokenomicsEngine::get_supply_report_at_height(state.best_height);
        let state_root = hex::encode(state.utxo_set.compute_state_root());

        println!("================================================================");
        println!(
            "   {} ({}) — L1 {} Full Node Status",
            TOKEN_NAME, SYMBOL, self.network_mode
        );
        println!("================================================================");
        println!("  Chain ID               : {} (0x{:x})", CHAIN_ID, CHAIN_ID);
        println!("  Genesis Owner Address  : {}", self.genesis_owner_address);
        println!("  Best Block Height      : #{}", state.best_height);
        println!("  BFT Finalized Height   : #{}", state.finalized_height);
        println!("  Active UTXO Notes      : {}", state.utxo_set.len());
        println!("  Spent Key-Images       : {}", ki_len);
        println!("  Mempool Pending Txs    : {}", state.mempool.len());
        println!("  Known DHT Peers        : {}", peers_known);
        println!(
            "  Total Minted Supply    : {} {}",
            RpcServer::format_atomic_to_eqx(report.total_minted_supply),
            SYMBOL
        );
        println!(
            "  Circulating Supply     : {} {}",
            RpcServer::format_atomic_to_eqx(report.circulating_supply),
            SYMBOL
        );
        println!(
            "  Locked Owner Supply    : {} {}",
            RpcServer::format_atomic_to_eqx(report.locked_owner_supply),
            SYMBOL
        );
        println!(
            "  Current Block Subsidy  : {} {}",
            RpcServer::format_atomic_to_eqx(report.current_block_reward),
            SYMBOL
        );
        println!("  State Merkle Root      : {}", state_root);
        println!("================================================================");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let is_testnet = args.iter().any(|a| a == "--testnet");

    let (network_mode, default_dir, p2p_port, rpc_port) = if is_testnet {
        (
            "TESTNET",
            "./equinox_testnet_data",
            DEFAULT_P2P_PORT.saturating_add(10_000),
            DEFAULT_RPC_PORT.saturating_add(10_000),
        )
    } else {
        (
            "MAINNET",
            "./equinox_mainnet_data",
            DEFAULT_P2P_PORT,
            DEFAULT_RPC_PORT,
        )
    };

    let data_dir = env::var("EQX_DATA_DIR").unwrap_or_else(|_| default_dir.to_string());

    if let Some(pos) = args.iter().position(|a| a == "--new-wallet") {
        let pass = args
            .get(pos + 1)
            .map(|s| s.as_str())
            .unwrap_or("Equinox#MasterVault2026");
        if let Err(e) = EquinoxNodeEngine::create_master_wallet_files(&data_dir, pass) {
            eprintln!("[ERROR] নতুন ওয়ালেট তৈরি ব্যর্থ: {}", e);
            std::process::exit(1);
        }
        if let Ok(mut eng) = EquinoxNodeEngine::initialize_with_mode(&data_dir, network_mode) {
            let _ = eng.generate_fresh_master_wallet(pass);
        }
        return;
    }

    let mut engine = match EquinoxNodeEngine::initialize_with_mode(&data_dir, network_mode) {
        Ok(eng) => eng,
        Err(e) => {
            eprintln!("[FATAL] Equinox L1 নোড ইনিশিয়ালাইজেশন ব্যর্থ: {}", e);
            std::process::exit(1);
        }
    };

    // P2P পোর্ট সবসময় 0.0.0.0-তে বাইন্ড হবে যাতে ইন্টারনেট ও লোকাল উভয় পিয়ার যুক্ত হতে পারে
    let p2p_bind = env::var("EQX_P2P_BIND").unwrap_or_else(|_| format!("0.0.0.0:{}", p2p_port));
    if let Ok(bound_p2p) = engine.start_p2p_server_background(Some(&p2p_bind)) {
        println!("[OK] P2P TCP Wire-Frame সার্ভার সচল: {}", bound_p2p);
    }

    let rpc_bind = env::var("EQX_RPC_BIND").unwrap_or_else(|_| format!("127.0.0.1:{}", rpc_port));
    if let Ok(bound_rpc) =
        RpcServer::start_background(Some(&rpc_bind), Arc::clone(&engine.shared_state))
    {
        println!(
            "[OK] JSON-RPC 2.0 & Web3 API সার্ভার সচল: http://{}",
            bound_rpc
        );
    }

    engine.print_node_status();
    println!("কমান্ড তালিকা: 'new-wallet <password>', 'status', 'mine [count]', 'balance <addr>', 'supply [height]', 'quit'");

    let stdin = io::stdin();
    loop {
        print!("\nequinox-core> ");
        let _ = io::stdout().flush();

        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = engine
                    .shared_state
                    .lock()
                    .map(|s| s.dex_pool.save_to_file(&engine.dex_state_path));
                break;
            }
            Ok(_) => {}
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("new-wallet") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let pass = parts.get(1).copied().unwrap_or("Equinox#MasterVault2026");
            if let Err(e) = engine.generate_fresh_master_wallet(pass) {
                println!("[ERROR] {}", e);
            }
            continue;
        }

        match CliCommandHandler::parse_command_line(trimmed) {
            Ok(NodeCliCommand::Status) => engine.print_node_status(),
            Ok(NodeCliCommand::Mine { count, address }) => {
                let default_miner = engine.genesis_owner_address.clone();
                let miner = address.as_deref().unwrap_or(&default_miner);
                for _ in 0..count {
                    match engine.mine_next_block(miner) {
                        Ok(blk) => println!(
                            "[MINED] Block #{} | Hash: {} | Nonce: {}",
                            blk.header.height,
                            hex::encode(blk.hash()),
                            blk.header.nonce
                        ),
                        Err(e) => {
                            eprintln!("[ERROR] {}", e);
                            break;
                        }
                    }
                }
            }
            Ok(NodeCliCommand::Quit) => {
                let _ = engine
                    .shared_state
                    .lock()
                    .map(|s| s.dex_pool.save_to_file(&engine.dex_state_path));
                println!("নোড এবং DEX স্টেট নিরাপদে ডিস্কে সংরক্ষণ করে বন্ধ করা হচ্ছে...");
                break;
            }
            Ok(other_cmd) => {
                if let Ok(output) =
                    CliCommandHandler::execute_readonly_query(&other_cmd, &engine.shared_state)
                {
                    println!("{}", output);
                }
            }
            Err(e) => println!("{}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PREMINE_SUPPLY;

    fn temp_node_dir(name: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("eqx_fullnode_fastboot_test_{}", name));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn test_full_mainnet_node_instant_snapshot_fastboot_and_p2p_handshake() {
        let dir = temp_node_dir("fastboot_and_p2p");

        let mut node = EquinoxNodeEngine::initialize(&dir).expect("Node bootstrap must succeed");
        assert_eq!(node.current_total_supply, PREMINE_SUPPLY);

        let miner_addr = node.genesis_owner_address.clone();
        for expected_h in 1..=3 {
            let mined = node
                .mine_next_block(&miner_addr)
                .expect("Mining block must succeed");
            assert_eq!(mined.header.height, expected_h);
        }

        let supply_after_3 = node.current_total_supply;

        let bound_p2p = node
            .start_p2p_server_background(Some("127.0.0.1:0"))
            .expect("P2P TCP listener must bind");

        let mut client = TcpStream::connect(&bound_p2p).unwrap();
        let ping_frame = PeerManager::encode_wire_frame(&P2PMessage::Ping(777)).unwrap();
        client.write_all(&ping_frame).unwrap();
        client.flush().unwrap();

        let mut reply_buf = vec![0u8; 256];
        let n = client.read(&mut reply_buf).unwrap();
        let decoded_reply = PeerManager::decode_wire_frame(&reply_buf[..n]).unwrap();
        assert_eq!(decoded_reply, P2PMessage::Pong(777));

        drop(node);
        let restarted_node =
            EquinoxNodeEngine::initialize(&dir).expect("Instant fast-boot recovery must succeed");
        assert_eq!(
            restarted_node
                .fork_resolver
                .lock()
                .unwrap()
                .current_state()
                .height,
            3
        );
        assert_eq!(restarted_node.current_total_supply, supply_after_3);

        let _ = fs::remove_dir_all(&dir);
    }
}