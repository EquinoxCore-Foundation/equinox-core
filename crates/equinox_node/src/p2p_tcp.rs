#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use equinox_network::banlist::Misbehavior;
use equinox_network::protocol::{WireMessage, PROTOCOL_VERSION};
use equinox_network::ratelimit::PeerRateLimiter;
use equinox_network::transport::{
    EncryptedChannel, NodeStaticKey, NoiseHandshake, MAX_NOISE_PACKET_BYTES,
};

use crate::block::FullBlock;
use crate::genesis::to_hex;
use crate::runtime::{now_millis, now_secs, PeerBroadcaster, SharedNode};
use crate::tx::SignedTransaction;

fn write_framed(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_NOISE_PACKET_BYTES {
        return Err("Frame exceeds Noise packet cap".to_string());
    }
    let len_bytes = (data.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).map_err(|e| e.to_string())?;
    stream.write_all(data).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn read_framed_blocking(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_NOISE_PACKET_BYTES {
        return Err("Invalid or oversized P2P frame".to_string());
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| e.to_string())?;
    Ok(payload)
}

/// Polls for an incoming frame with a 100ms timeout so outbound live broadcasts never stall.
fn read_framed_poll(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, String> {
    let mut first = [0u8; 1];
    match stream.read(&mut first) {
        Ok(0) => return Err("Peer closed connection".to_string()),
        Ok(1) => {}
        Ok(_) => return Err("Unexpected byte count".to_string()),
        Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
            return Ok(None);
        }
        Err(e) => return Err(e.to_string()),
    }

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut rest_len = [0u8; 3];
    stream
        .read_exact(&mut rest_len)
        .map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes([first[0], rest_len[0], rest_len[1], rest_len[2]]) as usize;
    if len == 0 || len > MAX_NOISE_PACKET_BYTES {
        return Err("Invalid or oversized P2P frame".to_string());
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    Ok(Some(payload))
}

fn send_encrypted(
    stream: &mut TcpStream,
    ch: &mut EncryptedChannel,
    msg: &WireMessage,
) -> Result<(), String> {
    let raw = msg.encode();
    let enc = ch
        .encrypt_frame(&raw)
        .map_err(|_| "Noise encrypt failed".to_string())?;
    write_framed(stream, &enc)
}

fn decode_encrypted(
    enc: &[u8],
    ch: &mut EncryptedChannel,
    rl: &mut PeerRateLimiter,
) -> Result<WireMessage, String> {
    rl.check_and_consume(enc.len() as u64, now_millis())
        .map_err(|_| "Peer rate limit exceeded".to_string())?;
    let dec = ch
        .decrypt_frame(enc)
        .map_err(|_| "Noise decrypt failed".to_string())?;
    WireMessage::decode(&dec).map_err(|_| "Malformed wire message".to_string())
}

/// Shared persistent bidirectional live sync loop for both inbound and outbound Noise_XX peers.
fn run_peer_sync_loop(
    mut stream: TcpStream,
    mut channel: EncryptedChannel,
    peer_addr: SocketAddr,
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
    shutdown: Arc<AtomicBool>,
    initial_peer_height: u64,
    request_initial_sync: bool,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let (peer_id, rx) = broadcaster.register();
    let mut rl = PeerRateLimiter::mainnet_default(now_millis());
    let mut peer_best_height = initial_peer_height;
    let mut last_sync_req = Instant::now();
    let mut mempool_synced = false;

    let chain_id = node.lock().unwrap().mode.chain_id();

    if request_initial_sync {
        let local_h = node.lock().unwrap().storage.tip_height();
        if peer_best_height > local_h {
            let _ = send_encrypted(
                &mut stream,
                &mut channel,
                &WireMessage::GetBlocks {
                    from_height: local_h + 1,
                    max_count: 25,
                },
            );
            last_sync_req = Instant::now();
        }
        let _ = send_encrypted(&mut stream, &mut channel, &WireMessage::GetMempool);
        mempool_synced = true;
    }

    while !shutdown.load(Ordering::Relaxed) {
        // 1. Flush all live outbound broadcasts (new blocks & mempool transactions)
        let mut send_failed = false;
        while let Ok(out_msg) = rx.try_recv() {
            if send_encrypted(&mut stream, &mut channel, &out_msg).is_err() {
                send_failed = true;
                break;
            }
        }
        if send_failed {
            break;
        }

        // 2. Periodic catch-up sync after handshake settles (avoids colliding with Ping/Pong)
        if last_sync_req.elapsed() >= Duration::from_millis(350) {
            let local_tip = node.lock().unwrap().storage.tip_height();
            if peer_best_height > local_tip {
                if send_encrypted(
                    &mut stream,
                    &mut channel,
                    &WireMessage::GetBlocks {
                        from_height: local_tip + 1,
                        max_count: 25,
                    },
                )
                .is_err()
                {
                    break;
                }
            }
            if !mempool_synced {
                if send_encrypted(&mut stream, &mut channel, &WireMessage::GetMempool).is_err() {
                    break;
                }
                mempool_synced = true;
            }
            last_sync_req = Instant::now();
        }

        // 3. Poll incoming encrypted wire frames
        let enc_frame = match read_framed_poll(&mut stream) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(_) => break,
        };

        let msg = match decode_encrypted(&enc_frame, &mut channel, &mut rl) {
            Ok(m) => m,
            Err(_) => {
                node.lock()
                    .unwrap()
                    .banlist
                    .record_offense(peer_addr.ip(), Misbehavior::MalformedFrame, now_secs());
                break;
            }
        };

        match msg {
            WireMessage::Version {
                chain_id: peer_chain,
                best_height: peer_h,
                ..
            } => {
                if peer_chain != chain_id {
                    break;
                }
                peer_best_height = peer_best_height.max(peer_h);
                // Reply cleanly with ONLY VerAck so the initiator's Ping/Pong completes cleanly
                if send_encrypted(&mut stream, &mut channel, &WireMessage::VerAck).is_err() {
                    break;
                }
                last_sync_req = Instant::now();
            }
            WireMessage::Ping(n) => {
                if send_encrypted(&mut stream, &mut channel, &WireMessage::Pong(n)).is_err() {
                    break;
                }
            }
            WireMessage::GetBlocks {
                from_height,
                max_count,
            } => {
                let blocks = node
                    .lock()
                    .unwrap()
                    .get_blocks_from(from_height, max_count as usize);
                for blk in blocks {
                    if send_encrypted(
                        &mut stream,
                        &mut channel,
                        &WireMessage::BlockData(blk.encode_bytes()),
                    )
                    .is_err()
                    {
                        break;
                    }
                }
            }
            WireMessage::BlockData(raw_block) => match FullBlock::decode_bytes(&raw_block) {
                Ok(blk) => {
                    let incoming_h = blk.height;
                    peer_best_height = peer_best_height.max(incoming_h);
                    let apply_res = node.lock().unwrap().apply_synced_block(blk);
                    match apply_res {
                        Ok(Some((summary, accepted_blk))) => {
                            println!(
                                "[SYNC] Block #{} synced from {} | Hash: {}.. | Txs: {} | Verified PoW + UTXO",
                                summary.height,
                                peer_addr,
                                &summary.hash_hex[..16],
                                summary.tx_count
                            );
                            broadcaster.broadcast(
                                WireMessage::BlockData(accepted_blk.encode_bytes()),
                                Some(peer_id),
                            );
                        }
                        Ok(None) => {}
                        Err(err) if err.starts_with("GAP:") => {
                            let my_h = node.lock().unwrap().storage.tip_height();
                            let _ = send_encrypted(
                                &mut stream,
                                &mut channel,
                                &WireMessage::GetBlocks {
                                    from_height: my_h + 1,
                                    max_count: 25,
                                },
                            );
                            last_sync_req = Instant::now();
                        }
                        Err(err) => {
                            eprintln!("[SYNC REJECT] Invalid block from {}: {}", peer_addr, err);
                            node.lock().unwrap().banlist.record_offense(
                                peer_addr.ip(),
                                Misbehavior::InvalidBlockPoW,
                                now_secs(),
                            );
                            break;
                        }
                    }
                }
                Err(_) => {
                    node.lock().unwrap().banlist.record_offense(
                        peer_addr.ip(),
                        Misbehavior::MalformedFrame,
                        now_secs(),
                    );
                    break;
                }
            },
            WireMessage::GetMempool => {
                let txs = node.lock().unwrap().mempool.all_transactions(50);
                for tx in txs {
                    if send_encrypted(
                        &mut stream,
                        &mut channel,
                        &WireMessage::TxData(tx.encode_bytes()),
                    )
                    .is_err()
                    {
                        break;
                    }
                }
            }
            WireMessage::TxData(raw_tx) => {
                if let Ok(tx) = SignedTransaction::decode_bytes(&raw_tx) {
                    let sub_res = node.lock().unwrap().submit_transaction(tx);
                    if let Ok((txid, fee)) = sub_res {
                        println!(
                            "[SYNC] Mempool TX synced from {}: {}.. (fee: {} atomic)",
                            peer_addr,
                            &to_hex(&txid)[..16],
                            fee
                        );
                        broadcaster.broadcast(WireMessage::TxData(raw_tx), Some(peer_id));
                    }
                }
            }
            WireMessage::VerAck
            | WireMessage::Pong(_)
            | WireMessage::InvBlock(_)
            | WireMessage::InvTx(_)
            | WireMessage::GetPeers => {}
        }
    }

    broadcaster.unregister(peer_id);
    node.lock().unwrap().slots.disconnect(&peer_addr);
}

fn handle_inbound_peer(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
    shutdown: Arc<AtomicBool>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let (chain_id, best_height, hs_res) = {
        let mut st = node.lock().unwrap();
        if st.banlist.is_banned(peer_addr.ip(), now_secs()) {
            return;
        }
        if st.slots.add_inbound(peer_addr).is_err() {
            return;
        }
        let prologue = st.mode.noise_prologue();
        let hs = NoiseHandshake::new_responder(&st.node_key, prologue);
        (st.mode.chain_id(), st.storage.tip_height(), hs)
    };

    let mut hs = match hs_res {
        Ok(h) => h,
        Err(_) => {
            node.lock().unwrap().slots.disconnect(&peer_addr);
            return;
        }
    };

    let handshake_ok = (|| -> Result<EncryptedChannel, String> {
        let m1 = read_framed_blocking(&mut stream)?;
        hs.read_step(&m1).map_err(|_| "Noise step 1 failed".to_string())?;

        let m2 = hs
            .write_step(b"EQX_RESPONDER_V1")
            .map_err(|_| "Noise step 2 failed".to_string())?;
        write_framed(&mut stream, &m2)?;

        let m3 = read_framed_blocking(&mut stream)?;
        hs.read_step(&m3).map_err(|_| "Noise step 3 failed".to_string())?;

        hs.into_transport()
            .map_err(|_| "Noise transport transition failed".to_string())
    })();

    let mut channel = match handshake_ok {
        Ok(ch) => ch,
        Err(_) => {
            let mut st = node.lock().unwrap();
            st.banlist
                .record_offense(peer_addr.ip(), Misbehavior::HandshakeFailure, now_secs());
            st.slots.disconnect(&peer_addr);
            return;
        }
    };

    if let Some(pk) = channel.remote_public_key() {
        println!(
            "[P2P] Inbound Noise_XX E2EE peer authenticated: {} (pubkey {}..)",
            peer_addr,
            &to_hex(&pk)[..12]
        );
    }

    let our_ver = WireMessage::Version {
        protocol_version: PROTOCOL_VERSION,
        chain_id,
        best_height,
        nonce: now_millis(),
    };
    if send_encrypted(&mut stream, &mut channel, &our_ver).is_err() {
        node.lock().unwrap().slots.disconnect(&peer_addr);
        return;
    }

    run_peer_sync_loop(
        stream,
        channel,
        peer_addr,
        node,
        broadcaster,
        shutdown,
        0,
        false,
    );
}

/// Spawns live TCP P2P listener on `bind_addr` (e.g. 0.0.0.0:19333).
pub fn spawn_p2p_listener(
    bind_addr: &str,
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
    shutdown: Arc<AtomicBool>,
) -> Result<SocketAddr, String> {
    let listener =
        TcpListener::bind(bind_addr).map_err(|e| format!("P2P bind {} failed: {}", bind_addr, e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("P2P nonblocking error: {}", e))?;
    let local_addr = listener.local_addr().map_err(|e| e.to_string())?;

    thread::spawn(move || {
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer_addr)) => {
                    let n = Arc::clone(&node);
                    let b = Arc::clone(&broadcaster);
                    let s = Arc::clone(&shutdown);
                    thread::spawn(move || handle_inbound_peer(stream, peer_addr, n, b, s));
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(40));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });

    Ok(local_addr)
}

/// Connects outbound over TCP, completes Noise_XX handshake, and keeps a live auto-sync thread running.
pub fn spawn_outbound_peer(
    remote_addr: SocketAddr,
    node: SharedNode,
    broadcaster: Arc<PeerBroadcaster>,
    shutdown: Arc<AtomicBool>,
) -> Result<([u8; 32], u64), String> {
    let (prologue, chain_id, local_height) = {
        let mut st = node.lock().unwrap();
        st.slots
            .add_outbound(remote_addr, false)
            .map_err(|_| "Outbound peer slot limit reached".to_string())?;
        (
            st.mode.noise_prologue(),
            st.mode.chain_id(),
            st.storage.tip_height(),
        )
    };

    let mut stream = match TcpStream::connect_timeout(&remote_addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            node.lock().unwrap().slots.disconnect(&remote_addr);
            return Err(format!("TCP connect {} failed: {}", remote_addr, e));
        }
    };
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let key = NodeStaticKey::generate().map_err(|_| "Keygen failed".to_string())?;
    let mut hs = NoiseHandshake::new_initiator(&key, prologue)
        .map_err(|_| "Initiator init failed".to_string())?;

    let m1 = hs.write_step(b"").map_err(|_| "Step 1 failed".to_string())?;
    write_framed(&mut stream, &m1)?;

    let m2 = read_framed_blocking(&mut stream)?;
    hs.read_step(&m2).map_err(|_| "Step 2 failed".to_string())?;

    let m3 = hs
        .write_step(b"EQX_INITIATOR_V1")
        .map_err(|_| "Step 3 failed".to_string())?;
    write_framed(&mut stream, &m3)?;

    let mut ch = hs
        .into_transport()
        .map_err(|_| "Transport transition failed".to_string())?;
    let remote_pk = ch
        .remote_public_key()
        .ok_or_else(|| "Missing remote static pubkey".to_string())?;

    let mut rl = PeerRateLimiter::mainnet_default(now_millis());

    // Read responder Version
    let ver_enc = read_framed_blocking(&mut stream)?;
    let peer_height = match decode_encrypted(&ver_enc, &mut ch, &mut rl)? {
        WireMessage::Version {
            chain_id: peer_chain,
            best_height: h,
            ..
        } => {
            if peer_chain != chain_id {
                node.lock().unwrap().slots.disconnect(&remote_addr);
                return Err("Remote peer has different chain_id".to_string());
            }
            h
        }
        _ => {
            node.lock().unwrap().slots.disconnect(&remote_addr);
            return Err("Expected Version message".to_string());
        }
    };

    // Send our Version and verify VerAck + encrypted Ping/Pong
    send_encrypted(
        &mut stream,
        &mut ch,
        &WireMessage::Version {
            protocol_version: PROTOCOL_VERSION,
            chain_id,
            best_height: local_height,
            nonce: now_millis(),
        },
    )?;
    let ack_enc = read_framed_blocking(&mut stream)?;
    if decode_encrypted(&ack_enc, &mut ch, &mut rl)? != WireMessage::VerAck {
        node.lock().unwrap().slots.disconnect(&remote_addr);
        return Err("Expected VerAck".to_string());
    }

    let ping_nonce = 0x9333_CAFEu64;
    send_encrypted(&mut stream, &mut ch, &WireMessage::Ping(ping_nonce))?;

    let mut got_pong = false;
    for _ in 0..8 {
        let enc = read_framed_blocking(&mut stream)?;
        match decode_encrypted(&enc, &mut ch, &mut rl)? {
            WireMessage::Pong(n) if n == ping_nonce => {
                got_pong = true;
                break;
            }
            WireMessage::GetMempool | WireMessage::GetBlocks { .. } => continue,
            _ => break,
        }
    }
    if !got_pong {
        node.lock().unwrap().slots.disconnect(&remote_addr);
        return Err("Invalid Pong response".to_string());
    }

    // Keep persistent Noise_XX connection alive in background for automatic Block & Mempool Sync
    thread::spawn(move || {
        run_peer_sync_loop(
            stream,
            ch,
            remote_addr,
            node,
            broadcaster,
            shutdown,
            peer_height,
            true,
        );
    });

    Ok((remote_pk, peer_height))
}
