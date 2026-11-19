#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use equinox_network::banlist::Misbehavior;
use equinox_network::protocol::{WireMessage, PROTOCOL_VERSION};
use equinox_network::ratelimit::PeerRateLimiter;
use equinox_network::transport::{
    EncryptedChannel, NodeStaticKey, NoiseHandshake, MAX_NOISE_PACKET_BYTES,
};

use crate::genesis::to_hex;
use crate::runtime::{now_millis, now_secs, SharedNode};

fn write_framed(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_NOISE_PACKET_BYTES {
        return Err("Frame exceeds Noise packet cap".to_string());
    }
    let len_bytes = (data.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).map_err(|e| e.to_string())?;
    stream.write_all(data).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn read_framed(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
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

fn recv_encrypted(
    stream: &mut TcpStream,
    ch: &mut EncryptedChannel,
    rl: &mut PeerRateLimiter,
) -> Result<WireMessage, String> {
    let enc = read_framed(stream)?;
    rl.check_and_consume(enc.len() as u64, now_millis())
        .map_err(|_| "Peer rate limit exceeded".to_string())?;
    let dec = ch
        .decrypt_frame(&enc)
        .map_err(|_| "Noise decrypt failed".to_string())?;
    WireMessage::decode(&dec).map_err(|_| "Malformed wire message".to_string())
}

fn handle_inbound_peer(mut stream: TcpStream, peer_addr: SocketAddr, node: SharedNode) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let (prologue, chain_id, best_height, hs_res) = {
        let mut st = node.lock().unwrap();
        if st.banlist.is_banned(peer_addr.ip(), now_secs()) {
            return;
        }
        if st.slots.add_inbound(peer_addr).is_err() {
            return;
        }
        let prologue = st.mode.noise_prologue();
        let hs = NoiseHandshake::new_responder(&st.node_key, prologue);
        (prologue, st.mode.chain_id(), st.storage.tip_height(), hs)
    };

    let _ = prologue;
    let mut hs = match hs_res {
        Ok(h) => h,
        Err(_) => {
            node.lock().unwrap().slots.disconnect(&peer_addr);
            return;
        }
    };

    // 3-step Noise_XX Responder Handshake (<- m1, -> m2, <- m3)
    let handshake_ok = (|| -> Result<EncryptedChannel, String> {
        let m1 = read_framed(&mut stream)?;
        hs.read_step(&m1).map_err(|_| "Noise step 1 failed".to_string())?;

        let m2 = hs
            .write_step(b"EQX_RESPONDER_V1")
            .map_err(|_| "Noise step 2 failed".to_string())?;
        write_framed(&mut stream, &m2)?;

        let m3 = read_framed(&mut stream)?;
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

    let mut rl = PeerRateLimiter::mainnet_default(now_millis());

    // Exchange Version / VerAck and respond to Ping / GetPeers
    let _ = (|| -> Result<(), String> {
        let our_ver = WireMessage::Version {
            protocol_version: PROTOCOL_VERSION,
            chain_id,
            best_height,
            nonce: now_millis(),
        };
        send_encrypted(&mut stream, &mut channel, &our_ver)?;

        loop {
            match recv_encrypted(&mut stream, &mut channel, &mut rl) {
                Ok(WireMessage::Version {
                    chain_id: peer_chain,
                    ..
                }) => {
                    if peer_chain != chain_id {
                        return Err("Chain ID mismatch".to_string());
                    }
                    send_encrypted(&mut stream, &mut channel, &WireMessage::VerAck)?;
                }
                Ok(WireMessage::Ping(n)) => {
                    send_encrypted(&mut stream, &mut channel, &WireMessage::Pong(n))?;
                }
                Ok(WireMessage::VerAck) | Ok(WireMessage::Pong(_)) => {}
                Ok(WireMessage::InvBlock(_)) | Ok(WireMessage::InvTx(_)) | Ok(WireMessage::GetPeers) => {}
                Err(_) => break,
            }
        }
        Ok(())
    })();

    node.lock().unwrap().slots.disconnect(&peer_addr);
}

/// Spawns live TCP P2P listener on `bind_addr` (e.g. 0.0.0.0:19333). Returns actual bound SocketAddr.
pub fn spawn_p2p_listener(
    bind_addr: &str,
    node: SharedNode,
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
                    thread::spawn(move || handle_inbound_peer(stream, peer_addr, n));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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

/// Connects outbound over TCP to a remote Equinox peer, completes Noise_XX E2EE handshake, and tests Ping/Pong.
pub fn dial_and_verify_peer(
    remote_addr: SocketAddr,
    prologue: &[u8],
    chain_id: u64,
    best_height: u64,
) -> Result<([u8; 32], u64), String> {
    let mut stream = TcpStream::connect_timeout(&remote_addr, Duration::from_secs(5))
        .map_err(|e| format!("TCP connect {} failed: {}", remote_addr, e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let key = NodeStaticKey::generate().map_err(|_| "Keygen failed".to_string())?;
    let mut hs = NoiseHandshake::new_initiator(&key, prologue)
        .map_err(|_| "Initiator init failed".to_string())?;

    let m1 = hs.write_step(b"").map_err(|_| "Step 1 failed".to_string())?;
    write_framed(&mut stream, &m1)?;

    let m2 = read_framed(&mut stream)?;
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

    // Receive responder's Version
    let peer_height = match recv_encrypted(&mut stream, &mut ch, &mut rl)? {
        WireMessage::Version {
            chain_id: peer_chain,
            best_height: h,
            ..
        } => {
            if peer_chain != chain_id {
                return Err("Remote peer has different chain_id".to_string());
            }
            h
        }
        _ => return Err("Expected Version message".to_string()),
    };

    // Send our Version and expect VerAck
    send_encrypted(
        &mut stream,
        &mut ch,
        &WireMessage::Version {
            protocol_version: PROTOCOL_VERSION,
            chain_id,
            best_height,
            nonce: now_millis(),
        },
    )?;
    if recv_encrypted(&mut stream, &mut ch, &mut rl)? != WireMessage::VerAck {
        return Err("Expected VerAck".to_string());
    }

    // Encrypted Ping / Pong roundtrip
    let ping_nonce = 0x9333_CAFEu64;
    send_encrypted(&mut stream, &mut ch, &WireMessage::Ping(ping_nonce))?;
    match recv_encrypted(&mut stream, &mut ch, &mut rl)? {
        WireMessage::Pong(n) if n == ping_nonce => Ok((remote_pk, peer_height)),
        _ => Err("Invalid Pong response".to_string()),
    }
}
