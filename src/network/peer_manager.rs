#![allow(dead_code)]
// src/network/peer_manager.rs
// Equinox (EQX) L1 — Audit-Grade Active Peer Connection Handler, Dual-Stack (IPv4/IPv6) Subnet Guard,
// Inbound/Outbound Slot Reservation (Anti-Eclipse) & 12-Byte Checksummed Wire Framing Engine.

use crate::config::NETWORK_MAGIC;
use crate::crypto::hash::{constant_time_eq, sha256d, Hash256};
use crate::network::banman::{BanManager, MisbehaviorReason};
use crate::network::discovery::{PeerNodeInfo, MAX_SANE_BLOCK_HEIGHT};
use crate::primitives::block::{Block, BlockHeader, CompactBlock};
use crate::primitives::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

/// সর্বোচ্চ সক্রিয় পিয়ার কানেকশন সংখ্যা (Inbound + Outbound)
pub const MAX_ACTIVE_PEERS: usize = 64;

/// ইনবাউন্ড কানেকশন মনোপলি রোধে সর্বোচ্চ অনুমোদিত ইনবাউন্ড পিয়ার সংখ্যা (বাকি ১৬টি স্লট Outbound-এর জন্য সংরক্ষিত)
pub const MAX_INBOUND_PEERS: usize = 48;

/// Eclipse Attack রোধে একই `/24` (IPv4) বা `/48` (IPv6) সাবনেট থেকে সর্বোচ্চ অনুমোদিত কানেকশন
pub const MAX_PEERS_PER_SUBNET: usize = 3;

/// P2P ওয়্যার মেসেজের সর্বোচ্চ সাইজ (৪ মেগাবাইট)
pub const MAX_P2P_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// ওয়্যার ফ্রেম হেডার আকার: [Magic (4B)] + [Payload Length (4B)] + [SHA-256d Checksum (4B)] = 12 Bytes
pub const WIRE_HEADER_BYTES: usize = 12;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerError {
    #[error("আইপি অ্যাড্রেসটি বর্তমানে অটো-ব্যান তালিকায় ব্লক করা আছে: {0}")]
    IpBanned(String),

    #[error("সর্বোচ্চ পিয়ার কানেকশন সীমা ({MAX_ACTIVE_PEERS}) পূর্ণ হয়ে গেছে")]
    MaxPeersReached,

    #[error("একই সাবনেট থেকে অতিরিক্ত কানেকশন ব্লক করা হয়েছে (Eclipse Attack সুরক্ষা)")]
    SubnetLimitExceeded,

    #[error("অবৈধ নেটওয়ার্ক ম্যাজিক বাইটস (ভিন্ন ব্লকচেইন বা হ্যাকার প্যাকেট)")]
    InvalidMagicBytes,

    #[error("মেসেজ সাইজ সীমার বাইরে বা ক্ষতিগ্রস্ত পেলোড: {0}")]
    FrameDecodeError(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

/// Equinox P2P নেটওয়ার্কের সব ধরনের মেসেজ প্রটোকল
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2PMessage {
    /// কানেকশন শুরুর হ্যান্ডশেক মেসেজ
    Version {
        protocol_version: u32,
        best_height: u64,
        finalized_checkpoint: u64,
        node_id: Hash256,
        listen_port: u16,
    },
    /// হ্যান্ডশেক নিশ্চিতকরণ
    VerAck,
    /// কানেকশন সচল আছে কি না দেখার হার্টবিট
    Ping(u64),
    Pong(u64),
    /// DHT পিয়ার তালিকা আদান-প্রদান
    GetPeers,
    Peers(Vec<PeerNodeInfo>),
    /// হেডার-ফার্স্ট সিঙ্কের জন্য ব্লক হেডার রিকোয়েস্ট ও রেসপন্স
    GetHeaders {
        start_height: u64,
        max_count: u32,
    },
    Headers(Vec<BlockHeader>),
    /// ৯৫% ব্যান্ডউইথ সাশ্রয়ী ৬-বাইট শর্ট আইডির কম্প্যাক্ট ব্লক ব্রডকাস্ট
    NewCompactBlock(CompactBlock),
    /// কম্প্যাক্ট ব্লকে থাকা যে ১-২টি ট্রানজ্যাকশন মেমপুলে নেই শুধু সেগুলোর রিকোয়েস্ট
    GetBlockTransactions {
        block_hash: Hash256,
        missing_indices: Vec<usize>,
    },
    /// মিসিং ট্রানজ্যাকশনগুলোর রেসপন্স
    BlockTransactions {
        block_hash: Hash256,
        transactions: Vec<Transaction>,
    },
    /// সম্পূর্ণ ব্লক ডাউনলোড রিকোয়েস্ট ও রেসপন্স (ইনিশিয়াল সিঙ্কের জন্য)
    GetFullBlock(Hash256),
    FullBlock(Block),
    /// নতুন আনকনফার্মড ট্রানজ্যাকশন ব্রডকাস্ট
    RelayTransaction(Transaction),
}

/// সংযুক্ত থাকা একটি সক্রিয় পিয়ারের স্টেট
#[derive(Clone, Debug)]
pub struct ConnectedPeer {
    pub socket_addr: String,
    pub ip_only: String,
    pub subnet_prefix: String,
    pub direction: PeerDirection,
    pub handshake_completed: bool,
    pub best_height: u64,
    pub finalized_checkpoint: u64,
    pub last_message_timestamp: u64,
}

/// নোড কানেকশন হ্যান্ডলার ও মেসেজ ফ্রেমিং ইঞ্জিন
#[derive(Clone, Debug)]
pub struct PeerManager {
    peers: HashMap<String, ConnectedPeer>,
    pub ban_manager: BanManager,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            ban_manager: BanManager::new(),
        }
    }

    /// সকেট অ্যাড্রেস থেকে নিখুঁতভাবে আইপি এবং `/24` (IPv4) বা `/48` (IPv6) সাবনেট প্রিফিক্স বের করে।
    /// যেমন: `"203.0.113.45:9333"` -> `("203.0.113.45", "203.0.113")`
    /// এবং `"[2001:db8:85a3::1]:9333"` -> `("2001:db8:85a3::1", "2001:0db8:85a3")`
    pub fn extract_ip_and_subnet(socket_addr: &str) -> (String, String) {
        let trimmed = socket_addr.trim();

        // ১. স্ট্যান্ডার্ড SocketAddr (IPv4 ও ব্র্যাকেটেড IPv6) পার্সিং
        if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
            return Self::format_ip_and_subnet(parsed.ip());
        }

        // ২. যদি পোর্ট ছাড়া শুধু IP দেওয়া থাকে
        if let Ok(ip_addr) = trimmed.parse::<IpAddr>() {
            return Self::format_ip_and_subnet(ip_addr);
        }

        // ৩. ডোমেইন হোস্টনেম বা ফলব্যাক পার্সিং (`rsplit_once(':')` ব্যবহার করায় IPv6 ভাঙবে না)
        let host = if let Some((h, _port)) = trimmed.rsplit_once(':') {
            h.trim_matches(|c| c == '[' || c == ']')
        } else {
            trimmed
        };

        if let Ok(ip_addr) = host.parse::<IpAddr>() {
            return Self::format_ip_and_subnet(ip_addr);
        }

        let parts: Vec<&str> = host.split('.').collect();
        let subnet = if parts.len() == 4 {
            format!("{}.{}.{}", parts[0], parts[1], parts[2])
        } else {
            host.to_ascii_lowercase()
        };

        (host.to_string(), subnet)
    }

    fn format_ip_and_subnet(ip: IpAddr) -> (String, String) {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    return (v4.to_string(), "127.0.0".to_string());
                }
                let octets = v4.octets();
                let subnet = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
                (v4.to_string(), subnet)
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return (v6.to_string(), "127.0.0".to_string());
                }
                let segs = v6.segments();
                let subnet = format!("{:04x}:{:04x}:{:04x}", segs[0], segs[1], segs[2]);
                (v6.to_string(), subnet)
            }
        }
    }

    /// নতুন পিয়ার কানেকশন যাচাই (ব্যান চেক + ইনবাউন্ড কোটা + সাবনেট লিমিট চেক) করে যুক্ত করে
    pub fn register_peer(
        &mut self,
        socket_addr: &str,
        direction: PeerDirection,
        current_timestamp: u64,
    ) -> Result<(), PeerManagerError> {
        let clean_addr = socket_addr.trim();
        let (ip, subnet) = Self::extract_ip_and_subnet(clean_addr);

        // ১. হ্যাকারের আইপি ব্যান তালিকায় আছে কি না চেক
        if self.ban_manager.is_banned(&ip, current_timestamp) {
            return Err(PeerManagerError::IpBanned(ip));
        }

        if !self.peers.contains_key(clean_addr) {
            // ২. মোট পিয়ার সীমা (৬৪) চেক
            if self.peers.len() >= MAX_ACTIVE_PEERS {
                return Err(PeerManagerError::MaxPeersReached);
            }

            // ৩. ইনবাউন্ড মনোপলি গার্ড: ইনবাউন্ড পিয়ার ৪৮টির বেশি হতে পারবে না (১৬টি স্লট Outbound-এর জন্য সংরক্ষিত)
            if direction == PeerDirection::Inbound {
                let current_inbound = self
                    .peers
                    .values()
                    .filter(|p| p.direction == PeerDirection::Inbound)
                    .count();
                if current_inbound >= MAX_INBOUND_PEERS {
                    return Err(PeerManagerError::MaxPeersReached);
                }
            }

            // ৪. Eclipse Attack প্রতিরোধে একই সাবনেট থেকে ৩টির বেশি কানেকশন আটকে দেওয়া (লোকালহোস্ট ছাড়া)
            if subnet != "127.0.0" {
                let same_subnet_count = self
                    .peers
                    .values()
                    .filter(|p| p.subnet_prefix == subnet)
                    .count();
                if same_subnet_count >= MAX_PEERS_PER_SUBNET {
                    return Err(PeerManagerError::SubnetLimitExceeded);
                }
            }
        }

        let peer = ConnectedPeer {
            socket_addr: clean_addr.to_string(),
            ip_only: ip,
            subnet_prefix: subnet,
            direction,
            handshake_completed: false,
            best_height: 0,
            finalized_checkpoint: 0,
            last_message_timestamp: current_timestamp,
        };

        self.peers.insert(clean_addr.to_string(), peer);
        Ok(())
    }

    /// পিয়ারের হ্যান্ডশেক (`Version`) সম্পন্ন করে (হাইট ও ফাইনালিটি স্যানিটি চেকসহ)
    pub fn complete_handshake(
        &mut self,
        socket_addr: &str,
        best_height: u64,
        finalized_checkpoint: u64,
        current_timestamp: u64,
    ) {
        let clean_addr = socket_addr.trim();
        let clamped_height = best_height.min(MAX_SANE_BLOCK_HEIGHT);
        let clamped_checkpoint = finalized_checkpoint.min(clamped_height);

        if let Some(peer) = self.peers.get_mut(clean_addr) {
            peer.handshake_completed = true;
            peer.best_height = clamped_height;
            peer.finalized_checkpoint = clamped_checkpoint;
            peer.last_message_timestamp = current_timestamp;
        }
    }

    /// ক্ষতিকর আচরণ করা পিয়ারকে পেনাল্টি দেয় এবং ১০০ পয়েন্ট হলে কানেকশন কেটে ব্যান করে
    pub fn penalize_peer(
        &mut self,
        socket_addr: &str,
        reason: MisbehaviorReason,
        current_timestamp: u64,
    ) -> bool {
        let (ip, _) = Self::extract_ip_and_subnet(socket_addr);
        let banned = self
            .ban_manager
            .record_misbehavior(&ip, reason, current_timestamp);

        if banned {
            // ওই আইপি থেকে থাকা সব কানেকশন তাৎক্ষণিক বিচ্ছিন্ন করে দেওয়া হবে
            self.peers.retain(|_, p| p.ip_only != ip);
        }
        banned
    }

    /// P2P মেসেজকে সুরক্ষিত ১২-বাইট হেডারযুক্ত বাইনারি ওয়্যার ফ্রেমে
    /// (`[Magic 4B] + [Length 4B] + [SHA256d Checksum 4B] + [Payload]`) রূপান্তর করে
    pub fn encode_wire_frame(msg: &P2PMessage) -> Result<Vec<u8>, PeerManagerError> {
        let payload = bincode::serialize(msg)
            .map_err(|e| PeerManagerError::FrameDecodeError(e.to_string()))?;

        if payload.is_empty() || payload.len() > MAX_P2P_MESSAGE_BYTES {
            return Err(PeerManagerError::FrameDecodeError(
                "পেলোড সাইজ ৪ মেগাবাইট সীমা ছাড়িয়েছে".to_string(),
            ));
        }

        let len_bytes = (payload.len() as u32).to_le_bytes();
        let checksum_hash = sha256d(&payload);

        let mut frame = Vec::with_capacity(WIRE_HEADER_BYTES + payload.len());
        frame.extend_from_slice(&NETWORK_MAGIC);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&checksum_hash[..4]);
        frame.extend_from_slice(&payload);

        Ok(frame)
    }

    /// বাইনারি ওয়্যার ফ্রেম থেকে কনস্ট্যান্ট-টাইমে ম্যাজিক বাইটস ও ৪-বাইট `sha256d` চেকসাম যাচাই করে `P2PMessage` ডিকোড করে
    pub fn decode_wire_frame(frame: &[u8]) -> Result<P2PMessage, PeerManagerError> {
        if frame.len() < WIRE_HEADER_BYTES {
            return Err(PeerManagerError::FrameDecodeError(
                "ফ্রেম হেডার অসম্পূর্ণ (ন্যূনতম ১২ বাইট প্রয়োজন)".to_string(),
            ));
        }

        if !constant_time_eq(&frame[0..4], &NETWORK_MAGIC) {
            return Err(PeerManagerError::InvalidMagicBytes);
        }

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&frame[4..8]);
        let expected_len = u32::from_le_bytes(len_bytes) as usize;

        if expected_len == 0
            || expected_len > MAX_P2P_MESSAGE_BYTES
            || frame.len() < WIRE_HEADER_BYTES + expected_len
        {
            return Err(PeerManagerError::FrameDecodeError(
                "পেলোড সাইজ মেলেনি বা সীমার বাইরে".to_string(),
            ));
        }

        let expected_checksum = &frame[8..12];
        let payload = &frame[WIRE_HEADER_BYTES..WIRE_HEADER_BYTES + expected_len];

        let actual_checksum = sha256d(payload);
        if !constant_time_eq(&actual_checksum[..4], expected_checksum) {
            return Err(PeerManagerError::FrameDecodeError(
                "ওয়্যার ফ্রেম SHA-256d চেকসাম মেলেনি! প্যাকেট করাপ্টেড বা টেম্পারড".to_string(),
            ));
        }

        bincode::deserialize(payload)
            .map_err(|e| PeerManagerError::FrameDecodeError(e.to_string()))
    }

    /// হ্যান্ডশেক সম্পন্ন হওয়া সব সক্রিয় পিয়ারের অ্যাড্রেস তালিকা দেয় (মেসেজ ব্রডকাস্টের জন্য)
    pub fn broadcast_targets(&self) -> Vec<String> {
        let mut targets: Vec<String> = self
            .peers
            .values()
            .filter(|p| p.handshake_completed)
            .map(|p| p.socket_addr.clone())
            .collect();
        targets.sort();
        targets
    }

    #[inline]
    pub fn active_peer_count(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_framing_checksum_and_ipv4_ipv6_subnet_protection() {
        let mut pm = PeerManager::new();
        let now = 1_729_468_800;

        // ১. একই IPv4 সাবনেট (203.0.113.x) থেকে ৩টি নোড যুক্ত হতে পারবে
        assert!(pm
            .register_peer("203.0.113.1:9333", PeerDirection::Inbound, now)
            .is_ok());
        assert!(pm
            .register_peer("203.0.113.2:9333", PeerDirection::Inbound, now)
            .is_ok());
        assert!(pm
            .register_peer("203.0.113.3:9333", PeerDirection::Inbound, now)
            .is_ok());

        // ৪র্থ নোড একই সাবনেট থেকে এলে Eclipse Attack হিসেবে ব্লক হবে
        assert_eq!(
            pm.register_peer("203.0.113.4:9333", PeerDirection::Inbound, now),
            Err(PeerManagerError::SubnetLimitExceeded)
        );

        // ২. ভিন্ন IPv6 সাবনেটগুলো সঠিকভাবে আলাদা হিসেবে চিহ্নিত হবে
        assert!(pm
            .register_peer("[2001:db8:1111::1]:9333", PeerDirection::Inbound, now)
            .is_ok());
        assert!(pm
            .register_peer("[2001:db8:2222::1]:9333", PeerDirection::Inbound, now)
            .is_ok());

        // ৩. ১২-বাইট চেকসামযুক্ত মেসেজ ফ্রেমিং ও ডিকোড টেস্ট
        let ping = P2PMessage::Ping(99999);
        let mut encoded = PeerManager::encode_wire_frame(&ping).unwrap();
        let decoded = PeerManager::decode_wire_frame(&encoded).unwrap();
        assert_eq!(ping, decoded);

        // পেলোডের ১ বিট পরিবর্তন করলেই চেকসাম গার্ড তা ব্লক করবে
        let last_idx = encoded.len() - 1;
        encoded[last_idx] ^= 0x01;
        assert!(PeerManager::decode_wire_frame(&encoded).is_err());
    }
}
