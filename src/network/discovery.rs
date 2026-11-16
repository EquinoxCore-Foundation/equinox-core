#![allow(dead_code)]
// src/network/discovery.rs
// Equinox (EQX) L1 — Audit-Grade Kademlia XOR Distributed Peer Discovery (DHT) & Bootstrap Engine
// Features: /24 & IPv6 Subnet Sybil/Eclipse Defense, Seed Node Immunity, Zero-ID Rejection,
// and Outlier-Filtered Sync Peer Selection (Anti-u64::MAX Sync Hijacking).

use crate::config::DEFAULT_P2P_PORT;
use crate::crypto::hash::{constant_time_eq, sha256d, Hash256, ZERO_HASH};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

/// প্রাথমিক বুটস্ট্র্যাপ সিড নোড তালিকা (নতুন নোড চালু হলে প্রথমে এগুলোর সাথে যোগাযোগ করবে)
pub const DEFAULT_BOOTSTRAP_SEEDS: &[&str] = &[
    "seed1.equinoxchain.org:9333",
    "seed2.equinoxchain.org:9333",
    "seed3.equinoxchain.org:9333",
    "127.0.0.1:9333",
];

/// রাউটিং টেবিলে সর্বোচ্চ অনুমোদিত পিয়ার সংখ্যা
pub const DEFAULT_MAX_ROUTING_TABLE_SIZE: usize = 1000;

/// Eclipse ও Sybil Attack রোধে একই `/24` সাবনেট থেকে DHT রাউটিং টেবিলে সর্বোচ্চ অনুমোদিত নোড সংখ্যা
pub const MAX_DHT_PEERS_PER_SUBNET: usize = 4;

/// ভুয়া `u64::MAX` হাইট অ্যাটাক রোধে সর্বোচ্চ যৌক্তিক ব্লক হাইট সীমা (~১,০০০ বছরের ব্লক)
pub const MAX_SANE_BLOCK_HEIGHT: u64 = 2_500_000_000;

/// নেটওয়ার্ক মেডিয়ানের তুলনায় কোনো পিয়ার এক লাফে সর্বোচ্চ কত ব্লক এগিয়ে থাকতে পারে (Outlier Guard)
pub const MAX_SYNC_OUTLIER_JUMP_BLOCKS: u64 = 10_000_000;

/// নেটওয়ার্কের একটি নোডের পরিচিতি ও রাউটিং তথ্য
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerNodeInfo {
    /// নোডের ২৫৬-বিট ইউনিক DHT আইডি
    pub node_id: Hash256,
    /// নোডের আইপি ও পোর্ট (যেমন: "203.0.113.5:9333")
    pub socket_addr: String,
    /// সর্বশেষ কখন নোডটিকে সক্রিয় দেখা গেছে
    pub last_seen: u64,
    /// নোডটির কাছে থাকা সর্বশেষ ব্লক হাইট
    pub best_height: u64,
    /// এটি অফিশিয়াল বুটস্ট্র্যাপ সিড নোড কি না
    pub is_seed: bool,
}

/// Kademlia DHT ও সিড নোড ডিসকভারি ইঞ্জিন
#[derive(Clone, Debug)]
pub struct PeerDiscovery {
    local_node_id: Hash256,
    /// Socket Address -> PeerNodeInfo
    known_peers: HashMap<String, PeerNodeInfo>,
    max_routing_table_size: usize,
}

impl PeerDiscovery {
    /// লোকাল নোড আইডি দিয়ে ডিসকভারি ইঞ্জিন চালু করে এবং ডিফল্ট সিড নোডগুলো লোড করে
    pub fn new(local_node_id: Hash256, bootstrap_timestamp: u64) -> Self {
        let mut discovery = Self {
            local_node_id,
            known_peers: HashMap::new(),
            max_routing_table_size: DEFAULT_MAX_ROUTING_TABLE_SIZE,
        };

        discovery.load_default_seeds(bootstrap_timestamp);
        discovery
    }

    /// অফিশিয়াল সিড নোডগুলো রাউটিং টেবিলে যুক্ত করে
    pub fn load_default_seeds(&mut self, timestamp: u64) {
        for &seed_addr in DEFAULT_BOOTSTRAP_SEEDS {
            let deterministic_id = sha256d(seed_addr.as_bytes());
            let info = PeerNodeInfo {
                node_id: deterministic_id,
                socket_addr: seed_addr.to_string(),
                last_seen: timestamp,
                best_height: 0,
                is_seed: true,
            };
            self.known_peers.insert(seed_addr.to_string(), info);
        }
    }

    /// সকেট অ্যাড্রেস বৈধ কি না তা পরীক্ষা করে এবং `/24` (IPv4) বা `/48` (IPv6) সাবনেট প্রিফিক্স বের করে
    pub fn extract_validated_subnet(socket_addr: &str) -> Option<String> {
        let trimmed = socket_addr.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            return None;
        }

        // ১. যদি সরাসরি IPv4 বা IPv6 SocketAddr হয়
        if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
            if parsed.port() == 0 {
                return None;
            }
            return match parsed.ip() {
                std::net::IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    Some(format!("{}.{}.{}", octets[0], octets[1], octets[2]))
                }
                std::net::IpAddr::V6(v6) => {
                    let segs = v6.segments();
                    Some(format!("{:04x}:{:04x}:{:04x}", segs[0], segs[1], segs[2]))
                }
            };
        }

        // ২. যদি ডোমেইন সিড অ্যাড্রেস হয় (যেমন: "seed1.equinoxchain.org:9333")
        let (host, port_str) = trimmed.rsplit_once(':')?;
        let port = port_str.parse::<u16>().ok()?;
        if port == 0 || host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return None;
        }

        Some(host.to_ascii_lowercase())
    }

    /// নতুন কোনো পিয়ারের সন্ধান পেলে Sybil, Subnet ও Sanity চেক সম্পন্ন করে রাউটিং টেবিলে যুক্ত বা আপডেট করে
    pub fn add_or_update_peer(&mut self, mut peer: PeerNodeInfo) {
        let clean_addr = peer.socket_addr.trim().to_string();
        peer.socket_addr = clean_addr.clone();

        // ১. নিজের নোড আইডি অথবা শূন্য (All-Zero) নোড আইডি গ্রহণ করা হবে না
        if constant_time_eq(&peer.node_id, &self.local_node_id)
            || constant_time_eq(&peer.node_id, &ZERO_HASH)
        {
            return;
        }

        // ২. সকেট অ্যাড্রেস ফরম্যাট ও সাবনেট যাচাই
        let Some(subnet_key) = Self::extract_validated_subnet(&clean_addr) else {
            return;
        };

        // ৩. অস্বাভাবিক বা ভুয়া `u64::MAX` ব্লক হাইট ক্ল্যাম্প বা রিজেক্ট করা
        if peer.best_height > MAX_SANE_BLOCK_HEIGHT {
            return;
        }

        // ৪. বাহ্যিক গসিপ মেসেজ কখনোই নিজেকে অফিশিয়াল সিড (`is_seed = true`) দাবি করতে পারবে না
        let is_official_seed = DEFAULT_BOOTSTRAP_SEEDS.contains(&clean_addr.as_str());
        peer.is_seed = is_official_seed;

        // ৫. একই `node_id` দিয়ে অন্য সকেট অ্যাড্রেস স্পুফিং প্রতিরোধ
        if self
            .known_peers
            .values()
            .any(|existing| existing.socket_addr != clean_addr && constant_time_eq(&existing.node_id, &peer.node_id))
        {
            return;
        }

        // ৬. যদি অ্যাড্রেসটি আগে থেকেই টেবিলে থাকে, তবে নিরাপদে আপডেট করা
        if let Some(existing) = self.known_peers.get_mut(&clean_addr) {
            // অফিশিয়াল সিডের নোড আইডি পরিবর্তন হতে দেওয়া হবে না
            if existing.is_seed {
                existing.last_seen = existing.last_seen.max(peer.last_seen);
                existing.best_height = existing.best_height.max(peer.best_height);
            } else {
                *existing = peer;
            }
            return;
        }

        // ৭. সাবনেট ডাইভার্সিটি গার্ড: একই সাবনেট থেকে ৪টির বেশি পিয়ার ঢুকতে দেওয়া হবে না (লোকালহোস্ট ছাড়া)
        if subnet_key != "127.0.0" && !is_official_seed {
            let same_subnet_count = self
                .known_peers
                .values()
                .filter(|p| {
                    Self::extract_validated_subnet(&p.socket_addr).as_deref() == Some(subnet_key.as_str())
                })
                .count();

            if same_subnet_count >= MAX_DHT_PEERS_PER_SUBNET {
                return;
            }
        }

        // ৮. টেবিল পূর্ণ হলে সবচেয়ে পুরোনো নন-সিড নোডটি সরিয়ে জায়গা তৈরি করা
        if self.known_peers.len() >= self.max_routing_table_size {
            if let Some(oldest_addr) = self
                .known_peers
                .values()
                .filter(|p| !p.is_seed)
                .min_by_key(|p| p.last_seen)
                .map(|p| p.socket_addr.clone())
            {
                self.known_peers.remove(&oldest_addr);
            } else {
                return;
            }
        }

        self.known_peers.insert(clean_addr, peer);
    }

    /// দুটি ২৫৬-বিট নোড আইডির মধ্যে Kademlia XOR দূরত্ব (`a ^ b`) হিসাব করে
    #[inline]
    pub fn xor_distance(a: &Hash256, b: &Hash256) -> Hash256 {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = a[i] ^ b[i];
        }
        dist
    }

    /// নির্দিষ্ট টার্গেট আইডির সবচেয়ে কাছাকাছি থাকা `count` সংখ্যক নোড খুঁজে বের করে (Kademlia K-Closest Lookup)
    pub fn find_closest_peers(&self, target_id: &Hash256, count: usize) -> Vec<PeerNodeInfo> {
        let mut peers: Vec<PeerNodeInfo> = self.known_peers.values().cloned().collect();
        peers.sort_by(|p1, p2| {
            let d1 = Self::xor_distance(&p1.node_id, target_id);
            let d2 = Self::xor_distance(&p2.node_id, target_id);
            d1.cmp(&d2)
                .then_with(|| p1.socket_addr.cmp(&p2.socket_addr))
        });
        peers.into_iter().take(count).collect()
    }

    /// ব্লক ডাউনলোড বা সিঙ্ক করার জন্য ভুয়া আউটলায়ার (`u64::MAX`) বাদ দিয়ে সবচেয়ে নির্ভরযোগ্য সক্রিয় নোডগুলোর তালিকা দেয়
    pub fn select_best_sync_peers(&self, max_count: usize) -> Vec<PeerNodeInfo> {
        if self.known_peers.is_empty() || max_count == 0 {
            return Vec::new();
        }

        // নন-জিরো হাইট থাকা পিয়ারদের মেডিয়ান হাইট বের করে আউটলায়ার সীমা নির্ধারণ
        let mut non_zero_heights: Vec<u64> = self
            .known_peers
            .values()
            .map(|p| p.best_height)
            .filter(|&h| h > 0 && h <= MAX_SANE_BLOCK_HEIGHT)
            .collect();

        let max_allowed_height = if non_zero_heights.len() >= 3 {
            non_zero_heights.sort_unstable();
            let median = non_zero_heights[non_zero_heights.len() / 2];
            median.saturating_add(MAX_SYNC_OUTLIER_JUMP_BLOCKS)
        } else {
            MAX_SANE_BLOCK_HEIGHT
        };

        let mut peers: Vec<PeerNodeInfo> = self
            .known_peers
            .values()
            .filter(|p| p.best_height <= max_allowed_height)
            .cloned()
            .collect();

        peers.sort_by(|a, b| {
            b.best_height
                .cmp(&a.best_height)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
                .then_with(|| a.socket_addr.cmp(&b.socket_addr))
        });

        peers.into_iter().take(max_count).collect()
    }

    /// রাউটিং টেবিলে থাকা মোট নোড সংখ্যা
    #[inline]
    pub fn known_peers_count(&self) -> usize {
        self.known_peers.len()
    }

    /// ডিফল্ট পোর্টসহ লোকাল লিসেন অ্যাড্রেস ফরম্যাট করে
    pub fn default_listen_addr(ip: &str) -> String {
        format!("{}:{}", ip.trim(), DEFAULT_P2P_PORT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_xor_closest_peer_lookup() {
        let local_id = sha256d(b"local_node");
        let mut discovery = PeerDiscovery::new(local_id, 1000);

        let target = [0xAAu8; 32];
        let close_peer = PeerNodeInfo {
            node_id: [0xABu8; 32],
            socket_addr: "198.51.100.10:9333".to_string(),
            last_seen: 1050,
            best_height: 500,
            is_seed: false,
        };
        let far_peer = PeerNodeInfo {
            node_id: [0x01u8; 32],
            socket_addr: "198.51.100.20:9333".to_string(),
            last_seen: 1050,
            best_height: 100,
            is_seed: false,
        };

        discovery.add_or_update_peer(close_peer.clone());
        discovery.add_or_update_peer(far_peer);

        let closest = discovery.find_closest_peers(&target, 1);
        assert_eq!(closest[0].socket_addr, close_peer.socket_addr);
    }

    #[test]
    fn test_subnet_flood_and_fake_height_hijack_defense() {
        let local_id = sha256d(b"local_node");
        let mut discovery = PeerDiscovery::new(local_id, 1000);

        // একই সাবনেট (203.0.113.x) থেকে ১০টি নোড ঢোকার চেষ্টা করলে মাত্র ৪টি ঢুকতে পারবে
        for i in 1..=10u8 {
            discovery.add_or_update_peer(PeerNodeInfo {
                node_id: [i; 32],
                socket_addr: format!("203.0.113.{}:9333", i),
                last_seen: 2000 + (i as u64),
                best_height: 1_000,
                is_seed: false,
            });
        }

        let subnet_count = discovery
            .known_peers
            .values()
            .filter(|p| p.socket_addr.starts_with("203.0.113."))
            .count();
        assert_eq!(subnet_count, MAX_DHT_PEERS_PER_SUBNET);

        // হ্যাকার u64::MAX হাইট দাবি করলে সেটি সম্পূর্ণ রিজেক্ট হবে
        discovery.add_or_update_peer(PeerNodeInfo {
            node_id: [0xEEu8; 32],
            socket_addr: "192.0.2.99:9333".to_string(),
            last_seen: 9999,
            best_height: u64::MAX,
            is_seed: false,
        });

        let best = discovery.select_best_sync_peers(1);
        assert_eq!(best[0].best_height, 1_000);
    }
}
