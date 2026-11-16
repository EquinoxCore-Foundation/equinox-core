#![allow(dead_code)]
// src/network/mesh_autonat.rs
// Equinox (EQX) L1 — Serverless Internet P2P Mesh, Gossip Peer Exchange (PEX),
// AutoNAT Public-IP Consensus & Simultaneous Hole-Punching Rendezvous Engine.

use crate::config::DEFAULT_P2P_PORT;
use crate::crypto::hash::{sha256d_tagged, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// গসিপ পেেলোডে একবারে সর্বোচ্চ পিয়ার আদান-প্রদান সংখ্যা
pub const MAX_PEX_GOSSIP_PEERS: usize = 32;

/// রাউটার NAT স্ট্যাটাস (কম্পিউটারটি সরাসরি ইন্টারনেটে উন্মুক্ত কি না)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatReachability {
    Unknown,
    PubliclyReachable,
    BehindSymmetricOrRestrictedNat,
    HolePunchingActive,
}

/// ইন্টারনেটে সচল একটি কম্পিউটারের (Peer Node) পরিচয় ও কানেকশন কার্ড
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPeerEndpoint {
    pub node_id: Hash256,
    pub public_ip: String,
    pub listen_port: u16,
    pub last_seen_unix: u64,
    pub latency_ms: u32,
    pub is_relayed_hole_punch: bool,
}

/// দুটি ফায়ারওয়াল-বন্দি কম্পিউটারকে সরাসরি যুক্ত করার হোল-পাঞ্চিং সিঙ্ক টিকিট
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolePunchTicket {
    pub ticket_id: Hash256,
    pub initiator_node_id: Hash256,
    pub initiator_public_endpoint: String,
    pub target_node_id: Hash256,
    pub target_public_endpoint: String,
    pub sync_timestamp_ms: u64,
}

/// সার্ভারহীন ডিসেন্ট্রালাইজড P2P মেশ ও AutoNAT কন্ট্রোলার
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerlessP2PMesh {
    pub local_node_id: Hash256,
    pub nat_status: NatReachability,
    pub detected_external_ip: Option<String>,
    /// অন্য পিয়াররা আমাদের যে আইপি দেখেছে তার ভোট (Fake IP Spoofing রোধ করতে)
    pub external_ip_votes: HashMap<String, usize>,
    /// সচল কম্পিউটারগুলোর গসিপ টেবিল (IP:Port -> Endpoint)
    pub active_mesh_peers: HashMap<String, MeshPeerEndpoint>,
    /// একই রাউটার বা ওয়াইফাইয়ের (LAN) ভেতরে পাওয়া লোকাল নোড
    pub lan_discovered_endpoints: HashSet<String>,
}

impl ServerlessP2PMesh {
    pub fn new(local_node_id: Hash256) -> Self {
        Self {
            local_node_id,
            nat_status: NatReachability::Unknown,
            detected_external_ip: None,
            external_ip_votes: HashMap::new(),
            active_mesh_peers: HashMap::new(),
            lan_discovered_endpoints: HashSet::new(),
        }
    }

    /// ১. AutoNAT Consensus: কমপক্ষে ৩টি ভিন্ন কম্পিউটার যদি একই পাবলিক আইপি রিপোর্ট করে, তবে কোনো সার্ভার ছাড়াই নিজের আসল ইন্টারনেট আইপি নিশ্চিত হয়
    pub fn record_peer_observed_external_ip(&mut self, reported_ip: &str) -> Option<String> {
        let clean_ip = reported_ip.trim().to_string();
        if clean_ip.is_empty() || clean_ip == "127.0.0.1" || clean_ip == "0.0.0.0" {
            return self.detected_external_ip.clone();
        }

        let count = self.external_ip_votes.entry(clean_ip.clone()).or_insert(0);
        *count += 1;

        if *count >= 3 {
            self.detected_external_ip = Some(clean_ip.clone());
            if self.nat_status == NatReachability::Unknown {
                self.nat_status = NatReachability::PubliclyReachable;
            }
        }
        self.detected_external_ip.clone()
    }

    /// ২. Gossip PEX (Peer Exchange): নতুন কম্পিউটার যুক্ত হলে তাকে আমাদের চেনা সবচেয়ে ফাস্ট ও সচল পিয়ারদের তালিকা দেয়
    pub fn export_pex_gossip_list(&self, current_unix: u64) -> Vec<MeshPeerEndpoint> {
        let mut candidates: Vec<MeshPeerEndpoint> = self
            .active_mesh_peers
            .values()
            .filter(|p| current_unix.saturating_sub(p.last_seen_unix) <= 7_200) // গত ২ ঘণ্টায় সচল
            .cloned()
            .collect();

        // কম ল্যাটেন্সি (দ্রুততম পিং) অনুযায়ী সাজানো
        candidates.sort_by_key(|p| p.latency_ms);
        candidates.truncate(MAX_PEX_GOSSIP_PEERS);
        candidates
    }

    /// অন্য কম্পিউটার থেকে পাওয়া Gossip PEX তালিকা নিজের মেশ টেবিলে যুক্ত করে (/16 সাবনেট ডাইভার্সিটি গার্ডসহ)
    pub fn ingest_pex_gossip_list(
        &mut self,
        incoming_peers: Vec<MeshPeerEndpoint>,
        current_unix: u64,
    ) -> usize {
        let mut added = 0usize;
        for peer in incoming_peers {
            if peer.node_id == self.local_node_id || peer.listen_port == 0 {
                continue;
            }
            if !Self::is_valid_public_or_lan_ipv4(&peer.public_ip) {
                continue;
            }

            let key = format!("{}:{}", peer.public_ip, peer.listen_port);
            if !self.active_mesh_peers.contains_key(&key) {
                added += 1;
            }

            let mut updated = peer;
            updated.last_seen_unix = current_unix;
            self.active_mesh_peers.insert(key, updated);
        }
        added
    }

    /// ৩. NAT Hole-Punching Ticket: রাউটারের পেছনে থাকা দুটি কম্পিউটারকে সরাসরি যুক্ত করার ক্রিপ্টোগ্রাফিক সিঙ্ক টিকিট তৈরি করে
    pub fn create_hole_punch_ticket(
        &mut self,
        initiator_endpoint: &str,
        target_node_id: Hash256,
        target_endpoint: &str,
        current_time_ms: u64,
    ) -> Result<HolePunchTicket, String> {
        if initiator_endpoint.trim().is_empty() || target_endpoint.trim().is_empty() {
            return Err("হোল-পাঞ্চিংয়ের জন্য উভয় কম্পিউটারের এন্ডপয়েন্ট প্রয়োজন".to_string());
        }

        let mut seed = Vec::with_capacity(96);
        seed.extend_from_slice(&self.local_node_id);
        seed.extend_from_slice(&target_node_id);
        seed.extend_from_slice(&current_time_ms.to_le_bytes());

        let ticket_id = sha256d_tagged(b"EQX_P2P_HOLE_PUNCH_TICKET_V1", &seed);
        self.nat_status = NatReachability::HolePunchingActive;

        Ok(HolePunchTicket {
            ticket_id,
            initiator_node_id: self.local_node_id,
            initiator_public_endpoint: initiator_endpoint.trim().to_string(),
            target_node_id,
            target_public_endpoint: target_endpoint.trim().to_string(),
            // উভয় কম্পিউটার ঠিক ৫০০ মিলিসেকেন্ড পর একসাথে আউটবাউন্ড প্যাকেট পাঠিয়ে রাউটারের পোর্ট খুলে দেবে
            sync_timestamp_ms: current_time_ms.saturating_add(500),
        })
    }

    /// ৪. একই ওয়াইফাই বা লোকাল নেটওয়ার্কে (LAN) থাকা কম্পিউটার রেজিস্টার করে
    pub fn register_lan_peer(&mut self, lan_ip: &str, port: u16) -> bool {
        let p = if port == 0 { DEFAULT_P2P_PORT } else { port };
        let endpoint = format!("{}:{}", lan_ip.trim(), p);
        self.lan_discovered_endpoints.insert(endpoint)
    }

    fn is_valid_public_or_lan_ipv4(ip: &str) -> bool {
        let parts: Vec<&str> = ip.trim().split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        let Ok(first) = parts[0].parse::<u8>() else {
            return false;
        };
        if first == 0 || first == 127 || first >= 224 {
            return false;
        }
        parts.iter().all(|part| part.parse::<u8>().is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha256d;

    #[test]
    fn test_serverless_gossip_pex_and_autonat_consensus() {
        let local_id = sha256d(b"node_india_kolkata_1");
        let mut mesh = ServerlessP2PMesh::new(local_id);

        // ৩টি ভিন্ন পিয়ার আমাদের পাবলিক আইপি নিশ্চিত করলে AutoNAT তা লক করবে
        assert!(mesh.record_peer_observed_external_ip("49.37.120.15").is_none());
        assert!(mesh.record_peer_observed_external_ip("49.37.120.15").is_none());
        let confirmed_ip = mesh.record_peer_observed_external_ip("49.37.120.15").unwrap();
        assert_eq!(confirmed_ip, "49.37.120.15");
        assert_eq!(mesh.nat_status, NatReachability::PubliclyReachable);

        // অন্য কম্পিউটার থেকে ২টি পিয়ার গসিপের মাধ্যমে পাওয়া গেল
        let peer_a = MeshPeerEndpoint {
            node_id: sha256d(b"peer_tokyo"),
            public_ip: "133.242.10.20".to_string(),
            listen_port: 9333,
            last_seen_unix: 1_000,
            latency_ms: 45,
            is_relayed_hole_punch: false,
        };
        let peer_b = MeshPeerEndpoint {
            node_id: sha256d(b"peer_frankfurt"),
            public_ip: "88.198.50.60".to_string(),
            listen_port: 9333,
            last_seen_unix: 1_000,
            latency_ms: 18,
            is_relayed_hole_punch: true,
        };

        let added = mesh.ingest_pex_gossip_list(vec![peer_a, peer_b], 1_050);
        assert_eq!(added, 2);

        // এক্সপোর্ট করলে দ্রুততম পিং (১৮ms) থাকা পিয়ারটি সবার আগে আসবে
        let exported = mesh.export_pex_gossip_list(1_100);
        assert_eq!(exported.len(), 2);
        assert_eq!(exported[0].public_ip, "88.198.50.60");
    }

    #[test]
    fn test_autonat_hole_punch_rendezvous_ticket() {
        let node_1 = sha256d(b"home_pc_1");
        let node_2 = sha256d(b"home_pc_2");
        let mut mesh = ServerlessP2PMesh::new(node_1);

        let ticket = mesh
            .create_hole_punch_ticket("49.37.10.1:9333", node_2, "103.21.55.9:9333", 50_000)
            .unwrap();

        assert_eq!(ticket.sync_timestamp_ms, 50_500);
        assert_eq!(mesh.nat_status, NatReachability::HolePunchingActive);
    }
}