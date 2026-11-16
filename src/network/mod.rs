#![allow(dead_code, unused_imports)]
// src/network/mod.rs
// Equinox (EQX) L1 — Decentralized P2P Networking, Kademlia DHT Discovery,
// Auto-Ban Firewall, CompactBlock Sync & Serverless AutoNAT/Gossip PEX Mesh.

pub mod banman;
pub mod discovery;
pub mod mesh_autonat;
pub mod peer_manager;
pub mod sync;

pub use crate::config::PEER_BAN_SCORE_THRESHOLD;
pub use banman::{BanEntry, BanManager};
pub use discovery::PeerDiscovery;
pub use mesh_autonat::{
    HolePunchTicket, MeshPeerEndpoint, NatReachability, ServerlessP2PMesh, MAX_PEX_GOSSIP_PEERS,
};
pub use peer_manager::{
    P2PMessage, PeerDirection, PeerManager, MAX_PEERS_PER_SUBNET,
};
pub use sync::{BlockSyncEngine, SyncState};
