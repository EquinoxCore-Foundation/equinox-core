#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::NetworkError;

pub const MAX_PEX_BATCH_SIZE: usize = 32;

/// Network prefix key (/16 for IPv4, /32 for IPv6) used to block Sybil & Eclipse attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubnetKey {
    V4([u8; 2]),
    V6([u16; 2]),
}

pub fn subnet_key(ip: IpAddr) -> SubnetKey {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            SubnetKey::V4([o[0], o[1]])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            SubnetKey::V6([s[0], s[1]])
        }
    }
}

pub fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_documentation()
                && !v4.is_unspecified()
                && !v4.is_multicast()
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified() && !v6.is_multicast(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRecord {
    pub addr: SocketAddr,
    pub last_seen_secs: u64,
    pub is_seed: bool,
}

/// Eclipse-resistant peer discovery table enforcing strict per-subnet diversity caps.
pub struct PeerTable {
    max_total_peers: usize,
    max_per_subnet: usize,
    allow_private_lan: bool,
    peers: HashMap<SocketAddr, PeerRecord>,
    subnet_counts: HashMap<SubnetKey, usize>,
}

impl PeerTable {
    pub fn mainnet_default() -> Self {
        Self {
            max_total_peers: 2_048,
            max_per_subnet: 2, // Max 2 peers from the same /16 IPv4 block
            allow_private_lan: false,
            peers: HashMap::new(),
            subnet_counts: HashMap::new(),
        }
    }

    pub fn new(max_total_peers: usize, max_per_subnet: usize, allow_private_lan: bool) -> Self {
        Self {
            max_total_peers,
            max_per_subnet,
            allow_private_lan,
            peers: HashMap::new(),
            subnet_counts: HashMap::new(),
        }
    }

    pub fn add_peer(
        &mut self,
        addr: SocketAddr,
        now_secs: u64,
        is_seed: bool,
    ) -> Result<bool, NetworkError> {
        if addr.port() == 0 {
            return Err(NetworkError::NonRoutableAddress);
        }
        if !self.allow_private_lan && !is_globally_routable(addr.ip()) {
            return Err(NetworkError::NonRoutableAddress);
        }
        if let Some(existing) = self.peers.get_mut(&addr) {
            existing.last_seen_secs = now_secs;
            return Ok(false);
        }
        if self.peers.len() >= self.max_total_peers {
            return Err(NetworkError::PeerTableFull);
        }

        let skey = subnet_key(addr.ip());
        let count = self.subnet_counts.get(&skey).copied().unwrap_or(0);
        if count >= self.max_per_subnet {
            return Err(NetworkError::SubnetCapExceeded);
        }

        self.peers.insert(
            addr,
            PeerRecord {
                addr,
                last_seen_secs: now_secs,
                is_seed,
            },
        );
        self.subnet_counts.insert(skey, count + 1);
        Ok(true)
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        if self.peers.remove(addr).is_some() {
            let skey = subnet_key(addr.ip());
            if let Some(c) = self.subnet_counts.get_mut(&skey) {
                if *c <= 1 {
                    self.subnet_counts.remove(&skey);
                } else {
                    *c -= 1;
                }
            }
        }
    }

    /// Returns a bounded, deterministic PEX gossip batch excluding the requesting peer.
    pub fn select_pex_batch(&self, requester_ip: IpAddr, limit: usize) -> Vec<SocketAddr> {
        let cap = limit.min(MAX_PEX_BATCH_SIZE);
        let mut candidates: Vec<&PeerRecord> = self
            .peers
            .values()
            .filter(|r| r.addr.ip() != requester_ip)
            .collect();
        candidates.sort_by(|a, b| b.last_seen_secs.cmp(&a.last_seen_secs));
        candidates.into_iter().take(cap).map(|r| r.addr).collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}
