#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use crate::discovery::{is_globally_routable, subnet_key, SubnetKey};
use crate::NetworkError;

/// Infers this node's external NAT IP only when multiple distinct /16 subnets agree.
pub struct ExternalAddressConsensus {
    min_distinct_subnets: usize,
    reports: HashMap<SubnetKey, IpAddr>,
}

impl ExternalAddressConsensus {
    pub fn new(min_distinct_subnets: usize) -> Self {
        Self {
            min_distinct_subnets: min_distinct_subnets.max(1),
            reports: HashMap::new(),
        }
    }

    pub fn record_peer_report(&mut self, reporter_ip: IpAddr, observed_external_ip: IpAddr) {
        if !is_globally_routable(observed_external_ip) {
            return;
        }
        // Only one vote per /16 reporter subnet prevents single-attacker IP spoofing
        let reporter_subnet = subnet_key(reporter_ip);
        self.reports.insert(reporter_subnet, observed_external_ip);
    }

    pub fn resolved_external_ip(&self) -> Option<IpAddr> {
        let mut tallies: HashMap<IpAddr, usize> = HashMap::new();
        for &ip in self.reports.values() {
            *tallies.entry(ip).or_insert(0) += 1;
        }
        tallies
            .into_iter()
            .filter(|(_, votes)| *votes >= self.min_distinct_subnets)
            .max_by_key(|(_, votes)| *votes)
            .map(|(ip, _)| ip)
    }
}

/// Strict inbound/outbound connection slot manager with eclipse-resistant anchor slots.
pub struct ConnectionSlotManager {
    max_outbound: usize,
    max_inbound: usize,
    outbound: HashSet<SocketAddr>,
    inbound: HashSet<SocketAddr>,
    anchors: HashSet<SocketAddr>,
}

impl ConnectionSlotManager {
    pub fn mainnet_default() -> Self {
        Self {
            max_outbound: 8,
            max_inbound: 42,
            outbound: HashSet::new(),
            inbound: HashSet::new(),
            anchors: HashSet::new(),
        }
    }

    pub fn new(max_outbound: usize, max_inbound: usize) -> Self {
        Self {
            max_outbound,
            max_inbound,
            outbound: HashSet::new(),
            inbound: HashSet::new(),
            anchors: HashSet::new(),
        }
    }

    pub fn add_outbound(&mut self, addr: SocketAddr, is_anchor: bool) -> Result<(), NetworkError> {
        if self.outbound.contains(&addr) {
            return Ok(());
        }
        if self.outbound.len() >= self.max_outbound {
            return Err(NetworkError::SlotLimitReached);
        }
        self.outbound.insert(addr);
        if is_anchor {
            self.anchors.insert(addr);
        }
        Ok(())
    }

    pub fn add_inbound(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        if self.inbound.contains(&addr) {
            return Ok(());
        }
        if self.inbound.len() >= self.max_inbound {
            return Err(NetworkError::SlotLimitReached);
        }
        self.inbound.insert(addr);
        Ok(())
    }

    pub fn disconnect(&mut self, addr: &SocketAddr) {
        self.outbound.remove(addr);
        self.inbound.remove(addr);
        self.anchors.remove(addr);
    }

    pub fn total_connected(&self) -> usize {
        self.outbound.len() + self.inbound.len()
    }

    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }
}
