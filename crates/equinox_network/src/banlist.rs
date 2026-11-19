#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehavior {
    InvalidBlockPoW,
    InvalidSignature,
    MalformedFrame,
    RateLimitExceeded,
    HandshakeFailure,
    ProtocolViolation,
}

impl Misbehavior {
    pub fn penalty_score(self) -> u32 {
        match self {
            Misbehavior::InvalidBlockPoW => 100,
            Misbehavior::InvalidSignature => 50,
            Misbehavior::MalformedFrame => 35,
            Misbehavior::ProtocolViolation => 40,
            Misbehavior::HandshakeFailure => 25,
            Misbehavior::RateLimitExceeded => 20,
        }
    }
}

/// Automatic peer reputation tracker and 24-hour IP banlist with seed whitelist protection.
pub struct BanManager {
    ban_threshold: u32,
    ban_duration_secs: u64,
    whitelist: HashSet<IpAddr>,
    scores: HashMap<IpAddr, u32>,
    banned_until: HashMap<IpAddr, u64>,
}

impl BanManager {
    pub fn new(ban_threshold: u32, ban_duration_secs: u64) -> Self {
        Self {
            ban_threshold,
            ban_duration_secs,
            whitelist: HashSet::new(),
            scores: HashMap::new(),
            banned_until: HashMap::new(),
        }
    }

    pub fn mainnet_default() -> Self {
        Self::new(100, 86_400) // 100 points -> 24-hour ban
    }

    pub fn whitelist_ip(&mut self, ip: IpAddr) {
        self.whitelist.insert(ip);
        self.banned_until.remove(&ip);
        self.scores.remove(&ip);
    }

    /// Records misbehavior and returns true if the peer crossed the ban threshold.
    pub fn record_offense(&mut self, ip: IpAddr, reason: Misbehavior, now_secs: u64) -> bool {
        if self.whitelist.contains(&ip) {
            return false;
        }
        let score = self.scores.entry(ip).or_insert(0);
        *score = score.saturating_add(reason.penalty_score());
        if *score >= self.ban_threshold {
            self.banned_until
                .insert(ip, now_secs.saturating_add(self.ban_duration_secs));
            self.scores.remove(&ip);
            return true;
        }
        false
    }

    pub fn is_banned(&mut self, ip: IpAddr, now_secs: u64) -> bool {
        if self.whitelist.contains(&ip) {
            return false;
        }
        if let Some(&expiry) = self.banned_until.get(&ip) {
            if now_secs < expiry {
                return true;
            }
            self.banned_until.remove(&ip);
        }
        false
    }

    pub fn score_of(&self, ip: IpAddr) -> u32 {
        self.scores.get(&ip).copied().unwrap_or(0)
    }

    pub fn prune_expired(&mut self, now_secs: u64) {
        self.banned_until.retain(|_, expiry| now_secs < *expiry);
    }
}
