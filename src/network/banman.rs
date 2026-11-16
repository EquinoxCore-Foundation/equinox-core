#![allow(dead_code)]
// src/network/banman.rs
// Equinox (EQX) L1 — Peer Reputation Tracker, Misbehavior Scoring & Anti-Hacker Auto-Ban Firewall.

use crate::config::{PEER_BAN_DURATION_SECS, PEER_BAN_SCORE_THRESHOLD};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// নেটওয়ার্কে ক্ষতিকর আচরণের ধরন এবং তার পেনাল্টি স্কোর
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MisbehaviorReason {
    /// ভুল নেটওয়ার্ক ম্যাজিক বাইটস পাঠানো (তাৎক্ষণিক ব্যান: ১০০ পয়েন্ট)
    InvalidMagicBytes,
    /// BFT ফাইনালিটি চেকপয়েন্টের নিচের ব্লক রিভার্স করার চেষ্টা বা ৫১% অ্যাটাক (তাৎক্ষণিক ব্যান: ১০০ পয়েন্ট)
    FinalityCheckpointViolation,
    /// ভুয়া প্রুফ-অফ-ওয়ার্ক (PoW) বা অবৈধ ব্লক হেডার পাঠানো (৫০ পয়েন্ট)
    InvalidBlockHeaderOrPoW,
    /// অবৈধ ডিজিটাল সিগনেচারযুক্ত ট্রানজ্যাকশন বা ব্লক পাঠানো (৫০ পয়েন্ট)
    InvalidSignature,
    /// ডাবল-স্পেন্ডিং ট্রানজ্যাকশন ব্রডকাস্ট করার চেষ্টা (২৫ পয়েন্ট)
    DoubleSpendAttempt,
    /// বিকৃত বা অপাঠযোগ্য বাইনারি প্যাকেট পাঠানো (২০ পয়েন্ট)
    MalformedMessage,
    /// অতিরিক্ত রিকোয়েস্ট পাঠিয়ে নেটওয়ার্ক ফ্লাডিং বা স্প্যামিং করা (১০ পয়েন্ট)
    SpammingOrRateLimit,
}

impl MisbehaviorReason {
    #[inline]
    pub fn penalty_points(&self) -> u32 {
        match self {
            MisbehaviorReason::InvalidMagicBytes => 100,
            MisbehaviorReason::FinalityCheckpointViolation => 100,
            MisbehaviorReason::InvalidBlockHeaderOrPoW => 50,
            MisbehaviorReason::InvalidSignature => 50,
            MisbehaviorReason::DoubleSpendAttempt => 25,
            MisbehaviorReason::MalformedMessage => 20,
            MisbehaviorReason::SpammingOrRateLimit => 10,
        }
    }
}

/// ব্যান হওয়া আইপি অ্যাড্রেসের রেকর্ড
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanEntry {
    pub ip_address: String,
    pub banned_at_timestamp: u64,
    pub ban_expires_at: u64,
    pub last_reason: MisbehaviorReason,
}

/// পিয়ার রেপুটেশন ও অটো-ব্যান ম্যানেজার
#[derive(Default, Clone, Debug)]
pub struct BanManager {
    penalty_scores: HashMap<String, u32>,
    banned_ips: HashMap<String, BanEntry>,
}

impl BanManager {
    pub fn new() -> Self {
        Self {
            penalty_scores: HashMap::new(),
            banned_ips: HashMap::new(),
        }
    }

    pub fn is_banned(&self, ip: &str, current_timestamp: u64) -> bool {
        if let Some(entry) = self.banned_ips.get(ip) {
            return current_timestamp < entry.ban_expires_at;
        }
        false
    }

    pub fn record_misbehavior(
        &mut self,
        ip: &str,
        reason: MisbehaviorReason,
        current_timestamp: u64,
    ) -> bool {
        if self.is_banned(ip, current_timestamp) {
            return true;
        }

        let added_score = reason.penalty_points();
        let score_entry = self.penalty_scores.entry(ip.to_string()).or_insert(0);
        *score_entry = score_entry.saturating_add(added_score);

        if *score_entry >= PEER_BAN_SCORE_THRESHOLD {
            let ban_entry = BanEntry {
                ip_address: ip.to_string(),
                banned_at_timestamp: current_timestamp,
                ban_expires_at: current_timestamp.saturating_add(PEER_BAN_DURATION_SECS),
                last_reason: reason,
            };
            self.banned_ips.insert(ip.to_string(), ban_entry);
            self.penalty_scores.remove(ip);
            return true;
        }

        false
    }

    pub fn unban_ip(&mut self, ip: &str) {
        self.banned_ips.remove(ip);
        self.penalty_scores.remove(ip);
    }

    pub fn cleanup_expired_bans(&mut self, current_timestamp: u64) -> usize {
        let before = self.banned_ips.len();
        self.banned_ips
            .retain(|_, entry| current_timestamp < entry.ban_expires_at);
        before - self.banned_ips.len()
    }

    pub fn get_penalty_score(&self, ip: &str) -> u32 {
        self.penalty_scores.get(ip).copied().unwrap_or(0)
    }

    pub fn banned_count(&self) -> usize {
        self.banned_ips.len()
    }
}
