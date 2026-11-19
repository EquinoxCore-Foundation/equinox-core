#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use subtle::ConstantTimeEq;

pub const MAX_RPC_BODY_BYTES: usize = 1024 * 1024; // 1 MiB
pub const MAX_RPC_BATCH_SIZE: usize = 20;

#[derive(Debug, Clone)]
struct IpBucket {
    tokens: u64,
    last_ms: u64,
}

/// Per-IP integer token bucket + constant-time Bearer token guard for admin RPCs.
pub struct RpcSecurityGuard {
    burst_capacity: u64,
    refill_per_sec: u64,
    max_tracked_ips: usize,
    buckets: HashMap<IpAddr, IpBucket>,
    admin_token: Option<String>,
}

impl RpcSecurityGuard {
    pub fn new(burst_capacity: u64, refill_per_sec: u64, admin_token: Option<String>) -> Self {
        Self {
            burst_capacity,
            refill_per_sec,
            max_tracked_ips: 10_000,
            buckets: HashMap::new(),
            admin_token,
        }
    }

    pub fn allow_request(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        if !self.buckets.contains_key(&ip) && self.buckets.len() >= self.max_tracked_ips {
            // Evict oldest inactive bucket to prevent memory exhaustion under spoofed IP flood
            if let Some(oldest_ip) = self
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last_ms)
                .map(|(k, _)| *k)
            {
                self.buckets.remove(&oldest_ip);
            }
        }

        let bucket = self.buckets.entry(ip).or_insert(IpBucket {
            tokens: self.burst_capacity,
            last_ms: now_ms,
        });

        if now_ms > bucket.last_ms {
            let elapsed = now_ms - bucket.last_ms;
            let added = ((elapsed as u128) * (self.refill_per_sec as u128) / 1_000) as u64;
            if added > 0 {
                bucket.tokens = bucket.tokens.saturating_add(added).min(self.burst_capacity);
                bucket.last_ms = now_ms;
            }
        }

        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }

    pub fn verify_admin_token(&self, provided: Option<&str>) -> bool {
        match (&self.admin_token, provided) {
            (Some(expected), Some(got)) => bool::from(expected.as_bytes().ct_eq(got.as_bytes())),
            _ => false,
        }
    }
}
