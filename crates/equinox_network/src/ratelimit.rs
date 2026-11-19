#![forbid(unsafe_code)]

use crate::NetworkError;

/// Integer-only deterministic token bucket for anti-DoS rate limiting.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_per_sec: u64,
    last_refill_ms: u64,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_per_sec: u64, now_ms: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last_refill_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_refill_ms {
            return;
        }
        let elapsed_ms = now_ms - self.last_refill_ms;
        let added = ((elapsed_ms as u128) * (self.refill_per_sec as u128) / 1_000) as u64;
        if added > 0 {
            self.tokens = self.tokens.saturating_add(added).min(self.capacity);
            let consumed_ms = ((added as u128) * 1_000 / (self.refill_per_sec.max(1) as u128)) as u64;
            self.last_refill_ms = self.last_refill_ms.saturating_add(consumed_ms).min(now_ms);
        }
    }

    pub fn try_consume(&mut self, amount: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        if amount > self.tokens {
            return false;
        }
        self.tokens -= amount;
        true
    }
}

/// Dual message-rate and bandwidth-rate guard per peer connection.
#[derive(Debug, Clone)]
pub struct PeerRateLimiter {
    msg_bucket: TokenBucket,
    byte_bucket: TokenBucket,
}

impl PeerRateLimiter {
    pub fn mainnet_default(now_ms: u64) -> Self {
        Self {
            // Max burst 100 msgs, sustained 30 msgs/sec
            msg_bucket: TokenBucket::new(100, 30, now_ms),
            // Max burst 4 MiB, sustained 1 MiB/sec per peer
            byte_bucket: TokenBucket::new(4 * 1024 * 1024, 1024 * 1024, now_ms),
        }
    }

    pub fn custom(
        msg_burst: u64,
        msg_per_sec: u64,
        byte_burst: u64,
        bytes_per_sec: u64,
        now_ms: u64,
    ) -> Self {
        Self {
            msg_bucket: TokenBucket::new(msg_burst, msg_per_sec, now_ms),
            byte_bucket: TokenBucket::new(byte_burst, bytes_per_sec, now_ms),
        }
    }

    pub fn check_and_consume(&mut self, frame_bytes: u64, now_ms: u64) -> Result<(), NetworkError> {
        if !self.msg_bucket.try_consume(1, now_ms) {
            return Err(NetworkError::RateLimitExceeded);
        }
        if !self.byte_bucket.try_consume(frame_bytes, now_ms) {
            return Err(NetworkError::RateLimitExceeded);
        }
        Ok(())
    }
}
