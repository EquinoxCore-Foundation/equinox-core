// File: src/consensus/pow.rs
#![forbid(unsafe_code)]

use crate::config::{DAA_AVERAGING_WINDOW, DAA_MAX_ADJUSTMENT_FACTOR, TARGET_BLOCK_TIME_SECS};
use crate::consensus::asert::{
    AsertDifficultyEngine, TargetU256, ASERT_HALF_LIFE_SECS, MAX_COMPACT_NBITS, MIN_COMPACT_NBITS,
};
use crate::primitives::block::{BlockHeader, MAX_DIFFICULTY_BITS};

pub const MIN_DIFFICULTY_BITS: u32 = 1;
pub const DEFAULT_INITIAL_DIFFICULTY_BITS: u32 = 4;
pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 120;
pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;

pub struct ProofOfWorkEngine;

impl ProofOfWorkEngine {
    /// যেকোনো `difficulty_target` (লিডিং-জিরো বিট `1..=256` অথবা কম্প্যাক্ট `nBits`) থেকে ২৫৬-বিট `TargetU256` বের করে
    pub fn resolve_target_u256(difficulty_target: u32) -> Result<TargetU256, String> {
        if difficulty_target >= MIN_COMPACT_NBITS {
            AsertDifficultyEngine::validate_and_decode_compact_nbits(difficulty_target)
        } else if (MIN_DIFFICULTY_BITS..=MAX_DIFFICULTY_BITS).contains(&difficulty_target) {
            TargetU256::from_leading_zero_bits(difficulty_target)
        } else {
            Err(format!("Invalid difficulty target value: {}", difficulty_target))
        }
    }

    /// ২৫৬-বিট টার্গেট থেকে গাণিতিকভাবে নিখুঁত কাজের পরিমাণ হিসাব করে:
    /// ফর্মুলা: `Work(T) = floor((2^256 - 1 - T) / (T + 1)) + 1`
    pub fn calculate_work_from_target256(target: &TargetU256) -> u128 {
        if target.is_zero() {
            return u128::MAX;
        }
        if *target == TargetU256::MAX {
            return 1;
        }
        let not_target = target.bit_not();
        let target_plus_one = target.checked_add(&TargetU256::ONE).unwrap_or(TargetU256::MAX);
        let quotient = not_target
            .checked_div(&target_plus_one)
            .unwrap_or(TargetU256::ZERO);
        let work_256 = quotient
            .checked_add(&TargetU256::ONE)
            .unwrap_or(TargetU256::MAX);
        work_256.to_u128_saturating()
    }

    /// কোনো বিট-শিফট শর্টকাট ছাড়াই আসল ২৫৬-বিট টার্গেট ডিভিশন দিয়ে ব্লকের কাজের পরিমাণ হিসাব করে
    #[inline]
    pub fn calculate_block_work(difficulty_target: u32) -> u128 {
        match Self::resolve_target_u256(difficulty_target) {
            Ok(target_256) => Self::calculate_work_from_target256(&target_256),
            Err(_) => 0,
        }
    }

    /// প্রকৃত টাইমস্প্যানের সাপেক্ষে আনুপাতিক ওয়ার্ক হিসাব করে
    pub fn calculate_proportional_work_target(
        base_difficulty_bits: u32,
        actual_window_secs: u64,
    ) -> u128 {
        let base_work = Self::calculate_block_work(base_difficulty_bits);
        if base_work == 0 {
            return 0;
        }
        let expected_secs = DAA_AVERAGING_WINDOW.saturating_mul(TARGET_BLOCK_TIME_SECS);
        let min_secs = (expected_secs / DAA_MAX_ADJUSTMENT_FACTOR).max(1);
        let max_secs = expected_secs.saturating_mul(DAA_MAX_ADJUSTMENT_FACTOR);
        let clamped_actual = actual_window_secs.clamp(min_secs, max_secs) as u128;

        base_work
            .saturating_mul(expected_secs as u128)
            .checked_div(clamped_actual)
            .unwrap_or(base_work)
            .max(1)
    }

    /// একক ইউনিফায়েড ২৫৬-বিট ASERT ডিফিকাল্টি অ্যাডজাস্টমেন্ট ইঞ্জিন
    pub fn calculate_next_difficulty(
        current_header: &BlockHeader,
        anchor_header: Option<&BlockHeader>,
    ) -> u32 {
        let Some(anchor) = anchor_header else {
            return current_header.difficulty_target;
        };
        if current_header.height <= anchor.height {
            return current_header.difficulty_target;
        }

        // ১. যদি কম্প্যাক্ট nBits মোডে থাকে, তবে সরাসরি ২৫৬-বিট ASERT টার্গেট থেকে নতুন nBits বের করা হয়
        if current_header.difficulty_target >= MIN_COMPACT_NBITS
            && anchor.difficulty_target >= MIN_COMPACT_NBITS
        {
            if let Ok(anchor_t256) =
                AsertDifficultyEngine::validate_and_decode_compact_nbits(anchor.difficulty_target)
            {
                if let Ok(next_t256) = AsertDifficultyEngine::calculate_next_asert_target_256(
                    &anchor_t256,
                    anchor.height,
                    anchor.timestamp,
                    current_header.height,
                    current_header.timestamp,
                ) {
                    return AsertDifficultyEngine::target256_to_compact_nbits(&next_t256)
                        .clamp(MIN_COMPACT_NBITS, MAX_COMPACT_NBITS);
                }
            }
        }

        // ২. লিডিং-জিরো বিট মোডে (`1..=256`) ২৫৬-বিট ASERT অনুপাত অনুযায়ী বিট ডিফিকাল্টি সমন্বয়
        let current_diff = current_header
            .difficulty_target
            .clamp(MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS);
        let Ok(anchor_t256) = TargetU256::from_leading_zero_bits(current_diff) else {
            return current_diff;
        };
        let Ok(next_t256) = AsertDifficultyEngine::calculate_next_asert_target_256(
            &anchor_t256,
            anchor.height,
            anchor.timestamp,
            current_header.height,
            current_header.timestamp,
        ) else {
            return current_diff;
        };

        let half_anchor = anchor_t256.shr_bits(1);
        let double_anchor = anchor_t256
            .checked_add(&anchor_t256)
            .unwrap_or(TargetU256::MAX);

        if next_t256 <= half_anchor {
            current_diff.saturating_add(1).min(MAX_DIFFICULTY_BITS)
        } else if next_t256 >= double_anchor {
            current_diff.saturating_sub(1).max(MIN_DIFFICULTY_BITS)
        } else {
            current_diff
        }
    }

    /// দীর্ঘসময় ব্লক না হলে ASERT ফর্মুলায় জরুরি ডিফিকাল্টি রিল্যাক্সেশন
    pub fn calculate_emergency_asert_difficulty(
        parent_header: &BlockHeader,
        candidate_timestamp: u64,
    ) -> u32 {
        let base_diff = parent_header
            .difficulty_target
            .clamp(MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS);
        let elapsed = candidate_timestamp.saturating_sub(parent_header.timestamp) as i128;

        if elapsed >= ASERT_HALF_LIFE_SECS {
            let halvings = (elapsed / ASERT_HALF_LIFE_SECS).min(8) as u32;
            base_diff.saturating_sub(halvings).max(MIN_DIFFICULTY_BITS)
        } else {
            base_diff
        }
    }

    pub fn compute_median_time_past(recent_headers: &[BlockHeader]) -> u64 {
        if recent_headers.is_empty() {
            return 0;
        }
        let take_count = recent_headers.len().min(MEDIAN_TIME_PAST_WINDOW);
        let mut timestamps: Vec<u64> = recent_headers
            .iter()
            .rev()
            .take(take_count)
            .map(|h| h.timestamp)
            .collect();
        timestamps.sort_unstable();
        timestamps[timestamps.len() / 2]
    }

    pub fn validate_block_timestamp(
        new_block_timestamp: u64,
        recent_headers: &[BlockHeader],
        current_network_time: u64,
    ) -> Result<(), String> {
        let max_allowed_future = current_network_time.saturating_add(MAX_FUTURE_BLOCK_TIME_SECS);
        if new_block_timestamp > max_allowed_future {
            return Err(format!(
                "Block timestamp ({}) exceeds maximum future drift ({})",
                new_block_timestamp, max_allowed_future
            ));
        }
        if !recent_headers.is_empty() {
            let mtp = Self::compute_median_time_past(recent_headers);
            if new_block_timestamp <= mtp {
                return Err(format!(
                    "Time-warp attack rejected: timestamp ({}) must be strictly > MTP-11 ({})",
                    new_block_timestamp, mtp
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::ZERO_HASH;

    #[test]
    fn test_true_256bit_target_division_work_and_mtp_guard() {
        // 1. Verify exact 256-bit division work: Work(d=4) == 16, Work(d=8) == 256
        assert_eq!(ProofOfWorkEngine::calculate_block_work(4), 16);
        assert_eq!(ProofOfWorkEngine::calculate_block_work(8), 256);

        // 2. Verify compact nBits work scales inversely with target
        let work_easy = ProofOfWorkEngine::calculate_block_work(0x1f00_ffff);
        let work_harder = ProofOfWorkEngine::calculate_block_work(0x1e00_ffff);
        assert!(work_harder > work_easy * 200);

        // 3. Verify strict MTP-11 timestamp enforcement
        let mut headers = Vec::new();
        for i in 1..=11u64 {
            headers.push(BlockHeader {
                version: 1,
                height: i,
                prev_block_hash: ZERO_HASH,
                merkle_root: ZERO_HASH,
                timestamp: 1_000 + i * 15,
                difficulty_target: 4,
                nonce: 0,
            });
        }
        let mtp = ProofOfWorkEngine::compute_median_time_past(&headers);
        assert_eq!(mtp, 1_000 + 6 * 15);
        assert!(ProofOfWorkEngine::validate_block_timestamp(mtp, &headers, 2_000).is_err());
        assert!(ProofOfWorkEngine::validate_block_timestamp(mtp + 1, &headers, 2_000).is_ok());
    }
}