#![allow(dead_code)]
// src/mempool/fee_estimator.rs
// Equinox (EQX) L1 — Audit-Grade Integer Dynamic Fee Estimator & Mempool Congestion Analyzer
// Features: Fast / Standard / Economy Fee Tier Calculation, Rolling Block History & Zero Floating-Point.

use crate::config::{MAX_SUPPLY, MIN_RELAY_TX_FEE};
use crate::mempool::pool::MAX_MEMPOOL_TXS;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// ফি হিসাবের জন্য সর্বশেষ কতগুলো ব্লকের গড় নেওয়া হবে
pub const FEE_HISTORY_BLOCKS_WINDOW: usize = 20;

/// ওয়ালেটের জন্য ৩টি স্ট্যান্ডার্ড ফি ক্যাটাগরি (অ্যাটমিক ইউনিটে)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEstimateReport {
    /// পরবর্তী ১-২ ব্লকের মধ্যে দ্রুত কনফার্মেশনের ফি
    pub fast_fee_atomic: u64,
    /// ৩-৫ ব্লকের মধ্যে স্বাভাবিক কনফার্মেশনের ফি
    pub standard_fee_atomic: u64,
    /// কম খরচে কনফার্মেশনের ন্যূনতম বৈধ ফি
    pub economy_fee_atomic: u64,
    /// মেমপুলের বর্তমান চাপের শতকরা হার (0..=100%)
    pub mempool_load_percent: u8,
}

/// ডাইনামিক ফি এস্টিমেটর ইঞ্জিন
#[derive(Clone, Debug)]
pub struct FeeEstimator {
    recent_block_avg_fees: VecDeque<u64>,
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl FeeEstimator {
    pub fn new() -> Self {
        Self {
            recent_block_avg_fees: VecDeque::with_capacity(FEE_HISTORY_BLOCKS_WINDOW),
        }
    }

    /// নতুন ব্লক মাইন বা কনফার্ম হওয়ার পর ওই ব্লকের ট্রানজ্যাকশনগুলোর গড় ফি রেকর্ড করে
    pub fn record_confirmed_block_fees(&mut self, total_fees_atomic: u64, user_tx_count: usize) {
        let avg_fee = if user_tx_count == 0 {
            MIN_RELAY_TX_FEE
        } else {
            (total_fees_atomic / (user_tx_count as u64)).max(MIN_RELAY_TX_FEE)
        };

        if self.recent_block_avg_fees.len() >= FEE_HISTORY_BLOCKS_WINDOW {
            self.recent_block_avg_fees.pop_front();
        }
        self.recent_block_avg_fees.push_back(avg_fee);
    }

    /// মেমপুলে থাকা বর্তমান ট্রানজ্যাকশন সংখ্যার ওপর ভিত্তি করে Fast, Standard ও Economy ফি নির্ণয় করে
    pub fn estimate_fees(&self, current_mempool_len: usize) -> FeeEstimateReport {
        let load_percent = ((current_mempool_len.saturating_mul(100)) / MAX_MEMPOOL_TXS.max(1))
            .min(100) as u8;

        let historical_median = if self.recent_block_avg_fees.is_empty() {
            MIN_RELAY_TX_FEE
        } else {
            let mut sorted: Vec<u64> = self.recent_block_avg_fees.iter().copied().collect();
            sorted.sort_unstable();
            sorted[sorted.len() / 2].max(MIN_RELAY_TX_FEE)
        };

        // কনজেশন মাল্টিপ্লায়ার (মেমপুল যত ভরবে, দ্রুত কনফার্মেশনের ফি আনুপাতিক হারে তত বাড়বে)
        let standard_fee = if load_percent > 80 {
            historical_median.saturating_mul(2)
        } else if load_percent > 50 {
            historical_median.saturating_mul(3) / 2
        } else {
            historical_median
        }
        .clamp(MIN_RELAY_TX_FEE, MAX_SUPPLY);

        let fast_fee = standard_fee
            .saturating_mul(2)
            .clamp(MIN_RELAY_TX_FEE, MAX_SUPPLY);

        let economy_fee = historical_median
            .max(MIN_RELAY_TX_FEE)
            .min(standard_fee);

        FeeEstimateReport {
            fast_fee_atomic: fast_fee,
            standard_fee_atomic: standard_fee,
            economy_fee_atomic: economy_fee,
            mempool_load_percent: load_percent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_estimator_tiers_and_congestion_scaling() {
        let mut estimator = FeeEstimator::new();
        estimator.record_confirmed_block_fees(200_000, 10); // গড় 20,000

        let report = estimator.estimate_fees(500);
        assert!(report.fast_fee_atomic >= report.standard_fee_atomic);
        assert!(report.standard_fee_atomic >= report.economy_fee_atomic);
        assert!(report.economy_fee_atomic >= MIN_RELAY_TX_FEE);
    }
}
