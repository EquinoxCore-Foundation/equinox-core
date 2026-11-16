#![allow(dead_code)]
// src/consensus/royalty.rs
// Equinox (EQX) L1 — Audit-Grade 2.0% Combined Zero-Burn Royalty & Dividend Split Engine
// Exact Mathematical Formula:
// 1. Mining Block Subsidy Royalty : 1.70% (170 BPS) — From new block minting (98.30% to Miner).
// 2. Anti-Hack Guardian Vault Fee : 0.20% (20 BPS Annual) — Ultra-low institutional protection fee.
// 3. DEX & Transaction Fee Share  : 0.10% (10 BPS) — Lowest swap fee in crypto, 0% Burn.
// Total Combined Protocol Rate    : 2.00% (200 BPS), split between Owner Treasury & O(1) Dividend Pool.

use crate::config::{BLOCKS_PER_YEAR, MAX_SUPPLY};
use crate::wallet::address::is_valid_address;
use serde::{Deserialize, Serialize};

/// ১০০% = ১০,০০০ বেসিস পয়েন্ট (Basis Points - BPS)
pub const BPS_DENOMINATOR: u128 = 10_000;

/// ১. প্রতি ১৫ সেকেন্ডের ব্লক মাইনিং সাবসিডি থেকে রয়্যালটি: ১.৭০% (170 BPS)
pub const BLOCK_SUBSIDY_OWNER_ROYALTY_BPS: u128 = 170;

/// ২. অ্যান্টি-হ্যাক গার্ডিয়ান ভল্টের বার্ষিক সার্ভিস রয়্যালটি: ০.২০% (20 BPS)
pub const DEFAULT_ANNUAL_ROYALTY_BPS: u16 = 20;
pub const MIN_ANNUAL_ROYALTY_BPS: u16 = 10;  // সর্বনিম্ন ০.১০%
pub const MAX_ANNUAL_ROYALTY_BPS: u16 = 600; // সর্বোচ্চ ৬.০০% হার্ড-ক্যাপ

/// ৩. DEX সোয়াপ ও নেটওয়ার্ক ট্রানজ্যাকশন রয়্যালটি: ০.১০% (10 BPS)
pub const DEX_SWAP_ROYALTY_BPS: u128 = 10;

/// সংগৃহীত রয়্যালটির মধ্যে ৭৫% সরাসরি ওনার ট্রেজারিতে যাবে এবং ২৫% হোল্ডার ডিভিডেন্ড পুলে যাবে (০% বার্ন)
pub const OWNER_TREASURY_SHARE_OF_ROYALTY_BPS: u128 = 7_500; // 75% of Royalty
pub const HOLDER_DIVIDEND_SHARE_OF_ROYALTY_BPS: u128 = 2_500; // 25% of Royalty

/// ব্লক মাইনিং সাবসিডি বণ্টনের ফলাফল (৯৮.৩০% মাইনার, ১.৭০% প্রটোকল রয়্যালটি ও ডিভিডেন্ড)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRewardSplit {
    pub total_subsidy_atomic: u64,
    pub miner_share_atomic: u64,
    pub total_royalty_atomic: u64,
    pub owner_treasury_atomic: u64,
    pub holder_dividend_atomic: u64,
}

/// DEX সোয়াপ ও ট্রানজ্যাকশন ফি বণ্টনের ফলাফল (০% বার্ন — কোনো কয়েন নষ্ট হবে না)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxFeeSplit {
    pub total_amount_atomic: u64,
    pub miner_or_lp_share_atomic: u64,
    pub owner_royalty_atomic: u64,
    pub holder_dividend_atomic: u64,
}

/// প্রটোকল ওনার রয়্যালটি ও ট্রেজারি ইঞ্জিন
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRoyaltyEngine {
    pub owner_royalty_address: String,
    pub annual_vault_royalty_bps: u16,
    pub cumulative_owner_royalty_collected: u64,
    pub cumulative_holder_dividends_routed: u64,
}

impl ProtocolRoyaltyEngine {
    pub fn new(owner_royalty_address: String, annual_royalty_bps: u16) -> Result<Self, String> {
        let trimmed = owner_royalty_address.trim().to_string();
        if !is_valid_address(&trimmed) {
            return Err(format!("অবৈধ ওনার রয়্যালটি অ্যাড্রেস: {}", trimmed));
        }

        let clamped_bps = annual_royalty_bps.clamp(MIN_ANNUAL_ROYALTY_BPS, MAX_ANNUAL_ROYALTY_BPS);

        Ok(Self {
            owner_royalty_address: trimmed,
            annual_vault_royalty_bps: clamped_bps,
            cumulative_owner_royalty_collected: 0,
            cumulative_holder_dividends_routed: 0,
        })
    }

    pub fn set_annual_royalty_rate_bps(&mut self, new_bps: u16) -> Result<(), String> {
        if !(MIN_ANNUAL_ROYALTY_BPS..=MAX_ANNUAL_ROYALTY_BPS).contains(&new_bps) {
            return Err(format!(
                "বার্ষিক ভল্ট রয়্যালটি অবশ্যই ০.১% (10 BPS) থেকে ৬.০% (600 BPS)-এর মধ্যে হতে হবে (প্রদত্ত: {})",
                new_bps
            ));
        }
        self.annual_vault_royalty_bps = new_bps;
        Ok(())
    }

    /// ১. ব্লক মাইনিং রিওয়ার্ড থেকে ৯৮.৩০% মাইনার এবং ১.৭০% রয়্যালটি (ওনার ট্রেজারি + হোল্ডার ডিভিডেন্ড) আলাদা করে
    pub fn split_block_subsidy(total_allowed_subsidy: u64) -> BlockRewardSplit {
        if total_allowed_subsidy == 0 {
            return BlockRewardSplit {
                total_subsidy_atomic: 0,
                miner_share_atomic: 0,
                total_royalty_atomic: 0,
                owner_treasury_atomic: 0,
                holder_dividend_atomic: 0,
            };
        }

        let subsidy_u128 = total_allowed_subsidy as u128;
        let total_royalty =
            (subsidy_u128.saturating_mul(BLOCK_SUBSIDY_OWNER_ROYALTY_BPS)) / BPS_DENOMINATOR;
        let miner_cut = subsidy_u128.saturating_sub(total_royalty);

        let owner_treasury =
            (total_royalty.saturating_mul(OWNER_TREASURY_SHARE_OF_ROYALTY_BPS)) / BPS_DENOMINATOR;
        let holder_dividend = total_royalty.saturating_sub(owner_treasury);

        BlockRewardSplit {
            total_subsidy_atomic: total_allowed_subsidy,
            miner_share_atomic: miner_cut as u64,
            total_royalty_atomic: total_royalty as u64,
            owner_treasury_atomic: owner_treasury as u64,
            holder_dividend_atomic: holder_dividend as u64,
        }
    }

    /// ২. DEX সোয়াপ বা ট্রানজ্যাকশন ভলিউম থেকে ০.১০% (10 BPS) রয়্যালটি হিসাব করে (০% বার্ন)
    pub fn split_dex_or_tx_volume(volume_atomic: u64) -> TxFeeSplit {
        if volume_atomic == 0 {
            return TxFeeSplit {
                total_amount_atomic: 0,
                miner_or_lp_share_atomic: 0,
                owner_royalty_atomic: 0,
                holder_dividend_atomic: 0,
            };
        }

        let vol_u128 = volume_atomic as u128;
        let total_royalty = (vol_u128.saturating_mul(DEX_SWAP_ROYALTY_BPS)) / BPS_DENOMINATOR;
        let remaining = vol_u128.saturating_sub(total_royalty);

        let owner_cut =
            (total_royalty.saturating_mul(OWNER_TREASURY_SHARE_OF_ROYALTY_BPS)) / BPS_DENOMINATOR;
        let dividend_cut = total_royalty.saturating_sub(owner_cut);

        TxFeeSplit {
            total_amount_atomic: volume_atomic,
            miner_or_lp_share_atomic: remaining as u64,
            owner_royalty_atomic: owner_cut as u64,
            holder_dividend_atomic: dividend_cut as u64,
        }
    }

    /// ৩. বার্ষিক ০.২০% (20 BPS) হারে অ্যান্টি-হ্যাক গার্ডিয়ান ভল্ট ব্যালেন্সের ওপর অটোমেটিক রয়্যালটি হিসাব করে
    pub fn calculate_annualized_vault_royalty(
        &self,
        principal_amount_atomic: u64,
        elapsed_blocks: u64,
    ) -> u64 {
        if principal_amount_atomic == 0 || elapsed_blocks == 0 {
            return 0;
        }

        let principal_u128 = principal_amount_atomic.min(MAX_SUPPLY) as u128;
        let bps_u128 = self.annual_vault_royalty_bps as u128;
        let blocks_u128 = elapsed_blocks as u128;
        let year_blocks_u128 = BLOCKS_PER_YEAR as u128;

        let numerator = principal_u128
            .saturating_mul(bps_u128)
            .saturating_mul(blocks_u128);
        let denominator = BPS_DENOMINATOR.saturating_mul(year_blocks_u128);

        let royalty = numerator / denominator;
        (royalty as u64).min(principal_amount_atomic)
    }

    pub fn record_royalty_and_dividend(&mut self, owner_amount: u64, dividend_amount: u64) {
        self.cumulative_owner_royalty_collected = self
            .cumulative_owner_royalty_collected
            .saturating_add(owner_amount)
            .min(MAX_SUPPLY);

        self.cumulative_holder_dividends_routed = self
            .cumulative_holder_dividends_routed
            .saturating_add(dividend_amount)
            .min(MAX_SUPPLY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{COIN, INITIAL_BLOCK_REWARD};
    use crate::wallet::address::derive_deterministic_genesis_address;

    #[test]
    fn test_exact_1_7_mining_and_0_1_dex_zero_burn_splits() {
        // ১. ব্লক সাবসিডি (0.40640000 EQX = 40,640,000 atomic) থেকে ১.৭% (690,880 atomic) রয়্যালটি যাচাই
        let split = ProtocolRoyaltyEngine::split_block_subsidy(INITIAL_BLOCK_REWARD);
        assert_eq!(split.total_royalty_atomic, 690_880); // ঠিক 1.70%
        assert_eq!(split.miner_share_atomic, 39_949_120); // ঠিক 98.30%
        assert_eq!(
            split.miner_share_atomic + split.owner_treasury_atomic + split.holder_dividend_atomic,
            INITIAL_BLOCK_REWARD
        );

        // ২. DEX ভলিউম (1,000 EQX) থেকে ০.১% (1 EQX) রয়্যালটি যাচাই (০% বার্ন)
        let dex_split = ProtocolRoyaltyEngine::split_dex_or_tx_volume(1_000 * COIN);
        assert_eq!(
            dex_split.owner_royalty_atomic + dex_split.holder_dividend_atomic,
            1 * COIN
        );
        assert_eq!(dex_split.miner_or_lp_share_atomic, 999 * COIN);
    }

    #[test]
    fn test_annual_vault_royalty_0_2_percent_default() {
        let owner_addr = derive_deterministic_genesis_address("EQX_MAINNET_OWNER_VAULT");
        let engine = ProtocolRoyaltyEngine::new(owner_addr, DEFAULT_ANNUAL_ROYALTY_BPS).unwrap();

        // ১০,০০০ EQX ১ বছর ভল্টে থাকলে ০.২% হারে মাত্র ২০ EQX ফি হবে
        let deposit = 10_000 * COIN;
        let royalty = engine.calculate_annualized_vault_royalty(deposit, BLOCKS_PER_YEAR);
        assert_eq!(royalty, 20 * COIN);
    }
}