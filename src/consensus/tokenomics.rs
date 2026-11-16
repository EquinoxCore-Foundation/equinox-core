#![allow(dead_code)]
// src/consensus/tokenomics.rs
// Equinox (EQX) L1 — Audit-Grade Tokenomics Engine, O(1) Supply Calculator,
// 21M Hard-Cap Invariant Verifier & EIP-1559 Integer Dynamic Fee Market.

use crate::config::{
    calculate_block_reward, calculate_capped_block_reward, get_unlocked_owner_allocation,
    BLOCKS_PER_YEAR, HALVING_DURATION_YEARS, MAX_SUPPLY, MIN_RELAY_TX_FEE, PREMINE_OWNER_TOTAL,
    PREMINE_SUPPLY, TAIL_EMISSION_REWARD,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyReport {
    pub block_height: u64,
    pub total_minted_supply: u64,
    pub circulating_supply: u64,
    pub locked_owner_supply: u64,
    pub unlocked_owner_supply: u64,
    pub current_block_reward: u64,
    pub remaining_mineable_supply: u64,
}

pub struct TokenomicsEngine;

impl TokenomicsEngine {
    pub fn get_supply_report_at_height(block_height: u64) -> SupplyReport {
        let mut cumulative_minted: u128 = PREMINE_SUPPLY as u128;
        let max_supply_u128 = MAX_SUPPLY as u128;

        if block_height > 0 {
            let full_years = (block_height - 1) / BLOCKS_PER_YEAR;
            let remaining_blocks_in_current_year = ((block_height - 1) % BLOCKS_PER_YEAR) + 1;

            let capped_halving_years = full_years.min(HALVING_DURATION_YEARS);
            for year_idx in 0..capped_halving_years {
                let sample_height = (year_idx * BLOCKS_PER_YEAR) + 1;
                let yearly_block_reward = calculate_block_reward(sample_height) as u128;
                let year_total = yearly_block_reward.saturating_mul(BLOCKS_PER_YEAR as u128);
                cumulative_minted = cumulative_minted
                    .saturating_add(year_total)
                    .min(max_supply_u128);

                if cumulative_minted >= max_supply_u128 {
                    break;
                }
            }

            if full_years > HALVING_DURATION_YEARS && cumulative_minted < max_supply_u128 {
                let tail_years = (full_years - HALVING_DURATION_YEARS) as u128;
                let tail_year_total = (TAIL_EMISSION_REWARD as u128)
                    .saturating_mul(BLOCKS_PER_YEAR as u128)
                    .saturating_mul(tail_years);
                cumulative_minted = cumulative_minted
                    .saturating_add(tail_year_total)
                    .min(max_supply_u128);
            }

            if cumulative_minted < max_supply_u128 {
                let current_year_reward = calculate_block_reward(block_height) as u128;
                let partial_year_total = current_year_reward
                    .saturating_mul(remaining_blocks_in_current_year as u128);
                cumulative_minted = cumulative_minted
                    .saturating_add(partial_year_total)
                    .min(max_supply_u128);
            }
        }

        let total_minted_supply = (cumulative_minted as u64).min(MAX_SUPPLY);
        let unlocked_owner_supply = get_unlocked_owner_allocation(block_height);
        let locked_owner_supply = PREMINE_OWNER_TOTAL.saturating_sub(unlocked_owner_supply);
        let circulating_supply = total_minted_supply.saturating_sub(locked_owner_supply);

        // ২১ মিলিয়ন ক্যাপ পূর্ণ হয়ে গেলে ব্লক রিওয়ার্ড কঠোরভাবে শূন্য (0) হয়ে যাবে
        let current_block_reward = if total_minted_supply >= MAX_SUPPLY {
            0
        } else if block_height == 0 {
            calculate_block_reward(1)
        } else {
            let prev_minted = total_minted_supply.saturating_sub(calculate_block_reward(block_height));
            calculate_capped_block_reward(block_height, prev_minted)
        };

        let remaining_mineable_supply = MAX_SUPPLY.saturating_sub(total_minted_supply);

        SupplyReport {
            block_height,
            total_minted_supply,
            circulating_supply,
            locked_owner_supply,
            unlocked_owner_supply,
            current_block_reward,
            remaining_mineable_supply,
        }
    }

    pub fn verify_block_conservation_of_value(
        current_total_supply: u64,
        block_inputs_sum: u64,
        block_outputs_sum: u64,
        protocol_allowed_block_subsidy: u64,
    ) -> Result<u64, String> {
        let inputs_u128 = block_inputs_sum as u128;
        let outputs_u128 = block_outputs_sum as u128;
        let subsidy_u128 = protocol_allowed_block_subsidy as u128;

        let total_available_value = inputs_u128
            .checked_add(subsidy_u128)
            .ok_or_else(|| "গাণিতিক ওভারফ্লো: ইনপুট ও সাবসিডি যোগফল সীমার বাইরে".to_string())?;

        if outputs_u128 > total_available_value {
            return Err(format!(
                "ইনফ্লেশন অ্যাটাক প্রতিরোধ: ব্লকের মোট আউটপুট ({}) অনুমোদিত ইনপুট + রিওয়ার্ড ({}) অপেক্ষা বেশি!",
                outputs_u128, total_available_value
            ));
        }

        let net_minted_delta = outputs_u128.saturating_sub(inputs_u128);
        if net_minted_delta > subsidy_u128 {
            return Err("মাইনার অনুমোদিত সাবসিডির চেয়ে বেশি কয়েন মিন্ট করার চেষ্টা করেছে!".to_string());
        }

        let new_total_supply = (current_total_supply as u128)
            .checked_add(net_minted_delta)
            .ok_or_else(|| "গাণিতিক ওভারফ্লো: মোট সাপ্লাই যোগফল সীমার বাইরে".to_string())?;

        if new_total_supply > (MAX_SUPPLY as u128) {
            return Err(format!(
                "২১ মিলিয়ন হার্ড-ক্যাপ লঙ্ঘন: নতুন সাপ্লাই ({}) সর্বোচ্চ সীমা ({}) অতিক্রম করেছে!",
                new_total_supply, MAX_SUPPLY
            ));
        }

        Ok(new_total_supply as u64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicFeeMarket {
    pub current_base_fee: u64,
    pub target_block_gas: u64,
    pub max_block_gas: u64,
}

impl DynamicFeeMarket {
    pub fn new(target_gas: u64) -> Self {
        let safe_target = target_gas.max(1);
        Self {
            current_base_fee: MIN_RELAY_TX_FEE,
            target_block_gas: safe_target,
            max_block_gas: safe_target.saturating_mul(2),
        }
    }

    pub fn calculate_next_base_fee(&mut self, parent_gas_used: u64) -> u64 {
        let target = self.target_block_gas as u128;
        let used = (parent_gas_used.min(self.max_block_gas)) as u128;
        let base = self.current_base_fee as u128;

        if used == target {
            return self.current_base_fee;
        }

        if used > target {
            let gas_delta = used - target;
            let num = base.saturating_mul(gas_delta);
            let denom = target.saturating_mul(8);
            let fee_increase = (num / denom).max(1);
            self.current_base_fee = base
                .saturating_add(fee_increase)
                .min(MAX_SUPPLY as u128) as u64;
        } else {
            let gas_delta = target - used;
            let num = base.saturating_mul(gas_delta);
            let denom = target.saturating_mul(8);
            let fee_decrease = num / denom;
            self.current_base_fee = base
                .saturating_sub(fee_decrease)
                .max(MIN_RELAY_TX_FEE as u128) as u64;
        }

        self.current_base_fee
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;

    #[test]
    fn test_genesis_and_multi_year_supply_reports() {
        let r0 = TokenomicsEngine::get_supply_report_at_height(0);
        assert_eq!(r0.total_minted_supply, 2_000_000 * COIN);
        assert_eq!(r0.unlocked_owner_supply, 200_000 * COIN);
        assert_eq!(r0.locked_owner_supply, 1_000_000 * COIN);
        assert_eq!(r0.circulating_supply, 1_000_000 * COIN);

        let r_year5 = TokenomicsEngine::get_supply_report_at_height(BLOCKS_PER_YEAR * 5);
        assert_eq!(r_year5.locked_owner_supply, 0);
        assert_eq!(r_year5.unlocked_owner_supply, 1_200_000 * COIN);
        assert_eq!(r_year5.circulating_supply, r_year5.total_minted_supply);

        let r_far_future = TokenomicsEngine::get_supply_report_at_height(500_000_000_000);
        assert_eq!(r_far_future.total_minted_supply, MAX_SUPPLY);
        assert_eq!(r_far_future.current_block_reward, 0);
        assert_eq!(r_far_future.remaining_mineable_supply, 0);
    }

    #[test]
    fn test_conservation_of_value_and_inflation_guard() {
        let current_supply = 2_000_000 * COIN;
        let subsidy = 40_640_000;

        let valid_new = TokenomicsEngine::verify_block_conservation_of_value(
            current_supply,
            100 * COIN,
            100 * COIN + subsidy,
            subsidy,
        )
        .unwrap();
        assert_eq!(valid_new, current_supply + subsidy);

        assert!(TokenomicsEngine::verify_block_conservation_of_value(
            current_supply,
            100 * COIN,
            100 * COIN + subsidy + 1,
            subsidy,
        )
        .is_err());

        assert!(TokenomicsEngine::verify_block_conservation_of_value(
            MAX_SUPPLY,
            0,
            1,
            1,
        )
        .is_err());
    }
}
