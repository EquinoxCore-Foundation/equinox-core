#![allow(dead_code)]
// src/consensus/dividend.rs
// Equinox (EQX) L1 — O(1) Mathematical Holder Dividend Accumulator Engine
// Architecture: Zero-Loop 10^12 Fixed-Point Global Reward Index (u128 Integer Math).
// Distributes protocol dividends to millions of Guardian Vault holders in O(1) constant time!

use crate::config::MAX_SUPPLY;
use crate::wallet::address::is_valid_address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ফ্লোটিং-পয়েন্ট এড়াতে ১০^১২ (1,000,000,000,000) ফিক্সড-পয়েন্ট স্কেলিং ফ্যাক্টর
pub const DIVIDEND_PRECISION_SCALE: u128 = 1_000_000_000_000;

/// একজন ভল্ট হোল্ডারের স্টেক ও ডিভিডেন্ড পজিশন
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeholderPosition {
    pub holder_address: String,
    pub vaulted_balance_atomic: u64,
    pub entry_reward_index_fp12: u128,
    pub accrued_unclaimed_atomic: u64,
    pub total_claimed_atomic: u64,
}

/// গ্লোবাল O(1) ডিভিডেন্ড ডিস্ট্রিবিউটর স্টেট
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalDividendDistributor {
    /// বর্তমান গ্লোবাল ডিভিডেন্ড ইনডেক্স (10^12 স্কেলে)
    pub global_reward_index_fp12: u128,
    /// বর্তমানে সব গার্ডিয়ান ভল্টে লক থাকা মোট EQX ব্যালেন্স
    pub total_vaulted_supply_atomic: u64,
    /// আজ পর্যন্ত বণ্টিত মোট ডিভিডেন্ড
    pub total_dividends_distributed_atomic: u64,
    /// হোল্ডারদের দ্বারা উত্তোলিত মোট ডিভিডেন্ড
    pub total_dividends_claimed_atomic: u64,
    /// যখন ভল্টে কেউ কয়েন রাখেনি তখনকার জমা থাকা রিজার্ভ ডিভিডেন্ড (যাতে ১টি কয়েনও হারিয়ে না যায়)
    pub unallocated_reserve_atomic: u64,
    /// প্রতিটি হোল্ডারের পজিশন ম্যাপ
    pub positions: HashMap<String, StakeholderPosition>,
}

impl Default for GlobalDividendDistributor {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalDividendDistributor {
    pub fn new() -> Self {
        Self {
            global_reward_index_fp12: 0,
            total_vaulted_supply_atomic: 0,
            total_dividends_distributed_atomic: 0,
            total_dividends_claimed_atomic: 0,
            unallocated_reserve_atomic: 0,
            positions: HashMap::new(),
        }
    }

    /// প্রতি ব্লকে (১৫ সেকেন্ডে) সংগৃহীত ডিভিডেন্ড কোনো লুপ ছাড়াই O(1) সময়ে গ্লোবাল ইনডেক্সে যোগ করে
    pub fn distribute_block_dividend(&mut self, block_dividend_atomic: u64) -> Result<(), String> {
        if block_dividend_atomic == 0 {
            return Ok(());
        }

        if self.total_vaulted_supply_atomic == 0 {
            self.unallocated_reserve_atomic = self
                .unallocated_reserve_atomic
                .saturating_add(block_dividend_atomic)
                .min(MAX_SUPPLY);
            return Ok(());
        }

        let total_to_distribute = (block_dividend_atomic as u128)
            .saturating_add(self.unallocated_reserve_atomic as u128);
        self.unallocated_reserve_atomic = 0;

        let index_delta = total_to_distribute
            .saturating_mul(DIVIDEND_PRECISION_SCALE)
            / (self.total_vaulted_supply_atomic as u128);

        self.global_reward_index_fp12 = self.global_reward_index_fp12.saturating_add(index_delta);
        self.total_dividends_distributed_atomic = self
            .total_dividends_distributed_atomic
            .saturating_add(total_to_distribute as u64)
            .min(MAX_SUPPLY);

        Ok(())
    }

    /// নির্দিষ্ট হোল্ডারের বর্তমান প্রাপ্য (Unclaimed) ডিভিডেন্ড O(1) ফর্মুলায় হিসাব করে
    pub fn calculate_pending_dividend(&self, holder_address: &str) -> u64 {
        let Some(pos) = self.positions.get(holder_address.trim()) else {
            return 0;
        };

        if pos.vaulted_balance_atomic == 0
            || self.global_reward_index_fp12 <= pos.entry_reward_index_fp12
        {
            return pos.accrued_unclaimed_atomic;
        }

        let index_diff = self
            .global_reward_index_fp12
            .saturating_sub(pos.entry_reward_index_fp12);

        let newly_earned = ((pos.vaulted_balance_atomic as u128).saturating_mul(index_diff))
            / DIVIDEND_PRECISION_SCALE;

        pos.accrued_unclaimed_atomic
            .saturating_add(newly_earned as u64)
            .min(MAX_SUPPLY)
    }

    /// হোল্ডারের পজিশন বর্তমান গ্লোবাল ইনডেক্সের সাথে সেটেল (Settle) করে
    fn settle_holder_position(&mut self, clean_address: &str) {
        let current_index = self.global_reward_index_fp12;
        if let Some(pos) = self.positions.get_mut(clean_address) {
            if pos.vaulted_balance_atomic > 0 && current_index > pos.entry_reward_index_fp12 {
                let index_diff = current_index.saturating_sub(pos.entry_reward_index_fp12);
                let earned = ((pos.vaulted_balance_atomic as u128).saturating_mul(index_diff))
                    / DIVIDEND_PRECISION_SCALE;
                pos.accrued_unclaimed_atomic = pos
                    .accrued_unclaimed_atomic
                    .saturating_add(earned as u64)
                    .min(MAX_SUPPLY);
            }
            pos.entry_reward_index_fp12 = current_index;
        }
    }

    /// গার্ডিয়ান ভল্টে কয়েন ডিপোজিট করে ডিভিডেন্ড অর্জন শুরু করে
    pub fn deposit_stake(&mut self, holder_address: &str, amount_atomic: u64) -> Result<(), String> {
        let clean = holder_address.trim();
        if !is_valid_address(clean) {
            return Err(format!("অবৈধ হোল্ডার ওয়ালেট অ্যাড্রেস: {}", clean));
        }
        if amount_atomic == 0 || amount_atomic > MAX_SUPPLY {
            return Err("ডিপোজিট পরিমাণ শূন্য বা সীমার বাইরে হতে পারবে না".to_string());
        }

        self.settle_holder_position(clean);

        let current_idx = self.global_reward_index_fp12;
        let entry = self
            .positions
            .entry(clean.to_string())
            .or_insert_with(|| StakeholderPosition {
                holder_address: clean.to_string(),
                vaulted_balance_atomic: 0,
                entry_reward_index_fp12: current_idx,
                accrued_unclaimed_atomic: 0,
                total_claimed_atomic: 0,
            });

        entry.vaulted_balance_atomic = entry
            .vaulted_balance_atomic
            .saturating_add(amount_atomic)
            .min(MAX_SUPPLY);
        entry.entry_reward_index_fp12 = current_idx;

        self.total_vaulted_supply_atomic = self
            .total_vaulted_supply_atomic
            .saturating_add(amount_atomic)
            .min(MAX_SUPPLY);

        // আগে কোনো আন-অ্যালোকেটেড রিজার্ভ ডিভিডেন্ড থাকলে তা সাথে সাথে প্রথম ডিপোজিটরের ইনডেক্সে যুক্ত হবে
        if self.unallocated_reserve_atomic > 0 {
            let reserve = self.unallocated_reserve_atomic;
            self.unallocated_reserve_atomic = 0;
            self.distribute_block_dividend(reserve)?;
        }

        Ok(())
    }

    /// জমে থাকা ফ্রি ডিভিডেন্ড কয়েন ক্লেইম (উত্তোলন) করে
    pub fn claim_dividend(&mut self, holder_address: &str) -> Result<u64, String> {
        let clean = holder_address.trim();
        self.settle_holder_position(clean);

        let Some(pos) = self.positions.get_mut(clean) else {
            return Err("এই অ্যাড্রেসে কোনো ভল্ট পজিশন পাওয়া যায়নি".to_string());
        };

        let claimable = pos.accrued_unclaimed_atomic;
        if claimable == 0 {
            return Err("উত্তোলনের জন্য কোনো বকেয়া ডিভিডেন্ড নেই".to_string());
        }

        pos.accrued_unclaimed_atomic = 0;
        pos.total_claimed_atomic = pos.total_claimed_atomic.saturating_add(claimable);
        self.total_dividends_claimed_atomic = self
            .total_dividends_claimed_atomic
            .saturating_add(claimable);

        Ok(claimable)
    }

    /// ভল্ট থেকে মূল স্টেক উত্তোলন করে (বকেয়া ডিভিডেন্ড অক্ষুণ্ণ রেখে)
    pub fn withdraw_stake(
        &mut self,
        holder_address: &str,
        amount_atomic: u64,
    ) -> Result<u64, String> {
        let clean = holder_address.trim();
        self.settle_holder_position(clean);

        let Some(pos) = self.positions.get_mut(clean) else {
            return Err("এই অ্যাড্রেসে কোনো ভল্ট পজিশন নেই".to_string());
        };

        if amount_atomic == 0 || pos.vaulted_balance_atomic < amount_atomic {
            return Err("ভল্টে পর্যাপ্ত ব্যালেন্স নেই".to_string());
        }

        pos.vaulted_balance_atomic -= amount_atomic;
        self.total_vaulted_supply_atomic = self
            .total_vaulted_supply_atomic
            .saturating_sub(amount_atomic);

        Ok(amount_atomic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_o1_mathematical_dividend_proportional_distribution() {
        let mut engine = GlobalDividendDistributor::new();

        let alice_kp = KeyPair::generate();
        let bob_kp = KeyPair::generate();
        let alice = pubkey_to_address(&alice_kp.public_key());
        let bob = pubkey_to_address(&bob_kp.public_key());

        // অ্যালিস ৭৫০ EQX (৭৫%) এবং বব ২৫০ EQX (২৫%) ভল্টে রাখল (মোট ১,০০০ EQX)
        engine.deposit_stake(&alice, 750 * COIN).unwrap();
        engine.deposit_stake(&bob, 250 * COIN).unwrap();

        // নেটওয়ার্কে ১০০ EQX ডিভিডেন্ড এল — O(1) ফর্মুলায় অ্যালিস ৭৫ EQX ও বব ২৫ EQX পাবে!
        engine.distribute_block_dividend(100 * COIN).unwrap();

        assert_eq!(engine.calculate_pending_dividend(&alice), 75 * COIN);
        assert_eq!(engine.calculate_pending_dividend(&bob), 25 * COIN);

        let alice_claimed = engine.claim_dividend(&alice).unwrap();
        let bob_claimed = engine.claim_dividend(&bob).unwrap();
        assert_eq!(alice_claimed, 75 * COIN);
        assert_eq!(bob_claimed, 25 * COIN);
        assert_eq!(engine.calculate_pending_dividend(&alice), 0);
    }
}