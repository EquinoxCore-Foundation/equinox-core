#![allow(dead_code)]
// src/state/coin_selection.rs
// Equinox (EQX) L1 — Audit-Grade Deterministic Coin Selection & Dust-Aware Change Engine
// Features: Canonical OutPoint Tie-Breaking, Single-Coin Optimal Match, Max-Input DoS Cap,
// 21M Supply Overflow Protection & Anti-Dust Change Calculation.

use crate::config::{MAX_SUPPLY, MIN_RELAY_TX_FEE};
use crate::primitives::transaction::TxOutput;
use crate::state::outpoint::OutPoint;
use crate::wallet::address::is_valid_address;
use std::collections::HashMap;

/// একটি একক ট্রানজ্যাকশনে সর্বোচ্চ অনুমোদিত ইনপুট সংখ্যা (ব্লক সাইজ ও ভেরিফিকেশন DoS প্রতিরোধে)
pub const MAX_INPUTS_PER_TX: usize = 256;

/// ডাস্ট (Dust) আউটপুট প্রতিরোধ সীমা: ১,০০০ অ্যাটমিক ইউনিট (০.০০০০১০০০ EQX)।
/// ভাংতি (Change) এর চেয়ে কম হলে তা নতুন UTXO না বানিয়ে মাইনার ফি হিসেবে যুক্ত হবে।
pub const DUST_CHANGE_THRESHOLD: u64 = 1_000;

/// কয়েন সিলেকশন ও ভাংতি হিসাবের পূর্ণাঙ্গ ফলাফল
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionResult {
    pub selected_coins: Vec<(OutPoint, TxOutput)>,
    pub total_accumulated: u64,
    pub change_amount: u64,
    pub effective_fee: u64,
}

pub struct CoinSelection;

impl CoinSelection {
    /// প্রেরকের অ্যাড্রেস থেকে প্রয়োজনীয় পরিমাণ কয়েন ডিটারমিনিস্টিকভাবে বাছাই করে এবং টাইম-লকড কয়েনগুলো স্বয়ংক্রিয়ভাবে বাদ দেয়।
    /// রিটার্ন করে: `(selected_utxos, total_accumulated_amount)`
    pub fn select_coins(
        utxo_pool: &HashMap<OutPoint, TxOutput>,
        sender_address: &str,
        target_amount: u64,
        fee: u64,
        current_block_height: u64,
    ) -> Result<(Vec<(OutPoint, TxOutput)>, u64), String> {
        let detailed = Self::select_coins_detailed(
            utxo_pool,
            sender_address,
            target_amount,
            fee,
            current_block_height,
        )?;
        Ok((detailed.selected_coins, detailed.total_accumulated))
    }

    /// ডাস্ট-সচেতন ভাংতি (`change_amount`) ও কার্যকরী ফি (`effective_fee`)-সহ পূর্ণাঙ্গ কয়েন সিলেকশন ইঞ্জিন
    pub fn select_coins_detailed(
        utxo_pool: &HashMap<OutPoint, TxOutput>,
        sender_address: &str,
        target_amount: u64,
        fee: u64,
        current_block_height: u64,
    ) -> Result<SelectionResult, String> {
        let sender_trimmed = sender_address.trim();
        if !is_valid_address(sender_trimmed) {
            return Err("প্রেরকের ওয়ালেট অ্যাড্রেস বৈধ নয়".to_string());
        }

        if target_amount == 0 {
            return Err("পাঠানোর কয়েন পরিমাণ শূন্য (0) হতে পারবে না".to_string());
        }

        if target_amount > MAX_SUPPLY || fee > MAX_SUPPLY {
            return Err("কয়েনের পরিমাণ ২১ মিলিয়ন সর্বোচ্চ সাপ্লাই সীমার বাইরে".to_string());
        }

        let required_total = target_amount
            .checked_add(fee)
            .ok_or_else(|| "টোটাল অ্যামাউন্ট ও ফি যোগফলে গাণিতিক ওভারফ্লো হয়েছে".to_string())?;

        if required_total > MAX_SUPPLY {
            return Err("প্রয়োজনীয় মোট কয়েন ২১ মিলিয়ন হার্ড-ক্যাপ অতিক্রম করেছে".to_string());
        }

        // ১. শুধুমাত্র প্রেরকের বৈধ, অ-শূন্য এবং বর্তমান ব্লক হাইটে আনলকড কয়েনগুলো বাছাই করা
        let mut available_coins: Vec<(OutPoint, TxOutput)> = utxo_pool
            .iter()
            .filter(|(op, out)| {
                !op.is_null()
                    && out.amount > 0
                    && out.amount <= MAX_SUPPLY
                    && out.recipient_address == sender_trimmed
                    && out.is_spendable_at(current_block_height)
            })
            .map(|(op, out)| (op.clone(), out.clone()))
            .collect();

        if available_coins.is_empty() {
            return Err(format!(
                "অ্যাড্রেস {}-এ বর্তমানে কোনো খরচযোগ্য (Spendable) কয়েন নেই",
                sender_trimmed
            ));
        }

        // ২. অপটিমাইজেশন ধাপ ক: যদি একটিমাত্র কয়েন দিয়েই প্রয়োজনীয় খরচ মেটানো যায়,
        // তবে সবচেয়ে ছোট উপযুক্ত একক কয়েনটি (Smallest Sufficient Single UTXO) বেছে নেওয়া হবে।
        available_coins.sort_by(|a, b| {
            a.1.amount
                .cmp(&b.1.amount)
                .then_with(|| a.0.cmp(&b.0))
        });

        if let Some(best_single) = available_coins
            .iter()
            .find(|(_, out)| out.amount >= required_total)
            .cloned()
        {
            let accumulated = best_single.1.amount;
            let (change_amount, effective_fee) =
                Self::compute_dust_safe_change(accumulated, target_amount, fee)?;

            return Ok(SelectionResult {
                selected_coins: vec![best_single],
                total_accumulated: accumulated,
                change_amount,
                effective_fee,
            });
        }

        // ৩. অপটিমাইজেশন ধাপ খ: একক কয়েনে না কুলোলে বড় কয়েনগুলো আগে বাছাই করার জন্য
        // সম্পূর্ণ ডিটারমিনিস্টিক ডিসেন্ডিং সর্ট (অ্যামাউন্ট সমান হলে OutPoint দিয়ে টাই-ব্রেক)
        available_coins.sort_by(|a, b| {
            b.1.amount
                .cmp(&a.1.amount)
                .then_with(|| a.0.cmp(&b.0))
        });

        let mut selected = Vec::new();
        let mut accumulated: u128 = 0;
        let required_u128 = required_total as u128;

        for (op, out) in available_coins {
            if selected.len() >= MAX_INPUTS_PER_TX {
                return Err(format!(
                    "ট্রানজ্যাকশনে সর্বোচ্চ অনুমোদিত ইনপুট সীমা ({}) পূর্ণ হয়ে গেছে! দয়া করে আগে UTXO কনসোলিডেট করুন।",
                    MAX_INPUTS_PER_TX
                ));
            }

            accumulated = accumulated
                .checked_add(out.amount as u128)
                .ok_or_else(|| "কয়েন যোগফলে গাণিতিক ওভারফ্লো হয়েছে".to_string())?;

            selected.push((op, out));

            if accumulated >= required_u128 {
                break;
            }
        }

        if accumulated < required_u128 {
            return Err(format!(
                "পর্যাপ্ত খরচযোগ্য (Spendable) ব্যালেন্স নেই! প্রয়োজন: {}, উপলব্ধ: {}",
                required_total, accumulated
            ));
        }

        if accumulated > (MAX_SUPPLY as u128) {
            return Err("বাছাইকৃত কয়েনের যোগফল ২১ মিলিয়ন সাপ্লাই ক্যাপ অতিক্রম করেছে".to_string());
        }

        let total_accumulated = accumulated as u64;
        let (change_amount, effective_fee) =
            Self::compute_dust_safe_change(total_accumulated, target_amount, fee)?;

        Ok(SelectionResult {
            selected_coins: selected,
            total_accumulated,
            change_amount,
            effective_fee,
        })
    }

    /// ভাংতি (Change) যদি ডাস্ট সীমার (`DUST_CHANGE_THRESHOLD`) নিচে হয়, তবে লেজার পরিষ্কার রাখতে সেটি ফিতে যোগ করে
    pub fn compute_dust_safe_change(
        accumulated: u64,
        target_amount: u64,
        base_fee: u64,
    ) -> Result<(u64, u64), String> {
        let effective_base_fee = base_fee.max(MIN_RELAY_TX_FEE.min(base_fee));
        let required = target_amount
            .checked_add(effective_base_fee)
            .ok_or_else(|| "টার্গেট ও ফি যোগফলে ওভারফ্লো".to_string())?;

        if accumulated < required {
            return Err("সংগৃহীত কয়েন প্রয়োজনীয় পরিমাণের চেয়ে কম".to_string());
        }

        let raw_change = accumulated - required;
        if raw_change > 0 && raw_change < DUST_CHANGE_THRESHOLD {
            // ডাস্ট ভাংতি নতুন আউটপুট হিসেবে না বানিয়ে মাইনার ফি হিসেবে যুক্ত করা হলো
            let adjusted_fee = effective_base_fee.saturating_add(raw_change);
            Ok((0, adjusted_fee))
        } else {
            Ok((raw_change, effective_base_fee))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_deterministic_tie_breaking_and_single_coin_optimization() {
        let kp = KeyPair::generate();
        let sender = pubkey_to_address(&kp.public_key());

        let mut pool = HashMap::new();
        let op_small_a = OutPoint::new([0x01u8; 32], 0);
        let op_small_b = OutPoint::new([0x02u8; 32], 0);
        let op_huge = OutPoint::new([0x03u8; 32], 0);

        // দুটি সমান ৫০ EQX-এর কয়েন এবং একটি ১,০০০ EQX-এর বড় কয়েন
        pool.insert(
            op_small_b.clone(),
            TxOutput {
                amount: 50 * COIN,
                recipient_address: sender.clone(),
                unlock_height: 0,
            },
        );
        pool.insert(
            op_small_a.clone(),
            TxOutput {
                amount: 50 * COIN,
                recipient_address: sender.clone(),
                unlock_height: 0,
            },
        );
        pool.insert(
            op_huge.clone(),
            TxOutput {
                amount: 1_000 * COIN,
                recipient_address: sender.clone(),
                unlock_height: 0,
            },
        );

        // ১. যখন ৩০ EQX পাঠানো হবে, তখন ১,০০০ EQX-এর বড় কয়েন না ভেঙে ৫০ EQX-এর কয়েনটি বেছে নেবে
        // এবং টাই-ব্রেকিংয়ে সবসময় 0x01 (op_small_a) আগে আসবে!
        let (selected, total) =
            CoinSelection::select_coins(&pool, &sender, 30 * COIN, 10_000, 10).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, op_small_a);
        assert_eq!(total, 50 * COIN);

        // ২. যখন ৮০ EQX পাঠানো হবে, তখন একটি কয়েনে হবে না—তখন ডিসেন্ডিং সর্টে ১,০০০ EQX বাছাই হবে
        let (selected_multi, _) =
            CoinSelection::select_coins(&pool, &sender, 80 * COIN, 10_000, 10).unwrap();
        assert_eq!(selected_multi.len(), 1);
        assert_eq!(selected_multi[0].0, op_huge);
    }

    #[test]
    fn test_timelocked_coins_skipped_and_dust_absorbed() {
        let kp = KeyPair::generate();
        let sender = pubkey_to_address(&kp.public_key());

        let mut pool = HashMap::new();
        // ব্লক #১০০ পর্যন্ত লকড কয়েন
        pool.insert(
            OutPoint::new([0xAAu8; 32], 0),
            TxOutput {
                amount: 500 * COIN,
                recipient_address: sender.clone(),
                unlock_height: 100,
            },
        );
        // আনলকড কয়েন
        pool.insert(
            OutPoint::new([0xBBu8; 32], 0),
            TxOutput {
                amount: 10 * COIN + 10_500, // পাঠানোর পর মাত্র 500 অ্যাটমিক ইউনিট (Dust) বাঁচবে
                recipient_address: sender.clone(),
                unlock_height: 0,
            },
        );

        // ব্লক #১০-এ ৫০০ EQX লকড থাকায় ২০০ EQX পাঠাতে গেলে এরর দেবে
        assert!(CoinSelection::select_coins(&pool, &sender, 200 * COIN, 10_000, 10).is_err());

        // ১০ EQX পাঠালে ৫০০ ইউনিটের ডাস্ট ভাংতি নতুন আউটপুট না হয়ে ফিতে যুক্ত হয়ে যাবে
        let res =
            CoinSelection::select_coins_detailed(&pool, &sender, 10 * COIN, 10_000, 10).unwrap();
        assert_eq!(res.change_amount, 0);
        assert_eq!(res.effective_fee, 10_500);
    }
}
