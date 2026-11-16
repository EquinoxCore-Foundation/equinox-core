#![allow(dead_code)]
// Equinox Super Wallet — Anti-Fraud 24H Quarantine & Clawback Misuse Prevention Engine
// Prevents Chargeback/Double-Spend Scams via 4 Mathematical Rules:
// 1. DEX Swaps & Merchant Payments use InstantIrreversible mode (Clawback impossible).
// 2. Quarantined transfers stay in Pre-Settlement Escrow (Receiver knows it is unfinalized).
// 3. Once 24h (5,760 blocks) elapses, transaction is permanently irreversible.
// 4. Triggering Panic Clawback deducts a 1% Anti-Abuse Fee and freezes funds in Cold Recovery for 7 days (40,320 blocks).

pub const QUARANTINE_WINDOW_BLOCKS: u64 = 5_760;      // 24 Hours
pub const POST_CLAWBACK_FREEZE_BLOCKS: u64 = 40_320; // 7 Days Cold Freeze
pub const ANTI_ABUSE_SLASH_BPS: u64 = 100;           // 1.00% Anti-Spam Fee

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferSettlementMode {
    InstantIrreversibleDexOrMerchant,
    QuarantinedVaultEscrow24H,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClawbackResolution {
    pub refunded_to_cold_recovery_atomic: u64,
    pub anti_abuse_fee_atomic: u64,
    pub frozen_until_block_height: u64,
}

pub struct AntiFraudVaultGuard;

impl AntiFraudVaultGuard {
    pub fn execute_safe_clawback(
        mode: TransferSettlementMode,
        gross_amount_atomic: u64,
        initiated_height: u64,
        current_height: u64,
    ) -> Result<ClawbackResolution, String> {
        // নিয়ম ১: DEX বা মার্চেন্ট পেমেন্ট কখনোই ক্ল-ব্যাক করা যাবে না
        if mode == TransferSettlementMode::InstantIrreversibleDexOrMerchant {
            return Err("Anti-Fraud Rule #1: Instant DEX/Merchant transfers are 100% irreversible!".to_string());
        }

        // নিয়ম ২: ২৪ ঘণ্টা (৫,৭৬০ ব্লক) পার হয়ে ফাইনাল হয়ে গেলে আর ক্ল-ব্যাক করা যাবে না
        if current_height >= initiated_height.saturating_add(QUARANTINE_WINDOW_BLOCKS) {
            return Err("Anti-Fraud Rule #2: 24-Hour Escrow window expired; transfer is permanently finalized!".to_string());
        }

        // নিয়ম ৩ ও ৪: ১% অ্যান্টি-ফ্রড ফি কেটে বাকি ৯৯% কয়েন ৭ দিনের জন্য কোল্ড রিকভারি ভল্টে লক করা হবে
        let fee = (gross_amount_atomic as u128 * ANTI_ABUSE_SLASH_BPS as u128 / 10_000) as u64;
        let net_refund = gross_amount_atomic.saturating_sub(fee);
        let freeze_until = current_height.saturating_add(POST_CLAWBACK_FREEZE_BLOCKS);

        Ok(ClawbackResolution {
            refunded_to_cold_recovery_atomic: net_refund,
            anti_abuse_fee_atomic: fee,
            frozen_until_block_height: freeze_until,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_fraud_clawback_rules_prevent_merchant_scam() {
        // DEX বা দোকানদারের পেমেন্ট ক্ল-ব্যাক করার চেষ্টা করলে সাথে সাথে ব্লক হবে
        assert!(AntiFraudVaultGuard::execute_safe_clawback(
            TransferSettlementMode::InstantIrreversibleDexOrMerchant,
            1_000_000_000,
            100,
            110
        ).is_err());

        // ২৪ ঘণ্টা পার হওয়ার পর ক্ল-ব্যাক ব্লক হবে
        assert!(AntiFraudVaultGuard::execute_safe_clawback(
            TransferSettlementMode::QuarantinedVaultEscrow24H,
            1_000_000_000,
            100,
            100 + QUARANTINE_WINDOW_BLOCKS
        ).is_err());

        // বৈধ ২৪-ঘণ্টার এসক্রো ক্ল-ব্যাকে ১% অ্যান্টি-ফ্রড ফি কাটবে এবং ৭ দিনের জন্য কোল্ড লক করবে
        let res = AntiFraudVaultGuard::execute_safe_clawback(
            TransferSettlementMode::QuarantinedVaultEscrow24H,
            100_000_000_000, // 1,000 EQX
            100,
            200,
        ).unwrap();

        assert_eq!(res.anti_abuse_fee_atomic, 1_000_000_000); // 10 EQX (1%)
        assert_eq!(res.refunded_to_cold_recovery_atomic, 99_000_000_000); // 990 EQX (99%)
        assert_eq!(res.frozen_until_block_height, 200 + POST_CLAWBACK_FREEZE_BLOCKS);
    }
}
