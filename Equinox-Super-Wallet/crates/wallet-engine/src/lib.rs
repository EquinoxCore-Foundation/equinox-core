#![forbid(unsafe_code)]
#![allow(dead_code)]
// Equinox Super Wallet — Synthesized Multi-Chain Wallet Engine
// Combines:
// 1. Trust Wallet Core: TransactionPlanner (plan -> preImageHashes -> compile)
// 2. Phantom SDK: 2-Step Pre-Sign Security Simulation (ExpectedChange + Severity 1..4 Warnings)
// 3. BlueWallet / Sparrow: BIP-173 Bech32 polymod SegWit Address & UTXO Dust-Safe Coin Selection

pub const DUST_THRESHOLD_ATOMIC: u64 = 1_000;
pub const MAX_SUPPLY_ATOMIC: u64 = 2_100_000_000_000_000; // 21M EQX

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR: [u32; 5] = [
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoNote {
    pub txid: String,
    pub vout: u32,
    pub amount_atomic: u64,
}

/// Trust Wallet Core style SigningMode (Normal vs HashOnly estimation vs External)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningMode {
    Normal,
    HashOnlyEstimation,
    ExternalSignature,
}

/// Trust Wallet Core style TransactionPlan
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionPlan {
    pub selected_utxos: Vec<UtxoNote>,
    pub total_input_atomic: u64,
    pub send_amount_atomic: u64,
    pub fee_atomic: u64,
    pub change_amount_atomic: u64,
    pub recipient_address: String,
    pub change_address: String,
}

/// Phantom SDK style StateChangeSign (PLUS / MINUS / EQUAL)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateChangeSign {
    Plus,
    Minus,
    Equal,
}

/// Phantom SDK style SimulationWarningSeverity (1 = CriticalAlert .. 4 = Error)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimulationWarningSeverity {
    CriticalAlert = 1,
    Alert = 2,
    CriticalError = 3,
    InfoNotice = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedAssetChange {
    pub symbol: String,
    pub sign: StateChangeSign,
    pub amount_atomic: u64,
    pub human_readable: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationWarning {
    pub severity: SimulationWarningSeverity,
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreSignSimulationReport {
    pub status: &'static str,
    pub plan: TransactionPlan,
    pub pre_image_digest: [u8; 32],
    pub expected_changes: Vec<ExpectedAssetChange>,
    pub warnings: Vec<SimulationWarning>,
    pub is_safe_to_sign: bool,
}

pub struct WalletEngine;

impl WalletEngine {
    /// ডিটারমিনিস্টিক UTXO কয়েন সিলেকশন এবং ডাস্ট-গার্ড চেঞ্জ ক্যালকুলেশন
    pub fn select_utxos(
        utxos: &[UtxoNote],
        target_atomic: u64,
        fee_atomic: u64,
    ) -> Result<(Vec<UtxoNote>, u64), String> {
        if target_atomic == 0 {
            return Err("Transfer amount must be greater than zero".to_string());
        }
        let required = target_atomic.saturating_add(fee_atomic);

        // ১. যদি একটিমাত্র UTXO দিয়েই কাজ হয়ে যায়, তবে সবচেয়ে ছোট উপযুক্ত নোটটি বেছে নেওয়া (Optimal Single Match)
        let mut sorted = utxos.to_vec();
        sorted.sort_by(|a, b| {
            a.amount_atomic
                .cmp(&b.amount_atomic)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });

        if let Some(single) = sorted.iter().find(|u| u.amount_atomic >= required) {
            let change = single.amount_atomic - required;
            return Ok((vec![single.clone()], change));
        }

        // ২. একক নোটে না কুলোলে বড় নোটগুলো আগে বাছাই করা (Largest-First Deterministic)
        sorted.sort_by(|a, b| {
            b.amount_atomic
                .cmp(&a.amount_atomic)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });

        let mut selected = Vec::new();
        let mut accumulated = 0u64;

        for u in sorted {
            if u.amount_atomic == 0 {
                continue;
            }
            selected.push(u.clone());
            accumulated = accumulated.saturating_add(u.amount_atomic);
            if accumulated >= required {
                let change = accumulated - required;
                return Ok((selected, change));
            }
        }
        Err("Insufficient UTXO balance".to_string())
    }

    /// Trust Wallet Core style `TransactionSigner::plan` (ডাস্ট চেঞ্জ স্বয়ংক্রিয়ভাবে ফিতে মার্জ করে)
    pub fn plan_transaction(
        utxos: &[UtxoNote],
        recipient_address: &str,
        change_address: &str,
        send_amount_atomic: u64,
        base_fee_atomic: u64,
    ) -> Result<TransactionPlan, String> {
        let clean_to = recipient_address.trim();
        let clean_change = change_address.trim();
        if clean_to.is_empty() || clean_change.is_empty() {
            return Err("Recipient and change addresses are required".to_string());
        }

        let (selected, raw_change) =
            Self::select_utxos(utxos, send_amount_atomic, base_fee_atomic)?;
        let total_in: u64 = selected.iter().map(|u| u.amount_atomic).sum();

        // ডাস্ট ভাংতি (< 1,000 atomic) হলে তা নতুন UTXO না বানিয়ে মাইনার ফি হিসেবে যুক্ত করা
        let (final_change, effective_fee) =
            if raw_change > 0 && raw_change < DUST_THRESHOLD_ATOMIC {
                (0, base_fee_atomic.saturating_add(raw_change))
            } else {
                (raw_change, base_fee_atomic)
            };

        Ok(TransactionPlan {
            selected_utxos: selected,
            total_input_atomic: total_in,
            send_amount_atomic,
            fee_atomic: effective_fee,
            change_amount_atomic: final_change,
            recipient_address: clean_to.to_string(),
            change_address: clean_change.to_string(),
        })
    }

    /// Trust Wallet Core style `preImageHashes` (SigningMode_HashOnly)
    pub fn compute_pre_image_digest(plan: &TransactionPlan, chain_id: u64) -> [u8; 32] {
        let mut state = [
            0x6a09e667bb67ae85u64 ^ chain_id,
            0x3c6ef372a54ff53au64 ^ plan.send_amount_atomic,
            0x510e527f9b05688cu64 ^ plan.fee_atomic,
            0x1f83d9ab5be0cd19u64 ^ plan.change_amount_atomic,
        ];

        for u in &plan.selected_utxos {
            for (i, b) in u.txid.bytes().enumerate() {
                state[i % 4] = state[i % 4]
                    .wrapping_add(b as u64)
                    .wrapping_mul(0x100000001b3)
                    .rotate_left(11);
            }
            state[0] ^= (u.vout as u64).wrapping_mul(0x9e3779b97f4a7c15);
            state[1] ^= u.amount_atomic;
        }

        for (i, b) in plan
            .recipient_address
            .bytes()
            .chain(plan.change_address.bytes())
            .enumerate()
        {
            state[i % 4] = (state[i % 4] ^ (b as u64)).wrapping_mul(0x100000001b3);
        }

        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
        }
        out
    }

    /// Phantom SDK + Rabby style 2-Step Pre-Sign Security Simulation
    pub fn simulate_transaction_pre_sign(
        utxos: &[UtxoNote],
        sender_address: &str,
        recipient_address: &str,
        send_amount_atomic: u64,
        base_fee_atomic: u64,
        chain_id: u64,
    ) -> Result<PreSignSimulationReport, String> {
        let plan = Self::plan_transaction(
            utxos,
            recipient_address,
            sender_address,
            send_amount_atomic,
            base_fee_atomic,
        )?;
        let digest = Self::compute_pre_image_digest(&plan, chain_id);

        let total_deducted = plan.send_amount_atomic.saturating_add(plan.fee_atomic);
        let expected_changes = vec![
            ExpectedAssetChange {
                symbol: "EQX".to_string(),
                sign: StateChangeSign::Minus,
                amount_atomic: total_deducted,
                human_readable: format!(
                    "-{}.{:08} EQX (Includes {}.{:08} EQX Network Fee)",
                    total_deducted / 100_000_000,
                    total_deducted % 100_000_000,
                    plan.fee_atomic / 100_000_000,
                    plan.fee_atomic % 100_000_000
                ),
            },
            ExpectedAssetChange {
                symbol: "EQX".to_string(),
                sign: StateChangeSign::Plus,
                amount_atomic: plan.send_amount_atomic,
                human_readable: format!(
                    "+{}.{:08} EQX -> {}",
                    plan.send_amount_atomic / 100_000_000,
                    plan.send_amount_atomic % 100_000_000,
                    plan.recipient_address
                ),
            },
        ];

        let mut warnings = Vec::new();
        let mut is_safe = true;

        // Warning 1: Self-Transfer Check
        if sender_address.trim() == recipient_address.trim() {
            warnings.push(SimulationWarning {
                severity: SimulationWarningSeverity::Alert,
                kind: "SELF_TRANSFER".to_string(),
                message: "Sender and recipient addresses are identical.".to_string(),
            });
        }

        // Warning 2: High Fee Ratio Check (> 10% of transfer amount)
        if plan.fee_atomic.saturating_mul(10) > plan.send_amount_atomic {
            warnings.push(SimulationWarning {
                severity: SimulationWarningSeverity::Alert,
                kind: "HIGH_NETWORK_FEE".to_string(),
                message: "Network fee exceeds 10% of the transfer amount.".to_string(),
            });
        }

        // Warning 3: Full Balance Drain Warning (> 95% of total inputs)
        if total_deducted.saturating_mul(100) >= plan.total_input_atomic.saturating_mul(95) {
            warnings.push(SimulationWarning {
                severity: SimulationWarningSeverity::InfoNotice,
                kind: "NEAR_MAX_BALANCE_SPEND".to_string(),
                message: "This transaction spends over 95% of the selected UTXO balance."
                    .to_string(),
            });
        }

        // Warning 4: Invalid Address Prefix Check
        if !plan.recipient_address.starts_with('E') || plan.recipient_address.len() < 26 {
            warnings.push(SimulationWarning {
                severity: SimulationWarningSeverity::CriticalAlert,
                kind: "INVALID_RECIPIENT_FORMAT".to_string(),
                message: "Recipient address does not match Equinox Base58Check format!"
                    .to_string(),
            });
            is_safe = false;
        }

        Ok(PreSignSimulationReport {
            status: "pending_confirmation",
            plan,
            pre_image_digest: digest,
            expected_changes,
            warnings,
            is_safe_to_sign: is_safe,
        })
    }

    /// BlueWallet (`bech32.js`) & Trust Wallet (`SegwitAddress.cpp`) BIP-173 Bech32 Polynomial Mod
    fn bech32_polymod(values: &[u8]) -> u32 {
        let mut chk: u32 = 1;
        for &v in values {
            let top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
            for (i, &gen) in BECH32_GENERATOR.iter().enumerate() {
                if ((top >> i) & 1) != 0 {
                    chk ^= gen;
                }
            }
        }
        chk
    }

    fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
        let mut ret = Vec::with_capacity(hrp.len() * 2 + 1);
        for b in hrp.bytes() {
            ret.push(b >> 5);
        }
        ret.push(0);
        for b in hrp.bytes() {
            ret.push(b & 31);
        }
        ret
    }

    fn convert_bits_8_to_5(data: &[u8], pad: bool) -> Vec<u8> {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut ret = Vec::new();
        let maxv: u32 = (1 << 5) - 1;

        for &value in data {
            acc = (acc << 8) | (value as u32);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                ret.push(((acc >> bits) & maxv) as u8);
            }
        }
        if pad && bits > 0 {
            ret.push(((acc << (5 - bits)) & maxv) as u8);
        }
        ret
    }

    /// ২০-বাইট প্রোগ্রাম হ্যাশ থেকে আসল BIP-173 Native SegWit (`bc1q...`) অ্যাড্রেস তৈরি করে
    pub fn encode_segwit_bech32_address(
        hrp: &str,
        witness_version: u8,
        witness_program_20b: &[u8; 20],
    ) -> String {
        let mut data = Vec::with_capacity(33);
        data.push(witness_version & 31);
        data.extend_from_slice(&Self::convert_bits_8_to_5(witness_program_20b, true));

        let mut chk_input = Self::bech32_hrp_expand(hrp);
        chk_input.extend_from_slice(&data);
        chk_input.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

        let polymod = Self::bech32_polymod(&chk_input) ^ 1;
        for p in 0..6 {
            data.push(((polymod >> (5 * (5 - p))) & 31) as u8);
        }

        let mut out = String::with_capacity(hrp.len() + 1 + data.len());
        out.push_str(hrp);
        out.push('1');
        for d in data {
            out.push(BECH32_CHARSET[d as usize] as char);
        }
        out
    }

    /// BIP-173 Bech32 অ্যাড্রেসের ৬-ক্যারেক্টার পলিনোমিয়াল চেকসাম যাচাই করে
    pub fn verify_segwit_bech32_address(expected_hrp: &str, addr: &str) -> bool {
        let lower = addr.trim().to_ascii_lowercase();
        let Some(pos) = lower.rfind('1') else {
            return false;
        };
        if pos < 1 || pos + 7 > lower.len() || lower.len() > 90 {
            return false;
        }
        let hrp = &lower[..pos];
        if hrp != expected_hrp {
            return false;
        }

        let mut data = Vec::with_capacity(lower.len() - pos - 1);
        for ch in lower[pos + 1..].bytes() {
            let Some(idx) = BECH32_CHARSET.iter().position(|&c| c == ch) else {
                return false;
            };
            data.push(idx as u8);
        }

        let mut chk_input = Self::bech32_hrp_expand(hrp);
        chk_input.extend_from_slice(&data);
        Self::bech32_polymod(&chk_input) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_coin_selection_and_change() {
        let notes = vec![
            UtxoNote {
                txid: "0xaaa".to_string(),
                vout: 0,
                amount_atomic: 300_000_000,
            },
            UtxoNote {
                txid: "0xbbb".to_string(),
                vout: 1,
                amount_atomic: 500_000_000,
            },
        ];
        let (sel, change) = WalletEngine::select_utxos(&notes, 600_000_000, 10_000).unwrap();
        assert_eq!(sel.len(), 2);
        assert_eq!(change, 199_990_000);
    }

    #[test]
    fn test_trustwallet_plan_phantom_simulation_and_bluewallet_bech32() {
        let notes = vec![UtxoNote {
            txid: "0x1111222233334444".to_string(),
            vout: 0,
            amount_atomic: 1_000_000_000, // 10.00000000 EQX
        }];

        // ১. Phantom + TrustWallet Pre-Sign Simulation যাচাই
        let sim = WalletEngine::simulate_transaction_pre_sign(
            &notes,
            "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx",
            "EEScV6oAqbKaSDgfpSNRVSk7fTLHHDvg1aP",
            250_000_000, // 2.50 EQX
            10_000,      // 0.0001 EQX Fee
            9333,
        )
        .unwrap();

        assert_eq!(sim.status, "pending_confirmation");
        assert!(sim.is_safe_to_sign);
        assert_eq!(sim.expected_changes.len(), 2);
        assert_eq!(sim.expected_changes[0].sign, StateChangeSign::Minus);
        assert_eq!(sim.expected_changes[0].amount_atomic, 250_010_000);
        assert_eq!(sim.plan.change_amount_atomic, 749_990_000);

        // ২. BlueWallet / TrustWallet BIP-173 Bech32 SegWit Address ও Checksum যাচাই
        let sample_prog = [0x75u8; 20];
        let btc_addr = WalletEngine::encode_segwit_bech32_address("bc", 0, &sample_prog);
        assert!(btc_addr.starts_with("bc1q"));
        assert!(WalletEngine::verify_segwit_bech32_address("bc", &btc_addr));

        // ১টি অক্ষর পরিবর্তন করলে Bech32 polymod চেকসাম তা ধরে ফেলবে
        let mut corrupted = btc_addr.clone();
        corrupted.pop();
        corrupted.push('z');
        assert!(!WalletEngine::verify_segwit_bech32_address("bc", &corrupted));
    }
}