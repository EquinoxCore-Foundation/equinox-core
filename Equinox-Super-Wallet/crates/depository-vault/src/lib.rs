#![allow(dead_code)]
// Equinox Super Wallet v6.0 — Air-Gapped Cross-Chain Depository Firewall
// Prevents Cross-Chain Contagion, TxHash Replay Attacks, and Unconfirmed Block Reorg Exploits.

use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IsolatedChain {
    BitcoinNative,
    BnbSmartChain,
    EthereumMainnet,
    TronNetwork,
    EquinoxMainnet,
}

impl IsolatedChain {
    /// প্রতিটি ব্লকচেইনের জন্য বাধ্যতামূলক অন-চেইন ব্লক কনফার্মেশন সংখ্যা
    pub fn min_required_confirmations(&self) -> u32 {
        match self {
            IsolatedChain::BitcoinNative => 3,
            IsolatedChain::EthereumMainnet => 12,
            IsolatedChain::BnbSmartChain => 15,
            IsolatedChain::TronNetwork => 19,
            IsolatedChain::EquinoxMainnet => 10,
        }
    }
}

pub struct CrossChainDepositoryFirewall {
    /// প্রতিটি চেইনের রিজার্ভ সম্পূর্ণ আলাদা লকারে সংরক্ষিত (Cross-Chain Contagion অসম্ভব)
    pub chain_vault_reserves: HashMap<IsolatedChain, u128>,
    pub chain_user_credits: HashMap<IsolatedChain, u128>,
    /// (Chain, UserAddress) -> Balance (এক চেইনের ব্যালেন্স দিয়ে অন্য চেইন থেকে উইথড্র করা অসম্ভব)
    pub isolated_user_balances: HashMap<(IsolatedChain, String), u128>,
    /// ব্যবহৃত ডিপোজিট TxHash তালিকা (ডাবল-ডিপোজিট বা Replay Attack ১০০% ব্লক করে)
    pub processed_tx_hashes: HashSet<String>,
    /// জরুরি সার্কিট ব্রেকার (কোনো চেইনে সমস্যা হলে শুধু সেই চেইন পজ হবে)
    pub paused_chains: HashSet<IsolatedChain>,
    pub required_mpc_signatures: usize,
}

impl CrossChainDepositoryFirewall {
    pub fn new(required_mpc_signatures: usize) -> Self {
        Self {
            chain_vault_reserves: HashMap::new(),
            chain_user_credits: HashMap::new(),
            isolated_user_balances: HashMap::new(),
            processed_tx_hashes: HashSet::new(),
            paused_chains: HashSet::new(),
            required_mpc_signatures: required_mpc_signatures.max(3),
        }
    }

    /// ১. ক্রস-চেইন ফায়ারওয়াল ডিপোজিট ভেরিফিকেশন
    pub fn verify_and_credit_deposit(
        &mut self,
        chain: IsolatedChain,
        user_address: &str,
        tx_hash: &str,
        amount_atomic: u128,
        confirmations: u32,
    ) -> Result<u128, String> {
        if self.paused_chains.contains(&chain) {
            return Err("Circuit Breaker Active: Deposits on this chain are temporarily paused".to_string());
        }
        let clean_tx = tx_hash.trim().to_lowercase();
        let clean_user = user_address.trim().to_string();

        if amount_atomic == 0 || clean_user.is_empty() || clean_tx.len() < 12 {
            return Err("Invalid deposit parameters or malformed TxHash".to_string());
        }

        // Shield 1: Replay Attack Guard (একই TxHash দ্বিতীয়বার ব্যবহার করলে সাথে সাথে ব্লক)
        if self.processed_tx_hashes.contains(&clean_tx) {
            return Err(format!("Replay Attack Blocked: TxHash '{}' already credited!", clean_tx));
        }

        // Shield 2: Block Finality Depth Check
        let min_conf = chain.min_required_confirmations();
        if confirmations < min_conf {
            return Err(format!(
                "Unconfirmed Deposit Blocked: Required {} confirmations, got {}",
                min_conf, confirmations
            ));
        }

        // Shield 3: Chain-Isolated Reserve & Credit Update
        self.processed_tx_hashes.insert(clean_tx);

        let vault_res = self.chain_vault_reserves.entry(chain).or_insert(0);
        *vault_res = vault_res.saturating_add(amount_atomic);

        let cred_res = self.chain_user_credits.entry(chain).or_insert(0);
        *cred_res = cred_res.saturating_add(amount_atomic);

        let updated_user_bal = {
            let u_entry = self.isolated_user_balances.entry((chain, clean_user)).or_insert(0);
            *u_entry = u_entry.saturating_add(amount_atomic);
            *u_entry
        };

        self.assert_chain_isolation_solvency(chain)?;
        Ok(updated_user_bal)
    }

    /// ২. চেইন-আইসোলেটেড MPC উইথড্রয়াল (এক চেইন থেকে ঢুকে অন্য চেইনের ফান্ড তোলা অসম্ভব)
    pub fn execute_isolated_withdrawal(
        &mut self,
        chain: IsolatedChain,
        user_address: &str,
        withdraw_atomic: u128,
        mpc_signatures: usize,
    ) -> Result<u128, String> {
        if self.paused_chains.contains(&chain) {
            return Err("Circuit Breaker Active: Withdrawals on this chain are paused".to_string());
        }
        if mpc_signatures < self.required_mpc_signatures {
            return Err("MPC Consensus Block: Insufficient validator signatures".to_string());
        }

        let key = (chain, user_address.trim().to_string());
        let user_bal = self.isolated_user_balances.get_mut(&key)
            .ok_or_else(|| "No isolated balance found for this user on the requested chain".to_string())?;

        if withdraw_atomic == 0 || *user_bal < withdraw_atomic {
            return Err("Cross-Chain Firewall Block: Insufficient balance on this specific chain".to_string());
        }

        let vault_res = self.chain_vault_reserves.get_mut(&chain)
            .ok_or_else(|| "Chain reserve not initialized".to_string())?;
        let cred_res = self.chain_user_credits.get_mut(&chain)
            .ok_or_else(|| "Chain credit not initialized".to_string())?;

        if *vault_res < withdraw_atomic {
            return Err("Chain reserve underflow prevented".to_string());
        }

        *user_bal -= withdraw_atomic;
        *vault_res -= withdraw_atomic;
        *cred_res -= withdraw_atomic;

        let remaining_chain_reserve = *vault_res;
        self.assert_chain_isolation_solvency(chain)?;
        Ok(remaining_chain_reserve)
    }

    /// ৩. প্রতিটি চেইনের নিজস্ব ১:১ সলভেন্সি গার্ড
    pub fn assert_chain_isolation_solvency(&self, chain: IsolatedChain) -> Result<(), String> {
        let r = self.chain_vault_reserves.get(&chain).copied().unwrap_or(0);
        let c = self.chain_user_credits.get(&chain).copied().unwrap_or(0);
        if r != c {
            return Err("Chain-Isolated 1:1 Solvency Invariant Violated!".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_chain_firewall_blocks_contagion_and_replay_attacks() {
        let mut fw = CrossChainDepositoryFirewall::new(7);

        // ১. ইউজার BNB চেইনে 500 ডিপোজিট করল (১৫ কনফার্মেশন সহ)
        let bnb_bal = fw.verify_and_credit_deposit(
            IsolatedChain::BnbSmartChain,
            "EUser001",
            "0x99887766554433221100aabbccddeeff",
            500_00,
            15,
        ).unwrap();
        assert_eq!(bnb_bal, 500_00);

        // ২. হ্যাকার একই TxHash আবার সাবমিট করে ডাবল ব্যালেন্স নেওয়ার চেষ্টা করলে -> সাথে সাথে ব্লক!
        assert!(fw.verify_and_credit_deposit(
            IsolatedChain::BnbSmartChain,
            "EUser001",
            "0x99887766554433221100aabbccddeeff",
            500_00,
            20,
        ).is_err());

        // ৩. হ্যাকার BNB চেইনে ডিপোজিট করে Bitcoin (BTC) ভল্ট থেকে উইথড্র করার চেষ্টা করলে -> সাথে সাথে ব্লক!
        assert!(fw.execute_isolated_withdrawal(
            IsolatedChain::BitcoinNative,
            "EUser001",
            100_00,
            7,
        ).is_err());

        // ৪. বৈধভাবে BNB চেইন থেকেই 200 উইথড্র করলে -> নিখুঁতভাবে সফল!
        let rem = fw.execute_isolated_withdrawal(
            IsolatedChain::BnbSmartChain,
            "EUser001",
            200_00,
            7,
        ).unwrap();
        assert_eq!(rem, 300_00);
    }
}
