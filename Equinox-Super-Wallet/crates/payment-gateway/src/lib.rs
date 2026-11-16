#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PaymentChain {
    BitcoinMainnet,
    EthereumMainnet,
    BnbSmartChain,
    TronMainnet,
    EquinoxNative,
}

impl PaymentChain {
    pub fn required_confirmations(&self) -> u32 {
        match self {
            PaymentChain::BitcoinMainnet => 3,
            PaymentChain::EthereumMainnet => 12,
            PaymentChain::BnbSmartChain => 15,
            PaymentChain::TronMainnet => 19,
            PaymentChain::EquinoxNative => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetKind {
    NativeCoin,
    UsdtToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoiceState {
    Pending,
    Detected,
    Confirming { current_confirmations: u32, required: u32 },
    Settled,
    PartiallyPaid,
    Overpaid,
    Expired,
    Reorged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invoice {
    pub invoice_id: u64,
    pub user_id: String,
    pub chain: PaymentChain,
    pub asset: AssetKind,
    pub derivation_index: u32,
    pub unique_deposit_address: String,
    pub requested_amount_atomic: u128,
    pub actual_received_atomic: u128,
    pub expires_at_unix: u64,
    pub state: InvoiceState,
    pub linked_tx_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcessedTxKey {
    pub chain: PaymentChain,
    pub tx_hash: String,
    pub log_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub entry_id: u64,
    pub invoice_id: u64,
    pub user_id: String,
    pub chain: PaymentChain,
    pub debit_account: String,
    pub credit_account: String,
    pub amount_atomic: u128,
    pub tx_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeaderRecord {
    pub height: u64,
    pub block_hash: String,
    pub parent_hash: String,
}

#[derive(Clone, Debug)]
pub struct OnChainTransferEvent {
    pub chain: PaymentChain,
    pub tx_hash: String,
    pub log_index: u32,
    pub to_address: String,
    pub token_contract: Option<String>,
    pub actual_amount_atomic: u128,
    pub confirmations: u32,
    pub is_rbf_replaceable: bool,
    pub block_height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub current_unix_time: u64,
}

pub struct SovereignPaymentGateway {
    pub watch_only_xpub: String,
    pub next_derivation_index: u32,
    pub next_invoice_id: u64,
    pub invoices: HashMap<u64, Invoice>,
    pub address_to_invoice: HashMap<String, u64>,
    pub processed_txs: HashSet<ProcessedTxKey>,
    pub ledger_entries: Vec<LedgerEntry>,
    pub whitelisted_usdt_contracts: HashMap<PaymentChain, String>,
    pub chain_blocks: HashMap<(PaymentChain, u64), BlockHeaderRecord>,
    pub dust_threshold_atomic: u128,
}

impl SovereignPaymentGateway {
    pub fn new(watch_only_xpub: &str) -> Self {
        let mut whitelist = HashMap::new();
        whitelist.insert(
            PaymentChain::EthereumMainnet,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
        );
        whitelist.insert(
            PaymentChain::BnbSmartChain,
            "0x55d398326f99059ff775485246999027b3197955".to_string(),
        );
        whitelist.insert(
            PaymentChain::TronMainnet,
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".to_string(),
        );

        Self {
            watch_only_xpub: watch_only_xpub.trim().to_string(),
            next_derivation_index: 0,
            next_invoice_id: 1001,
            invoices: HashMap::new(),
            address_to_invoice: HashMap::new(),
            processed_txs: HashSet::new(),
            ledger_entries: Vec::new(),
            whitelisted_usdt_contracts: whitelist,
            chain_blocks: HashMap::new(),
            dust_threshold_atomic: 100,
        }
    }

    /// Watch-only xpub থেকে প্রতিটি ইনভয়েসের জন্য ইউনিক ডিপোজিট অ্যাড্রেস ডেরিভেশন (প্রাইভেট কি ছাড়া)
    pub fn derive_watch_only_address(&self, chain: PaymentChain, index: u32) -> String {
        let seed_str = format!("{}:{:?}:{}", self.watch_only_xpub, chain, index);
        let mut h: u64 = 0xcbf29ce484222325;
        for b in seed_str.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        match chain {
            PaymentChain::BitcoinMainnet => format!("bc1q{:016x}{:08x}eqx", h, index),
            PaymentChain::EthereumMainnet | PaymentChain::BnbSmartChain => {
                format!("0x{:016x}{:016x}{:08x}", h, h.rotate_left(17), index)
            }
            PaymentChain::TronMainnet => format!("T{:016X}{:08X}EQX", h, index),
            PaymentChain::EquinoxNative => format!("E{:016X}{:08X}VLT", h, index),
        }
    }

    /// ধাপ ৫.২: নতুন Pending ইনভয়েস তৈরি (প্রতি ইনভয়েসে আলাদা অ্যাড্রেস ও ৩০ মিনিট মেয়াদ)
    pub fn create_invoice(
        &mut self,
        user_id: &str,
        chain: PaymentChain,
        asset: AssetKind,
        requested_amount_atomic: u128,
        current_unix_time: u64,
        ttl_seconds: u64,
    ) -> Result<Invoice, String> {
        if user_id.trim().is_empty() || requested_amount_atomic <= self.dust_threshold_atomic {
            return Err("Invalid user or amount below dust threshold".to_string());
        }

        let idx = self.next_derivation_index;
        self.next_derivation_index = self.next_derivation_index.saturating_add(1);

        let unique_addr = self.derive_watch_only_address(chain, idx);
        let inv_id = self.next_invoice_id;
        self.next_invoice_id = self.next_invoice_id.saturating_add(1);

        let invoice = Invoice {
            invoice_id: inv_id,
            user_id: user_id.trim().to_string(),
            chain,
            asset,
            derivation_index: idx,
            unique_deposit_address: unique_addr.clone(),
            requested_amount_atomic,
            actual_received_atomic: 0,
            expires_at_unix: current_unix_time.saturating_add(ttl_seconds),
            state: InvoiceState::Pending,
            linked_tx_hash: None,
        };

        self.address_to_invoice.insert(unique_addr, inv_id);
        self.invoices.insert(inv_id, invoice.clone());
        Ok(invoice)
    }

    /// ধাপ ৫.৩: ব্লকচেইন রিঅর্গ (Reorg) শনাক্তকরণ এবং প্রভাবিত ইনভয়েস রোলব্যাক
    pub fn record_block_and_check_reorg(
        &mut self,
        chain: PaymentChain,
        height: u64,
        block_hash: &str,
        parent_hash: &str,
    ) -> Result<(), String> {
        if height > 0 {
            if let Some(prev) = self.chain_blocks.get(&(chain, height - 1)) {
                if prev.block_hash != parent_hash {
                    // Reorg detected! Rollback any Confirming invoices on this chain
                    for inv in self.invoices.values_mut() {
                        if inv.chain == chain && matches!(inv.state, InvoiceState::Confirming { .. } | InvoiceState::Detected) {
                            inv.state = InvoiceState::Reorged;
                        }
                    }
                    return Err(format!("Chain Reorg Detected at height {}!", height));
                }
            }
        }
        self.chain_blocks.insert(
            (chain, height),
            BlockHeaderRecord {
                height,
                block_hash: block_hash.to_string(),
                parent_hash: parent_hash.to_string(),
            },
        );
        Ok(())
    }

    /// ধাপ ৫.২ ও ৮: অন-চেইন ট্রানজ্যাকশন প্রসেস, ফেক টোকেন ব্লক, RBF ব্লক এবং ডবল-এন্ট্রি লেজার সেটেলমেন্ট
    pub fn process_on_chain_event(&mut self, ev: OnChainTransferEvent) -> Result<InvoiceState, String> {
        // ১. ডাস্ট অ্যাটাক (Dust Attack) প্রতিরোধ
        if ev.actual_amount_atomic <= self.dust_threshold_atomic {
            return Err("Dust transfer ignored".to_string());
        }

        // ২. ব্লক রিঅর্গ চেক
        self.record_block_and_check_reorg(ev.chain, ev.block_height, &ev.block_hash, &ev.parent_hash)?;

        // ৩. ইউনিক ডিপোজিট অ্যাড্রেস থেকে ইনভয়েস খুঁজে বের করা
        let inv_id = *self.address_to_invoice.get(&ev.to_address)
            .ok_or_else(|| "Unknown deposit address".to_string())?;

        let tx_key = ProcessedTxKey {
            chain: ev.chain,
            tx_hash: ev.tx_hash.trim().to_lowercase(),
            log_index: ev.log_index,
        };

        // ৪. ডুপ্লিকেট ক্রেডিট / রিপ্লে অ্যাটাক প্রতিরোধ (processed_txs UNIQUE)
        if self.processed_txs.contains(&tx_key) {
            return Err("Duplicate transaction event ignored (Idempotency Guard)".to_string());
        }

        let required_conf = ev.chain.required_confirmations();
        let expected_usdt_contract = self.whitelisted_usdt_contracts.get(&ev.chain).cloned();

        let inv = self.invoices.get_mut(&inv_id).ok_or("Invoice missing")?;

        // ৫. মেয়াদোত্তীর্ণ ইনভয়েস চেক
        if inv.state == InvoiceState::Pending && ev.current_unix_time > inv.expires_at_unix {
            inv.state = InvoiceState::Expired;
            return Ok(InvoiceState::Expired);
        }

        // ৬. নকল USDT টোকেন কন্ট্রাক্ট প্রতিরোধ (Contract Whitelist Check)
        if inv.asset == AssetKind::UsdtToken {
            let valid_contract = expected_usdt_contract
                .ok_or_else(|| "USDT not supported on this chain".to_string())?;
            let actual_contract = ev.token_contract.as_deref().unwrap_or("");
            if !actual_contract.eq_ignore_ascii_case(&valid_contract) {
                return Err("Fake token contract rejected by whitelist!".to_string());
            }
        }

        // ৭. বিটকয়েন RBF (Replace-By-Fee) ০-কনফার্মেশন প্রতিরোধ
        if ev.chain == PaymentChain::BitcoinMainnet && ev.is_rbf_replaceable && ev.confirmations == 0 {
            inv.state = InvoiceState::Detected;
            return Err("Unconfirmed RBF transaction held until block confirmation".to_string());
        }

        inv.linked_tx_hash = Some(ev.tx_hash.clone());
        inv.actual_received_atomic = ev.actual_amount_atomic;

        // ৮. কনফার্মেশন ডেপথ যাচাই
        if ev.confirmations == 0 {
            inv.state = InvoiceState::Detected;
            return Ok(inv.state);
        }
        if ev.confirmations < required_conf {
            inv.state = InvoiceState::Confirming {
                current_confirmations: ev.confirmations,
                required: required_conf,
            };
            return Ok(inv.state);
        }

        // ৯. Partial (কম পেমেন্ট) বা Overpaid হ্যান্ডলিং (Fail-Closed নীতি)
        if ev.actual_amount_atomic < inv.requested_amount_atomic {
            inv.state = InvoiceState::PartiallyPaid;
            return Ok(InvoiceState::PartiallyPaid);
        }

        let final_state = if ev.actual_amount_atomic > inv.requested_amount_atomic {
            InvoiceState::Overpaid
        } else {
            InvoiceState::Settled
        };

        // ১০. অ্যাটমিক সেটেলমেন্ট: processed_txs ইনসার্ট + Append-Only Double-Entry Ledger
        self.processed_txs.insert(tx_key);
        inv.state = final_state;

        let entry_id = (self.ledger_entries.len() as u64) + 1;
        self.ledger_entries.push(LedgerEntry {
            entry_id,
            invoice_id: inv.invoice_id,
            user_id: inv.user_id.clone(),
            chain: inv.chain,
            debit_account: format!("CHAIN_VAULT::{:?}", inv.chain),
            credit_account: format!("USER_LEDGER::{}", inv.user_id),
            // সবসময় চেইনে আসা আসল অ্যামাউন্ট ক্রেডিট হবে
            amount_atomic: ev.actual_amount_atomic,
            tx_hash: ev.tx_hash,
        });

        Ok(final_state)
    }

    /// ধাপ ৬: ইউজারের ব্যালেন্স সবসময় অ্যাপেন্ড-অনলি লেজার এন্ট্রির যোগফল থেকে আসবে
    pub fn get_user_ledger_balance(&self, user_id: &str, chain: PaymentChain) -> u128 {
        let target_acc = format!("USER_LEDGER::{}", user_id.trim());
        self.ledger_entries
            .iter()
            .filter(|e| e.chain == chain && e.credit_account == target_acc)
            .map(|e| e.amount_atomic)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_xpub_invoice_and_strict_settlement() {
        let mut gw = SovereignPaymentGateway::new("xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz");

        let inv1 = gw.create_invoice("user_alice", PaymentChain::BnbSmartChain, AssetKind::UsdtToken, 500_00, 1_700_000_000, 1800).unwrap();
        let inv2 = gw.create_invoice("user_alice", PaymentChain::BnbSmartChain, AssetKind::UsdtToken, 500_00, 1_700_000_000, 1800).unwrap();

        // প্রতি ইনভয়েসে আলাদা ইউনিক ডিপোজিট অ্যাড্রেস তৈরি হতে হবে
        assert_ne!(inv1.unique_deposit_address, inv2.unique_deposit_address);
        assert_eq!(gw.get_user_ledger_balance("user_alice", PaymentChain::BnbSmartChain), 0);

        // ১. নকল টোকেন কন্ট্রাক্ট দিয়ে ডিপোজিট পাঠালে সাথে সাথে ব্লক হবে
        let fake_token_ev = OnChainTransferEvent {
            chain: PaymentChain::BnbSmartChain,
            tx_hash: "0x11112222333344445555666677778888".to_string(),
            log_index: 0,
            to_address: inv1.unique_deposit_address.clone(),
            token_contract: Some("0xDeadBeefFakeUsdtContract000000000000".to_string()),
            actual_amount_atomic: 500_00,
            confirmations: 15,
            is_rbf_replaceable: false,
            block_height: 100,
            block_hash: "0xblock100".to_string(),
            parent_hash: "0xblock099".to_string(),
            current_unix_time: 1_700_000_100,
        };
        assert!(gw.process_on_chain_event(fake_token_ev).is_err());
        assert_eq!(gw.get_user_ledger_balance("user_alice", PaymentChain::BnbSmartChain), 0);

        // ২. আসল অফিশিয়াল USDT কন্ট্রাক্টে ৩ কনফার্মেশন এলে স্ট্যাটাস হবে Confirming (ব্যালেন্স তখনো ০ থাকবে)
        let confirming_ev = OnChainTransferEvent {
            chain: PaymentChain::BnbSmartChain,
            tx_hash: "0xaaaa2222333344445555666677778888".to_string(),
            log_index: 1,
            to_address: inv1.unique_deposit_address.clone(),
            token_contract: Some("0x55d398326f99059ff775485246999027b3197955".to_string()),
            actual_amount_atomic: 500_00,
            confirmations: 3,
            is_rbf_replaceable: false,
            block_height: 100,
            block_hash: "0xblock100".to_string(),
            parent_hash: "0xblock099".to_string(),
            current_unix_time: 1_700_000_200,
        };
        let st = gw.process_on_chain_event(confirming_ev.clone()).unwrap();
        assert_eq!(st, InvoiceState::Confirming { current_confirmations: 3, required: 15 });
        assert_eq!(gw.get_user_ledger_balance("user_alice", PaymentChain::BnbSmartChain), 0);

        // ৩. ১৫ কনফার্মেশন পূর্ণ হলে Settled হবে এবং লেজারে ব্যালেন্স যুক্ত হবে
        let mut settled_ev = confirming_ev;
        settled_ev.confirmations = 15;
        let st_final = gw.process_on_chain_event(settled_ev.clone()).unwrap();
        assert_eq!(st_final, InvoiceState::Settled);
        assert_eq!(gw.get_user_ledger_balance("user_alice", PaymentChain::BnbSmartChain), 500_00);

        // ৪. একই ট্রানজ্যাকশন দ্বিতীয়বার পাঠালে (Replay Attack) ব্লক হবে
        assert!(gw.process_on_chain_event(settled_ev).is_err());
        assert_eq!(gw.get_user_ledger_balance("user_alice", PaymentChain::BnbSmartChain), 500_00);
    }
}
