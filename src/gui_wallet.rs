#![allow(dead_code)]
// src/gui_wallet.rs
// Equinox (EQX) L1 — Audit-Grade Super-App GUI Wallet State Controller,
// Zero-Float 8-Decimal Parser, Block & Tokenomics Explorer, and AMM DEX Swap Interface.

use crate::config::{CHAIN_ID, COIN, MAX_SUPPLY, MIN_RELAY_TX_FEE, SYMBOL, TOKEN_NAME};
use crate::consensus::tokenomics::{SupplyReport, TokenomicsEngine};
use crate::crypto::hash::Hash256;
use crate::dex::LiquidityPool;
use crate::primitives::transaction::{Transaction, TxInput, TxOutput};
use crate::rpc_server::{RpcServer, RpcSharedState};
use crate::state::coin_selection::CoinSelection;
use crate::wallet::address::is_valid_address;
use crate::wallet::manager::WalletManager;
use crate::wallet::signer::OfflineSigner;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActiveGuiTab {
    Dashboard,
    SendAndReceive,
    DexSwap,
    BlockExplorer,
    SecurityVault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletDashboardView {
    pub token_name: String,
    pub symbol: String,
    pub chain_id: u64,
    pub primary_address: String,
    pub change_address: String,
    pub spendable_atomic: u64,
    pub locked_atomic: u64,
    pub spendable_formatted: String,
    pub locked_formatted: String,
    pub utxo_note_count: usize,
    pub best_block_height: u64,
    pub finalized_height: u64,
    pub mempool_pending_txs: usize,
    pub active_peers: usize,
}

pub struct GuiWalletApp {
    pub active_tab: ActiveGuiTab,
    pub wallet_file_path: PathBuf,
    wallet_manager: Option<WalletManager>,
    pub shared_node_state: Arc<Mutex<RpcSharedState>>,
    pub dex_pool: LiquidityPool,
    pub password_input: String,
    pub recovery_mnemonic_input: String,
    pub recipient_address_input: String,
    pub send_amount_input: String,
    pub custom_fee_input: String,
    pub explorer_height_input: String,
    pub dex_input_token: String,
    pub dex_input_amount: String,
    pub dex_min_output_amount: String,
    pub status_message: String,
    pub last_broadcast_txid: Option<String>,
    pub latest_supply_report: SupplyReport,
}

impl GuiWalletApp {
    pub fn new<P: AsRef<Path>>(
        wallet_file_path: P,
        shared_node_state: Arc<Mutex<RpcSharedState>>,
    ) -> Self {
        let initial_height = shared_node_state
            .lock()
            .map(|s| s.best_height)
            .unwrap_or(0);

        let mut default_pool = LiquidityPool::new(SYMBOL.to_string(), "USDT".to_string());
        let _ = default_pool.add_initial_liquidity(
            "GENESIS_LP_VAULT",
            100_000 * (COIN as u128),
            500_000 * (COIN as u128),
        );

        Self {
            active_tab: ActiveGuiTab::Dashboard,
            wallet_file_path: wallet_file_path.as_ref().to_path_buf(),
            wallet_manager: None,
            shared_node_state,
            dex_pool: default_pool,
            password_input: String::new(),
            recovery_mnemonic_input: String::new(),
            recipient_address_input: String::new(),
            send_amount_input: String::new(),
            custom_fee_input: RpcServer::format_atomic_to_eqx(MIN_RELAY_TX_FEE),
            explorer_height_input: initial_height.to_string(),
            dex_input_token: SYMBOL.to_string(),
            dex_input_amount: String::new(),
            dex_min_output_amount: String::new(),
            status_message: "ওয়ালেট লক করা আছে। পাসওয়ার্ড দিয়ে আনলক বা নতুন ওয়ালেট তৈরি করুন।".to_string(),
            last_broadcast_txid: None,
            latest_supply_report: TokenomicsEngine::get_supply_report_at_height(initial_height),
        }
    }

    pub fn parse_eqx_to_atomic(input: &str) -> Result<u64, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("কয়েনের পরিমাণ খালি রাখা যাবে না".to_string());
        }
        if trimmed.starts_with('-') || trimmed.starts_with('+') {
            return Err("অ্যামাউন্টে চিহ্ন ব্যবহার করা যাবে না".to_string());
        }

        let mut parts = trimmed.split('.');
        let whole_str = parts.next().unwrap_or("0");
        let frac_str = parts.next();

        if parts.next().is_some() {
            return Err("অবৈধ দশমিক ফরম্যাট: একাধিক দশমিক বিন্দু দেওয়া হয়েছে".to_string());
        }
        if whole_str.is_empty() || !whole_str.chars().all(|c| c.is_ascii_digit()) {
            return Err("পূর্ণসংখ্যা অংশে শুধুমাত্র ইংরেজি সংখ্যা থাকতে হবে".to_string());
        }

        let whole_units: u128 = whole_str
            .parse::<u128>()
            .map_err(|_| "পূর্ণসংখ্যা অংশ সীমার বাইরে".to_string())?;

        let frac_units: u128 = match frac_str {
            None => 0,
            Some(f) => {
                if f.is_empty() || !f.chars().all(|c| c.is_ascii_digit()) {
                    return Err("দশমিকের পরের অংশে শুধুমাত্র সংখ্যা থাকতে হবে".to_string());
                }
                if f.len() > 8 {
                    return Err("সর্বোচ্চ ৮ ঘর দশমিক পর্যন্ত অনুমোদিত".to_string());
                }
                let padded = format!("{:0<8}", f);
                padded
                    .parse::<u128>()
                    .map_err(|_| "দশমিক অংশ পার্স করা যায়নি".to_string())?
            }
        };

        let total_atomic = whole_units
            .checked_mul(COIN as u128)
            .and_then(|w| w.checked_add(frac_units))
            .ok_or_else(|| "কয়েনের পরিমাণে গাণিতিক ওভারফ্লো হয়েছে".to_string())?;

        if total_atomic == 0 {
            return Err("কয়েনের পরিমাণ শূন্য হতে পারবে না".to_string());
        }
        if total_atomic > (MAX_SUPPLY as u128) {
            return Err("কয়েনের পরিমাণ ২১ মিলিয়ন সর্বোচ্চ সাপ্লাই সীমার বাইরে".to_string());
        }

        Ok(total_atomic as u64)
    }

    pub fn action_create_wallet_12(&mut self) -> Result<String, String> {
        let pass_copy = self.password_input.clone();
        self.password_input.zeroize();
        self.password_input.clear();

        let res = WalletManager::create_new(&self.wallet_file_path, &pass_copy);
        let mut zero_pass = pass_copy;
        zero_pass.zeroize();

        match res {
            Ok((manager, phrase)) => {
                self.wallet_manager = Some(manager);
                self.status_message = "নতুন ১২-শব্দের ওয়ালেট সফলভাবে তৈরি হয়েছে!".to_string();
                Ok(phrase)
            }
            Err(e) => {
                self.status_message = format!("ওয়ালেট তৈরি ব্যর্থ: {}", e);
                Err(e)
            }
        }
    }

    pub fn action_create_wallet_24(&mut self) -> Result<String, String> {
        let pass_copy = self.password_input.clone();
        self.password_input.zeroize();
        self.password_input.clear();

        let res = WalletManager::create_new_24_words(&self.wallet_file_path, &pass_copy);
        let mut zero_pass = pass_copy;
        zero_pass.zeroize();

        match res {
            Ok((manager, phrase)) => {
                self.wallet_manager = Some(manager);
                self.status_message = "নতুন ২৪-শব্দের ওয়ালেট সফলভাবে তৈরি হয়েছে!".to_string();
                Ok(phrase)
            }
            Err(e) => {
                self.status_message = format!("ওয়ালেট তৈরি ব্যর্থ: {}", e);
                Err(e)
            }
        }
    }

    pub fn action_unlock_wallet(&mut self) -> Result<(), String> {
        let pass_copy = self.password_input.clone();
        self.password_input.zeroize();
        self.password_input.clear();

        let res = WalletManager::load_from_file(&self.wallet_file_path, &pass_copy);
        let mut zero_pass = pass_copy;
        zero_pass.zeroize();

        match res {
            Ok(manager) => {
                self.wallet_manager = Some(manager);
                self.status_message = "ওয়ালেট সফলভাবে আনলক করা হয়েছে।".to_string();
                Ok(())
            }
            Err(e) => {
                self.status_message = format!("ওয়ালেট আনলক ব্যর্থ: {}", e);
                Err(e)
            }
        }
    }

    pub fn action_recover_wallet(&mut self) -> Result<(), String> {
        let pass_copy = self.password_input.clone();
        let phrase_copy = self.recovery_mnemonic_input.clone();

        self.password_input.zeroize();
        self.password_input.clear();
        self.recovery_mnemonic_input.zeroize();
        self.recovery_mnemonic_input.clear();

        let res =
            WalletManager::recover_from_mnemonic(&phrase_copy, &self.wallet_file_path, &pass_copy);

        let mut zero_pass = pass_copy;
        let mut zero_phrase = phrase_copy;
        zero_pass.zeroize();
        zero_phrase.zeroize();

        match res {
            Ok(mut manager) => {
                manager.scrub_mnemonic_from_ram();
                self.wallet_manager = Some(manager);
                self.status_message = "সিড ফ্রেজ থেকে ওয়ালেট রিকভার করা হয়েছে!".to_string();
                Ok(())
            }
            Err(e) => {
                self.status_message = format!("ওয়ালেট রিকভারি ব্যর্থ: {}", e);
                Err(e)
            }
        }
    }

    pub fn acknowledge_and_scrub_seed(&mut self) {
        if let Some(manager) = &mut self.wallet_manager {
            manager.scrub_mnemonic_from_ram();
            self.status_message = "র‍্যাম থেকে সিড ফ্রেজ মুছে ফেলা হয়েছে।".to_string();
        }
    }

    pub fn lock_wallet(&mut self) {
        self.wallet_manager = None;
        self.password_input.zeroize();
        self.password_input.clear();
        self.recovery_mnemonic_input.zeroize();
        self.recovery_mnemonic_input.clear();
        self.status_message = "ওয়ালেট নিরাপদে লক করা হয়েছে।".to_string();
    }

    #[inline]
    pub fn is_unlocked(&self) -> bool {
        self.wallet_manager.is_some()
    }

    pub fn get_dashboard_view(&self) -> Result<WalletDashboardView, String> {
        let manager = self
            .wallet_manager
            .as_ref()
            .ok_or_else(|| "ওয়ালেট আনলক করা নেই".to_string())?;

        let primary_address = manager.get_address(0, 0)?;
        let change_address = manager.get_change_address(0, 0)?;

        let state = self
            .shared_node_state
            .lock()
            .map_err(|_| "নোড স্টেট লক ত্রুটি".to_string())?;

        let (spendable_atomic, locked_atomic, utxo_note_count) = state
            .utxo_set
            .get_balance_with_count(&primary_address, state.best_height);

        Ok(WalletDashboardView {
            token_name: TOKEN_NAME.to_string(),
            symbol: SYMBOL.to_string(),
            chain_id: CHAIN_ID,
            primary_address,
            change_address,
            spendable_atomic,
            locked_atomic,
            spendable_formatted: RpcServer::format_atomic_to_eqx(spendable_atomic),
            locked_formatted: RpcServer::format_atomic_to_eqx(locked_atomic),
            utxo_note_count,
            best_block_height: state.best_height,
            finalized_height: state.finalized_height,
            mempool_pending_txs: state.mempool.len(),
            active_peers: state.peer_count,
        })
    }

    pub fn send_eqx_transaction(&mut self) -> Result<Hash256, String> {
        let manager = self
            .wallet_manager
            .as_ref()
            .ok_or_else(|| "ট্রানজ্যাকশন পাঠাতে আগে ওয়ালেট আনলক করুন".to_string())?;

        let recipient = self.recipient_address_input.trim().to_string();
        if !is_valid_address(&recipient) {
            return Err(format!("প্রাপকের ওয়ালেট অ্যাড্রেস বৈধ নয়: {}", recipient));
        }

        let target_amount = Self::parse_eqx_to_atomic(&self.send_amount_input)?;
        let base_fee = if self.custom_fee_input.trim().is_empty() {
            MIN_RELAY_TX_FEE
        } else {
            Self::parse_eqx_to_atomic(&self.custom_fee_input)?
        };

        if base_fee < MIN_RELAY_TX_FEE {
            return Err(format!(
                "ন্যূনতম নেটওয়ার্ক ফি {} EQX হতে হবে",
                RpcServer::format_atomic_to_eqx(MIN_RELAY_TX_FEE)
            ));
        }

        let sender_kp = manager.get_keypair(0, 0)?;
        let sender_pubkey = sender_kp.public_key();
        let sender_address = manager.get_address(0, 0)?;

        let mut state = self
            .shared_node_state
            .lock()
            .map_err(|_| "নোড স্টেট লক ত্রুটি".to_string())?;

        let selection = CoinSelection::select_coins_detailed(
            &state.utxo_set.utxos,
            &sender_address,
            target_amount,
            base_fee,
            state.best_height,
        )?;

        let inputs: Vec<TxInput> = selection
            .selected_coins
            .iter()
            .map(|(op, _)| TxInput::new(op.clone(), sender_pubkey))
            .collect();

        let mut outputs = vec![TxOutput::new(target_amount, recipient)];
        if selection.change_amount > 0 {
            outputs.push(TxOutput::new(selection.change_amount, sender_address));
        }

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_729_468_800);

        let mut tx = Transaction::new(inputs, outputs, now_ts, selection.effective_fee);

        let mut raw_secret = sender_kp.secret_bytes();
        let sign_res = OfflineSigner::sign_all_inputs(&mut tx, &raw_secret);
        raw_secret.zeroize();
        sign_res?;

        let utxo_snapshot = state.utxo_set.clone();
        let current_height = state.best_height;
        let txid = state
            .mempool
            .add_transaction_verified(tx, &utxo_snapshot, current_height)?;

        let txid_hex = hex::encode(txid);
        self.last_broadcast_txid = Some(txid_hex.clone());
        self.send_amount_input.clear();
        self.status_message = format!("ট্রানজ্যাকশন মেমপুলে ব্রডকাস্ট হয়েছে! TxID: {}", txid_hex);

        Ok(txid)
    }

    pub fn query_explorer_supply_report(&mut self) -> Result<SupplyReport, String> {
        let height: u64 = self
            .explorer_height_input
            .trim()
            .parse()
            .map_err(|_| "ব্লক হাইট পূর্ণসংখ্যা হতে হবে".to_string())?;

        let report = TokenomicsEngine::get_supply_report_at_height(height);
        self.latest_supply_report = report;
        self.status_message = format!("ব্লক #{} এর সাপ্লাই রিপোর্ট লোড হয়েছে।", height);
        Ok(report)
    }

    pub fn execute_dex_swap(&mut self) -> Result<u128, String> {
        let amount_in = Self::parse_eqx_to_atomic(&self.dex_input_amount)? as u128;
        let min_out = if self.dex_min_output_amount.trim().is_empty() {
            1
        } else {
            Self::parse_eqx_to_atomic(&self.dex_min_output_amount)? as u128
        };

        let token_in = self.dex_input_token.trim().to_string();
        let out_amount = self.dex_pool.swap(&token_in, amount_in, min_out)?;

        self.dex_input_amount.clear();
        self.status_message = format!(
            "DEX সোয়াপ সফল! আউটপুট: {}",
            RpcServer::format_atomic_to_eqx(out_amount as u64)
        );
        Ok(out_amount)
    }
}
