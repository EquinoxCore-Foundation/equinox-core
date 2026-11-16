// File: Equinox-Super-Wallet/crates/payment-ledger/src/lib.rs
#![forbid(unsafe_code)]

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// ERC-20 standard Transfer(address indexed from, address indexed to, uint256 value) topic0
pub const ERC20_TRANSFER_TOPIC0: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GatewayLedgerError {
    #[error("SQLite database error: {0}")]
    DatabaseError(String),
    #[error("RPC communication or parse error: {0}")]
    RpcError(String),
    #[error("Transaction failed on-chain (receipt status 0 or VM error)")]
    TransactionFailedOnChain,
    #[error("Untrusted or fake token contract/mint: {0}")]
    UntrustedTokenContract(String),
    #[error("Token decimals mismatch: expected {expected}, got {actual}")]
    DecimalsMismatch { expected: u8, actual: u8 },
    #[error("No matching transfer output found for recipient address {0}")]
    RecipientOutputNotFound(String),
    #[error("Unconfirmed Bitcoin RBF transaction held until block confirmation")]
    UnconfirmedRbfTransaction,
    #[error("Duplicate transaction/event blocked by idempotency key ({chain}:{tx_hash}:{log_index})")]
    DuplicateIdempotencyKey {
        chain: String,
        tx_hash: String,
        log_index: u32,
    },
    #[error("Chain reorg detected at height {height} on {chain}: parent hash mismatch")]
    ChainReorgDetected { chain: String, height: u64 },
    #[error("Invalid address or hex data: {0}")]
    ValidationError(String),
}

impl From<rusqlite::Error> for GatewayLedgerError {
    fn from(e: rusqlite::Error) -> Self {
        GatewayLedgerError::DatabaseError(e.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    BitcoinMainnet,
    EthereumMainnet,
    BnbSmartChain,
    ArbitrumOne,
    PolygonPos,
    SolanaMainnet,
    EquinoxL1,
}

impl ChainId {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainId::BitcoinMainnet => "BTC_MAINNET",
            ChainId::EthereumMainnet => "ETH_MAINNET",
            ChainId::BnbSmartChain => "BSC_MAINNET",
            ChainId::ArbitrumOne => "ARBITRUM_ONE",
            ChainId::PolygonPos => "POLYGON_POS",
            ChainId::SolanaMainnet => "SOLANA_MAINNET",
            ChainId::EquinoxL1 => "EQUINOX_9333",
        }
    }

    pub fn required_finality_confirmations(&self) -> u64 {
        match self {
            ChainId::BitcoinMainnet => 3,
            ChainId::EthereumMainnet => 12,
            ChainId::BnbSmartChain => 15,
            ChainId::ArbitrumOne => 15,
            ChainId::PolygonPos => 30,
            ChainId::SolanaMainnet => 32,
            ChainId::EquinoxL1 => 10,
        }
    }
}

/// ৫টি পৃথক ডিপোজিট স্ট্যাটাস (নির্দেশনা ৫ অনুযায়ী)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    Pending,   // 0 confirmations (seen in mempool, zero balance credit)
    Confirmed, // 1..finality-1 confirmations (in block, awaiting finality depth)
    Finalized, // >= finality confirmations (spendable ledger entry credited)
    Reorged,   // Block invalidated by chain reorganization (credit voided)
    Failed,    // Reverted on-chain (status 0x0 or VM error)
}

impl DepositStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DepositStatus::Pending => "PENDING",
            DepositStatus::Confirmed => "CONFIRMED",
            DepositStatus::Finalized => "FINALIZED",
            DepositStatus::Reorged => "REORGED",
            DepositStatus::Failed => "FAILED",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "PENDING" => DepositStatus::Pending,
            "CONFIRMED" => DepositStatus::Confirmed,
            "FINALIZED" => DepositStatus::Finalized,
            "REORGED" => DepositStatus::Reorged,
            _ => DepositStatus::Failed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenWhitelistConfig {
    pub chain: ChainId,
    pub asset_symbol: String,
    pub contract_or_mint: String,
    pub expected_decimals: u8,
}

/// অন-চেইন RPC থেকে যাচাইকৃত ডিপোজিট ইভেন্ট
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedDepositEvent {
    pub chain: ChainId,
    pub user_id: String,
    pub asset_symbol: String,
    pub tx_hash: String,
    pub log_index: u32,
    pub recipient_address: String,
    pub token_contract: String,
    pub decimals: u8,
    pub amount_atomic: u128,
    pub block_height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub confirmations: u64,
    pub on_chain_succeeded: bool,
    pub observed_at_unix: u64,
}

// ============================================================================
// MODULE 4: MULTI-CHAIN ON-CHAIN RECEIPT & EVENT VERIFIER
// ============================================================================

#[derive(Clone, Debug, Deserialize)]
pub struct EvmRpcLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(rename = "logIndex")]
    pub log_index_hex: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EvmTransactionReceipt {
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    pub status: String,
    #[serde(rename = "blockNumber")]
    pub block_number_hex: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    pub logs: Vec<EvmRpcLog>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcVin {
    pub sequence: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcVout {
    pub value: u64,
    pub scriptpubkey_address: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcTransaction {
    pub txid: String,
    pub vin: Vec<BtcVin>,
    pub vout: Vec<BtcVout>,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SolanaTokenBalance {
    pub owner: String,
    pub mint: String,
    pub decimals: u8,
    pub amount_atomic: u128,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SolanaTransactionMeta {
    pub signature: String,
    pub has_error: bool,
    pub slot: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub confirmations: u64,
    pub pre_token_balances: Vec<SolanaTokenBalance>,
    pub post_token_balances: Vec<SolanaTokenBalance>,
}

pub struct MultiChainReceiptVerifier {
    whitelisted_tokens: HashMap<(ChainId, String), TokenWhitelistConfig>,
}

impl MultiChainReceiptVerifier {
    pub fn new_with_official_usdt_whitelist() -> Self {
        let mut map = HashMap::new();
        let defaults = [
            TokenWhitelistConfig {
                chain: ChainId::EthereumMainnet,
                asset_symbol: "USDT".into(),
                contract_or_mint: "0xdac17f958d2ee523a2206206994597c13d831ec7".into(),
                expected_decimals: 6,
            },
            TokenWhitelistConfig {
                chain: ChainId::BnbSmartChain,
                asset_symbol: "USDT".into(),
                contract_or_mint: "0x55d398326f99059ff775485246999027b3197955".into(),
                expected_decimals: 18,
            },
            TokenWhitelistConfig {
                chain: ChainId::ArbitrumOne,
                asset_symbol: "USDT".into(),
                contract_or_mint: "0xfd086bcc7cd5c481dcc9c85ebe478a1c0b69fcbb".into(),
                expected_decimals: 6,
            },
            TokenWhitelistConfig {
                chain: ChainId::PolygonPos,
                asset_symbol: "USDT".into(),
                contract_or_mint: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f".into(),
                expected_decimals: 6,
            },
            TokenWhitelistConfig {
                chain: ChainId::SolanaMainnet,
                asset_symbol: "USDT".into(),
                contract_or_mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".into(),
                expected_decimals: 6,
            },
        ];

        for cfg in defaults {
            map.insert((cfg.chain, cfg.asset_symbol.clone()), cfg);
        }
        Self {
            whitelisted_tokens: map,
        }
    }

    fn parse_hex_u64(hex_str: &str) -> Result<u64, GatewayLedgerError> {
        let clean = hex_str.trim().trim_start_matches("0x");
        u64::from_str_radix(clean, 16)
            .map_err(|e| GatewayLedgerError::ValidationError(e.to_string()))
    }

    fn parse_hex_u128_256bit(hex_str: &str) -> Result<u128, GatewayLedgerError> {
        let clean = hex_str.trim().trim_start_matches("0x");
        if clean.is_empty() || clean.len() > 64 {
            return Err(GatewayLedgerError::ValidationError(
                "Invalid uint256 hex length".into(),
            ));
        }
        let padded = format!("{:0>64}", clean);
        // Ensure top 16 bytes are zero so it fits safely in u128
        if u128::from_str_radix(&padded[0..32], 16).unwrap_or(1) != 0 {
            return Err(GatewayLedgerError::ValidationError(
                "uint256 overflows u128".into(),
            ));
        }
        u128::from_str_radix(&padded[32..64], 16)
            .map_err(|e| GatewayLedgerError::ValidationError(e.to_string()))
    }

    /// 4.1: EVM ERC-20 Token Deposit Verification (Receipt Status, Contract, Transfer Topic, Recipient, Amount, Decimals)
    pub fn verify_evm_erc20_receipt(
        &self,
        chain: ChainId,
        user_id: &str,
        asset_symbol: &str,
        expected_recipient: &str,
        reported_token_decimals: u8,
        receipt: &EvmTransactionReceipt,
        parent_block_hash: &str,
        latest_chain_height: u64,
        observed_at_unix: u64,
    ) -> Result<VerifiedDepositEvent, GatewayLedgerError> {
        let wl = self
            .whitelisted_tokens
            .get(&(chain, asset_symbol.to_string()))
            .ok_or_else(|| GatewayLedgerError::UntrustedTokenContract(asset_symbol.into()))?;

        if reported_token_decimals != wl.expected_decimals {
            return Err(GatewayLedgerError::DecimalsMismatch {
                expected: wl.expected_decimals,
                actual: reported_token_decimals,
            });
        }

        let block_height = Self::parse_hex_u64(&receipt.block_number_hex)?;
        let confirmations = if latest_chain_height >= block_height {
            latest_chain_height - block_height + 1
        } else {
            0
        };

        // Check if transaction reverted on-chain (status != 0x1)
        if receipt.status.trim().to_lowercase() != "0x1" {
            return Ok(VerifiedDepositEvent {
                chain,
                user_id: user_id.to_string(),
                asset_symbol: asset_symbol.to_string(),
                tx_hash: receipt.transaction_hash.to_lowercase(),
                log_index: 0,
                recipient_address: expected_recipient.to_lowercase(),
                token_contract: wl.contract_or_mint.clone(),
                decimals: wl.expected_decimals,
                amount_atomic: 0,
                block_height,
                block_hash: receipt.block_hash.to_lowercase(),
                parent_hash: parent_block_hash.to_lowercase(),
                confirmations,
                on_chain_succeeded: false,
                observed_at_unix,
            });
        }

        let clean_recipient = expected_recipient
            .trim()
            .trim_start_matches("0x")
            .to_lowercase();
        if clean_recipient.len() != 40 {
            return Err(GatewayLedgerError::ValidationError(
                "Expected 20-byte EVM recipient address".into(),
            ));
        }
        let expected_topic2 = format!("0x{:0>64}", clean_recipient);

        for log in &receipt.logs {
            let log_contract = log.address.trim().to_lowercase();
            if log_contract != wl.contract_or_mint.to_lowercase() {
                continue;
            }
            if log.topics.len() < 3 {
                continue;
            }
            if log.topics[0].trim().to_lowercase() != ERC20_TRANSFER_TOPIC0 {
                continue;
            }
            if log.topics[2].trim().to_lowercase() != expected_topic2 {
                continue;
            }

            let amount_atomic = Self::parse_hex_u128_256bit(&log.data)?;
            if amount_atomic == 0 {
                continue;
            }
            let log_index = Self::parse_hex_u64(&log.log_index_hex)? as u32;

            return Ok(VerifiedDepositEvent {
                chain,
                user_id: user_id.to_string(),
                asset_symbol: asset_symbol.to_string(),
                tx_hash: receipt.transaction_hash.to_lowercase(),
                log_index,
                recipient_address: expected_recipient.to_string(),
                token_contract: log_contract,
                decimals: wl.expected_decimals,
                amount_atomic,
                block_height,
                block_hash: receipt.block_hash.to_lowercase(),
                parent_hash: parent_block_hash.to_lowercase(),
                confirmations,
                on_chain_succeeded: true,
                observed_at_unix,
            });
        }

        Err(GatewayLedgerError::RecipientOutputNotFound(
            expected_recipient.into(),
        ))
    }

    /// 4.2: Bitcoin Transaction Output & RBF Verification
    pub fn verify_bitcoin_deposit(
        &self,
        user_id: &str,
        expected_deposit_address: &str,
        btc_tx: &BtcTransaction,
        parent_block_hash: &str,
        latest_btc_height: u64,
        observed_at_unix: u64,
    ) -> Result<VerifiedDepositEvent, GatewayLedgerError> {
        let is_rbf_signaled = btc_tx.vin.iter().any(|vin| vin.sequence < 0xffff_fffe);
        let confirmations = match btc_tx.block_height {
            Some(h) if latest_btc_height >= h => latest_btc_height - h + 1,
            _ => 0,
        };

        // Block unconfirmed RBF transactions from being credited
        if confirmations == 0 && is_rbf_signaled {
            return Err(GatewayLedgerError::UnconfirmedRbfTransaction);
        }

        for (vout_idx, out) in btc_tx.vout.iter().enumerate() {
            if out.scriptpubkey_address.as_deref() == Some(expected_deposit_address.trim())
                && out.value > 0
            {
                return Ok(VerifiedDepositEvent {
                    chain: ChainId::BitcoinMainnet,
                    user_id: user_id.to_string(),
                    asset_symbol: "BTC".into(),
                    tx_hash: btc_tx.txid.to_lowercase(),
                    log_index: vout_idx as u32,
                    recipient_address: expected_deposit_address.trim().to_string(),
                    token_contract: "NATIVE_BTC".into(),
                    decimals: 8,
                    amount_atomic: out.value as u128,
                    block_height: btc_tx.block_height.unwrap_or(0),
                    block_hash: btc_tx.block_hash.clone().unwrap_or_default(),
                    parent_hash: parent_block_hash.to_string(),
                    confirmations,
                    on_chain_succeeded: true,
                    observed_at_unix,
                });
            }
        }

        Err(GatewayLedgerError::RecipientOutputNotFound(
            expected_deposit_address.into(),
        ))
    }

    /// 4.3: Solana SPL Token Mint, Owner & Balance Delta Verification
    pub fn verify_solana_spl_deposit(
        &self,
        user_id: &str,
        asset_symbol: &str,
        expected_recipient_owner: &str,
        provided_mint: &str,
        sol_meta: &SolanaTransactionMeta,
        observed_at_unix: u64,
    ) -> Result<VerifiedDepositEvent, GatewayLedgerError> {
        let wl = self
            .whitelisted_tokens
            .get(&(ChainId::SolanaMainnet, asset_symbol.to_string()))
            .ok_or_else(|| GatewayLedgerError::UntrustedTokenContract(asset_symbol.into()))?;

        if provided_mint.trim() != wl.contract_or_mint {
            return Err(GatewayLedgerError::UntrustedTokenContract(
                provided_mint.into(),
            ));
        }

        if sol_meta.has_error {
            return Err(GatewayLedgerError::TransactionFailedOnChain);
        }

        let pre_bal = sol_meta
            .pre_token_balances
            .iter()
            .find(|b| b.owner == expected_recipient_owner && b.mint == wl.contract_or_mint)
            .map(|b| b.amount_atomic)
            .unwrap_or(0);

        let post_entry = sol_meta
            .post_token_balances
            .iter()
            .find(|b| b.owner == expected_recipient_owner && b.mint == wl.contract_or_mint)
            .ok_or_else(|| {
                GatewayLedgerError::RecipientOutputNotFound(expected_recipient_owner.into())
            })?;

        if post_entry.decimals != wl.expected_decimals {
            return Err(GatewayLedgerError::DecimalsMismatch {
                expected: wl.expected_decimals,
                actual: post_entry.decimals,
            });
        }

        if post_entry.amount_atomic <= pre_bal {
            return Err(GatewayLedgerError::RecipientOutputNotFound(
                "Zero or negative SPL token balance delta".into(),
            ));
        }

        let delta = post_entry.amount_atomic - pre_bal;

        Ok(VerifiedDepositEvent {
            chain: ChainId::SolanaMainnet,
            user_id: user_id.to_string(),
            asset_symbol: asset_symbol.to_string(),
            tx_hash: sol_meta.signature.clone(),
            log_index: 0,
            recipient_address: expected_recipient_owner.to_string(),
            token_contract: wl.contract_or_mint.clone(),
            decimals: wl.expected_decimals,
            amount_atomic: delta,
            block_height: sol_meta.slot,
            block_hash: sol_meta.block_hash.clone(),
            parent_hash: sol_meta.parent_hash.clone(),
            confirmations: sol_meta.confirmations,
            on_chain_succeeded: true,
            observed_at_unix,
        })
    }
}

// ============================================================================
// MODULE 5: PERSISTENT SQLITE ACID LEDGER & REORG / REPLAY ENGINE
// ============================================================================

pub struct SqliteAcidPaymentLedger {
    conn: Connection,
}

impl SqliteAcidPaymentLedger {
    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self, GatewayLedgerError> {
        let conn = Connection::open(db_path)?;
        let ledger = Self { conn };
        ledger.init_schema()?;
        Ok(ledger)
    }

    pub fn open_in_memory() -> Result<Self, GatewayLedgerError> {
        let conn = Connection::open_in_memory()?;
        let ledger = Self { conn };
        ledger.init_schema()?;
        Ok(ledger)
    }

    fn init_schema(&self) -> Result<(), GatewayLedgerError> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;

             CREATE TABLE IF NOT EXISTS block_headers (
                 chain TEXT NOT NULL,
                 height INTEGER NOT NULL,
                 block_hash TEXT NOT NULL,
                 parent_hash TEXT NOT NULL,
                 PRIMARY KEY (chain, height)
             );

             CREATE TABLE IF NOT EXISTS deposit_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 chain TEXT NOT NULL,
                 tx_hash TEXT NOT NULL,
                 log_index INTEGER NOT NULL,
                 user_id TEXT NOT NULL,
                 asset_symbol TEXT NOT NULL,
                 recipient_address TEXT NOT NULL,
                 token_contract TEXT NOT NULL,
                 decimals INTEGER NOT NULL,
                 amount_atomic TEXT NOT NULL,
                 block_height INTEGER NOT NULL,
                 block_hash TEXT NOT NULL,
                 confirmations INTEGER NOT NULL,
                 status TEXT NOT NULL,
                 observed_at_unix INTEGER NOT NULL,
                 UNIQUE(chain, tx_hash, log_index)
             );

             CREATE TABLE IF NOT EXISTS ledger_entries (
                 entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id INTEGER NOT NULL UNIQUE,
                 user_id TEXT NOT NULL,
                 chain TEXT NOT NULL,
                 asset_symbol TEXT NOT NULL,
                 direction TEXT NOT NULL,
                 amount_atomic TEXT NOT NULL,
                 created_at_unix INTEGER NOT NULL,
                 FOREIGN KEY(event_id) REFERENCES deposit_events(id)
             );",
        )?;
        Ok(())
    }

    /// অ্যাটমিক ডাটাবেস ট্রানজ্যাকশনে ব্লক রিঅর্গ চেক, আইডেমপোটেন্সি গার্ড এবং স্ট্যাটাস ট্রানজিশন সম্পন্ন করে
    pub fn record_verified_deposit(
        &mut self,
        ev: &VerifiedDepositEvent,
    ) -> Result<DepositStatus, GatewayLedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let chain_str = ev.chain.as_str();

        // 1. Check Parent Block Continuity for Reorg Detection
        if ev.block_height > 0 && !ev.parent_hash.is_empty() {
            let prev_hash_opt: Option<String> = tx
                .query_row(
                    "SELECT block_hash FROM block_headers WHERE chain = ?1 AND height = ?2",
                    params![chain_str, ev.block_height - 1],
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(prev_recorded_hash) = prev_hash_opt {
                if prev_recorded_hash != ev.parent_hash {
                    // Reorg detected! Mark deposits at >= ev.block_height as REORGED and void their ledger credits
                    Self::rollback_reorged_blocks_in_tx(&tx, chain_str, ev.block_height - 1)?;
                    tx.commit()?;
                    return Err(GatewayLedgerError::ChainReorgDetected {
                        chain: chain_str.to_string(),
                        height: ev.block_height,
                    });
                }
            }

            tx.execute(
                "INSERT OR REPLACE INTO block_headers (chain, height, block_hash, parent_hash)
                 VALUES (?1, ?2, ?3, ?4)",
                params![chain_str, ev.block_height, ev.block_hash, ev.parent_hash],
            )?;
        }

        // 2. Determine Target DepositStatus
        let required_conf = ev.chain.required_finality_confirmations();
        let target_status = if !ev.on_chain_succeeded {
            DepositStatus::Failed
        } else if ev.confirmations == 0 {
            DepositStatus::Pending
        } else if ev.confirmations < required_conf {
            DepositStatus::Confirmed
        } else {
            DepositStatus::Finalized
        };

        // 3. Check if Idempotency Key (chain, tx_hash, log_index) already exists
        let existing_row: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, status FROM deposit_events WHERE chain = ?1 AND tx_hash = ?2 AND log_index = ?3",
                params![chain_str, ev.tx_hash, ev.log_index],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let event_db_id: i64 = match existing_row {
            Some((id, current_status_str)) => {
                let current_status = DepositStatus::from_db_str(&current_status_str);
                // Replay / Duplicate Credit Guard: Once FINALIZED, any re-submission is rejected!
                if current_status == DepositStatus::Finalized {
                    return Err(GatewayLedgerError::DuplicateIdempotencyKey {
                        chain: chain_str.to_string(),
                        tx_hash: ev.tx_hash.clone(),
                        log_index: ev.log_index,
                    });
                }

                // Upgrade status (e.g. PENDING -> CONFIRMED -> FINALIZED)
                tx.execute(
                    "UPDATE deposit_events
                     SET confirmations = ?1, block_height = ?2, block_hash = ?3, status = ?4
                     WHERE id = ?5",
                    params![
                        ev.confirmations,
                        ev.block_height,
                        ev.block_hash,
                        target_status.as_str(),
                        id
                    ],
                )?;
                id
            }
            None => {
                tx.execute(
                    "INSERT INTO deposit_events (
                        chain, tx_hash, log_index, user_id, asset_symbol, recipient_address,
                        token_contract, decimals, amount_atomic, block_height, block_hash,
                        confirmations, status, observed_at_unix
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        chain_str,
                        ev.tx_hash,
                        ev.log_index,
                        ev.user_id,
                        ev.asset_symbol,
                        ev.recipient_address,
                        ev.token_contract,
                        ev.decimals,
                        ev.amount_atomic.to_string(),
                        ev.block_height,
                        ev.block_hash,
                        ev.confirmations,
                        target_status.as_str(),
                        ev.observed_at_unix
                    ],
                )?;
                tx.last_insert_rowid()
            }
        };

        // 4. Only credit user ledger when status reaches FINALIZED
        if target_status == DepositStatus::Finalized {
            tx.execute(
                "INSERT INTO ledger_entries (
                    event_id, user_id, chain, asset_symbol, direction, amount_atomic, created_at_unix
                ) VALUES (?1, ?2, ?3, ?4, 'CREDIT', ?5, ?6)",
                params![
                    event_db_id,
                    ev.user_id,
                    chain_str,
                    ev.asset_symbol,
                    ev.amount_atomic.to_string(),
                    ev.observed_at_unix
                ],
            )?;
        }

        tx.commit()?;
        Ok(target_status)
    }

    fn rollback_reorged_blocks_in_tx(
        tx: &rusqlite::Transaction<'_>,
        chain_str: &str,
        fork_height: u64,
    ) -> Result<(), GatewayLedgerError> {
        tx.execute(
            "DELETE FROM ledger_entries WHERE event_id IN (
                SELECT id FROM deposit_events WHERE chain = ?1 AND block_height >= ?2
            )",
            params![chain_str, fork_height],
        )?;

        tx.execute(
            "UPDATE deposit_events SET status = 'REORGED', confirmations = 0
             WHERE chain = ?1 AND block_height >= ?2",
            params![chain_str, fork_height],
        )?;

        tx.execute(
            "DELETE FROM block_headers WHERE chain = ?1 AND height >= ?2",
            params![chain_str, fork_height],
        )?;
        Ok(())
    }

    /// শুধুমাত্র FINALIZED লেজার ক্রেডিটগুলোর যোগফল থেকে ইউজারের খরচযোগ্য ব্যালেন্স রিটার্ন করে
    pub fn get_finalized_user_balance(
        &self,
        user_id: &str,
        chain: ChainId,
        asset_symbol: &str,
    ) -> Result<u128, GatewayLedgerError> {
        let mut stmt = self.conn.prepare(
            "SELECT le.amount_atomic
             FROM ledger_entries le
             INNER JOIN deposit_events de ON le.event_id = de.id
             WHERE le.user_id = ?1 AND le.chain = ?2 AND le.asset_symbol = ?3
               AND de.status = 'FINALIZED' AND le.direction = 'CREDIT'",
        )?;

        let rows = stmt.query_map(
            params![user_id, chain.as_str(), asset_symbol],
            |row| row.get::<_, String>(0),
        )?;

        let mut total: u128 = 0;
        for r in rows {
            let amt_str = r?;
            let val: u128 = amt_str.parse().unwrap_or(0);
            total = total.saturating_add(val);
        }
        Ok(total)
    }

    pub fn get_deposit_status(
        &self,
        chain: ChainId,
        tx_hash: &str,
        log_index: u32,
    ) -> Result<Option<DepositStatus>, GatewayLedgerError> {
        let status_opt: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM deposit_events WHERE chain = ?1 AND tx_hash = ?2 AND log_index = ?3",
                params![chain.as_str(), tx_hash.to_lowercase(), log_index],
                |r| r.get(0),
            )
            .optional()?;
        Ok(status_opt.map(|s| DepositStatus::from_db_str(&s)))
    }
}

// ============================================================================
// MANDATORY TESTS (EVM Receipt, BTC RBF/Vout, Solana Delta, Replay & Reorg)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_erc20_receipt_verification_and_fake_contract_rejection() {
        let verifier = MultiChainReceiptVerifier::new_with_official_usdt_whitelist();
        let recipient = "0x71c7656ec7ab88b098defb751b7401b5f6d8976f";
        let topic_from = "0x0000000000000000000000001111111111111111111111111111111111111111";
        let topic_to = "0x00000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";
        // 500 USDT on BSC (18 decimals) = 500 * 10^18 = 0x1b1ae4d6e2ef500000
        let data_500_usdt = "0x00000000000000000000000000000000000000000000001b1ae4d6e2ef500000";

        let valid_receipt = EvmTransactionReceipt {
            transaction_hash: "0xabc1234567890defabc1234567890defabc1234567890defabc1234567890def".into(),
            status: "0x1".into(),
            block_number_hex: "0x64".into(), // block 100
            block_hash: "0xblock100".into(),
            logs: vec![EvmRpcLog {
                address: "0x55d398326f99059ff775485246999027b3197955".into(),
                topics: vec![
                    ERC20_TRANSFER_TOPIC0.into(),
                    topic_from.into(),
                    topic_to.into(),
                ],
                data: data_500_usdt.into(),
                log_index_hex: "0x2".into(),
            }],
        };

        let verified = verifier
            .verify_evm_erc20_receipt(
                ChainId::BnbSmartChain,
                "user_1",
                "USDT",
                recipient,
                18,
                &valid_receipt,
                "0xblock99",
                115, // 16 confirmations (>= 15 required)
                1_760_000_000,
            )
            .unwrap();

        assert_eq!(verified.amount_atomic, 500_000_000_000_000_000_000u128);
        assert_eq!(verified.log_index, 2);
        assert!(verified.on_chain_succeeded);

        // Wrong decimals must be rejected
        assert!(matches!(
            verifier.verify_evm_erc20_receipt(
                ChainId::BnbSmartChain,
                "user_1",
                "USDT",
                recipient,
                6,
                &valid_receipt,
                "0xblock99",
                115,
                1_760_000_000
            ),
            Err(GatewayLedgerError::DecimalsMismatch { .. })
        ));
    }

    #[test]
    fn test_bitcoin_vout_matching_and_rbf_guard() {
        let verifier = MultiChainReceiptVerifier::new_with_official_usdt_whitelist();
        let dep_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let mut btc_tx = BtcTransaction {
            txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".into(),
            vin: vec![BtcVin {
                sequence: 0xffff_fffd, // Signals RBF
            }],
            vout: vec![
                BtcVout {
                    value: 10_000,
                    scriptpubkey_address: Some("bc1qotherchangeaddress000000000000000000".into()),
                },
                BtcVout {
                    value: 250_000_000, // 2.50 BTC
                    scriptpubkey_address: Some(dep_addr.into()),
                },
            ],
            block_height: None,
            block_hash: None,
        };

        // 0-conf RBF transaction must be blocked
        assert_eq!(
            verifier.verify_bitcoin_deposit("user_btc", dep_addr, &btc_tx, "", 850_000, 100),
            Err(GatewayLedgerError::UnconfirmedRbfTransaction)
        );

        // Once mined with 3 confirmations, it succeeds and records vout index = 1
        btc_tx.block_height = Some(850_000);
        btc_tx.block_hash = Some("00000000000000000002a7c4c1e48d76".into());
        let ev = verifier
            .verify_bitcoin_deposit("user_btc", dep_addr, &btc_tx, "prev_hash", 850_002, 200)
            .unwrap();
        assert_eq!(ev.amount_atomic, 250_000_000);
        assert_eq!(ev.log_index, 1);
        assert_eq!(ev.confirmations, 3);
    }

    #[test]
    fn test_solana_spl_balance_delta_verification() {
        let verifier = MultiChainReceiptVerifier::new_with_official_usdt_whitelist();
        let owner = "7EqxCustomerSolanaVault8823456789ABCDEFGHJKL";
        let usdt_mint = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

        let meta = SolanaTransactionMeta {
            signature: "5SolSigRealVerifiedTransactionHash111111111111111111".into(),
            has_error: false,
            slot: 290_000_000,
            block_hash: "SolBlockHash290M".into(),
            parent_hash: "SolBlockHash289999999".into(),
            confirmations: 32,
            pre_token_balances: vec![SolanaTokenBalance {
                owner: owner.into(),
                mint: usdt_mint.into(),
                decimals: 6,
                amount_atomic: 100_000_000, // 100 USDT before
            }],
            post_token_balances: vec![SolanaTokenBalance {
                owner: owner.into(),
                mint: usdt_mint.into(),
                decimals: 6,
                amount_atomic: 850_000_000, // 850 USDT after (+750 USDT delta)
            }],
        };

        let ev = verifier
            .verify_solana_spl_deposit("user_sol", "USDT", owner, usdt_mint, &meta, 1_760_000_000)
            .unwrap();
        assert_eq!(ev.amount_atomic, 750_000_000);
    }

    #[test]
    fn test_sqlite_acid_idempotency_replay_guard_and_reorg_rollback() {
        let mut ledger = SqliteAcidPaymentLedger::open_in_memory().unwrap();

        // Step 1: Record Block #100 with 3 confirmations (CONFIRMED, not yet FINALIZED for BSC which needs 15)
        let mut ev = VerifiedDepositEvent {
            chain: ChainId::BnbSmartChain,
            user_id: "alice".into(),
            asset_symbol: "USDT".into(),
            tx_hash: "0x9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff".into(),
            log_index: 0,
            recipient_address: "0x71c7656ec7ab88b098defb751b7401b5f6d8976f".into(),
            token_contract: "0x55d398326f99059ff775485246999027b3197955".into(),
            decimals: 18,
            amount_atomic: 1_000_00,
            block_height: 100,
            block_hash: "0xhash100_canon".into(),
            parent_hash: "0xhash99".into(),
            confirmations: 3,
            on_chain_succeeded: true,
            observed_at_unix: 1_760_000_100,
        };

        let st1 = ledger.record_verified_deposit(&ev).unwrap();
        assert_eq!(st1, DepositStatus::Confirmed);
        // Balance must remain 0 until FINALIZED
        assert_eq!(
            ledger
                .get_finalized_user_balance("alice", ChainId::BnbSmartChain, "USDT")
                .unwrap(),
            0
        );

        // Step 2: Upgrade to 15 confirmations -> FINALIZED & credited
        ev.confirmations = 15;
        let st2 = ledger.record_verified_deposit(&ev).unwrap();
        assert_eq!(st2, DepositStatus::Finalized);
        assert_eq!(
            ledger
                .get_finalized_user_balance("alice", ChainId::BnbSmartChain, "USDT")
                .unwrap(),
            1_000_00
        );

        // Step 3: Replay Attack / Duplicate Credit Test -> Must fail with DuplicateIdempotencyKey
        assert!(matches!(
            ledger.record_verified_deposit(&ev),
            Err(GatewayLedgerError::DuplicateIdempotencyKey { .. })
        ));
        assert_eq!(
            ledger
                .get_finalized_user_balance("alice", ChainId::BnbSmartChain, "USDT")
                .unwrap(),
            1_000_00
        );

        // Step 4: Chain Reorg Simulation at Block #101 (parent_hash does NOT match Block #100's 0xhash100_canon)
        let reorg_ev = VerifiedDepositEvent {
            chain: ChainId::BnbSmartChain,
            user_id: "alice".into(),
            asset_symbol: "USDT".into(),
            tx_hash: "0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff".into(),
            log_index: 0,
            recipient_address: "0x71c7656ec7ab88b098defb751b7401b5f6d8976f".into(),
            token_contract: "0x55d398326f99059ff775485246999027b3197955".into(),
            decimals: 18,
            amount_atomic: 500_00,
            block_height: 101,
            block_hash: "0xhash101_fork".into(),
            parent_hash: "0xhash100_ORPHANED_DIFFERENT_BRANCH".into(),
            confirmations: 1,
            on_chain_succeeded: true,
            observed_at_unix: 1_760_000_200,
        };

        assert!(matches!(
            ledger.record_verified_deposit(&reorg_ev),
            Err(GatewayLedgerError::ChainReorgDetected { height: 101, .. })
        ));

        // Verify Block #100 deposit was rolled back to REORGED and balance reverted to 0
        assert_eq!(
            ledger
                .get_deposit_status(ChainId::BnbSmartChain, &ev.tx_hash, 0)
                .unwrap(),
            Some(DepositStatus::Reorged)
        );
        assert_eq!(
            ledger
                .get_finalized_user_balance("alice", ChainId::BnbSmartChain, "USDT")
                .unwrap(),
            0
        );
    }
}