// File: Equinox-Super-Wallet/crates/signing-dex-mpc/src/lib.rs
#![forbid(unsafe_code)]

pub mod broadcaster;
pub use broadcaster::{BroadcastReceipt, LiveTestnetBroadcaster, TestnetNetwork, TestnetRpcConfig};
use ed25519_dalek::{Signer as EdSigner, SigningKey as Ed25519SigningKey};
use hmac::{Hmac, Mac};
use k256::ecdsa::{SigningKey as SecpSigningKey, VerifyingKey as SecpVerifyingKey};
use k256::elliptic_curve::{Field, PrimeField};
use k256::Scalar;
use k256::elliptic_curve::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::{BTreeMap, HashMap, VecDeque};
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    #[error("Invalid recipient address checksum or format: {0}")]
    InvalidAddress(String),
    #[error("Invalid chain ID: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },
    #[error("Invalid fee, nonce, or UTXO balance: {0}")]
    InvalidTransactionParams(String),
    #[error("User approval missing, expired, or digest mismatch")]
    UnauthorizedSigningAttempt,
    #[error("Cryptographic signing error: {0}")]
    CryptoError(String),
    #[error("Swap deadline expired: deadline {deadline} < current {current}")]
    SwapDeadlineExpired { deadline: u64, current: u64 },
    #[error("Slippage exceeded: output {actual_out} < min {min_out}")]
    SlippageExceeded { actual_out: u128, min_out: u128 },
    #[error("Price impact {impact_bps} bps exceeds max {max_bps} bps")]
    PriceImpactTooHigh { impact_bps: u64, max_bps: u64 },
    #[error("Oracle deviation {dev_bps} bps exceeds max {max_bps} bps")]
    OracleDeviationExceeded { dev_bps: u64, max_bps: u64 },
    #[error("AMM invariant k_after < k_before violated")]
    AmmInvariantViolated,
    #[error("Order book error: {0}")]
    OrderBookError(String),
    #[error("Threshold MPC error: {0}")]
    ThresholdMpcError(String),
    #[error("RPC security violation: {0}")]
    RpcSecurityViolation(String),
}

// ============================================================================
// MODULE 6: REAL TRANSACTION SERIALIZATION, PRE-SIGN PREVIEW & SIGNING
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmUnsignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price_wei: u128,
    pub gas_limit: u64,
    pub to_address: [u8; 20],
    pub value_wei: u128,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EqxUtxoInput {
    pub prev_txid: [u8; 32],
    pub vout: u32,
    pub amount_atomic: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EqxUnsignedTx {
    pub chain_id: u64,
    pub inputs: Vec<EqxUtxoInput>,
    pub recipient_address: String,
    pub change_address: String,
    pub send_amount_atomic: u64,
    pub fee_atomic: u64,
    pub timestamp: u64,
}

/// প্রি-সাইন সিমুলেশন রিপোর্ট (এতে কোনো সিগনেচার বা র-ট্রানজ্যাকশন নেই, তাই ব্রডকাস্ট করা অসম্ভব)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreSignSimulationPreview {
    pub chain_id: u64,
    pub pre_image_signing_digest: [u8; 32],
    pub sender_total_debit_atomic: u128,
    pub recipient_net_credit_atomic: u128,
    pub network_fee_atomic: u128,
}

/// ইউজারের সুনির্দিষ্ট অনুমোদন টোকেন (নির্দিষ্ট `pre_image_signing_digest`-এর সাথে আবদ্ধ)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserApprovalToken {
    pub approved_digest: [u8; 32],
    pub approved_at_unix: u64,
    pub expires_at_unix: u64,
    pub explicit_user_consent: bool,
}

/// বাস্তব স্বাক্ষরিত ট্রানজ্যাকশন (শুধুমাত্র ইউজার অনুমোদন ও প্রাইভেট কি সাইনিংয়ের পর তৈরি হয়)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRawTransaction {
    pub chain_id: u64,
    pub tx_hash_hex: String,
    pub raw_tx_hex: String,
}

pub struct RlpSerializer;

impl RlpSerializer {
    pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return vec![bytes[0]];
        }
        let mut out = Self::encode_length(bytes.len(), 0x80);
        out.extend_from_slice(bytes);
        out
    }

    pub fn encode_u128(val: u128) -> Vec<u8> {
        if val == 0 {
            return vec![0x80];
        }
        let be = val.to_be_bytes();
        let first_non_zero = be.iter().position(|&b| b != 0).unwrap_or(15);
        Self::encode_bytes(&be[first_non_zero..])
    }

    pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload_len: usize = items.iter().map(|i| i.len()).sum();
        let mut out = Self::encode_length(payload_len, 0xc0);
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn encode_length(len: usize, offset: u8) -> Vec<u8> {
        if len < 56 {
            vec![offset + (len as u8)]
        } else {
            let be = len.to_be_bytes();
            let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
            let len_bytes = &be[first..];
            let mut out = Vec::with_capacity(1 + len_bytes.len());
            out.push(offset + 55 + (len_bytes.len() as u8));
            out.extend_from_slice(len_bytes);
            out
        }
    }
}

pub struct ChainTransactionSigner;

impl ChainTransactionSigner {
    pub fn verify_eqx_base58check(addr: &str) -> Result<(), ExecutionError> {
        let decoded = bs58::decode(addr.trim())
            .with_check(Some(0x21))
            .into_vec()
            .map_err(|_| ExecutionError::InvalidAddress(addr.to_string()))?;
        if decoded.len() != 21 {
            return Err(ExecutionError::InvalidAddress(addr.to_string()));
        }
        Ok(())
    }

    /// ধাপ ৬.১: EVM ট্রানজ্যাকশন যাচাই ও EIP-155 Pre-Image Digest তৈরি (Simulation Step)
    pub fn simulate_evm_transaction(
        tx: &EvmUnsignedTx,
        expected_chain_id: u64,
    ) -> Result<PreSignSimulationPreview, ExecutionError> {
        if tx.chain_id != expected_chain_id || tx.chain_id == 0 {
            return Err(ExecutionError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: tx.chain_id,
            });
        }
        if tx.gas_limit < 21_000 || tx.gas_price_wei == 0 {
            return Err(ExecutionError::InvalidTransactionParams(
                "Gas limit < 21000 or zero gas price".into(),
            ));
        }
        if tx.to_address == [0u8; 20] {
            return Err(ExecutionError::InvalidAddress("Zero EVM destination".into()));
        }

        // EIP-155 Pre-Image RLP: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let rlp_items = vec![
            RlpSerializer::encode_u128(tx.nonce as u128),
            RlpSerializer::encode_u128(tx.gas_price_wei),
            RlpSerializer::encode_u128(tx.gas_limit as u128),
            RlpSerializer::encode_bytes(&tx.to_address),
            RlpSerializer::encode_u128(tx.value_wei),
            RlpSerializer::encode_bytes(&tx.data),
            RlpSerializer::encode_u128(tx.chain_id as u128),
            RlpSerializer::encode_u128(0),
            RlpSerializer::encode_u128(0),
        ];
        let encoded_preimage = RlpSerializer::encode_list(&rlp_items);
        let digest: [u8; 32] = Keccak256::digest(&encoded_preimage).into();

        let fee_wei = tx.gas_price_wei.saturating_mul(tx.gas_limit as u128);
        let total_debit = tx.value_wei.saturating_add(fee_wei);

        Ok(PreSignSimulationPreview {
            chain_id: tx.chain_id,
            pre_image_signing_digest: digest,
            sender_total_debit_atomic: total_debit,
            recipient_net_credit_atomic: tx.value_wei,
            network_fee_atomic: fee_wei,
        })
    }

    /// ধাপ ৬.২: ইউজার অনুমোদন যাচাইয়ের পর প্রকৃত EIP-155 secp256k1 ECDSA সাইনিং ও RLP সিরিয়ালাইজেশন
    pub fn sign_evm_transaction(
        tx: &EvmUnsignedTx,
        approval: &UserApprovalToken,
        secret_key_32: &Zeroizing<[u8; 32]>,
        current_unix: u64,
    ) -> Result<SignedRawTransaction, ExecutionError> {
        let preview = Self::simulate_evm_transaction(tx, tx.chain_id)?;
        if !approval.explicit_user_consent
            || current_unix > approval.expires_at_unix
            || approval.approved_digest != preview.pre_image_signing_digest
        {
            return Err(ExecutionError::UnauthorizedSigningAttempt);
        }

        let signing_key = SecpSigningKey::from_slice(&**secret_key_32)
            .map_err(|e| ExecutionError::CryptoError(e.to_string()))?;
        let (sig, recid) = signing_key
            .sign_prehash_recoverable(&preview.pre_image_signing_digest)
            .map_err(|e| ExecutionError::CryptoError(e.to_string()))?;

        let sig_bytes = sig.to_bytes();
        let r = u128::from_be_bytes(sig_bytes[0..16].try_into().unwrap());
        let r_full = &sig_bytes[0..32];
        let s_full = &sig_bytes[32..64];
        let _ = r;

        // EIP-155 v = chain_id * 2 + 35 + recovery_id
        let v = (tx.chain_id as u128) * 2 + 35 + (recid.to_byte() as u128);

        fn trim_leading_zeros(slice: &[u8]) -> &[u8] {
            let first = slice.iter().position(|&b| b != 0).unwrap_or(slice.len());
            &slice[first..]
        }

        let signed_items = vec![
            RlpSerializer::encode_u128(tx.nonce as u128),
            RlpSerializer::encode_u128(tx.gas_price_wei),
            RlpSerializer::encode_u128(tx.gas_limit as u128),
            RlpSerializer::encode_bytes(&tx.to_address),
            RlpSerializer::encode_u128(tx.value_wei),
            RlpSerializer::encode_bytes(&tx.data),
            RlpSerializer::encode_u128(v),
            RlpSerializer::encode_bytes(trim_leading_zeros(r_full)),
            RlpSerializer::encode_bytes(trim_leading_zeros(s_full)),
        ];
        let raw_rlp = RlpSerializer::encode_list(&signed_items);
        let tx_hash: [u8; 32] = Keccak256::digest(&raw_rlp).into();

        Ok(SignedRawTransaction {
            chain_id: tx.chain_id,
            tx_hash_hex: format!("0x{}", hex::encode(tx_hash)),
            raw_tx_hex: format!("0x{}", hex::encode(raw_rlp)),
        })
    }

    /// ধাপ ৬.৩: Equinox L1 UTXO ট্রানজ্যাকশন সিমুলেশন ও যাচাই
    pub fn simulate_eqx_utxo_transaction(
        tx: &EqxUnsignedTx,
    ) -> Result<PreSignSimulationPreview, ExecutionError> {
        if tx.chain_id != 9333 {
            return Err(ExecutionError::ChainIdMismatch {
                expected: 9333,
                actual: tx.chain_id,
            });
        }
        Self::verify_eqx_base58check(&tx.recipient_address)?;
        Self::verify_eqx_base58check(&tx.change_address)?;

        if tx.inputs.is_empty() || tx.send_amount_atomic == 0 || tx.fee_atomic < 10_000 {
            return Err(ExecutionError::InvalidTransactionParams(
                "Missing inputs, zero amount, or fee below minimum relay fee".into(),
            ));
        }

        let total_in: u128 = tx.inputs.iter().map(|i| i.amount_atomic as u128).sum();
        let required: u128 = (tx.send_amount_atomic as u128) + (tx.fee_atomic as u128);
        if total_in < required {
            return Err(ExecutionError::InvalidTransactionParams(
                "UTXO inputs insufficient for send amount + fee".into(),
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(b"EQX_MAINNET_TX_SIGNING_V2");
        hasher.update(&tx.chain_id.to_le_bytes());
        hasher.update(&tx.timestamp.to_le_bytes());
        hasher.update(&tx.fee_atomic.to_le_bytes());
        for inp in &tx.inputs {
            hasher.update(&inp.prev_txid);
            hasher.update(&inp.vout.to_le_bytes());
            hasher.update(&inp.amount_atomic.to_le_bytes());
        }
        hasher.update(tx.recipient_address.as_bytes());
        hasher.update(&tx.send_amount_atomic.to_le_bytes());
        let first: [u8; 32] = hasher.finalize().into();
        let digest: [u8; 32] = Sha256::digest(first).into();

        Ok(PreSignSimulationPreview {
            chain_id: 9333,
            pre_image_signing_digest: digest,
            sender_total_debit_atomic: required,
            recipient_net_credit_atomic: tx.send_amount_atomic as u128,
            network_fee_atomic: tx.fee_atomic as u128,
        })
    }

    /// ধাপ ৬.৪: ইউজার অনুমোদন যাচাইয়ের পর Equinox L1 Ed25519 বাইনারি সাইনিং
    pub fn sign_eqx_utxo_transaction(
        tx: &EqxUnsignedTx,
        approval: &UserApprovalToken,
        ed25519_secret_32: &Zeroizing<[u8; 32]>,
        current_unix: u64,
    ) -> Result<SignedRawTransaction, ExecutionError> {
        let preview = Self::simulate_eqx_utxo_transaction(tx)?;
        if !approval.explicit_user_consent
            || current_unix > approval.expires_at_unix
            || approval.approved_digest != preview.pre_image_signing_digest
        {
            return Err(ExecutionError::UnauthorizedSigningAttempt);
        }

        let signing_key = Ed25519SigningKey::from_bytes(&**ed25519_secret_32);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(&preview.pre_image_signing_digest);

        let mut raw_payload = Vec::with_capacity(256);
        raw_payload.extend_from_slice(&preview.pre_image_signing_digest);
        raw_payload.extend_from_slice(&pubkey_bytes);
        raw_payload.extend_from_slice(&signature.to_bytes());

        let txid: [u8; 32] = Sha256::digest(Sha256::digest(&raw_payload)).into();

        Ok(SignedRawTransaction {
            chain_id: 9333,
            tx_hash_hex: format!("0x{}", hex::encode(txid)),
            raw_tx_hex: format!("0x{}", hex::encode(raw_payload)),
        })
    }
}

// ============================================================================
// MODULE 7: ON-CHAIN DEX ROUTER, ORACLE GUARD & ATOMIC ORDER BOOK
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainSwapQuoteAndCalldata {
    pub amount_in_atomic: u128,
    pub expected_amount_out_atomic: u128,
    pub min_amount_out_atomic: u128,
    pub lp_fee_atomic: u128,
    pub price_impact_bps: u64,
    pub k_invariant_before: u128,
    pub k_invariant_after: u128,
    pub router_calldata_hex: String,
}

pub struct OnChainDexRouter;

impl OnChainDexRouter {
    /// Uniswap V2 `swapExactTokensForTokens` 4-byte function selector: `0x38ed1739`
    pub const SWAP_EXACT_TOKENS_SELECTOR: [u8; 4] = [0x38, 0xed, 0x17, 0x39];

    /// AMM Invariant, Slippage, Deadline, Price Impact এবং TWAP Oracle Deviation যাচাই করে অন-চেইন রাউটার কলডেটা তৈরি করে
    pub fn build_verified_amm_swap(
        reserve_in: u128,
        reserve_out: u128,
        amount_in: u128,
        min_amount_out: u128,
        token_in_addr: [u8; 20],
        token_out_addr: [u8; 20],
        recipient_addr: [u8; 20],
        deadline_unix: u64,
        current_unix: u64,
        max_price_impact_bps: u64,
        twap_oracle_price_scaled_1e6: u128,
        max_oracle_deviation_bps: u64,
    ) -> Result<OnChainSwapQuoteAndCalldata, ExecutionError> {
        if deadline_unix < current_unix {
            return Err(ExecutionError::SwapDeadlineExpired {
                deadline: deadline_unix,
                current: current_unix,
            });
        }
        if reserve_in == 0 || reserve_out == 0 || amount_in == 0 {
            return Err(ExecutionError::InvalidTransactionParams(
                "Zero pool reserves or swap input".into(),
            ));
        }

        // 0.30% LP Fee (997 / 1000)
        let lp_fee = (amount_in * 3) / 1000;
        let amount_in_with_fee = amount_in.saturating_mul(997);
        let numerator = amount_in_with_fee.saturating_mul(reserve_out);
        let denominator = reserve_in
            .saturating_mul(1000)
            .saturating_add(amount_in_with_fee);
        let amount_out = numerator / denominator;

        if amount_out < min_amount_out {
            return Err(ExecutionError::SlippageExceeded {
                actual_out: amount_out,
                min_out: min_amount_out,
            });
        }

        // Price Impact in Basis Points
        let impact_bps = ((amount_in_with_fee * 10_000) / denominator) as u64;
        if impact_bps > max_price_impact_bps {
            return Err(ExecutionError::PriceImpactTooHigh {
                impact_bps,
                max_bps: max_price_impact_bps,
            });
        }

        // TWAP Oracle Price Protection
        let exec_price_1e6 = (amount_out.saturating_mul(1_000_000)) / amount_in;
        let diff = exec_price_1e6.abs_diff(twap_oracle_price_scaled_1e6);
        let dev_bps = ((diff * 10_000) / twap_oracle_price_scaled_1e6.max(1)) as u64;
        if dev_bps > max_oracle_deviation_bps {
            return Err(ExecutionError::OracleDeviationExceeded {
                dev_bps,
                max_bps: max_oracle_deviation_bps,
            });
        }

        // Verify AMM Constant-Product Invariant: k_after >= k_before
        let k_before = reserve_in.saturating_mul(reserve_out);
        let new_reserve_in = reserve_in.saturating_add(amount_in);
        let new_reserve_out = reserve_out.saturating_sub(amount_out);
        let k_after = new_reserve_in.saturating_mul(new_reserve_out);
        if k_after < k_before {
            return Err(ExecutionError::AmmInvariantViolated);
        }

        // Build EVM ABI Calldata for swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
        let mut calldata = Vec::with_capacity(4 + 32 * 7);
        calldata.extend_from_slice(&Self::SWAP_EXACT_TOKENS_SELECTOR);

        let push_u128_word = |buf: &mut Vec<u8>, v: u128| {
            buf.extend_from_slice(&[0u8; 16]);
            buf.extend_from_slice(&v.to_be_bytes());
        };
        let push_addr_word = |buf: &mut Vec<u8>, a: &[u8; 20]| {
            buf.extend_from_slice(&[0u8; 12]);
            buf.extend_from_slice(a);
        };

        push_u128_word(&mut calldata, amount_in);
        push_u128_word(&mut calldata, min_amount_out);
        push_u128_word(&mut calldata, 160); // offset to path[] dynamic array
        push_addr_word(&mut calldata, &recipient_addr);
        push_u128_word(&mut calldata, deadline_unix as u128);
        push_u128_word(&mut calldata, 2); // path.length = 2
        push_addr_word(&mut calldata, &token_in_addr);
        push_addr_word(&mut calldata, &token_out_addr);

        Ok(OnChainSwapQuoteAndCalldata {
            amount_in_atomic: amount_in,
            expected_amount_out_atomic: amount_out,
            min_amount_out_atomic: min_amount_out,
            lp_fee_atomic: lp_fee,
            price_impact_bps: impact_bps,
            k_invariant_before: k_before,
            k_invariant_after: k_after,
            router_calldata_hex: format!("0x{}", hex::encode(calldata)),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookOrder {
    pub order_id: u64,
    pub user_id: String,
    pub side: OrderSide,
    pub price_quote_per_base: u64,
    pub remaining_base_atomic: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderMatchFill {
    pub maker_order_id: u64,
    pub taker_order_id: u64,
    pub execution_price: u64,
    pub filled_base_atomic: u128,
    pub gross_quote_atomic: u128,
    pub maker_fee_quote_atomic: u128,
    pub taker_fee_quote_atomic: u128,
}

#[derive(Clone, Default, Debug)]
pub struct TraderBalances {
    pub avail_base: u128,
    pub reserved_base: u128,
    pub avail_quote: u128,
    pub reserved_quote: u128,
}

pub struct AtomicOrderBook {
    pub accounts: HashMap<String, TraderBalances>,
    pub bids: BTreeMap<u64, VecDeque<BookOrder>>,
    pub asks: BTreeMap<u64, VecDeque<BookOrder>>,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub exchange_fee_treasury_quote: u128,
    next_order_id: u64,
}

impl AtomicOrderBook {
    pub fn new(maker_fee_bps: u64, taker_fee_bps: u64) -> Self {
        Self {
            accounts: HashMap::new(),
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            maker_fee_bps,
            taker_fee_bps,
            exchange_fee_treasury_quote: 0,
            next_order_id: 1,
        }
    }

    pub fn credit_user(&mut self, user: &str, base: u128, quote: u128) {
        let entry = self.accounts.entry(user.to_string()).or_default();
        entry.avail_base = entry.avail_base.saturating_add(base);
        entry.avail_quote = entry.avail_quote.saturating_add(quote);
    }

    /// অ্যাটমিক প্রি-ট্রেড রিজার্ভেশন, পার্শিয়াল ফিল এবং মেকার/টেকার ফি অ্যাকাউন্টিং
    pub fn place_limit_order(
        &mut self,
        user: &str,
        side: OrderSide,
        price_quote_per_base: u64,
        base_qty_atomic: u128,
    ) -> Result<Vec<OrderMatchFill>, ExecutionError> {
        if price_quote_per_base == 0 || base_qty_atomic == 0 {
            return Err(ExecutionError::OrderBookError(
                "Zero price or quantity".into(),
            ));
        }

        let max_quote_needed = base_qty_atomic.saturating_mul(price_quote_per_base as u128);
        {
            let acct = self
                .accounts
                .get_mut(user)
                .ok_or_else(|| ExecutionError::OrderBookError("Unknown user".into()))?;
            match side {
                OrderSide::Buy => {
                    if acct.avail_quote < max_quote_needed {
                        return Err(ExecutionError::OrderBookError(
                            "Insufficient quote balance for Buy reservation".into(),
                        ));
                    }
                    acct.avail_quote -= max_quote_needed;
                    acct.reserved_quote += max_quote_needed;
                }
                OrderSide::Sell => {
                    if acct.avail_base < base_qty_atomic {
                        return Err(ExecutionError::OrderBookError(
                            "Insufficient base balance for Sell reservation".into(),
                        ));
                    }
                    acct.avail_base -= base_qty_atomic;
                    acct.reserved_base += base_qty_atomic;
                }
            }
        }

        let taker_id = self.next_order_id;
        self.next_order_id += 1;
        let mut incoming = BookOrder {
            order_id: taker_id,
            user_id: user.to_string(),
            side,
            price_quote_per_base,
            remaining_base_atomic: base_qty_atomic,
        };
        let mut fills = Vec::new();

        match side {
            OrderSide::Buy => {
                let ask_prices: Vec<u64> = self
                    .asks
                    .keys()
                    .copied()
                    .filter(|&p| p <= price_quote_per_base)
                    .collect();

                for ask_p in ask_prices {
                    if incoming.remaining_base_atomic == 0 {
                        break;
                    }
                    if let Some(queue) = self.asks.get_mut(&ask_p) {
                        while let Some(mut maker) = queue.pop_front() {
                            let fill_base = incoming
                                .remaining_base_atomic
                                .min(maker.remaining_base_atomic);
                            let gross_quote = fill_base * (ask_p as u128);
                            let reserved_at_limit =
                                fill_base * (incoming.price_quote_per_base as u128);
                            let price_improvement_refund = reserved_at_limit - gross_quote;

                            let maker_fee = (gross_quote * (self.maker_fee_bps as u128)) / 10_000;
                            let taker_fee = (gross_quote * (self.taker_fee_bps as u128)) / 10_000;
                            self.exchange_fee_treasury_quote += maker_fee + taker_fee;

                            {
                                let buyer = self.accounts.get_mut(&incoming.user_id).unwrap();
                                buyer.reserved_quote -= reserved_at_limit;
                                buyer.avail_quote += price_improvement_refund;
                                buyer.avail_base += fill_base;
                            }
                            {
                                let seller = self.accounts.get_mut(&maker.user_id).unwrap();
                                seller.reserved_base -= fill_base;
                                seller.avail_quote += gross_quote - (maker_fee + taker_fee);
                            }

                            incoming.remaining_base_atomic -= fill_base;
                            maker.remaining_base_atomic -= fill_base;

                            fills.push(OrderMatchFill {
                                maker_order_id: maker.order_id,
                                taker_order_id: incoming.order_id,
                                execution_price: ask_p,
                                filled_base_atomic: fill_base,
                                gross_quote_atomic: gross_quote,
                                maker_fee_quote_atomic: maker_fee,
                                taker_fee_quote_atomic: taker_fee,
                            });

                            if maker.remaining_base_atomic > 0 {
                                queue.push_front(maker);
                                break;
                            }
                        }
                    }
                    if self.asks.get(&ask_p).map(|q| q.is_empty()).unwrap_or(false) {
                        self.asks.remove(&ask_p);
                    }
                }
                if incoming.remaining_base_atomic > 0 {
                    self.bids
                        .entry(price_quote_per_base)
                        .or_default()
                        .push_back(incoming);
                }
            }
            OrderSide::Sell => {
                let bid_prices: Vec<u64> = self
                    .bids
                    .keys()
                    .rev()
                    .copied()
                    .filter(|&p| p >= price_quote_per_base)
                    .collect();

                for bid_p in bid_prices {
                    if incoming.remaining_base_atomic == 0 {
                        break;
                    }
                    if let Some(queue) = self.bids.get_mut(&bid_p) {
                        while let Some(mut maker) = queue.pop_front() {
                            let fill_base = incoming
                                .remaining_base_atomic
                                .min(maker.remaining_base_atomic);
                            let gross_quote = fill_base * (bid_p as u128);
                            let maker_fee = (gross_quote * (self.maker_fee_bps as u128)) / 10_000;
                            let taker_fee = (gross_quote * (self.taker_fee_bps as u128)) / 10_000;
                            self.exchange_fee_treasury_quote += maker_fee + taker_fee;

                            {
                                let buyer = self.accounts.get_mut(&maker.user_id).unwrap();
                                buyer.reserved_quote -= gross_quote;
                                buyer.avail_base += fill_base;
                            }
                            {
                                let seller = self.accounts.get_mut(&incoming.user_id).unwrap();
                                seller.reserved_base -= fill_base;
                                seller.avail_quote += gross_quote - (maker_fee + taker_fee);
                            }

                            incoming.remaining_base_atomic -= fill_base;
                            maker.remaining_base_atomic -= fill_base;

                            fills.push(OrderMatchFill {
                                maker_order_id: maker.order_id,
                                taker_order_id: incoming.order_id,
                                execution_price: bid_p,
                                filled_base_atomic: fill_base,
                                gross_quote_atomic: gross_quote,
                                maker_fee_quote_atomic: maker_fee,
                                taker_fee_quote_atomic: taker_fee,
                            });

                            if maker.remaining_base_atomic > 0 {
                                queue.push_front(maker);
                                break;
                            }
                        }
                    }
                    if self.bids.get(&bid_p).map(|q| q.is_empty()).unwrap_or(false) {
                        self.bids.remove(&bid_p);
                    }
                }
                if incoming.remaining_base_atomic > 0 {
                    self.asks
                        .entry(price_quote_per_base)
                        .or_default()
                        .push_back(incoming);
                }
            }
        }
        Ok(fills)
    }
}

// ============================================================================
// MODULE 8: TRUE THRESHOLD CRYPTOGRAPHY (GF(q) LAGRANGE) & RPC SECURITY GUARD
// ============================================================================

/// একটি ভ্যালিডেটর নোডের কাছে সংরক্ষিত গোপন থ্রেশহোল্ড শেয়ার $(x_i, y_i) \in \mathbb{F}_q$
#[derive(Clone)]
pub struct ThresholdKeyShare {
    pub participant_id: u32,
    pub share_scalar_bytes: Zeroizing<[u8; 32]>,
}

pub struct ThresholdMpcEngine;

impl ThresholdMpcEngine {
    /// secp256k1 প্রাইম ফিল্ডে $(t, n)$ Shamir Polynomial $f(x) = s + a_1 x + \dots + a_{t-1} x^{t-1} \pmod q$ দিয়ে প্রাইভেট কি ভাগ করে
    pub fn split_secret_into_threshold_shares(
        master_secret_32: &Zeroizing<[u8; 32]>,
        threshold_t: usize,
        total_n: usize,
    ) -> Result<(SecpVerifyingKey, Vec<ThresholdKeyShare>), ExecutionError> {
        if threshold_t < 2 || threshold_t > total_n || total_n > 32 {
            return Err(ExecutionError::ThresholdMpcError(
                "Invalid (t, n) threshold parameters".into(),
            ));
        }

        let sk = SecpSigningKey::from_slice(&**master_secret_32)
            .map_err(|e| ExecutionError::ThresholdMpcError(e.to_string()))?;
        let verifying_key = *sk.verifying_key();
        let secret_scalar: Scalar = *sk.as_nonzero_scalar().as_ref();

        let mut coeffs = Vec::with_capacity(threshold_t);
        coeffs.push(secret_scalar);
        for _ in 1..threshold_t {
            coeffs.push(Scalar::random(&mut OsRng));
        }

        let mut shares = Vec::with_capacity(total_n);
        for i in 1..=(total_n as u32) {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::ZERO;
            let mut x_pow = Scalar::ONE;
            for c in &coeffs {
                y += *c * x_pow;
                x_pow *= x;
            }
            let mut share_bytes = [0u8; 32];
            share_bytes.copy_from_slice(&y.to_bytes());
            shares.push(ThresholdKeyShare {
                participant_id: i,
                share_scalar_bytes: Zeroizing::new(share_bytes),
            });
        }

        for c in coeffs.iter_mut() {
            *c = Scalar::ZERO;
        }
        Ok((verifying_key, shares))
    }

    /// কমপক্ষে $t$ সংখ্যক শেয়ার থেকে Lagrange Interpolation $\sum y_i \prod_{j \ne i} \frac{x_j}{x_j - x_i} \pmod q$ করে ECDSA সিগনেচার তৈরি করে
    pub fn sign_with_threshold_shares(
        shares: &[ThresholdKeyShare],
        threshold_t: usize,
        pre_image_digest: &[u8; 32],
    ) -> Result<[u8; 64], ExecutionError> {
        if shares.len() < threshold_t {
            return Err(ExecutionError::ThresholdMpcError(format!(
                "Insufficient threshold shares: required {}, got {}",
                threshold_t,
                shares.len()
            )));
        }

        let active = &shares[0..threshold_t];
        let mut reconstructed_scalar = Scalar::ZERO;

        for (i_idx, share_i) in active.iter().enumerate() {
            let xi = Scalar::from(share_i.participant_id as u64);
            let yi_opt: Option<Scalar> =
                Scalar::from_repr((*share_i.share_scalar_bytes).into()).into();
            let yi = yi_opt.ok_or_else(|| {
                ExecutionError::ThresholdMpcError("Invalid share scalar representation".into())
            })?;

            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;

            for (j_idx, share_j) in active.iter().enumerate() {
                if i_idx == j_idx {
                    continue;
                }
                if share_i.participant_id == share_j.participant_id {
                    return Err(ExecutionError::ThresholdMpcError(
                        "Duplicate participant share ID detected".into(),
                    ));
                }
                let xj = Scalar::from(share_j.participant_id as u64);
                num *= xj;
                den *= xj - xi;
            }

            let den_inv_opt: Option<Scalar> = den.invert().into();
            let den_inv = den_inv_opt.ok_or_else(|| {
                ExecutionError::ThresholdMpcError("Non-invertible Lagrange denominator".into())
            })?;

            let lagrange_coeff = num * den_inv;
            reconstructed_scalar += yi * lagrange_coeff;
        }

        let mut raw_sk = Zeroizing::new([0u8; 32]);
        raw_sk.copy_from_slice(&reconstructed_scalar.to_bytes());
        reconstructed_scalar = Scalar::ZERO;
        let _ = reconstructed_scalar;

        let signing_key = SecpSigningKey::from_slice(&*raw_sk)
            .map_err(|e| ExecutionError::ThresholdMpcError(e.to_string()))?;
        let (sig, _) = signing_key
            .sign_prehash_recoverable(pre_image_digest)
            .map_err(|e| ExecutionError::ThresholdMpcError(e.to_string()))?;

        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        Ok(out)
    }
}

pub struct RpcSecurityGuard {
    hmac_secret: Zeroizing<[u8; 32]>,
    max_requests_per_min: u32,
    window_start_unix: u64,
    request_count: u32,
}

impl RpcSecurityGuard {
    pub fn new(hmac_secret: [u8; 32], max_requests_per_min: u32) -> Self {
        Self {
            hmac_secret: Zeroizing::new(hmac_secret),
            max_requests_per_min,
            window_start_unix: 0,
            request_count: 0,
        }
    }

    /// রিমোট RPC এন্ডপয়েন্টের জন্য বাধ্যতামূলক HTTPS/TLS এবং লোকালহোস্টের জন্য Loopback যাচাই
    pub fn validate_endpoint_url(url: &str) -> Result<(), ExecutionError> {
        let clean = url.trim();
        if clean.starts_with("https://")
            || clean.starts_with("http://127.0.0.1:")
            || clean.starts_with("http://localhost:")
        {
            Ok(())
        } else {
            Err(ExecutionError::RpcSecurityViolation(
                "Remote RPC endpoints must use TLS (https://)".into(),
            ))
        }
    }

    pub fn sign_rpc_request_hmac(&self, json_body: &str, timestamp_unix: u64) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&*self.hmac_secret).expect("HMAC init");
        mac.update(&timestamp_unix.to_be_bytes());
        mac.update(json_body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn verify_rate_limit_and_response(
        &mut self,
        expected_req_id: u64,
        raw_response_json: &str,
        current_unix: u64,
    ) -> Result<serde_json::Value, ExecutionError> {
        if current_unix.saturating_sub(self.window_start_unix) >= 60 {
            self.window_start_unix = current_unix;
            self.request_count = 0;
        }
        if self.request_count >= self.max_requests_per_min {
            return Err(ExecutionError::RpcSecurityViolation(
                "RPC client rate limit exceeded".into(),
            ));
        }
        self.request_count += 1;

        if raw_response_json.len() > 256 * 1024 {
            return Err(ExecutionError::RpcSecurityViolation(
                "Malicious oversized RPC response (>256KB)".into(),
            ));
        }

        let parsed: serde_json::Value = serde_json::from_str(raw_response_json)
            .map_err(|_| ExecutionError::RpcSecurityViolation("Malformed JSON response".into()))?;

        if parsed.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return Err(ExecutionError::RpcSecurityViolation(
                "Invalid JSON-RPC version".into(),
            ));
        }
        if parsed.get("id").and_then(|v| v.as_u64()) != Some(expected_req_id) {
            return Err(ExecutionError::RpcSecurityViolation(
                "RPC response ID mismatch (potential spoofing)".into(),
            ));
        }
        Ok(parsed)
    }
}

// ============================================================================
// MANDATORY TESTS FOR MODULE 6, 7 & 8
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    #[test]
    fn test_module6_evm_eip155_signing_and_user_approval_enforcement() {
        let tx = EvmUnsignedTx {
            chain_id: 56, // BNB Smart Chain
            nonce: 7,
            gas_price_wei: 3_000_000_000, // 3 Gwei
            gas_limit: 21_000,
            to_address: [0x11u8; 20],
            value_wei: 1_000_000_000_000_000_000, // 1.0 BNB
            data: Vec::new(),
        };

        let preview = ChainTransactionSigner::simulate_evm_transaction(&tx, 56).unwrap();
        let sk = Zeroizing::new([0x42u8; 32]);

        // 1. Attempting to sign without explicit user consent must fail
        let unapproved = UserApprovalToken {
            approved_digest: preview.pre_image_signing_digest,
            approved_at_unix: 1000,
            expires_at_unix: 1300,
            explicit_user_consent: false,
        };
        assert_eq!(
            ChainTransactionSigner::sign_evm_transaction(&tx, &unapproved, &sk, 1100),
            Err(ExecutionError::UnauthorizedSigningAttempt)
        );

        // 2. Valid user approval produces a verifiable RLP-encoded EIP-155 raw transaction
        let approved = UserApprovalToken {
            approved_digest: preview.pre_image_signing_digest,
            approved_at_unix: 1000,
            expires_at_unix: 1300,
            explicit_user_consent: true,
        };
        let signed =
            ChainTransactionSigner::sign_evm_transaction(&tx, &approved, &sk, 1100).unwrap();
        assert!(signed.raw_tx_hex.starts_with("0xf8"));
        assert_eq!(signed.tx_hash_hex.len(), 66);
    }

    #[test]
    fn test_module7_amm_router_invariant_oracle_and_order_book_partial_fill() {
        // 1. On-Chain DEX Router Quote & Calldata Verification
        let quote = OnChainDexRouter::build_verified_amm_swap(
            1_000_000_000_000, // 1M EQX reserve
            5_000_000_000_000, // 5M USDT reserve (Spot price = $5.00)
            1_000_000_000,     // Swap 1,000 EQX
            4_900_000_000,     // Min output 4,900 USDT
            [0xAAu8; 20],
            [0xBBu8; 20],
            [0xCCu8; 20],
            2_000,
            1_900,
            150,       // Max 1.50% price impact
            5_000_000, // TWAP Oracle = $5.00
            200,       // Max 2.00% oracle deviation
        )
        .unwrap();

        assert!(quote.k_invariant_after >= quote.k_invariant_before);
        assert!(quote.router_calldata_hex.starts_with("0x38ed1739"));

        // 2. Atomic Order Book Partial Fill + Maker/Taker Fee Accounting
        let mut book = AtomicOrderBook::new(10, 20); // 0.10% maker, 0.20% taker
        book.credit_user("maker_alice", 1_000, 0);
        book.credit_user("taker_bob", 0, 10_000);

        // Alice places Sell order for 1,000 EQX at $5
        assert!(book
            .place_limit_order("maker_alice", OrderSide::Sell, 5, 1_000)
            .unwrap()
            .is_empty());

        // Bob places Buy order for 400 EQX at $5 (Partial Fill of Alice's order)
        let fills = book
            .place_limit_order("taker_bob", OrderSide::Buy, 5, 400)
            .unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].filled_base_atomic, 400);
        assert_eq!(fills[0].gross_quote_atomic, 2_000);
        assert_eq!(fills[0].maker_fee_quote_atomic, 2); // 0.10% of 2000
        assert_eq!(fills[0].taker_fee_quote_atomic, 4); // 0.20% of 2000
        assert_eq!(book.exchange_fee_treasury_quote, 6);
    }

    #[test]
    fn test_module8_true_threshold_lagrange_signing_and_rpc_guard() {
        let master_secret = Zeroizing::new([0x33u8; 32]);
        let digest = [0x99u8; 32];

        // Split key into 3-of-5 threshold shares over secp256k1 scalar field
        let (verifying_key, shares) =
            ThresholdMpcEngine::split_secret_into_threshold_shares(&master_secret, 3, 5).unwrap();

        // 2 shares (< threshold 3) must fail
        assert!(ThresholdMpcEngine::sign_with_threshold_shares(&shares[0..2], 3, &digest).is_err());

        // Any 3 shares (e.g. shares[1], shares[2], shares[4]) reconstruct and sign validly!
        let subset = vec![shares[1].clone(), shares[2].clone(), shares[4].clone()];
        let sig_bytes =
            ThresholdMpcEngine::sign_with_threshold_shares(&subset, 3, &digest).unwrap();
        let ecdsa_sig = k256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        assert!(verifying_key.verify_prehash(&digest, &ecdsa_sig).is_ok());

        // RPC Guard must block non-TLS remote HTTP endpoints
        assert!(RpcSecurityGuard::validate_endpoint_url("http://88.198.10.20:8545").is_err());
        assert!(RpcSecurityGuard::validate_endpoint_url("https://rpc.equinoxnetwork.io").is_ok());
    }
}


