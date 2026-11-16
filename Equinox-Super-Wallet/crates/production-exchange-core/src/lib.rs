#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// প্রতিটি ব্লকচেইনের জন্য সম্পূর্ণ আলাদা বগি (Bulkhead Compartment)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExternalChain {
    EquinoxL1,
    BitcoinMainnet,
    EthereumMainnet,
    BnbSmartChain,
    SolanaMainnet,
}

impl ExternalChain {
    pub fn min_finality_confirmations(&self) -> u32 {
        match self {
            ExternalChain::EquinoxL1 => 10,
            ExternalChain::BitcoinMainnet => 3,
            ExternalChain::EthereumMainnet => 12,
            ExternalChain::BnbSmartChain => 15,
            ExternalChain::SolanaMainnet => 32, // Solana Finalized Commitment (Max Lockout)
        }
    }

    pub fn official_usdt_contract_or_mint(&self) -> Option<&'static str> {
        match self {
            ExternalChain::EthereumMainnet => Some("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            ExternalChain::BnbSmartChain => Some("0x55d398326f99059ff775485246999027b3197955"),
            ExternalChain::SolanaMainnet => Some("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpotAsset {
    EQX,
    USDT,
    BTC,
    ETH,
    BNB,
    SOL,
}

#[derive(Clone, Debug)]
pub struct ChainBulkheadState {
    pub is_paused: bool,
    pub max_hourly_outflow_atomic: u128,
    pub current_hourly_outflow_atomic: u128,
    pub total_verified_reserve_atomic: u128,
}

#[derive(Clone, Debug)]
pub struct UserSpotWallet {
    pub available: HashMap<SpotAsset, u128>,
    pub locked_in_orders: HashMap<SpotAsset, u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitOrder {
    pub order_id: u64,
    pub user_id: String,
    pub side: OrderSide,
    pub price_usdt_cents: u64,
    pub remaining_eqx_atomic: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TradeFill {
    pub buy_order_id: u64,
    pub sell_order_id: u64,
    pub execution_price_cents: u64,
    pub filled_eqx_atomic: u128,
}

pub struct SovereignExchangeAndIndexer {
    /// প্রতিটি চেইনের নিজস্ব সার্কিট ব্রেকার (এক চেইনে সমস্যা হলে অন্য চেইন ১০০% নিরাপদ থাকে)
    pub bulkheads: HashMap<ExternalChain, ChainBulkheadState>,
    pub processed_onchain_txs: HashSet<(ExternalChain, String, u32)>,
    pub user_wallets: HashMap<String, UserSpotWallet>,
    /// Price-Time Priority (FIFO) Order Book: Price -> Queue of Orders
    pub bids: BTreeMap<u64, VecDeque<LimitOrder>>,
    pub asks: BTreeMap<u64, VecDeque<LimitOrder>>,
    pub next_order_id: u64,
    pub audit_log_chain_hash: u64,
}

impl SovereignExchangeAndIndexer {
    pub fn new() -> Self {
        let mut bulkheads = HashMap::new();
        for chain in [
            ExternalChain::EquinoxL1,
            ExternalChain::BitcoinMainnet,
            ExternalChain::EthereumMainnet,
            ExternalChain::BnbSmartChain,
            ExternalChain::SolanaMainnet,
        ] {
            bulkheads.insert(
                chain,
                ChainBulkheadState {
                    is_paused: false,
                    max_hourly_outflow_atomic: 50_000_000_00, // Per-chain hourly circuit breaker limit
                    current_hourly_outflow_atomic: 0,
                    total_verified_reserve_atomic: 0,
                },
            );
        }

        Self {
            bulkheads,
            processed_onchain_txs: HashSet::new(),
            user_wallets: HashMap::new(),
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            next_order_id: 1,
            audit_log_chain_hash: 0xcbf29ce484222325,
        }
    }

    fn append_audit_log(&mut self, event: &str) {
        for b in event.bytes() {
            self.audit_log_chain_hash ^= b as u64;
            self.audit_log_chain_hash = self.audit_log_chain_hash.wrapping_mul(0x100000001b3);
        }
    }

    /// ১. মাল্টি-চেইন রিড-অনলি ইনডেক্সার (BTC, ETH, BNB, Solana, EQX)
    pub fn index_finalized_deposit(
        &mut self,
        chain: ExternalChain,
        user_id: &str,
        asset: SpotAsset,
        tx_hash: &str,
        log_index: u32,
        token_contract_or_mint: Option<&str>,
        amount_atomic: u128,
        confirmations: u32,
    ) -> Result<(), String> {
        let bh = self.bulkheads.get_mut(&chain).ok_or("Chain not configured")?;
        if bh.is_paused {
            return Err(format!("Bulkhead Circuit Breaker Active: {:?} is isolated and paused!", chain));
        }

        if confirmations < chain.min_finality_confirmations() {
            return Err("Deposit not yet finalized on-chain".to_string());
        }

        // যদি USDT হয়, তবে Ethereum, BNB বা Solana-এর অফিশিয়াল মিন্ট/কন্ট্রাক্ট হোয়াইটলিস্ট চেক
        if asset == SpotAsset::USDT {
            let expected_mint = chain
                .official_usdt_contract_or_mint()
                .ok_or("USDT not supported on this chain")?;
            let provided = token_contract_or_mint.unwrap_or("");
            if !provided.eq_ignore_ascii_case(expected_mint) {
                // কোনো হ্যাকার ভুয়া টোকেন পাঠালে সাথে সাথে ব্লক!
                return Err("Fake SPL/ERC20/BEP20 USDT contract rejected!".to_string());
            }
        }

        let key = (chain, tx_hash.trim().to_lowercase(), log_index);
        if self.processed_onchain_txs.contains(&key) {
            return Err("Replay attack blocked: Tx already indexed".to_string());
        }

        self.processed_onchain_txs.insert(key);
        bh.total_verified_reserve_atomic = bh.total_verified_reserve_atomic.saturating_add(amount_atomic);

        let wallet = self.user_wallets.entry(user_id.to_string()).or_insert_with(|| UserSpotWallet {
            available: HashMap::new(),
            locked_in_orders: HashMap::new(),
        });
        let bal = wallet.available.entry(asset).or_insert(0);
        *bal = bal.saturating_add(amount_atomic);

        self.append_audit_log(&format!("DEPOSIT:{:?}:{}:{}", chain, user_id, amount_atomic));
        Ok(())
    }

    /// ২. অটোমেটিক বাল্কহেড সার্কিট ব্রেকার (কোনো চেইনে অস্বাভাবিক আউটফ্লো হলে শুধু ওই চেইন ফ্রিজ হবে, Equinox বা অন্য চেইন চলবে!)
    pub fn request_isolated_chain_withdrawal(
        &mut self,
        chain: ExternalChain,
        user_id: &str,
        asset: SpotAsset,
        amount_atomic: u128,
    ) -> Result<(), String> {
        let bh = self.bulkheads.get_mut(&chain).ok_or("Chain not configured")?;
        if bh.is_paused {
            return Err(format!("Chain {:?} is paused by circuit breaker", chain));
        }

        // যদি ১ ঘণ্টার লিমিট অতিক্রম করে বা রিজার্ভের চেয়ে বেশি চায় -> সাথে সাথে শুধু ওই চেইন পজ!
        if bh.current_hourly_outflow_atomic.saturating_add(amount_atomic) > bh.max_hourly_outflow_atomic
            || amount_atomic > bh.total_verified_reserve_atomic
        {
            bh.is_paused = true;
            return Err(format!(
                "Anomaly Detected on {:?}! Auto-Circuit Breaker tripped & isolated this chain.",
                chain
            ));
        }

        let wallet = self.user_wallets.get_mut(user_id).ok_or("User not found")?;
        let avail = wallet.available.get_mut(&asset).ok_or("No asset balance")?;
        if *avail < amount_atomic {
            return Err("Insufficient user available balance".to_string());
        }

        *avail -= amount_atomic;
        bh.total_verified_reserve_atomic -= amount_atomic;
        bh.current_hourly_outflow_atomic += amount_atomic;

        self.append_audit_log(&format!("WITHDRAW:{:?}:{}:{}", chain, user_id, amount_atomic));
        Ok(())
    }

    /// ৩. সেন্ট্রাল স্পট ম্যাচিং ইঞ্জিন (Price-Time Priority FIFO + Pre-Trade Balance Lock)
    pub fn place_limit_order_eqx_usdt(
        &mut self,
        user_id: &str,
        side: OrderSide,
        price_usdt_cents: u64,
        eqx_qty_atomic: u128,
    ) -> Result<Vec<TradeFill>, String> {
        if price_usdt_cents == 0 || eqx_qty_atomic == 0 {
            return Err("Invalid price or quantity".to_string());
        }

        let required_usdt_atomic = (eqx_qty_atomic * (price_usdt_cents as u128)) / 100;

        // Pre-Trade Balance Lock (যাতে ইউজার একই ব্যালেন্স দিয়ে ডবল অর্ডার না দিতে পারে)
        {
            let wallet = self.user_wallets.get_mut(user_id).ok_or("User wallet not found")?;
            match side {
                OrderSide::Buy => {
                    let avail_usdt = wallet.available.entry(SpotAsset::USDT).or_insert(0);
                    if *avail_usdt < required_usdt_atomic {
                        return Err("Insufficient available USDT for Buy order".to_string());
                    }
                    *avail_usdt -= required_usdt_atomic;
                    *wallet.locked_in_orders.entry(SpotAsset::USDT).or_insert(0) += required_usdt_atomic;
                }
                OrderSide::Sell => {
                    let avail_eqx = wallet.available.entry(SpotAsset::EQX).or_insert(0);
                    if *avail_eqx < eqx_qty_atomic {
                        return Err("Insufficient available EQX for Sell order".to_string());
                    }
                    *avail_eqx -= eqx_qty_atomic;
                    *wallet.locked_in_orders.entry(SpotAsset::EQX).or_insert(0) += eqx_qty_atomic;
                }
            }
        }

        let order_id = self.next_order_id;
        self.next_order_id += 1;

        let mut incoming = LimitOrder {
            order_id,
            user_id: user_id.to_string(),
            side,
            price_usdt_cents,
            remaining_eqx_atomic: eqx_qty_atomic,
        };

        let mut fills = Vec::new();

        match side {
            OrderSide::Buy => {
                let ask_prices: Vec<u64> = self.asks.keys().copied().filter(|&p| p <= price_usdt_cents).collect();
                for ask_p in ask_prices {
                    if incoming.remaining_eqx_atomic == 0 {
                        break;
                    }
                    if let Some(queue) = self.asks.get_mut(&ask_p) {
                        while let Some(mut maker) = queue.pop_front() {
                            let fill_qty = incoming.remaining_eqx_atomic.min(maker.remaining_eqx_atomic);
                            let trade_usdt = (fill_qty * (ask_p as u128)) / 100;

                            // Settle Buyer & Seller balances atomically
                            {
                                let buyer_w = self.user_wallets.get_mut(&incoming.user_id).unwrap();
                                *buyer_w.locked_in_orders.get_mut(&SpotAsset::USDT).unwrap() -= trade_usdt;
                                *buyer_w.available.entry(SpotAsset::EQX).or_insert(0) += fill_qty;
                            }
                            {
                                let seller_w = self.user_wallets.get_mut(&maker.user_id).unwrap();
                                *seller_w.locked_in_orders.get_mut(&SpotAsset::EQX).unwrap() -= fill_qty;
                                *seller_w.available.entry(SpotAsset::USDT).or_insert(0) += trade_usdt;
                            }

                            incoming.remaining_eqx_atomic -= fill_qty;
                            maker.remaining_eqx_atomic -= fill_qty;

                            fills.push(TradeFill {
                                buy_order_id: incoming.order_id,
                                sell_order_id: maker.order_id,
                                execution_price_cents: ask_p,
                                filled_eqx_atomic: fill_qty,
                            });

                            if maker.remaining_eqx_atomic > 0 {
                                queue.push_front(maker);
                                break;
                            }
                        }
                    }
                    if self.asks.get(&ask_p).map(|q| q.is_empty()).unwrap_or(false) {
                        self.asks.remove(&ask_p);
                    }
                }
                if incoming.remaining_eqx_atomic > 0 {
                    self.bids.entry(price_usdt_cents).or_default().push_back(incoming);
                }
            }
            OrderSide::Sell => {
                let bid_prices: Vec<u64> = self.bids.keys().rev().copied().filter(|&p| p >= price_usdt_cents).collect();
                for bid_p in bid_prices {
                    if incoming.remaining_eqx_atomic == 0 {
                        break;
                    }
                    if let Some(queue) = self.bids.get_mut(&bid_p) {
                        while let Some(mut maker) = queue.pop_front() {
                            let fill_qty = incoming.remaining_eqx_atomic.min(maker.remaining_eqx_atomic);
                            let trade_usdt = (fill_qty * (bid_p as u128)) / 100;

                            {
                                let buyer_w = self.user_wallets.get_mut(&maker.user_id).unwrap();
                                *buyer_w.locked_in_orders.get_mut(&SpotAsset::USDT).unwrap() -= trade_usdt;
                                *buyer_w.available.entry(SpotAsset::EQX).or_insert(0) += fill_qty;
                            }
                            {
                                let seller_w = self.user_wallets.get_mut(&incoming.user_id).unwrap();
                                *seller_w.locked_in_orders.get_mut(&SpotAsset::EQX).unwrap() -= fill_qty;
                                *seller_w.available.entry(SpotAsset::USDT).or_insert(0) += trade_usdt;
                            }

                            incoming.remaining_eqx_atomic -= fill_qty;
                            maker.remaining_eqx_atomic -= fill_qty;

                            fills.push(TradeFill {
                                buy_order_id: maker.order_id,
                                sell_order_id: incoming.order_id,
                                execution_price_cents: bid_p,
                                filled_eqx_atomic: fill_qty,
                            });

                            if maker.remaining_eqx_atomic > 0 {
                                queue.push_front(maker);
                                break;
                            }
                        }
                    }
                    if self.bids.get(&bid_p).map(|q| q.is_empty()).unwrap_or(false) {
                        self.bids.remove(&bid_p);
                    }
                }
                if incoming.remaining_eqx_atomic > 0 {
                    self.asks.entry(price_usdt_cents).or_default().push_back(incoming);
                }
            }
        }

        Ok(fills)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_btc_eth_eqx_isolation_and_spot_matching_engine() {
        let mut ex = SovereignExchangeAndIndexer::new();

        // ১. ইউজার-১ Equinox চেইনে 1,000 EQX ডিপোজিট করল
        ex.index_finalized_deposit(
            ExternalChain::EquinoxL1,
            "seller_rahim",
            SpotAsset::EQX,
            "0xEqxTxHash000111222333",
            0,
            None,
            1_000_00,
            10,
        ).unwrap();

        // ২. ইউজার-২ Solana মেইননেটে অফিশিয়াল SPL-USDT ডিপোজিট করল (৩২ কনফার্মেশন সহ)
        ex.index_finalized_deposit(
            ExternalChain::SolanaMainnet,
            "buyer_karim",
            SpotAsset::USDT,
            "5SolanaTxSignatureFinalized999888777",
            0,
            Some("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
            2_500_00,
            32,
        ).unwrap();

        // ৩. কেউ যদি Solana-তে নকল/ফেক SPL টোকেন পাঠিয়ে USDT ব্যালেন্স নিতে চায় -> সাথে সাথে ব্লক!
        assert!(ex.index_finalized_deposit(
            ExternalChain::SolanaMainnet,
            "hacker_user",
            SpotAsset::USDT,
            "5FakeSolanaTokenSig000",
            0,
            Some("FakeSolanaMintAddress1111111111111111111"),
            999_999_00,
            40,
        ).is_err());

        // ৪. যদি কোনো কারণে Solana চেইনে অস্বাভাবিক বড় উইথড্রয়াল অ্যাটাক হয় -> শুধু Solana পজ হবে!
        assert!(ex.request_isolated_chain_withdrawal(
            ExternalChain::SolanaMainnet,
            "buyer_karim",
            SpotAsset::USDT,
            900_000_000_00, // Exceeds hourly limit & reserve
        ).is_err());
        assert!(ex.bulkheads.get(&ExternalChain::SolanaMainnet).unwrap().is_paused);

        // কিন্তু Equinox (EQX) এবং Bitcoin ১০০% সচল ও নিরাপদ থাকবে! (Zero Cross-Chain Contagion)
        assert!(!ex.bulkheads.get(&ExternalChain::EquinoxL1).unwrap().is_paused);
        assert!(!ex.bulkheads.get(&ExternalChain::BitcoinMainnet).unwrap().is_paused);

        // ৫. সেন্ট্রাল ম্যাচিং ইঞ্জিনে ট্রেড এক্সিকিউশন:
        // রহিম $2.50 (250 cents) দামে 500 EQX Sell অর্ডার বসাল
        let fills1 = ex.place_limit_order_eqx_usdt("seller_rahim", OrderSide::Sell, 250, 500_00).unwrap();
        assert!(fills1.is_empty());

        // করিম $2.50 দামে 500 EQX Buy অর্ডার বসাল -> সাথে সাথে ম্যাচ হয়ে ট্রেড সম্পন্ন!
        let fills2 = ex.place_limit_order_eqx_usdt("buyer_karim", OrderSide::Buy, 250, 500_00).unwrap();
        assert_eq!(fills2.len(), 1);
        assert_eq!(fills2[0].filled_eqx_atomic, 500_00);

        // ট্রেড শেষে করিমের ওয়ালেটে 500 EQX এবং রহিমের ওয়ালেটে 1,250 USDT জমা হয়েছে
        let karim_eqx = *ex.user_wallets.get("buyer_karim").unwrap().available.get(&SpotAsset::EQX).unwrap();
        let rahim_usdt = *ex.user_wallets.get("seller_rahim").unwrap().available.get(&SpotAsset::USDT).unwrap();
        assert_eq!(karim_eqx, 500_00);
        assert_eq!(rahim_usdt, 1_250_00);
    }
}
