use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidTicker,
    TickerAlreadyExists,
    ZeroSupply,
    TokenNotFound,
    InsufficientBalance,
    ArithmeticOverflow,
    InvalidAmount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTokenMeta {
    pub asset_id: String,
    pub name: String,
    pub ticker: String,
    pub decimals: u8,
    pub total_supply: u128,
    pub creator: String,
    pub mintable: bool,
    pub freezable: bool,
}

/// SPL-style Native Asset Registry enforced directly by Equinox Node consensus.
#[derive(Debug, Default, Clone)]
pub struct NativeTokenRegistry {
    /// asset_id -> metadata
    pub assets: HashMap<String, NativeTokenMeta>,
    /// uppercase ticker -> asset_id (prevents duplicate tickers)
    pub ticker_index: HashMap<String, String>,
    /// (asset_id, owner_address) -> balance
    pub balances: HashMap<(String, String), u128>,
}

impl NativeTokenRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministic 64-hex AssetId without external crate dependencies.
    pub fn compute_asset_id(creator: &str, ticker: &str, nonce: u64) -> String {
        let mut h1: u64 = 0xcbf29ce484222325;
        let mut h2: u64 = 0x84222325cbf29ce4;
        for b in creator.bytes().chain(ticker.bytes()).chain(nonce.to_le_bytes()) {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
            h2 = h2.rotate_left(7) ^ (b as u64).wrapping_mul(0x9e3779b97f4a7c15);
        }
        format!("eqx_asset_{:016x}{:016x}", h1, h2)
    }

    /// Deploys a new fixed-cap, anti-rug native token and credits creator.
    pub fn deploy_token(
        &mut self,
        creator: String,
        name: String,
        ticker: String,
        decimals: u8,
        total_supply: u128,
        nonce: u64,
    ) -> Result<NativeTokenMeta, TokenError> {
        let clean_ticker = ticker.trim().to_uppercase();
        if clean_ticker.len() < 2 || clean_ticker.len() > 10 || !clean_ticker.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(TokenError::InvalidTicker);
        }
        if total_supply == 0 {
            return Err(TokenError::ZeroSupply);
        }
        if self.ticker_index.contains_key(&clean_ticker) {
            return Err(TokenError::TickerAlreadyExists);
        }

        let asset_id = Self::compute_asset_id(&creator, &clean_ticker, nonce);
        let meta = NativeTokenMeta {
            asset_id: asset_id.clone(),
            name: name.trim().to_string(),
            ticker: clean_ticker.clone(),
            decimals,
            total_supply,
            creator: creator.clone(),
            mintable: false,
            freezable: false,
        };

        self.ticker_index.insert(clean_ticker, asset_id.clone());
        self.assets.insert(asset_id.clone(), meta.clone());
        self.balances.insert((asset_id, creator), total_supply);

        Ok(meta)
    }

    /// Transfers native token balance atomically with checked arithmetic.
    pub fn transfer(
        &mut self,
        asset_id: &str,
        from: &str,
        to: &str,
        amount: u128,
    ) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if !self.assets.contains_key(asset_id) {
            return Err(TokenError::TokenNotFound);
        }

        let from_key = (asset_id.to_string(), from.to_string());
        let to_key = (asset_id.to_string(), to.to_string());

        let sender_bal = *self.balances.get(&from_key).unwrap_or(&0);
        let new_sender_bal = sender_bal
            .checked_sub(amount)
            .ok_or(TokenError::InsufficientBalance)?;

        let receiver_bal = *self.balances.get(&to_key).unwrap_or(&0);
        let new_receiver_bal = receiver_bal
            .checked_add(amount)
            .ok_or(TokenError::ArithmeticOverflow)?;

        self.balances.insert(from_key, new_sender_bal);
        self.balances.insert(to_key, new_receiver_bal);
        Ok(())
    }

    pub fn balance_of(&self, asset_id: &str, owner: &str) -> u128 {
        *self
            .balances
            .get(&(asset_id.to_string(), owner.to_string()))
            .unwrap_or(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_and_transfer_native_token() {
        let mut reg = NativeTokenRegistry::new();
        let meta = reg
            .deploy_token(
                "eqx1creator".to_string(),
                "Equinox Gold".to_string(),
                "EGD".to_string(),
                6,
                1_000_000,
                1,
            )
            .expect("deploy should succeed");

        assert!(!meta.mintable);
        assert!(!meta.freezable);
        assert_eq!(reg.balance_of(&meta.asset_id, "eqx1creator"), 1_000_000);

        // Duplicate ticker must fail
        let dup = reg.deploy_token(
            "eqx1other".to_string(),
            "Fake Gold".to_string(),
            "egd".to_string(),
            6,
            500,
            2,
        );
        assert_eq!(dup, Err(TokenError::TickerAlreadyExists));

        // Transfer must update both balances atomically
        reg.transfer(&meta.asset_id, "eqx1creator", "eqx1alice", 250_000)
            .expect("transfer should succeed");
        assert_eq!(reg.balance_of(&meta.asset_id, "eqx1creator"), 750_000);
        assert_eq!(reg.balance_of(&meta.asset_id, "eqx1alice"), 250_000);
    }
}