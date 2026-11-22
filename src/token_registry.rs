use std::collections::HashMap;
use std::path::Path;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NativeTokenRegistry {
    /// asset_id -> metadata
    pub assets: HashMap<String, NativeTokenMeta>,
    /// uppercase ticker -> asset_id (prevents duplicate tickers)
    pub ticker_index: HashMap<String, String>,
    /// (asset_id, owner_address) -> balance
    /// Serialized as a Vec of (asset_id, owner, balance) tuples for JSON compatibility.
    #[serde(
        serialize_with = "serialize_balances",
        deserialize_with = "deserialize_balances"
    )]
    pub balances: HashMap<(String, String), u128>,
}

fn serialize_balances<S>(
    balances: &HashMap<(String, String), u128>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(balances.len()))?;
    for ((asset_id, owner), balance) in balances {
        seq.serialize_element(&(asset_id, owner, balance))?;
    }
    seq.end()
}

fn deserialize_balances<'de, D>(
    deserializer: D,
) -> Result<HashMap<(String, String), u128>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let entries: Vec<(String, String, u128)> = Deserialize::deserialize(deserializer)?;
    let mut map = HashMap::with_capacity(entries.len());
    for (asset_id, owner, balance) in entries {
        map.insert((asset_id, owner), balance);
    }
    Ok(map)
}

impl NativeTokenRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministic 64-hex AssetId without external crate dependencies.
    /// Cryptographic BLAKE3 AssetId with domain separation.
    pub fn compute_asset_id(creator: &str, ticker: &str, nonce: u64) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"EQUINOX_NATIVE_ASSET_V1");
        hasher.update(creator.as_bytes());
        hasher.update(b":");
        hasher.update(ticker.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        let hash = hasher.finalize();
        format!("eqx_asset_{}", &hash.to_hex()[..32])
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

    /// Atomic disk persistence: writes to .tmp then renames (crash-safe).
    pub fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create data dir: {}", e))?;
        }
        let tmp_path = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize error: {}", e))?;
        std::fs::write(&tmp_path, json.as_bytes())
            .map_err(|e| format!("Write tmp error: {}", e))?;
        std::fs::rename(&tmp_path, path)
            .map_err(|e| format!("Rename error: {}", e))?;
        Ok(())
    }

    /// Load registry state from disk.
    pub fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Read error: {}", e))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("Deserialize error: {}", e))
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

    #[test]
    fn test_blake3_domain_separated_asset_id() {
        let id1 = NativeTokenRegistry::compute_asset_id("creator_a", "TKN", 1);
        let id2 = NativeTokenRegistry::compute_asset_id("creator_a", "TKN", 2);
        let id3 = NativeTokenRegistry::compute_asset_id("creator_b", "TKN", 1);

        // All IDs must have eqx_asset_ prefix
        assert!(id1.starts_with("eqx_asset_"));
        // Different nonce => different IDs
        assert_ne!(id1, id2);
        // Different creator => different IDs
        assert_ne!(id1, id3);
        // IDs must be deterministic
        assert_eq!(id1, NativeTokenRegistry::compute_asset_id("creator_a", "TKN", 1));
    }

    #[test]
    fn test_atomic_disk_persistence_roundtrip() {
        let dir = std::env::temp_dir().join("eqx_token_persist_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token_registry.json");

        let mut reg = NativeTokenRegistry::new();
        let meta = reg
            .deploy_token(
                "eqx1persist".to_string(),
                "Persist Coin".to_string(),
                "PRC".to_string(),
                8,
                999_999,
                42,
            )
            .expect("deploy");
        reg.transfer(&meta.asset_id, "eqx1persist", "eqx1bob", 123)
            .expect("transfer");

        // Save atomically
        reg.save_to_disk(&path).expect("save_to_disk must succeed");
        assert!(path.exists());
        // .tmp must NOT exist after successful rename
        assert!(!path.with_extension("json.tmp").exists());

        // Load back
        let loaded = NativeTokenRegistry::load_from_disk(&path).expect("load_from_disk");
        assert_eq!(loaded.balance_of(&meta.asset_id, "eqx1persist"), 999_999 - 123);
        assert_eq!(loaded.balance_of(&meta.asset_id, "eqx1bob"), 123);
        assert!(loaded.assets.contains_key(&meta.asset_id));
        assert_eq!(loaded.ticker_index.get("PRC"), Some(&meta.asset_id));

        let _ = std::fs::remove_dir_all(&dir);
    }
}