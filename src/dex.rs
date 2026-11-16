// File: src/dex.rs
#![forbid(unsafe_code)]

use crate::crypto::hash::{constant_time_eq, sha256d, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DEX_FEE_NUMERATOR: u128 = 997;
pub const DEX_FEE_DENOMINATOR: u128 = 1000;
pub const MINIMUM_LIQUIDITY_LOCK: u128 = 1_000;
pub const DEX_SNAPSHOT_MAGIC: [u8; 4] = *b"EQXD";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DexDiskEnvelope {
    pub magic: [u8; 4],
    pub checksum: Hash256,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityPool {
    pub token_a: String,
    pub token_b: String,
    pub reserve_a: u128,
    pub reserve_b: u128,
    pub total_lp_shares: u128,
    pub lp_balances: HashMap<String, u128>,
}

impl LiquidityPool {
    pub fn new(token_a: String, token_b: String) -> Self {
        Self {
            token_a,
            token_b,
            reserve_a: 0,
            reserve_b: 0,
            total_lp_shares: 0,
            lp_balances: HashMap::new(),
        }
    }

    fn integer_sqrt_u128(n: u128) -> u128 {
        if n < 2 {
            return n;
        }
        let mut x0 = 1u128 << ((128 - n.leading_zeros() + 1) / 2);
        loop {
            let x1 = (x0 + n / x0) / 2;
            if x1 >= x0 {
                return x0;
            }
            x0 = x1;
        }
    }

    /// 128x128 -> 256-bit (hi, lo) exact multiplication for overflow-proof k invariant checks
    fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
        let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
        let a_hi = a >> 64;
        let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
        let b_hi = b >> 64;

        let p0 = a_lo * b_lo;
        let p1 = a_lo * b_hi;
        let p2 = a_hi * b_lo;
        let p3 = a_hi * b_hi;

        let cy = ((p0 >> 64) + (p1 & 0xFFFF_FFFF_FFFF_FFFF) + (p2 & 0xFFFF_FFFF_FFFF_FFFF)) >> 64;
        let lo = p0.wrapping_add(p1 << 64).wrapping_add(p2 << 64);
        let hi = p3 + (p1 >> 64) + (p2 >> 64) + cy;
        (hi, lo)
    }

    pub fn add_initial_liquidity(
        &mut self,
        provider: &str,
        amount_a: u128,
        amount_b: u128,
    ) -> Result<u128, String> {
        let clean_provider = provider.trim();
        if clean_provider.is_empty() || amount_a == 0 || amount_b == 0 {
            return Err("Provider and initial liquidity amounts must be non-empty and > 0".to_string());
        }
        if self.total_lp_shares > 0 {
            return Err("Pool already initialized; use add_liquidity".to_string());
        }

        let product = amount_a
            .checked_mul(amount_b)
            .ok_or_else(|| "Initial liquidity product overflow".to_string())?;
        let gross_shares = Self::integer_sqrt_u128(product);

        if gross_shares <= MINIMUM_LIQUIDITY_LOCK {
            return Err(format!(
                "Initial liquidity geometric mean ({}) must exceed MINIMUM_LIQUIDITY_LOCK ({})",
                gross_shares, MINIMUM_LIQUIDITY_LOCK
            ));
        }

        let user_shares = gross_shares - MINIMUM_LIQUIDITY_LOCK;
        self.reserve_a = amount_a;
        self.reserve_b = amount_b;
        self.total_lp_shares = gross_shares;

        self.lp_balances
            .insert("BURN_RESERVE_LOCK".to_string(), MINIMUM_LIQUIDITY_LOCK);
        self.lp_balances
            .insert(clean_provider.to_string(), user_shares);

        Ok(user_shares)
    }

    pub fn add_liquidity(
        &mut self,
        provider: &str,
        amount_a: u128,
        amount_b: u128,
    ) -> Result<u128, String> {
        if self.total_lp_shares == 0 {
            return self.add_initial_liquidity(provider, amount_a, amount_b);
        }
        let clean_provider = provider.trim();
        if clean_provider.is_empty() || amount_a == 0 || amount_b == 0 {
            return Err("Invalid liquidity deposit parameters".to_string());
        }

        let shares_a = amount_a
            .checked_mul(self.total_lp_shares)
            .ok_or_else(|| "LP share calculation overflow on token A".to_string())?
            / self.reserve_a;

        let shares_b = amount_b
            .checked_mul(self.total_lp_shares)
            .ok_or_else(|| "LP share calculation overflow on token B".to_string())?
            / self.reserve_b;

        let minted_shares = shares_a.min(shares_b);
        if minted_shares == 0 {
            return Err("Deposit amounts too small to mint 1 LP share".to_string());
        }

        let new_res_a = self
            .reserve_a
            .checked_add(amount_a)
            .ok_or_else(|| "Reserve A overflow".to_string())?;
        let new_res_b = self
            .reserve_b
            .checked_add(amount_b)
            .ok_or_else(|| "Reserve B overflow".to_string())?;
        let new_total_shares = self
            .total_lp_shares
            .checked_add(minted_shares)
            .ok_or_else(|| "Total LP shares overflow".to_string())?;

        let current_user = self.lp_balances.get(clean_provider).copied().unwrap_or(0);
        let new_user_bal = current_user
            .checked_add(minted_shares)
            .ok_or_else(|| "User LP balance overflow".to_string())?;

        self.reserve_a = new_res_a;
        self.reserve_b = new_res_b;
        self.total_lp_shares = new_total_shares;
        self.lp_balances
            .insert(clean_provider.to_string(), new_user_bal);

        Ok(minted_shares)
    }

    pub fn remove_liquidity(
        &mut self,
        provider: &str,
        lp_shares_to_burn: u128,
    ) -> Result<(u128, u128), String> {
        let clean_provider = provider.trim();
        if clean_provider == "BURN_RESERVE_LOCK" {
            return Err("Permanently locked minimum liquidity cannot be withdrawn".to_string());
        }
        if lp_shares_to_burn == 0 || self.total_lp_shares == 0 {
            return Err("Invalid LP burn amount".to_string());
        }

        let user_shares = self.lp_balances.get(clean_provider).copied().unwrap_or(0);
        if user_shares < lp_shares_to_burn {
            return Err("Insufficient LP share balance".to_string());
        }

        let out_a = lp_shares_to_burn
            .checked_mul(self.reserve_a)
            .ok_or_else(|| "Withdrawal calculation overflow on token A".to_string())?
            / self.total_lp_shares;

        let out_b = lp_shares_to_burn
            .checked_mul(self.reserve_b)
            .ok_or_else(|| "Withdrawal calculation overflow on token B".to_string())?
            / self.total_lp_shares;

        if out_a == 0 || out_b == 0 {
            return Err("Withdrawn token amounts would round to zero".to_string());
        }

        self.reserve_a = self
            .reserve_a
            .checked_sub(out_a)
            .ok_or_else(|| "Reserve A underflow".to_string())?;
        self.reserve_b = self
            .reserve_b
            .checked_sub(out_b)
            .ok_or_else(|| "Reserve B underflow".to_string())?;
        self.total_lp_shares = self
            .total_lp_shares
            .checked_sub(lp_shares_to_burn)
            .ok_or_else(|| "Total LP shares underflow".to_string())?;

        if let Some(bal) = self.lp_balances.get_mut(clean_provider) {
            *bal -= lp_shares_to_burn;
        }

        Ok((out_a, out_b))
    }

    pub fn get_swap_quote(&self, input_token: &str, input_amount: u128) -> Result<u128, String> {
        if input_amount == 0 {
            return Err("Swap input amount must be > 0".to_string());
        }

        let (input_reserve, output_reserve) = if input_token == self.token_a {
            (self.reserve_a, self.reserve_b)
        } else if input_token == self.token_b {
            (self.reserve_b, self.reserve_a)
        } else {
            return Err(format!("Unsupported token '{}' for this pool", input_token));
        };

        if input_reserve == 0 || output_reserve == 0 {
            return Err("Pool has zero liquidity".to_string());
        }

        let input_with_fee = input_amount
            .checked_mul(DEX_FEE_NUMERATOR)
            .ok_or_else(|| "Swap fee multiplication overflow".to_string())?;
        let numerator = input_with_fee
            .checked_mul(output_reserve)
            .ok_or_else(|| "Swap numerator overflow".to_string())?;
        let denominator = input_reserve
            .checked_mul(DEX_FEE_DENOMINATOR)
            .ok_or_else(|| "Swap denominator overflow".to_string())?
            .checked_add(input_with_fee)
            .ok_or_else(|| "Swap denominator addition overflow".to_string())?;

        let output_amount = numerator / denominator;
        if output_amount == 0 || output_amount >= output_reserve {
            return Err("Swap output is zero or drains entire reserve".to_string());
        }

        Ok(output_amount)
    }

    pub fn swap(
        &mut self,
        input_token: &str,
        input_amount: u128,
        min_output_amount: u128,
    ) -> Result<u128, String> {
        let output_amount = self.get_swap_quote(input_token, input_amount)?;
        if output_amount < min_output_amount {
            return Err(format!(
                "Slippage limit exceeded: output {} < minimum {}",
                output_amount, min_output_amount
            ));
        }

        let k_before = Self::mul_u128_wide(self.reserve_a, self.reserve_b);

        let (new_a, new_b) = if input_token == self.token_a {
            (
                self.reserve_a
                    .checked_add(input_amount)
                    .ok_or_else(|| "Reserve A overflow".to_string())?,
                self.reserve_b
                    .checked_sub(output_amount)
                    .ok_or_else(|| "Reserve B underflow".to_string())?,
            )
        } else {
            (
                self.reserve_a
                    .checked_sub(output_amount)
                    .ok_or_else(|| "Reserve A underflow".to_string())?,
                self.reserve_b
                    .checked_add(input_amount)
                    .ok_or_else(|| "Reserve B overflow".to_string())?,
            )
        };

        let k_after = Self::mul_u128_wide(new_a, new_b);
        if k_after < k_before {
            return Err("Constant-product invariant (k_after >= k_before) violated".to_string());
        }

        self.reserve_a = new_a;
        self.reserve_b = new_b;
        Ok(output_amount)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, file_path: P) -> Result<(), String> {
        let target = file_path.as_ref();
        let payload =
            bincode::serialize(self).map_err(|e| format!("DEX serialize error: {}", e))?;

        let envelope = DexDiskEnvelope {
            magic: DEX_SNAPSHOT_MAGIC,
            checksum: sha256d(&payload),
            payload,
        };

        let encoded =
            bincode::serialize(&envelope).map_err(|e| format!("DEX envelope error: {}", e))?;

        let mut tmp_os = target.as_os_str().to_os_string();
        tmp_os.push(".tmp");
        let tmp_path = PathBuf::from(tmp_os);

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| format!("DEX temp file error: {}", e))?;
            f.write_all(&encoded)
                .map_err(|e| format!("DEX write error: {}", e))?;
            f.sync_all()
                .map_err(|e| format!("DEX fsync error: {}", e))?;
        }

        fs::rename(&tmp_path, target).map_err(|e| format!("DEX atomic rename error: {}", e))?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(file_path: P) -> Result<Self, String> {
        let bytes =
            fs::read(file_path.as_ref()).map_err(|e| format!("DEX read error: {}", e))?;
        let envelope: DexDiskEnvelope =
            bincode::deserialize(&bytes).map_err(|e| format!("DEX decode error: {}", e))?;

        if !constant_time_eq(&envelope.magic, &DEX_SNAPSHOT_MAGIC) {
            return Err("Invalid DEX file magic bytes".to_string());
        }

        let actual_checksum = sha256d(&envelope.payload);
        if !constant_time_eq(&actual_checksum, &envelope.checksum) {
            return Err("DEX snapshot checksum mismatch".to_string());
        }

        bincode::deserialize(&envelope.payload).map_err(|e| format!("DEX state error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;

    #[test]
    fn test_dex_minimum_liquidity_lock_and_k_invariant() {
        let mut pool = LiquidityPool::new("EQX".to_string(), "USDT".to_string());

        // Dust initial liquidity <= 1000 must be rejected
        assert!(pool.add_initial_liquidity("ALICE", 500, 500).is_err());

        let user_shares = pool
            .add_initial_liquidity("ALICE", 1_000 * (COIN as u128), 5_000 * (COIN as u128))
            .unwrap();
        assert_eq!(
            pool.lp_balances.get("BURN_RESERVE_LOCK").copied().unwrap(),
            MINIMUM_LIQUIDITY_LOCK
        );
        assert_eq!(user_shares + MINIMUM_LIQUIDITY_LOCK, pool.total_lp_shares);

        let k_init = LiquidityPool::mul_u128_wide(pool.reserve_a, pool.reserve_b);
        let quote = pool.get_swap_quote("EQX", 100 * (COIN as u128)).unwrap();
        let out = pool.swap("EQX", 100 * (COIN as u128), quote).unwrap();
        assert_eq!(out, quote);

        let k_post = LiquidityPool::mul_u128_wide(pool.reserve_a, pool.reserve_b);
        assert!(k_post >= k_init);
    }
}