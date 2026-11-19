#![forbid(unsafe_code)]

use core::cmp::Ordering;

pub const CHAIN_ID_MAINNET: u64 = 9333;
pub const ATOMIC_UNITS_PER_EQX: u128 = 100_000_000;
pub const MAX_SUPPLY_ATOMIC: u128 = 21_000_000 * ATOMIC_UNITS_PER_EQX;
pub const GENESIS_PREMINE_ATOMIC: u128 = 2_000_000 * ATOMIC_UNITS_PER_EQX;
pub const MINEABLE_SUPPLY_ATOMIC: u128 = 19_000_000 * ATOMIC_UNITS_PER_EQX;
pub const TARGET_BLOCK_SPACING_SECS: i128 = 15;
pub const ASERT_HALF_LIFE_SECS: i128 = 14_400; // 4 hours (960 blocks)
pub const EMISSION_SPEED_FACTOR: u128 = 13_345_740; // ~4.4-year smooth half-life -> ~120-year full tail

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusError {
    InvalidHeightOrder,
    InvalidHalfLife,
    InvalidValidatorSet,
    ReorgPastFinalizedCheckpoint {
        attempted_height: u64,
        finalized_height: u64,
    },
    SupplyCapViolation,
}

/// Deterministic 256-bit unsigned integer (little-endian limbs) for PoW target arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const MAX: Self = Self([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        limbs[3] = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        limbs[2] = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        limbs[1] = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        limbs[0] = u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        Self(limbs)
    }

    pub fn from_u128(val: u128) -> Self {
        Self([val as u64, (val >> 64) as u64, 0, 0])
    }

    /// Overflow-free 256-bit x 64-bit -> 320-bit wide product.
    pub fn mul_u64_wide(self, rhs: u64) -> [u64; 5] {
        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..4 {
            let prod = (self.0[i] as u128) * (rhs as u128) + carry;
            out[i] = prod as u64;
            carry = prod >> 64;
        }
        out[4] = carry as u64;
        out
    }

    pub fn meets_target(hash_be: [u8; 32], target: U256) -> bool {
        Self::from_be_bytes(hash_be) <= target
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn shift_wide_clamped(wide: [u64; 5], net_shift: i128, min_t: U256, max_t: U256) -> U256 {
    if wide == [0; 5] {
        return min_t;
    }
    if net_shift >= 256 {
        return max_t;
    }
    if net_shift <= -320 {
        return min_t;
    }

    let candidate = if net_shift < 0 {
        let s = (-net_shift) as u32;
        let limb_shift = (s / 64) as usize;
        let bit_shift = s % 64;
        let mut res = [0u64; 5];
        for i in 0..5 {
            if i + limb_shift < 5 {
                res[i] = wide[i + limb_shift] >> bit_shift;
                if bit_shift > 0 && i + limb_shift + 1 < 5 {
                    res[i] |= wide[i + limb_shift + 1] << (64 - bit_shift);
                }
            }
        }
        if res[4] != 0 {
            return max_t;
        }
        U256([res[0], res[1], res[2], res[3]])
    } else {
        if wide[4] != 0 {
            return max_t;
        }
        let s = net_shift as u32;
        if s > 0 {
            for bit_idx in (256 - s)..256 {
                let limb = (bit_idx / 64) as usize;
                let offset = bit_idx % 64;
                if ((wide[limb] >> offset) & 1) != 0 {
                    return max_t;
                }
            }
        }
        let limb_shift = (s / 64) as usize;
        let bit_shift = s % 64;
        let mut res = [0u64; 4];
        for i in (0..4).rev() {
            if i >= limb_shift {
                res[i] = wide[i - limb_shift] << bit_shift;
                if bit_shift > 0 && i > limb_shift {
                    res[i] |= wide[i - limb_shift - 1] >> (64 - bit_shift);
                }
            }
        }
        U256(res)
    };

    if candidate < min_t {
        min_t
    } else if candidate > max_t {
        max_t
    } else {
        candidate
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AsertConfig {
    pub target_spacing_secs: i128,
    pub half_life_secs: i128,
    pub min_target: U256,
    pub max_target: U256,
}

impl Default for AsertConfig {
    fn default() -> Self {
        Self {
            target_spacing_secs: TARGET_BLOCK_SPACING_SECS,
            half_life_secs: ASERT_HALF_LIFE_SECS,
            min_target: U256::ONE,
            // Safe initial mainnet boundary (highest 16 bits zeroed)
            max_target: U256([u64::MAX, u64::MAX, u64::MAX, 0x0000_FFFF_FFFF_FFFF]),
        }
    }
}

impl AsertConfig {
    /// Exact integer ASERT3-2d difficulty retargeting (zero floating-point).
    pub fn calculate_next_target(
        &self,
        anchor_height: u64,
        anchor_timestamp: u64,
        anchor_target: U256,
        parent_height: u64,
        parent_timestamp: u64,
    ) -> Result<U256, ConsensusError> {
        if self.half_life_secs <= 0 {
            return Err(ConsensusError::InvalidHalfLife);
        }
        if parent_height < anchor_height {
            return Err(ConsensusError::InvalidHeightOrder);
        }

        let height_diff = (parent_height - anchor_height) as i128;
        let time_diff = (parent_timestamp as i128) - (anchor_timestamp as i128);
        let ideal_time = (height_diff + 1).saturating_mul(self.target_spacing_secs);
        let delta = time_diff.saturating_sub(ideal_time);

        let exponent = delta.saturating_mul(65_536) / self.half_life_secs;
        let shifts = exponent >> 16; // Arithmetic floor shift
        let frac = (exponent - (shifts << 16)) as u128; // Guaranteed 0..65536

        // Cubic minimax polynomial approximation for 2^(frac / 65536) * 65536
        let x = frac;
        let x2 = x * x;
        let x3 = x2 * x;
        let poly = 195_766_423_245_049u128 * x
            + 971_821_376u128 * x2
            + 5_127u128 * x3
            + (1u128 << 47);
        let factor = 65_536u128 + (poly >> 48);

        let wide = anchor_target.mul_u64_wide(factor as u64);
        let net_shift = shifts - 16;
        Ok(shift_wide_clamped(wide, net_shift, self.min_target, self.max_target))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRewardSplit {
    pub total_subsidy: u128,
    pub miner_reward: u128,
    pub dao_treasury_reward: u128,
}

/// Strictly hard-capped 120-year smooth geometric emission (90% PoW Miner / 10% DAO Treasury).
pub fn calculate_block_subsidy(already_mined_atomic: u128) -> Result<BlockRewardSplit, ConsensusError> {
    if already_mined_atomic > MINEABLE_SUPPLY_ATOMIC {
        return Err(ConsensusError::SupplyCapViolation);
    }
    let remaining = MINEABLE_SUPPLY_ATOMIC - already_mined_atomic;
    if remaining == 0 {
        return Ok(BlockRewardSplit {
            total_subsidy: 0,
            miner_reward: 0,
            dao_treasury_reward: 0,
        });
    }

    let raw = remaining / EMISSION_SPEED_FACTOR;
    let total_subsidy = if raw == 0 { 1 } else { raw }.min(remaining);
    let dao_treasury_reward = total_subsidy / 10;
    let miner_reward = total_subsidy - dao_treasury_reward;

    Ok(BlockRewardSplit {
        total_subsidy,
        miner_reward,
        dao_treasury_reward,
    })
}

/// BFT Finality Guard preventing deep 51% chain reorganizations past finalized checkpoints.
#[derive(Debug, Clone, Copy)]
pub struct BftFinalityGuard {
    pub finalized_height: u64,
    pub finalized_hash: [u8; 32],
    pub quorum_bps: u16, // 6667 = 66.67% (> 2/3 Byzantine supermajority)
}

impl BftFinalityGuard {
    pub fn new(genesis_hash: [u8; 32]) -> Self {
        Self {
            finalized_height: 0,
            finalized_hash: genesis_hash,
            quorum_bps: 6667,
        }
    }

    pub fn verify_supermajority(
        &self,
        valid_unique_sigs: usize,
        total_validators: usize,
    ) -> Result<bool, ConsensusError> {
        if total_validators == 0 || valid_unique_sigs > total_validators {
            return Err(ConsensusError::InvalidValidatorSet);
        }
        let lhs = (valid_unique_sigs as u128) * 10_000;
        let rhs = (total_validators as u128) * (self.quorum_bps as u128);
        Ok(lhs >= rhs)
    }

    pub fn commit_checkpoint(
        &mut self,
        new_height: u64,
        new_hash: [u8; 32],
        valid_unique_sigs: usize,
        total_validators: usize,
    ) -> Result<bool, ConsensusError> {
        if new_height <= self.finalized_height {
            return Ok(false);
        }
        if self.verify_supermajority(valid_unique_sigs, total_validators)? {
            self.finalized_height = new_height;
            self.finalized_hash = new_hash;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn validate_reorg_base(&self, fork_common_ancestor_height: u64) -> Result<(), ConsensusError> {
        if fork_common_ancestor_height < self.finalized_height {
            return Err(ConsensusError::ReorgPastFinalizedCheckpoint {
                attempted_height: fork_common_ancestor_height,
                finalized_height: self.finalized_height,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asert_exact_steady_state() {
        let cfg = AsertConfig::default();
        let anchor = U256([0, 0, 0, 0x0000_1000_0000_0000]);
        // Exact 15s block time -> target must stay identical
        let next = cfg.calculate_next_target(0, 1_000_000, anchor, 0, 1_000_015).unwrap();
        assert_eq!(next, anchor);
    }

    #[test]
    fn test_asert_doubles_and_halves_on_halflife() {
        let cfg = AsertConfig::default();
        let anchor = U256([0, 0, 0, 0x0000_1000_0000_0000]);

        // 1 half-life slower -> target doubles (difficulty halves)
        let slower = cfg
            .calculate_next_target(0, 1_000_000, anchor, 0, 1_000_015 + ASERT_HALF_LIFE_SECS as u64)
            .unwrap();
        assert_eq!(slower, U256([0, 0, 0, 0x0000_2000_0000_0000]));

        // 1 half-life faster -> target halves (difficulty doubles)
        let faster = cfg
            .calculate_next_target(0, 1_000_000, anchor, 1000, 1_000_000 + (1001 * 15) - ASERT_HALF_LIFE_SECS as u64)
            .unwrap();
        assert_eq!(faster, U256([0, 0, 0, 0x0000_0800_0000_0000]));
    }

    #[test]
    fn test_emission_never_exceeds_hard_cap() {
        let mut mined = 0u128;
        let first = calculate_block_subsidy(mined).unwrap();
        assert_eq!(first.miner_reward + first.dao_treasury_reward, first.total_subsidy);
        assert!(first.total_subsidy > 100_000_000); // > 1 EQX initially

        // Simulate near end-of-supply boundary
        mined = MINEABLE_SUPPLY_ATOMIC - 5;
        for _ in 0..5 {
            let split = calculate_block_subsidy(mined).unwrap();
            mined += split.total_subsidy;
        }
        assert_eq!(mined, MINEABLE_SUPPLY_ATOMIC);
        let after_cap = calculate_block_subsidy(mined).unwrap();
        assert_eq!(after_cap.total_subsidy, 0);
        assert_eq!(GENESIS_PREMINE_ATOMIC + mined, MAX_SUPPLY_ATOMIC);
    }

    #[test]
    fn test_bft_finality_blocks_deep_51_percent_reorg() {
        let mut guard = BftFinalityGuard::new([0u8; 32]);
        // 6 of 10 is 60% -> must NOT finalize
        assert!(!guard.commit_checkpoint(100, [7u8; 32], 6, 10).unwrap());
        // 7 of 10 is 70% (>= 66.67%) -> MUST finalize
        assert!(guard.commit_checkpoint(100, [7u8; 32], 7, 10).unwrap());
        assert_eq!(guard.finalized_height, 100);
        // Any reorg attempt below height 100 must be rejected
        assert!(guard.validate_reorg_base(99).is_err());
        assert!(guard.validate_reorg_base(100).is_ok());
    }
}
