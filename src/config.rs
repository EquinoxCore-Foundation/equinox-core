#![allow(dead_code)]
// src/config.rs
// Equinox (EQX) L1 — Master Protocol Constants, 21M Hard-Cap, 5-Year Time-Lock & 120-Year Halving Engine

pub const TOKEN_NAME: &str = "Equinox";
pub const SYMBOL: &str = "EQX";
pub const TOKEN_DECIMALS: u8 = 8;

pub const COIN: u64 = 100_000_000;
pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;
pub const PREMINE_SUPPLY: u64 = 2_000_000 * COIN;
pub const MINEABLE_SUPPLY: u64 = MAX_SUPPLY - PREMINE_SUPPLY;

pub const PREMINE_EXCHANGE_LIQUIDITY: u64 = 300_000 * COIN;
pub const PREMINE_MARKETING_AND_DEV: u64 = 300_000 * COIN;
pub const PREMINE_ECOSYSTEM_RESERVE: u64 = 200_000 * COIN;
pub const PREMINE_OWNER_TOTAL: u64 = 1_200_000 * COIN;

pub const CHAIN_ID: u64 = 9333;
pub const PROTOCOL_VERSION: u32 = 1;
pub const NETWORK_MAGIC: [u8; 4] = *b"EQX1";
pub const ADDRESS_VERSION_BYTE: u8 = 0x21;
pub const DEFAULT_P2P_PORT: u16 = 9333;
pub const DEFAULT_RPC_PORT: u16 = 8545;

pub const TARGET_BLOCK_TIME_SECS: u64 = 15;
pub const BLOCKS_PER_DAY: u64 = 86_400 / TARGET_BLOCK_TIME_SECS;
pub const BLOCKS_PER_YEAR: u64 = BLOCKS_PER_DAY * 365;

pub const OWNER_TIER1_UNLOCKED_AMOUNT: u64 = 200_000 * COIN;
pub const OWNER_TIER1_UNLOCK_HEIGHT: u64 = 0;

pub const OWNER_TIER2_LOCKED_AMOUNT: u64 = 500_000 * COIN;
pub const OWNER_TIER2_UNLOCK_HEIGHT: u64 = BLOCKS_PER_YEAR * 2;

pub const OWNER_TIER3_YEAR4_AMOUNT: u64 = 250_000 * COIN;
pub const OWNER_TIER3_YEAR4_UNLOCK_HEIGHT: u64 = BLOCKS_PER_YEAR * 4;

pub const OWNER_TIER3_YEAR5_AMOUNT: u64 = 250_000 * COIN;
pub const OWNER_TIER3_YEAR5_UNLOCK_HEIGHT: u64 = BLOCKS_PER_YEAR * 5;

pub const HALVING_DURATION_YEARS: u64 = 120;
pub const INITIAL_BLOCK_REWARD: u64 = 40_640_000;
pub const TAIL_EMISSION_REWARD: u64 = 100_000;

pub const MAX_BLOCK_SIZE_BYTES: usize = 2 * 1024 * 1024;
pub const MIN_RELAY_TX_FEE: u64 = 10_000;
pub const DAA_AVERAGING_WINDOW: u64 = 60;
pub const DAA_MAX_ADJUSTMENT_FACTOR: u64 = 4;
pub const BFT_FINALITY_CHECKPOINT_INTERVAL: u64 = 10;
pub const MAX_ALLOWED_REORG_DEPTH: u64 = 10;
pub const PEER_BAN_SCORE_THRESHOLD: u32 = 100;
pub const PEER_BAN_DURATION_SECS: u64 = 86_400;

pub fn calculate_block_reward(block_height: u64) -> u64 {
    if block_height == 0 {
        return PREMINE_SUPPLY;
    }
    let year_index = (block_height - 1) / BLOCKS_PER_YEAR;
    if year_index >= HALVING_DURATION_YEARS {
        return TAIL_EMISSION_REWARD;
    }

    let era = year_index / 4;
    let mut reward = INITIAL_BLOCK_REWARD as u128;
    for _ in 0..era {
        reward = (reward * 3) / 4;
    }

    let step_in_era = (year_index % 4) as u128;
    if step_in_era > 0 {
        let next_era_reward = (reward * 3) / 4;
        let diff = reward.saturating_sub(next_era_reward);
        reward = reward.saturating_sub((diff * step_in_era) / 4);
    }

    (reward as u64).max(TAIL_EMISSION_REWARD)
}

pub fn calculate_capped_block_reward(block_height: u64, current_total_supply: u64) -> u64 {
    if current_total_supply >= MAX_SUPPLY {
        return 0;
    }
    let remaining = MAX_SUPPLY - current_total_supply;
    calculate_block_reward(block_height).min(remaining)
}

pub fn get_unlocked_owner_allocation(current_block_height: u64) -> u64 {
    let mut unlocked = OWNER_TIER1_UNLOCKED_AMOUNT;
    if current_block_height >= OWNER_TIER2_UNLOCK_HEIGHT {
        unlocked = unlocked.saturating_add(OWNER_TIER2_LOCKED_AMOUNT);
    }
    if current_block_height >= OWNER_TIER3_YEAR4_UNLOCK_HEIGHT {
        unlocked = unlocked.saturating_add(OWNER_TIER3_YEAR4_AMOUNT);
    }
    if current_block_height >= OWNER_TIER3_YEAR5_UNLOCK_HEIGHT {
        unlocked = unlocked.saturating_add(OWNER_TIER3_YEAR5_AMOUNT);
    }
    unlocked.min(PREMINE_OWNER_TOTAL)
}

#[inline]
pub const fn is_timelock_expired(unlock_height: u64, current_block_height: u64) -> bool {
    current_block_height >= unlock_height
}


