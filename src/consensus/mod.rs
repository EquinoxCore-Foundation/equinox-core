#![allow(dead_code)]
// src/consensus/mod.rs
// Equinox (EQX) L1 — হাইব্রিড PoW + BFT কনসেনসাস, ASERT, টোকেনোমিক্স, রয়্যালটি, O(1) ডিভিডেন্ড
// এবং অ্যান্টি-সুপারকম্পিউটার/কোয়ান্টাম ল্যাটিস হাইপার-গার্ড মডিউল।

pub mod asert;
pub mod dividend;
pub mod fork_choice;
pub mod hyper_guard;
pub mod pow;
pub mod royalty;
pub mod tokenomics;
pub mod validator;

pub use asert::{AsertDifficultyEngine, ASERT_HALF_LIFE_SECS, MAX_COMPACT_NBITS, MIN_COMPACT_NBITS};
pub use dividend::{GlobalDividendDistributor, StakeholderPosition, DIVIDEND_PRECISION_SCALE};
pub use fork_choice::{ChainTipState, ForkResolver};
pub use hyper_guard::{
    HyperSecurityGuard, LatticeLweShield, SequentialVdfProof, TaprootMastGuard,
    ZkShieldedValueProof,
};
pub use pow::{
    ProofOfWorkEngine, DEFAULT_INITIAL_DIFFICULTY_BITS, MAX_FUTURE_BLOCK_TIME_SECS,
    MEDIAN_TIME_PAST_WINDOW, MIN_DIFFICULTY_BITS,
};
pub use royalty::{BlockRewardSplit, ProtocolRoyaltyEngine, TxFeeSplit};
pub use tokenomics::{DynamicFeeMarket, SupplyReport, TokenomicsEngine};
pub use validator::{BlockValidationOutcome, ConsensusValidator};