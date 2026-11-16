#![allow(dead_code)]
// src/state/mod.rs
// Equinox (EQX) L1 — ইউটিএক্সও (UTXO) স্টেট লেজার, ক্রিপ্টোগ্রাফিক স্টেট রুট,
// ডিটারমিনিস্টিক কয়েন সিলেকশন এবং অ্যাটমিক ডিস্ক স্ন্যাপশট ইঞ্জিন।

pub mod coin_selection;
pub mod outpoint;
pub mod snapshot;
pub mod utxo_set;

pub use coin_selection::{CoinSelection, SelectionResult, DUST_CHANGE_THRESHOLD, MAX_INPUTS_PER_TX};
pub use outpoint::OutPoint;
pub use snapshot::{ChainstateSnapshot, SnapshotEnvelope};
pub use utxo_set::UtxoSet;
