#![allow(dead_code)]
// src/primitives/mod.rs
// Equinox (EQX) L1 — কোর ব্লক, কম্প্যাক্ট ব্লক এবং UTXO ট্রানজ্যাকশন প্রিমিটিভস।

pub mod block;
pub mod transaction;

pub use block::{Block, BlockHeader, CompactBlock, GENESIS_TIMESTAMP, MAX_DIFFICULTY_BITS};
pub use transaction::{Transaction, TxInput, TxOutput};
