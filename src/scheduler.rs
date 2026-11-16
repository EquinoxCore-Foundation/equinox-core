// src/scheduler.rs
//! Equinox Core (EQX) 64-Bit Thread-Aware Parallel Scheduler & Cluster Mempool Linearizer

use crate::types::{EqxOutPoint, EqxTransaction};
use std::collections::HashMap;

pub type EqxThreadBitmask = u64;

#[derive(Default, Clone, Copy)]
struct ResourceLock {
    owner_thread: Option<u8>,
    ref_count: u32,
}

/// ৬৪-বিট বিটমাস্ক ভিত্তিক প্যারালাল UTXO লক শিডিউলার
pub struct EqxParallelScheduler {
    max_threads: u8,
    locks: HashMap<[u8; 32], ResourceLock>,
}

impl EqxParallelScheduler {
    pub fn new(max_threads: u8) -> Self {
        assert!(max_threads > 0 && max_threads <= 64);
        Self {
            max_threads,
            locks: HashMap::with_capacity(32768),
        }
    }

    /// ট্রানজ্যাকশনটি কোন ওয়ার্কার থ্রেডে কনফ্লিক্ট ছাড়া রান করা যাবে তা নির্ধারণ করে
    pub fn try_acquire_inputs(&mut self, inputs: &[EqxOutPoint]) -> Option<u8> {
        let mut candidate_mask: EqxThreadBitmask = if self.max_threads == 64 {
            u64::MAX
        } else {
            (1u64 << self.max_threads) - 1
        };

        for input in inputs {
            let key = input.to_storage_key();
            if let Some(lock) = self.locks.get(&key) {
                if let Some(tid) = lock.owner_thread {
                    candidate_mask &= 1u64 << tid;
                }
            }
            if candidate_mask == 0 {
                return None; // কনফ্লিক্ট পাওয়া গেছে, পরের ব্যাচে রান হবে
            }
        }

        let chosen_thread = candidate_mask.trailing_zeros() as u8;
        for input in inputs {
            let key = input.to_storage_key();
            let entry = self.locks.entry(key).or_default();
            entry.owner_thread = Some(chosen_thread);
            entry.ref_count += 1;
        }

        Some(chosen_thread)
    }

    pub fn release_inputs(&mut self, inputs: &[EqxOutPoint]) {
        for input in inputs {
            let key = input.to_storage_key();
            if let Some(entry) = self.locks.get_mut(&key) {
                entry.ref_count = entry.ref_count.saturating_sub(1);
                if entry.ref_count == 0 {
                    self.locks.remove(&key);
                }
            }
        }
    }
}

/// মেমপুলের ফি-রেট (Feerate) অনুযায়ী লিনিয়ারাইজড ট্রানজ্যাকশন চাঙ্ক
#[derive(Clone, Debug)]
pub struct EqxLinearChunk {
    pub transactions: Vec<EqxTransaction>,
    pub aggregate_fee: u64,
    pub aggregate_weight: u64,
}

impl EqxLinearChunk {
    #[inline(always)]
    pub fn fee_per_kw(&self) -> u64 {
        if self.aggregate_weight == 0 {
            0
        } else {
            (self.aggregate_fee * 1000) / self.aggregate_weight
        }
    }
}

/// Prefix-Merging অ্যালগরিদম দিয়ে সর্বোচ্চ ফি-যুক্ত ব্লক টেমপ্লেট তৈরি
pub fn linearize_transactions(txs: Vec<EqxTransaction>) -> Vec<EqxLinearChunk> {
    let mut chunks: Vec<EqxLinearChunk> = Vec::with_capacity(txs.len());
    for tx in txs {
        let mut current = EqxLinearChunk {
            aggregate_fee: tx.fee,
            aggregate_weight: tx.weight,
            transactions: vec![tx],
        };
        while let Some(prev) = chunks.last() {
            if current.fee_per_kw() >= prev.fee_per_kw() {
                let mut merged = chunks.pop().unwrap();
                merged.aggregate_fee += current.aggregate_fee;
                merged.aggregate_weight += current.aggregate_weight;
                merged.transactions.extend(current.transactions);
                current = merged;
            } else {
                break;
            }
        }
        chunks.push(current);
    }
    chunks
}