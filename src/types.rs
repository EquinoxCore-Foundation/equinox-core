// src/types.rs
//! Equinox Core (EQX) Fundamental Ledger & Tokenomics Data Structures

/// ২১ মিলিয়ন সর্বোচ্চ কয়েন সাপ্লাই (8 Decimal Precision: 1 EQX = 100,000,000 Sat/Unit)
pub const EQX_MAX_SUPPLY: u64 = 21_000_000 * 100_000_000;

/// UTXO রেফারেন্স পয়েন্টার (Transaction Hash + Output Index)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EqxOutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl EqxOutPoint {
    #[inline(always)]
    pub fn to_storage_key(&self) -> [u8; 32] {
        let mut key = self.txid;
        let v = self.vout.to_le_bytes();
        key[0] ^= v[0];
        key[1] ^= v[1];
        key[2] ^= v[2];
        key[3] ^= v[3];
        key
    }

    #[inline(always)]
    pub fn short_id(&self) -> u64 {
        let k = self.to_storage_key();
        u64::from_le_bytes(k[0..8].try_into().unwrap())
    }
}

/// Equinox UTXO স্টেট রেকর্ড (Time-Lock সাপোর্টসহ)
#[derive(Clone, Copy, Debug)]
pub struct EqxUtxoEntry {
    pub amount: u64,
    pub owner_address: [u8; 32],
    pub unlock_height: u64, // এই ব্লক হাইটের আগে কয়েন খরচ (Spend) করা যাবে না
    pub is_spent: bool,
}

/// Equinox নেটওয়ার্কের ট্রানজ্যাকশন স্ট্রাকচার
#[derive(Clone, Debug)]
pub struct EqxTransaction {
    pub txid: [u8; 32],
    pub inputs: Vec<EqxOutPoint>,
    pub outputs: Vec<EqxUtxoEntry>,
    pub fee: u64,
    pub weight: u64,
    pub sig_digest: [u8; 32],
}

impl EqxTransaction {
    #[inline(always)]
    pub fn short_sketch_id(&self) -> u64 {
        u64::from_le_bytes(self.txid[0..8].try_into().unwrap())
    }
}
ফাইল ২: src/sig_cache.rs (লক-ফ্রি সিগনেচার ক্যাশ ও রোলিং স্টেট হ্যাশ)
Rust
// src/sig_cache.rs
//! Equinox Core (EQX) Lock-Free Bit-Packed Signature Cache & Rolling State Commitment

use crate::types::{EqxOutPoint, EqxUtxoEntry};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::RwLock;

/// জিরো-কপি বাইনারি বাফার রিডার (মেমোরি অ্যালোকেশন ছাড়াই বাইট স্লাইস পড়ার জন্য)
pub struct EqxZeroCopySlice<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> EqxZeroCopySlice<'a> {
    #[inline(always)]
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    #[inline(always)]
    pub fn take_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.offset + len <= self.buffer.len() {
            let out = &self.buffer[self.offset..self.offset + len];
            self.offset += len;
            Some(out)
        } else {
            None
        }
    }
}

/// লক-ফ্রি বিট-প্যাকড সিগনেচার ভেরিফিকেশন ক্যাশ
pub struct EqxAtomicSigCache {
    buckets: Vec<RwLock<[u8; 32]>>,
    reclaim_bits: Vec<AtomicU8>,
    capacity: usize,
}

impl EqxAtomicSigCache {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(64);
        let mut buckets = Vec::with_capacity(cap);
        for _ in 0..cap {
            buckets.push(RwLock::new([0u8; 32]));
        }
        let bit_bytes = (cap + 7) / 8;
        let mut reclaim_bits = Vec::with_capacity(bit_bytes);
        for _ in 0..bit_bytes {
            reclaim_bits.push(AtomicU8::new(0xFF)); // শুরুতে সব স্লট লেখার জন্য উন্মুক্ত (1)
        }
        Self {
            buckets,
            reclaim_bits,
            capacity: cap,
        }
    }

    #[inline(always)]
    fn derive_indices(&self, digest: &[u8; 32]) -> [usize; 4] {
        let i0 = u64::from_le_bytes(digest[0..8].try_into().unwrap()) as usize % self.capacity;
        let i1 = u64::from_le_bytes(digest[8..16].try_into().unwrap()) as usize % self.capacity;
        let i2 = u64::from_le_bytes(digest[16..24].try_into().unwrap()) as usize % self.capacity;
        let i3 = u64::from_le_bytes(digest[24..32].try_into().unwrap()) as usize % self.capacity;
        [i0, i1, i2, i3]
    }

    #[inline(always)]
    fn is_reclaimable(&self, idx: usize) -> bool {
        (self.reclaim_bits[idx >> 3].load(Ordering::Relaxed) & (1u8 << (idx & 7))) != 0
    }

    #[inline(always)]
    fn set_occupied(&self, idx: usize) {
        self.reclaim_bits[idx >> 3].fetch_and(!(1u8 << (idx & 7)), Ordering::Relaxed);
    }

    #[inline(always)]
    fn set_reclaimable(&self, idx: usize) {
        self.reclaim_bits[idx >> 3].fetch_or(1u8 << (idx & 7), Ordering::Relaxed);
    }

    /// মেমপুলে ভেরিফাই হওয়া সিগনেচার ক্যাশে ঢোকানো
    pub fn insert(&self, mut sig_digest: [u8; 32]) {
        let mut prev = usize::MAX;
        for _ in 0..6 {
            let indices = self.derive_indices(&sig_digest);
            for &idx in &indices {
                if self.is_reclaimable(idx) {
                    if let Ok(mut slot) = self.buckets[idx].write() {
                        *slot = sig_digest;
                        self.set_occupied(idx);
                        return;
                    }
                }
            }
            let target = indices.into_iter().find(|&i| i != prev).unwrap_or(indices[0]);
            if let Ok(mut slot) = self.buckets[target].write() {
                std::mem::swap(&mut *slot, &mut sig_digest);
                self.set_occupied(target);
                prev = target;
            }
        }
    }

    /// ব্লক এক্সিকিউশনের সময় ক্যাশ থেকে চেক ও ফ্ল্যাগ রিলিজ করা
    pub fn verify_and_consume(&self, sig_digest: &[u8; 32]) -> bool {
        for &idx in &self.derive_indices(sig_digest) {
            if !self.is_reclaimable(idx) {
                if let Ok(slot) = self.buckets[idx].read() {
                    if &*slot == sig_digest {
                        self.set_reclaimable(idx);
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// রোলিং UTXO স্টেট হ্যাশ ইঞ্জিন (O(1) সময়ে গ্লোবাল UTXO স্টেট রুট আপডেট করে)
pub struct EqxRollingState {
    accumulators: [AtomicU64; 4],
}

impl EqxRollingState {
    pub fn new() -> Self {
        Self {
            accumulators: [
                AtomicU64::new(0x6A09_E667_F3BC_C908),
                AtomicU64::new(0xBB67_AE85_84CA_A73B),
                AtomicU64::new(0x3C6E_F372_FE94_F82B),
                AtomicU64::new(0xA54F_F53A_5F1D_36F1),
            ],
        }
    }

    #[inline(always)]
    fn hash_utxo_lanes(outpoint: &EqxOutPoint, utxo: &EqxUtxoEntry) -> [u64; 4] {
        let k = outpoint.to_storage_key();
        let a0 = u64::from_le_bytes(k[0..8].try_into().unwrap())
            .wrapping_add(utxo.amount)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let a1 = u64::from_le_bytes(k[8..16].try_into().unwrap())
            .wrapping_add(utxo.unlock_height)
            .wrapping_mul(0xBF58_476D_1CE4_E5B9);
        let a2 = u64::from_le_bytes(utxo.owner_address[0..8].try_into().unwrap())
            .wrapping_mul(0x94D0_49BB_1331_11EB);
        let a3 = u64::from_le_bytes(utxo.owner_address[8..16].try_into().unwrap())
            ^ a0.rotate_left(21);
        [a0, a1, a2, a3]
    }

    pub fn apply_new_utxo(&self, outpoint: &EqxOutPoint, utxo: &EqxUtxoEntry) {
        let lanes = Self::hash_utxo_lanes(outpoint, utxo);
        for i in 0..4 {
            self.accumulators[i].fetch_add(lanes[i], Ordering::Relaxed);
        }
    }

    pub fn remove_spent_utxo(&self, outpoint: &EqxOutPoint, utxo: &EqxUtxoEntry) {
        let lanes = Self::hash_utxo_lanes(outpoint, utxo);
        for i in 0..4 {
            self.accumulators[i].fetch_sub(lanes[i], Ordering::Relaxed);
        }
    }

    pub fn current_state_root(&self) -> [u8; 32] {
        let mut root = [0u8; 32];
        for i in 0..4 {
            let v = self.accumulators[i].load(Ordering::SeqCst);
            root[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        root
    }
}