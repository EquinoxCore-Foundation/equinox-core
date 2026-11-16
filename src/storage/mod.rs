#![allow(dead_code)]
// src/storage/mod.rs
// Equinox (EQX) L1 — অ্যাটমিক ও সেলফ-হিলিং বাইনারি ব্লক স্টোরেজ লেয়ার।

pub mod flatfile;

pub use flatfile::{
    BlockDiskLocation, FlatFileStorage, StorageError, DEFAULT_MAX_BLK_FILE_SIZE,
    MAX_RECORD_PAYLOAD_BYTES,
};
