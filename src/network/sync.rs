#![allow(dead_code)]
// src/network/sync.rs
// Equinox (EQX) L1 — Audit-Grade Header-First Sync Engine & BIP-152 Compact Block Reconstructor
// Features: Pre-Cache PoW & Finality Verification, Bounded Pending Cache (Anti-OOM DoS),
// Missing-Tx ShortID Cryptographic Matching & Post-Reconstruction Merkle Root Verification.

use crate::consensus::fork_choice::ForkResolver;
use crate::crypto::hash::{compute_short_txid, constant_time_eq, Hash256};
use crate::mempool::pool::Mempool;
use crate::network::banman::MisbehaviorReason;
use crate::network::peer_manager::{P2PMessage, PeerManager};
use crate::primitives::block::{Block, BlockHeader, CompactBlock};
use crate::primitives::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// এক বারে সর্বোচ্চ কতগুলো ব্লক হেডার ডাউনলোড বা প্রসেস করা যাবে
pub const MAX_HEADERS_PER_BATCH: u32 = 2_000;

/// র‍্যাম নিঃশেষ (OOM DoS) প্রতিরোধে সর্বোচ্চ কতগুলো অসম্পূর্ণ CompactBlock ক্যাশে রাখা যাবে
pub const MAX_PENDING_COMPACT_BLOCKS: usize = 64;

/// একটি কম্প্যাক্ট ব্লকে সর্বোচ্চ অনুমোদিত শর্ট ট্রানজ্যাকশন আইডি সংখ্যা
pub const MAX_SHORT_IDS_PER_COMPACT_BLOCK: usize = 10_000;

/// নোডের বর্তমান সিঙ্ক্রোনাইজেশন অবস্থা
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    Idle,
    DownloadingHeaders,
    DownloadingBlocks,
    Synced,
}

/// যে কম্প্যাক্ট ব্লকগুলোর ১-২টি ট্রানজ্যাকশন মেমপুলে পাওয়া যায়নি তাদের অস্থায়ী ক্যাশ এন্ট্রি
#[derive(Clone, Debug)]
struct PendingCompactEntry {
    pub compact_block: CompactBlock,
    pub missing_indices: Vec<usize>,
    pub received_timestamp: u64,
}

/// হেডার-ফার্স্ট ব্লক সিঙ্ক ও কম্প্যাক্ট ব্লক রিকনস্ট্রাকশন ইঞ্জিন
#[derive(Clone, Debug)]
pub struct BlockSyncEngine {
    pub state: SyncState,
    pending_compact_blocks: HashMap<Hash256, PendingCompactEntry>,
}

impl Default for BlockSyncEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockSyncEngine {
    pub fn new() -> Self {
        Self {
            state: SyncState::Idle,
            pending_compact_blocks: HashMap::new(),
        }
    }

    /// লোকাল চেইনের সর্বশেষ হাইটের পর থেকে নতুন ব্লক হেডার চাওয়ার মেসেজ তৈরি করে
    pub fn build_header_request(&mut self, local_best_height: u64) -> P2PMessage {
        self.state = SyncState::DownloadingHeaders;
        P2PMessage::GetHeaders {
            start_height: local_best_height.saturating_add(1),
            max_count: MAX_HEADERS_PER_BATCH,
        }
    }

    /// পিয়ারের কাছ থেকে আসা ব্লক হেডারগুলোর প্রুফ-অফ-ওয়ার্ক, প্যারেন্ট চেইন এবং BFT ফাইনালিটি যাচাই করে যুক্ত করে।
    /// অবৈধ হেডার পাঠালে পিয়ারকে স্বয়ংক্রিয়ভাবে পেনাল্টি দেয়।
    pub fn process_incoming_headers(
        &mut self,
        peer_addr: &str,
        headers: Vec<BlockHeader>,
        fork_resolver: &mut ForkResolver,
        peer_manager: &mut PeerManager,
        current_timestamp: u64,
    ) -> Result<usize, String> {
        if headers.is_empty() {
            self.state = SyncState::Synced;
            return Ok(0);
        }

        if headers.len() > (MAX_HEADERS_PER_BATCH as usize) {
            peer_manager.penalize_peer(
                peer_addr,
                MisbehaviorReason::SpammingOrRateLimit,
                current_timestamp,
            );
            return Err(format!(
                "পিয়ার অনুমোদিত সীমার ({}) চেয়ে বেশি হেডার পাঠিয়েছে",
                MAX_HEADERS_PER_BATCH
            ));
        }

        let mut accepted_count = 0usize;

        for hdr in headers {
            // ১. ফাইনালিটি চেকপয়েন্টের নিচের ব্লক ওভাররাইট করার চেষ্টা করলে তাৎক্ষণিক ১০০ পয়েন্ট ব্যান
            if hdr.height <= fork_resolver.finalized_height && hdr.height != 0 {
                peer_manager.penalize_peer(
                    peer_addr,
                    MisbehaviorReason::FinalityCheckpointViolation,
                    current_timestamp,
                );
                return Err(format!(
                    "পিয়ার {} ফাইনালিটি চেকপয়েন্ট (#{}) লঙ্ঘনের চেষ্টা করেছে!",
                    peer_addr, fork_resolver.finalized_height
                ));
            }

            // ২. প্রুফ-অফ-ওয়ার্ক (PoW) যাচাই
            if !hdr.meets_difficulty() {
                peer_manager.penalize_peer(
                    peer_addr,
                    MisbehaviorReason::InvalidBlockHeaderOrPoW,
                    current_timestamp,
                );
                return Err("পিয়ার অবৈধ প্রুফ-অফ-ওয়ার্ক (PoW) হেডার পাঠিয়েছে".to_string());
            }

            // ৩. মেইন চেইনে সংযোগ
            if let Err(e) = fork_resolver.append_to_main_chain(hdr) {
                peer_manager.penalize_peer(
                    peer_addr,
                    MisbehaviorReason::InvalidBlockHeaderOrPoW,
                    current_timestamp,
                );
                return Err(e);
            }

            accepted_count += 1;
        }

        self.state = SyncState::Synced;
        Ok(accepted_count)
    }

    /// নতুন কম্প্যাক্ট ব্লক (`CompactBlock`) আসার পর মেমপুল থেকে তাৎক্ষণিক পূর্ণাঙ্গ `Block` তৈরির চেষ্টা করে।
    /// - সব ট্রানজ্যাকশন মেমপুলে পাওয়া গেলে এবং মার্কেল রুট মিললে `Ok(Some(full_block))` রিটার্ন করে।
    /// - ১-২টি ট্রানজ্যাকশন মেমপুলে না থাকলে শুধুমাত্র সেই মিসিং ইনডেক্সগুলো চেয়ে `Err(P2PMessage::GetBlockTransactions)` রিটার্ন করে।
    pub fn handle_incoming_compact_block(
        &mut self,
        peer_addr: &str,
        compact: CompactBlock,
        mempool: &Mempool,
        fork_resolver: &ForkResolver,
        peer_manager: &mut PeerManager,
        current_timestamp: u64,
    ) -> Result<Option<Block>, P2PMessage> {
        let block_hash = compact.header.hash();

        // ১. প্রি-ক্যাশ ফাইনালিটি ও প্রুফ-অফ-ওয়ার্ক গার্ড
        if compact.header.height <= fork_resolver.finalized_height && compact.header.height != 0 {
            peer_manager.penalize_peer(
                peer_addr,
                MisbehaviorReason::FinalityCheckpointViolation,
                current_timestamp,
            );
            return Ok(None);
        }

        if !compact.header.meets_difficulty()
            || compact.coinbase_tx.is_none()
            || compact.short_txids.len() > MAX_SHORT_IDS_PER_COMPACT_BLOCK
        {
            peer_manager.penalize_peer(
                peer_addr,
                MisbehaviorReason::InvalidBlockHeaderOrPoW,
                current_timestamp,
            );
            return Ok(None);
        }

        // ২. মেমপুল থেকে রিকনস্ট্রাকশন চেষ্টা
        match mempool.reconstruct_from_compact_block(&compact) {
            Ok(reconstructed_block) => {
                // ক্রিটিক্যাল অডিট চেক: পুনর্গঠিত ব্লকের মার্কেল রুট, কয়েনবেস ও সাইজ বৈধ কি না তা পরীক্ষা করা
                if reconstructed_block.verify_structural_integrity().is_err() {
                    peer_manager.penalize_peer(
                        peer_addr,
                        MisbehaviorReason::InvalidBlockHeaderOrPoW,
                        current_timestamp,
                    );
                    return Ok(None);
                }
                self.state = SyncState::Synced;
                Ok(Some(reconstructed_block))
            }
            Err(missing_indices) => {
                // ৩. পেন্ডিং ক্যাশ লিমিট গার্ড (OOM DoS প্রতিরোধ)
                if self.pending_compact_blocks.len() >= MAX_PENDING_COMPACT_BLOCKS
                    && !self.pending_compact_blocks.contains_key(&block_hash)
                {
                    if let Some(oldest_hash) = self
                        .pending_compact_blocks
                        .iter()
                        .min_by_key(|(_, entry)| entry.received_timestamp)
                        .map(|(h, _)| *h)
                    {
                        self.pending_compact_blocks.remove(&oldest_hash);
                    }
                }

                self.pending_compact_blocks.insert(
                    block_hash,
                    PendingCompactEntry {
                        compact_block: compact,
                        missing_indices: missing_indices.clone(),
                        received_timestamp: current_timestamp,
                    },
                );

                self.state = SyncState::DownloadingBlocks;
                Err(P2PMessage::GetBlockTransactions {
                    block_hash,
                    missing_indices,
                })
            }
        }
    }

    /// পিয়ারের কাছ থেকে মিসিং ট্রানজ্যাকশনগুলো (`BlockTransactions`) পাওয়ার পর শর্ট-আইডি ও মার্কেল রুট যাচাই করে পূর্ণাঙ্গ ব্লক তৈরি করে
    pub fn complete_compact_block(
        &mut self,
        peer_addr: &str,
        block_hash: Hash256,
        missing_txs: Vec<Transaction>,
        mempool: &Mempool,
        peer_manager: &mut PeerManager,
        current_timestamp: u64,
    ) -> Result<Block, String> {
        let pending = self
            .pending_compact_blocks
            .remove(&block_hash)
            .ok_or_else(|| "এই ব্লক হ্যাশের জন্য কোনো পেন্ডিং কম্প্যাক্ট ব্লক পাওয়া যায়নি".to_string())?;

        if missing_txs.len() != pending.missing_indices.len() {
            peer_manager.penalize_peer(
                peer_addr,
                MisbehaviorReason::MalformedMessage,
                current_timestamp,
            );
            return Err(format!(
                "মিসিং ট্রানজ্যাকশন সংখ্যা মেলেনি: চাওয়া হয়েছিল {}, পাওয়া গেছে {}",
                pending.missing_indices.len(),
                missing_txs.len()
            ));
        }

        let compact = pending.compact_block;
        let nonce = compact.header.nonce;

        // ১. মেমপুলের বর্তমান ট্রানজ্যাকশনগুলোর শর্ট-আইডি ম্যাপ তৈরি
        let mut temp_mempool = mempool.clone();
        for tx in &missing_txs {
            // মিসিং ট্রানজ্যাকশনের ডিজিটাল সিগনেচার বৈধ কি না তা আগে চেক করা
            if tx.is_coinbase() || !tx.verify_signatures() {
                peer_manager.penalize_peer(
                    peer_addr,
                    MisbehaviorReason::InvalidSignature,
                    current_timestamp,
                );
                return Err("মিসিং ট্রানজ্যাকশনের সিগনেচার অবৈধ!".to_string());
            }
            let _ = temp_mempool.add_transaction(tx.clone());
        }

        // ২. পিয়ারের পাঠানো প্রতিটি মিসিং ট্রানজ্যাকশন আসলেই নির্ধারিত ইনডেক্সের ShortTxId-এর সাথে মেলে কি না তা যাচাই করা
        let mut missing_map: HashMap<usize, Transaction> =
            HashMap::with_capacity(missing_txs.len());

        for (idx_pos, &target_slot_idx) in pending.missing_indices.iter().enumerate() {
            let expected_short_id = compact
                .short_txids
                .get(target_slot_idx)
                .ok_or_else(|| "মিসিং ইনডেক্স কম্প্যাক্ট ব্লকের সীমার বাইরে".to_string())?;

            let provided_tx = &missing_txs[idx_pos];
            let actual_short_id = compute_short_txid(&provided_tx.txid(), nonce);

            if !constant_time_eq(&actual_short_id, expected_short_id) {
                peer_manager.penalize_peer(
                    peer_addr,
                    MisbehaviorReason::MalformedMessage,
                    current_timestamp,
                );
                return Err(format!(
                    "ইনডেক্স #{}-এর ট্রানজ্যাকশন শর্ট-আইডি (ShortTxId) মেলেনি!",
                    target_slot_idx
                ));
            }

            missing_map.insert(target_slot_idx, provided_tx.clone());
        }

        // ৩. পূর্ণাঙ্গ ট্রানজ্যাকশন তালিকা পুনর্গঠন
        let Some(coinbase) = compact.coinbase_tx.clone() else {
            return Err("কম্প্যাক্ট ব্লকে কয়েনবেস ট্রানজ্যাকশন অনুপস্থিত".to_string());
        };

        let mut full_txs = Vec::with_capacity(1 + compact.short_txids.len());
        full_txs.push(coinbase);

        // মেমপুল অথবা সদ্য প্রাপ্ত `missing_map` থেকে প্রতিটি স্লট পূরণ করা
        if let Ok(block_from_temp) = temp_mempool.reconstruct_from_compact_block(&compact) {
            full_txs = block_from_temp.transactions;
        } else {
            for (slot_idx, _) in compact.short_txids.iter().enumerate() {
                if let Some(tx) = missing_map.remove(&slot_idx) {
                    full_txs.push(tx);
                } else {
                    return Err(format!(
                        "কম্প্যাক্ট ব্লকের স্লট #{} পুনর্গঠন করা যায়নি",
                        slot_idx
                    ));
                }
            }
        }

        let reconstructed_block = Block {
            header: compact.header,
            transactions: full_txs,
        };

        // ৪. চূড়ান্ত ক্রিপ্টোগ্রাফিক Merkle Root, ডুপ্লিকেট Tx এবং ব্লক সাইজ যাচাই
        if let Err(e) = reconstructed_block.verify_structural_integrity() {
            peer_manager.penalize_peer(
                peer_addr,
                MisbehaviorReason::InvalidBlockHeaderOrPoW,
                current_timestamp,
            );
            return Err(format!(
                "পুনর্গঠিত কম্প্যাক্ট ব্লকের কাঠামোগত যাচাই ব্যর্থ: {}",
                e
            ));
        }

        self.state = SyncState::Synced;
        Ok(reconstructed_block)
    }

    #[inline]
    pub fn pending_compact_count(&self) -> usize {
        self.pending_compact_blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::primitives::transaction::{TxInput, TxOutput};
    use crate::state::outpoint::OutPoint;
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_compact_block_missing_tx_recovery_and_merkle_verification() {
        let mut sync_engine = BlockSyncEngine::new();
        let mut peer_manager = PeerManager::new();
        let mempool = Mempool::new(); // খালি মেমপুল (যাতে মিসিং ট্রানজ্যাকশন রিকভারি টেস্ট হয়)

        let kp = KeyPair::generate();
        let addr = pubkey_to_address(&kp.public_key());

        let mut genesis = Block::genesis(&addr, &addr, &addr, &addr);
        genesis.mine(Some(50_000));
        let fork_resolver = ForkResolver::new(genesis.header.clone());

        let cb1 = Transaction::new_coinbase(1, addr.clone(), 15_000, genesis.header.timestamp + 15);
        let mut user_tx = Transaction::new(
            vec![TxInput::new(OutPoint::new([0x22u8; 32], 0), kp.public_key())],
            vec![TxOutput::new(25 * COIN, addr)],
            genesis.header.timestamp + 15,
            15_000,
        );
        user_tx.sign_input(0, &kp).unwrap();

        let mut full_block = Block::new(
            1,
            genesis.hash(),
            vec![cb1, user_tx.clone()],
            2,
            genesis.header.timestamp + 15,
        );
        full_block.mine(Some(50_000));

        let compact = full_block.to_compact_block();

        // ১. যেহেতু মেমপুল খালি, তাই ইনডেক্স 0 মিসিং হিসেবে GetBlockTransactions রিকোয়েস্ট তৈরি হবে
        let res = sync_engine.handle_incoming_compact_block(
            "198.51.100.55:9333",
            compact,
            &mempool,
            &fork_resolver,
            &mut peer_manager,
            1_729_468_900,
        );

        assert_eq!(
            res,
            Err(P2PMessage::GetBlockTransactions {
                block_hash: full_block.hash(),
                missing_indices: vec![0],
            })
        );

        // ২. মিসিং ট্রানজ্যাকশনটি প্রদান করলে শর্ট-আইডি ও মার্কেল রুট মিলিয়ে পূর্ণাঙ্গ ব্লক ফিরে আসবে
        let completed = sync_engine
            .complete_compact_block(
                "198.51.100.55:9333",
                full_block.hash(),
                vec![user_tx],
                &mempool,
                &mut peer_manager,
                1_729_468_905,
            )
            .expect("Compact block completion must succeed");

        assert_eq!(completed, full_block);
    }
}
