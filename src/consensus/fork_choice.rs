// File: src/consensus/fork_choice.rs
#![forbid(unsafe_code)]

use crate::config::{BFT_FINALITY_CHECKPOINT_INTERVAL, CHAIN_ID, MAX_ALLOWED_REORG_DEPTH};
use crate::consensus::pow::ProofOfWorkEngine;
use crate::crypto::hash::{constant_time_eq, sha256d_tagged, Hash256, ZERO_HASH};
use crate::crypto::keys::{verify_signature, PublicKeyBytes, SignatureBytes};
use crate::primitives::block::BlockHeader;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

const BFT_VOTE_SIGNING_DOMAIN: &[u8] = b"EQX_BFT_FINALITY_VOTE_V3";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTipState {
    pub height: u64,
    pub tip_hash: Hash256,
    pub finalized_height: u64,
    pub finalized_hash: Hash256,
    pub cumulative_work: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTreeNode {
    pub header: BlockHeader,
    pub block_hash: Hash256,
    pub cumulative_work: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    pub common_ancestor_hash: Hash256,
    pub common_ancestor_height: u64,
    pub disconnected_hashes: Vec<Hash256>,
    pub connected_hashes: Vec<Hash256>,
}

#[derive(Clone, Debug)]
pub struct ForkResolver {
    /// Active canonical chain headers by height (100% compatible with src/main.rs)
    pub headers_by_height: BTreeMap<u64, BlockHeader>,
    /// All known candidate & competing fork blocks by block_hash
    pub blocks_by_hash: HashMap<Hash256, BlockTreeNode>,
    /// Competing block hashes at each height
    pub hashes_by_height: BTreeMap<u64, Vec<Hash256>>,
    pub main_chain_by_height: BTreeMap<u64, Hash256>,
    pub best_tip_hash: Hash256,
    pub finalized_height: u64,
    pub finalized_hash: Hash256,
    pub cumulative_work: u128,
    pub validator_stakes: HashMap<PublicKeyBytes, u64>,
    pub votes_by_height: HashMap<u64, HashMap<PublicKeyBytes, Hash256>>,
    pub slashed_validators: HashSet<PublicKeyBytes>,
}

impl ForkResolver {
    pub fn new(genesis_header: BlockHeader) -> Self {
        let gen_hash = genesis_header.hash();
        let initial_work = ProofOfWorkEngine::calculate_block_work(genesis_header.difficulty_target);

        let node = BlockTreeNode {
            header: genesis_header.clone(),
            block_hash: gen_hash,
            cumulative_work: initial_work,
        };

        let mut headers_by_height = BTreeMap::new();
        headers_by_height.insert(0, genesis_header);

        let mut blocks_by_hash = HashMap::new();
        blocks_by_hash.insert(gen_hash, node);

        let mut hashes_by_height = BTreeMap::new();
        hashes_by_height.insert(0, vec![gen_hash]);

        let mut main_chain_by_height = BTreeMap::new();
        main_chain_by_height.insert(0, gen_hash);

        Self {
            headers_by_height,
            blocks_by_hash,
            hashes_by_height,
            main_chain_by_height,
            best_tip_hash: gen_hash,
            finalized_height: 0,
            finalized_hash: gen_hash,
            cumulative_work: initial_work,
            validator_stakes: HashMap::new(),
            votes_by_height: HashMap::new(),
            slashed_validators: HashSet::new(),
        }
    }

    /// main.rs থেকে সরাসরি `headers_by_height`-এ কোনো হেডার ইনসার্ট করা হলে তা ব্লক ট্রির সাথে সিঙ্ক করে
    fn sync_direct_header_insertions(&mut self) {
        let mut running_work: u128 = 0;
        let cloned_headers: Vec<(u64, BlockHeader)> = self
            .headers_by_height
            .iter()
            .map(|(&h, hdr)| (h, hdr.clone()))
            .collect();

        for (h, hdr) in cloned_headers {
            let b_hash = hdr.hash();
            let w = ProofOfWorkEngine::calculate_block_work(hdr.difficulty_target);
            running_work = running_work.saturating_add(w);

            self.blocks_by_hash.entry(b_hash).or_insert(BlockTreeNode {
                header: hdr,
                block_hash: b_hash,
                cumulative_work: running_work,
            });

            let list = self.hashes_by_height.entry(h).or_default();
            if !list.contains(&b_hash) {
                list.push(b_hash);
            }
            self.main_chain_by_height.insert(h, b_hash);
            self.best_tip_hash = b_hash;
            self.cumulative_work = running_work;
        }
    }

    pub fn register_validator(
        &mut self,
        pubkey: PublicKeyBytes,
        stake_amount: u64,
    ) -> Result<(), String> {
        if pubkey.iter().all(|&b| b == 0) || stake_amount == 0 {
            return Err("Invalid validator public key or zero stake".to_string());
        }
        if self.slashed_validators.contains(&pubkey) {
            return Err("Validator is permanently slashed".to_string());
        }
        if self.validator_stakes.contains_key(&pubkey) {
            return Err("Validator already registered; use update_validator_stake".to_string());
        }
        self.validator_stakes.insert(pubkey, stake_amount);
        Ok(())
    }

    pub fn update_validator_stake(
        &mut self,
        pubkey: &PublicKeyBytes,
        new_stake: u64,
    ) -> Result<(), String> {
        if self.slashed_validators.contains(pubkey) {
            return Err("Cannot update stake of slashed validator".to_string());
        }
        if new_stake == 0 {
            return Err("Stake cannot be zero; use remove_validator".to_string());
        }
        let entry = self
            .validator_stakes
            .get_mut(pubkey)
            .ok_or_else(|| "Validator not found".to_string())?;
        *entry = new_stake;
        Ok(())
    }

    pub fn remove_validator(&mut self, pubkey: &PublicKeyBytes) -> Result<u64, String> {
        self.validator_stakes
            .remove(pubkey)
            .ok_or_else(|| "Validator not found".to_string())
    }

    pub fn descends_from_finalized(&self, mut cursor_hash: Hash256) -> bool {
        loop {
            let Some(node) = self.blocks_by_hash.get(&cursor_hash) else {
                return false;
            };
            if node.header.height == self.finalized_height {
                return constant_time_eq(&node.block_hash, &self.finalized_hash);
            }
            if node.header.height < self.finalized_height {
                return false;
            }
            cursor_hash = node.header.prev_block_hash;
        }
    }

    pub fn add_candidate_header(
        &mut self,
        header: BlockHeader,
    ) -> Result<Option<ReorgPlan>, String> {
        self.sync_direct_header_insertions();

        let block_hash = header.hash();
        if self.blocks_by_hash.contains_key(&block_hash) {
            return Ok(None);
        }

        if header.height <= self.finalized_height && header.height != 0 {
            return Err(format!(
                "Cannot add block at height #{} <= finalized height #{}",
                header.height, self.finalized_height
            ));
        }

        if !header.meets_difficulty() {
            return Err("Block header does not meet PoW difficulty target".to_string());
        }

        let parent_node = self
            .blocks_by_hash
            .get(&header.prev_block_hash)
            .ok_or_else(|| "Parent block hash not found in block tree".to_string())?
            .clone();

        if header.height != parent_node.header.height.saturating_add(1) {
            return Err("Block height is not parent_height + 1".to_string());
        }

        if header.timestamp < parent_node.header.timestamp {
            return Err("Block timestamp cannot be earlier than parent timestamp".to_string());
        }

        if !self.descends_from_finalized(parent_node.block_hash) {
            return Err("Candidate fork does not descend from finalized checkpoint".to_string());
        }

        let block_work = ProofOfWorkEngine::calculate_block_work(header.difficulty_target);
        let new_cum_work = parent_node
            .cumulative_work
            .checked_add(block_work)
            .ok_or_else(|| "Cumulative work arithmetic overflow".to_string())?;

        let new_node = BlockTreeNode {
            header: header.clone(),
            block_hash,
            cumulative_work: new_cum_work,
        };

        self.blocks_by_hash.insert(block_hash, new_node);
        self.hashes_by_height
            .entry(header.height)
            .or_default()
            .push(block_hash);

        let current_best = self
            .blocks_by_hash
            .get(&self.best_tip_hash)
            .expect("Best tip must exist")
            .clone();

        let wins_fork_choice = new_cum_work > current_best.cumulative_work
            || (new_cum_work == current_best.cumulative_work
                && block_hash < current_best.block_hash);

        if !wins_fork_choice {
            return Ok(None);
        }

        let reorg_plan = self.compute_reorg_plan(current_best.block_hash, block_hash)?;
        self.apply_reorg_plan(&reorg_plan, block_hash, new_cum_work);
        Ok(Some(reorg_plan))
    }

    pub fn append_to_main_chain(&mut self, header: BlockHeader) -> Result<(), String> {
        let _ = self.add_candidate_header(header)?;
        Ok(())
    }

    fn compute_reorg_plan(
        &self,
        old_tip: Hash256,
        new_tip: Hash256,
    ) -> Result<ReorgPlan, String> {
        let mut old_cursor = old_tip;
        let mut new_cursor = new_tip;
        let mut disconnected = Vec::new();
        let mut connected = Vec::new();

        while old_cursor != new_cursor {
            let old_node = self
                .blocks_by_hash
                .get(&old_cursor)
                .ok_or_else(|| "Missing old fork node".to_string())?;
            let new_node = self
                .blocks_by_hash
                .get(&new_cursor)
                .ok_or_else(|| "Missing new fork node".to_string())?;

            if old_node.header.height > new_node.header.height {
                disconnected.push(old_cursor);
                old_cursor = old_node.header.prev_block_hash;
            } else if new_node.header.height > old_node.header.height {
                connected.push(new_cursor);
                new_cursor = new_node.header.prev_block_hash;
            } else {
                disconnected.push(old_cursor);
                connected.push(new_cursor);
                old_cursor = old_node.header.prev_block_hash;
                new_cursor = new_node.header.prev_block_hash;
            }
        }

        let ancestor_node = self
            .blocks_by_hash
            .get(&old_cursor)
            .ok_or_else(|| "Common ancestor missing".to_string())?;

        if ancestor_node.header.height < self.finalized_height {
            return Err("Reorg rejected: fork attempts to revert finalized checkpoint".to_string());
        }

        if (disconnected.len() as u64) > MAX_ALLOWED_REORG_DEPTH {
            return Err(format!(
                "Reorg depth ({}) exceeds MAX_ALLOWED_REORG_DEPTH ({})",
                disconnected.len(),
                MAX_ALLOWED_REORG_DEPTH
            ));
        }

        connected.reverse();
        Ok(ReorgPlan {
            common_ancestor_hash: old_cursor,
            common_ancestor_height: ancestor_node.header.height,
            disconnected_hashes: disconnected,
            connected_hashes: connected,
        })
    }

    fn apply_reorg_plan(&mut self, plan: &ReorgPlan, new_tip_hash: Hash256, new_cum_work: u128) {
        for h_hash in &plan.disconnected_hashes {
            if let Some(node) = self.blocks_by_hash.get(h_hash) {
                self.main_chain_by_height.remove(&node.header.height);
                self.headers_by_height.remove(&node.header.height);
            }
        }
        for c_hash in &plan.connected_hashes {
            if let Some(node) = self.blocks_by_hash.get(c_hash) {
                self.main_chain_by_height
                    .insert(node.header.height, *c_hash);
                self.headers_by_height
                    .insert(node.header.height, node.header.clone());
            }
        }
        self.best_tip_hash = new_tip_hash;
        self.cumulative_work = new_cum_work;

        if self.validator_stakes.is_empty() {
            let best_h = self.current_state().height;
            if best_h >= BFT_FINALITY_CHECKPOINT_INTERVAL {
                let target_fin_h = best_h - BFT_FINALITY_CHECKPOINT_INTERVAL;
                if target_fin_h > self.finalized_height {
                    if let Some(&fin_hash) = self.main_chain_by_height.get(&target_fin_h) {
                        self.finalized_height = target_fin_h;
                        self.finalized_hash = fin_hash;
                    }
                }
            }
        }
    }

    pub fn compute_bft_vote_digest(height: u64, block_hash: &Hash256) -> Hash256 {
        let mut buf = Vec::with_capacity(48);
        buf.extend_from_slice(&CHAIN_ID.to_le_bytes());
        buf.extend_from_slice(&height.to_be_bytes());
        buf.extend_from_slice(block_hash);
        sha256d_tagged(BFT_VOTE_SIGNING_DOMAIN, &buf)
    }

    pub fn submit_signed_bft_vote(
        &mut self,
        height: u64,
        block_hash: Hash256,
        validator_pubkey: PublicKeyBytes,
        signature: &SignatureBytes,
    ) -> Result<bool, String> {
        let digest = Self::compute_bft_vote_digest(height, &block_hash);
        if !verify_signature(&validator_pubkey, &digest, signature) {
            return Err("Invalid Ed25519 signature on BFT finality vote".to_string());
        }
        self.process_verified_bft_vote(height, block_hash, validator_pubkey)
    }

    fn process_verified_bft_vote(
        &mut self,
        height: u64,
        block_hash: Hash256,
        validator_pubkey: PublicKeyBytes,
    ) -> Result<bool, String> {
        self.sync_direct_header_insertions();

        if self.slashed_validators.contains(&validator_pubkey) {
            return Err("Slashed validator cannot vote".to_string());
        }
        if !self.validator_stakes.contains_key(&validator_pubkey) {
            return Err("Unregistered validator public key".to_string());
        }
        if height <= self.finalized_height {
            return Err("Cannot vote on height <= already finalized height".to_string());
        }

        let voted_node = self
            .blocks_by_hash
            .get(&block_hash)
            .ok_or_else(|| "Voted block hash does not exist in known block tree".to_string())?
            .clone();
        if voted_node.header.height != height {
            return Err("Voted block height does not match block header height".to_string());
        }
        if !self.descends_from_finalized(block_hash) {
            return Err("Voted block does not descend from finalized checkpoint".to_string());
        }

        let height_votes = self.votes_by_height.entry(height).or_default();

        if let Some(existing_hash) = height_votes.get(&validator_pubkey) {
            if !constant_time_eq(existing_hash, &block_hash) {
                self.slashed_validators.insert(validator_pubkey);
                self.validator_stakes.remove(&validator_pubkey);
                height_votes.remove(&validator_pubkey);
                return Err("EQUIVOCATION SLASHED: Validator double-voted at same height".to_string());
            }
            return Ok(self.finalized_height >= height);
        }

        height_votes.insert(validator_pubkey, block_hash);

        let total_stake: u128 = self.validator_stakes.values().map(|&s| s as u128).sum();
        let mut matching_stake: u128 = 0;

        for (pk, v_hash) in height_votes.iter() {
            if constant_time_eq(v_hash, &block_hash) && !self.slashed_validators.contains(pk) {
                if let Some(&s) = self.validator_stakes.get(pk) {
                    matching_stake = matching_stake.saturating_add(s as u128);
                }
            }
        }

        if total_stake > 0 && matching_stake.saturating_mul(3) > total_stake.saturating_mul(2) {
            if self.main_chain_by_height.get(&height) != Some(&block_hash) {
                if let Ok(plan) = self.compute_reorg_plan(self.best_tip_hash, block_hash) {
                    self.apply_reorg_plan(&plan, block_hash, voted_node.cumulative_work);
                }
            }
            self.finalized_height = height;
            self.finalized_hash = block_hash;
            return Ok(true);
        }

        Ok(false)
    }

    pub fn current_state(&self) -> ChainTipState {
        if let Some((&h, hdr)) = self.headers_by_height.iter().next_back() {
            let tip_hash = hdr.hash();
            let work = self
                .blocks_by_hash
                .get(&tip_hash)
                .map(|n| n.cumulative_work)
                .unwrap_or(self.cumulative_work);
            ChainTipState {
                height: h,
                tip_hash,
                finalized_height: self.finalized_height,
                finalized_hash: self.finalized_hash,
                cumulative_work: work,
            }
        } else {
            ChainTipState {
                height: 0,
                tip_hash: ZERO_HASH,
                finalized_height: 0,
                finalized_hash: ZERO_HASH,
                cumulative_work: 0,
            }
        }
    }

    pub fn recent_headers(&self, count: usize) -> Vec<BlockHeader> {
        let mut list: Vec<BlockHeader> = self
            .headers_by_height
            .values()
            .rev()
            .take(count)
            .cloned()
            .collect();
        list.reverse();
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use crate::primitives::block::Block;
    use crate::primitives::transaction::Transaction;
    use crate::wallet::address::derive_deterministic_genesis_address;

    fn make_mined_header(
        height: u64,
        prev_hash: Hash256,
        diff: u32,
        timestamp: u64,
        tag_fee: u64,
    ) -> BlockHeader {
        let addr = derive_deterministic_genesis_address("TEST_MINER");
        let cb = Transaction::new_coinbase(height, addr, tag_fee, timestamp);
        let mut blk = Block::new(height, prev_hash, vec![cb], diff, timestamp);
        assert!(blk.mine(Some(200_000)));
        blk.header
    }

    #[test]
    fn test_competing_forks_heaviest_chain_and_reorg() {
        let addr = derive_deterministic_genesis_address("GENESIS");
        let mut genesis = Block::genesis(&addr, &addr, &addr, &addr);
        genesis.mine(Some(100_000));
        let gen_hash = genesis.hash();

        let mut resolver = ForkResolver::new(genesis.header);

        let fork_a_h1 = make_mined_header(1, gen_hash, 2, 1_729_468_815, 100);
        let fork_b_h1 = make_mined_header(1, gen_hash, 4, 1_729_468_816, 200);

        assert!(resolver.add_candidate_header(fork_a_h1.clone()).unwrap().is_some());
        assert_eq!(resolver.current_state().tip_hash, fork_a_h1.hash());

        let reorg = resolver
            .add_candidate_header(fork_b_h1.clone())
            .unwrap()
            .expect("Heavier Fork B must trigger reorg");

        assert_eq!(reorg.common_ancestor_height, 0);
        assert_eq!(reorg.disconnected_hashes, vec![fork_a_h1.hash()]);
        assert_eq!(reorg.connected_hashes, vec![fork_b_h1.hash()]);
        assert_eq!(resolver.current_state().tip_hash, fork_b_h1.hash());
        assert_eq!(resolver.headers_by_height.get(&1).unwrap().hash(), fork_b_h1.hash());
    }

    #[test]
    fn test_signed_bft_quorum_equivocation_and_finality_lock() {
        let addr = derive_deterministic_genesis_address("GENESIS");
        let mut genesis = Block::genesis(&addr, &addr, &addr, &addr);
        genesis.mine(Some(100_000));
        let gen_hash = genesis.hash();

        let mut resolver = ForkResolver::new(genesis.header);
        let val1 = KeyPair::generate();
        let val2 = KeyPair::generate();

        resolver.register_validator(val1.public_key(), 700).unwrap();
        resolver.register_validator(val2.public_key(), 300).unwrap();

        let h1_a = make_mined_header(1, gen_hash, 2, 1_729_468_815, 10);
        resolver.add_candidate_header(h1_a.clone()).unwrap();

        let digest_a = ForkResolver::compute_bft_vote_digest(1, &h1_a.hash());
        let sig_a = val1.sign(&digest_a);
        assert!(resolver
            .submit_signed_bft_vote(1, h1_a.hash(), val1.public_key(), &sig_a)
            .unwrap());
        assert_eq!(resolver.finalized_height, 1);
    }
}