// src/bft_consensus.rs
//! Equinox Core (EQX) BFT Finality Engine & O(log N) Merkle Frontier Accumulator

pub struct EqxBftAccumulator {
    frontier: [[u8; 32]; 32],
    finalized_blocks: u64,
}

impl EqxBftAccumulator {
    pub fn new() -> Self {
        Self {
            frontier: [[0u8; 32]; 32],
            finalized_blocks: 0,
        }
    }

    #[inline(always)]
    fn compress_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        for i in 0..32 {
            digest[i] = left[i]
                .wrapping_mul(37)
                .wrapping_add(right[i].rotate_left(5))
                ^ (i as u8).wrapping_mul(13);
        }
        digest
    }

    /// নতুন BFT ব্লক ফাইনালিটি পেলে O(log N) সময়ে অপরিবর্তনীয় ফাইনালিটি রুট জেনারেট করে
    pub fn commit_finalized_block(&mut self, state_root: [u8; 32]) -> [u8; 32] {
        let mut node = state_root;
        let mut idx = self.finalized_blocks;
        self.finalized_blocks += 1;

        for depth in 0..32 {
            if (idx & 1) == 0 {
                self.frontier[depth] = node;
                break;
            } else {
                node = Self::compress_nodes(&self.frontier[depth], &node);
                idx >>= 1;
            }
        }
        node
    }
}