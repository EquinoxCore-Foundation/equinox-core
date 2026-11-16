// File: Equinox-Super-Wallet/crates/runtime-governance/src/lib.rs
#![forbid(unsafe_code)]

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

pub const SHARD_COUNT: usize = 64;
pub const GOVERNANCE_SUPERMAJORITY_BPS: u64 = 6_700; // 67.00% quorum required

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("Empty batch submitted to parallel executor")]
    EmptyBatch,
    #[error("Shard #{shard_id} insufficient balance for user {user_id}: required {required}, available {available}")]
    InsufficientShardBalance {
        shard_id: usize,
        user_id: u64,
        required: u128,
        available: u128,
    },
    #[error("Duplicate operation nonce {nonce} for user {user_id} in shard #{shard_id}")]
    DuplicateOperationNonce {
        shard_id: usize,
        user_id: u64,
        nonce: u64,
    },
    #[error("Pruning error: {0}")]
    PruningError(String),
    #[error("Archive integrity checksum mismatch")]
    ArchiveCorrupted,
    #[error("Governance error: {0}")]
    GovernanceError(String),
}

// ============================================================================
// MODULE 9.1: REAL MULTI-CORE PARALLEL SHARD EXECUTION ENGINE (RAYON)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardOpKind {
    CreditDeposit,
    DebitWithdrawal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardOperation {
    pub user_id: u64,
    pub op_nonce: u64,
    pub kind: ShardOpKind,
    pub amount_atomic: u128,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IndependentShardState {
    pub shard_id: usize,
    pub user_balances: HashMap<u64, u128>,
    pub executed_nonces: HashSet<(u64, u64)>,
    pub total_reserve_atomic: u128,
    pub state_commitment_root: [u8; 32],
}

impl IndependentShardState {
    pub fn new(shard_id: usize) -> Self {
        Self {
            shard_id,
            user_balances: HashMap::new(),
            executed_nonces: HashSet::new(),
            total_reserve_atomic: 0,
            state_commitment_root: [0u8; 32],
        }
    }

    /// একটি একক শার্ডের ভেতরে অ্যাটমিক ব্যাচ এক্সিকিউশন (ব্যর্থ হলে পুরো শার্ড রোলব্যাক হয়)
    pub fn execute_shard_batch(&mut self, ops: &[ShardOperation]) -> Result<usize, RuntimeError> {
        if ops.is_empty() {
            return Ok(0);
        }

        let mut staged_balances = self.user_balances.clone();
        let mut staged_nonces = self.executed_nonces.clone();
        let mut staged_reserve = self.total_reserve_atomic;

        for op in ops {
            if op.amount_atomic == 0 {
                continue;
            }
            if !staged_nonces.insert((op.user_id, op.op_nonce)) {
                return Err(RuntimeError::DuplicateOperationNonce {
                    shard_id: self.shard_id,
                    user_id: op.user_id,
                    nonce: op.op_nonce,
                });
            }

            let user_bal = staged_balances.entry(op.user_id).or_insert(0);
            match op.kind {
                ShardOpKind::CreditDeposit => {
                    *user_bal = user_bal.saturating_add(op.amount_atomic);
                    staged_reserve = staged_reserve.saturating_add(op.amount_atomic);
                }
                ShardOpKind::DebitWithdrawal => {
                    if *user_bal < op.amount_atomic || staged_reserve < op.amount_atomic {
                        return Err(RuntimeError::InsufficientShardBalance {
                            shard_id: self.shard_id,
                            user_id: op.user_id,
                            required: op.amount_atomic,
                            available: *user_bal,
                        });
                    }
                    *user_bal -= op.amount_atomic;
                    staged_reserve -= op.amount_atomic;
                }
            }
        }

        // Compute deterministic SHA-256 commitment over sorted user balances
        let mut sorted_users: Vec<(&u64, &u128)> = staged_balances.iter().collect();
        sorted_users.sort_by_key(|&(uid, _)| *uid);

        let mut hasher = Sha256::new();
        hasher.update(b"EQX_SHARD_STATE_V1");
        hasher.update(&(self.shard_id as u32).to_le_bytes());
        hasher.update(&staged_reserve.to_le_bytes());
        for (uid, bal) in sorted_users {
            hasher.update(&uid.to_le_bytes());
            hasher.update(&bal.to_le_bytes());
        }

        self.user_balances = staged_balances;
        self.executed_nonces = staged_nonces;
        self.total_reserve_atomic = staged_reserve;
        self.state_commitment_root = hasher.finalize().into();

        Ok(ops.len())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelExecutionSummary {
    pub total_operations_executed: usize,
    pub active_shards_used: usize,
    pub global_state_merkle_root: [u8; 32],
}

pub struct ParallelShardExecutor {
    pub shards: Vec<IndependentShardState>,
}

impl Default for ParallelShardExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelShardExecutor {
    pub fn new() -> Self {
        let shards = (0..SHARD_COUNT).map(IndependentShardState::new).collect();
        Self { shards }
    }

    #[inline]
    pub fn shard_for_user(user_id: u64) -> usize {
        let mut h = Sha256::new();
        h.update(&user_id.to_le_bytes());
        let digest = h.finalize();
        (u64::from_le_bytes(digest[0..8].try_into().unwrap()) as usize) % SHARD_COUNT
    }

    /// Rayon `par_iter_mut()` ব্যবহার করে ৬৪টি শার্ড মাল্টি-কোর CPU-তে সমান্তরালভাবে এক্সিকিউট করে
    pub fn execute_parallel_batch(
        &mut self,
        ops: &[ShardOperation],
    ) -> Result<ParallelExecutionSummary, RuntimeError> {
        if ops.is_empty() {
            return Err(RuntimeError::EmptyBatch);
        }

        let mut partitioned: Vec<Vec<ShardOperation>> = vec![Vec::new(); SHARD_COUNT];
        for op in ops {
            let s_idx = Self::shard_for_user(op.user_id);
            partitioned[s_idx].push(op.clone());
        }

        // True multi-core parallel execution across all 64 shards
        let results: Vec<Result<usize, RuntimeError>> = self
            .shards
            .par_iter_mut()
            .zip(partitioned.par_iter())
            .map(|(shard, shard_ops)| shard.execute_shard_batch(shard_ops))
            .collect();

        let mut total_executed = 0usize;
        let mut active_shards = 0usize;
        for res in results {
            let count = res?;
            if count > 0 {
                active_shards += 1;
                total_executed += count;
            }
        }

        let global_root = self.compute_global_merkle_root();
        Ok(ParallelExecutionSummary {
            total_operations_executed: total_executed,
            active_shards_used: active_shards,
            global_state_merkle_root: global_root,
        })
    }

    pub fn compute_global_merkle_root(&self) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = self
            .shards
            .iter()
            .map(|s| s.state_commitment_root)
            .collect();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| {
                    let mut h = Sha256::new();
                    h.update([0x01]);
                    h.update(pair[0]);
                    h.update(pair[1]);
                    h.finalize().into()
                })
                .collect();
        }
        level[0]
    }
}

// ============================================================================
// MODULE 9.2: REAL STATE PRUNING, SNAPSHOT & ARCHIVE ENGINE
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalStateRecord {
    pub record_key: String,
    pub amount_atomic: u64,
    pub created_at_height: u64,
    pub spent_at_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedEpochBlob {
    pub up_to_block_height: u64,
    pub pruned_record_count: usize,
    pub sha256_checksum: [u8; 32],
    pub serialized_records: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruningExecutionReport {
    pub cutoff_block_height: u64,
    pub records_pruned: usize,
    pub remaining_active_records: usize,
    pub actual_bytes_freed: usize,
    pub archive_checksum: [u8; 32],
}

pub struct StatePrunerAndArchiver {
    pub active_state: BTreeMap<String, HistoricalStateRecord>,
    pub archives: Vec<ArchivedEpochBlob>,
}

impl Default for StatePrunerAndArchiver {
    fn default() -> Self {
        Self::new()
    }
}

impl StatePrunerAndArchiver {
    pub fn new() -> Self {
        Self {
            active_state: BTreeMap::new(),
            archives: Vec::new(),
        }
    }

    pub fn insert_record(&mut self, record: HistoricalStateRecord) {
        self.active_state.insert(record.record_key.clone(), record);
    }

    /// শুধুমাত্র ফাইনালিটি পাওয়া এবং `retention_window_blocks`-এর চেয়ে পুরোনো Spent রেকর্ড প্রুন করে আর্কাইভে সংরক্ষণ করে
    pub fn prune_and_archive_spent_state(
        &mut self,
        finalized_height: u64,
        retention_window_blocks: u64,
    ) -> Result<PruningExecutionReport, RuntimeError> {
        if finalized_height <= retention_window_blocks {
            return Err(RuntimeError::PruningError(
                "Finalized height has not yet passed retention window".into(),
            ));
        }

        let cutoff_height = finalized_height - retention_window_blocks;
        let bytes_before = bincode::serialize(&self.active_state)
            .map_err(|e| RuntimeError::PruningError(e.to_string()))?
            .len();

        let mut pruned_list = Vec::new();
        let keys_to_prune: Vec<String> = self
            .active_state
            .iter()
            .filter_map(|(k, rec)| match rec.spent_at_height {
                Some(spent_h) if spent_h <= cutoff_height => Some(k.clone()),
                _ => None,
            })
            .collect();

        for key in keys_to_prune {
            if let Some(removed) = self.active_state.remove(&key) {
                pruned_list.push(removed);
            }
        }

        let serialized_records = bincode::serialize(&pruned_list)
            .map_err(|e| RuntimeError::PruningError(e.to_string()))?;
        let checksum: [u8; 32] = Sha256::digest(&serialized_records).into();

        let bytes_after = bincode::serialize(&self.active_state)
            .map_err(|e| RuntimeError::PruningError(e.to_string()))?
            .len();
        let actual_bytes_freed = bytes_before.saturating_sub(bytes_after);

        let blob = ArchivedEpochBlob {
            up_to_block_height: cutoff_height,
            pruned_record_count: pruned_list.len(),
            sha256_checksum: checksum,
            serialized_records,
        };
        self.archives.push(blob);

        Ok(PruningExecutionReport {
            cutoff_block_height: cutoff_height,
            records_pruned: pruned_list.len(),
            remaining_active_records: self.active_state.len(),
            actual_bytes_freed,
            archive_checksum: checksum,
        })
    }

    pub fn verify_and_restore_archive(
        blob: &ArchivedEpochBlob,
    ) -> Result<Vec<HistoricalStateRecord>, RuntimeError> {
        let computed: [u8; 32] = Sha256::digest(&blob.serialized_records).into();
        if computed != blob.sha256_checksum {
            return Err(RuntimeError::ArchiveCorrupted);
        }
        bincode::deserialize(&blob.serialized_records)
            .map_err(|e| RuntimeError::PruningError(e.to_string()))
    }
}

// ============================================================================
// MODULE 9.3: EXPLICIT ON-CHAIN PROTOCOL UPGRADE & GOVERNANCE MECHANISM
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalState {
    VotingActive,
    ApprovedTimelocked { activation_height: u64 },
    Executed,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeProposal {
    pub proposal_id: u64,
    pub target_protocol_version: u32,
    pub code_artifact_sha256: [u8; 32],
    pub voting_deadline_height: u64,
    pub activation_delay_blocks: u64,
    pub yes_stake_atomic: u128,
    pub no_stake_atomic: u128,
    pub voted_validators: HashSet<String>,
    pub state: ProposalState,
}

pub struct ProtocolGovernanceEngine {
    pub active_protocol_version: u32,
    pub validator_stakes: HashMap<String, u128>,
    pub proposals: HashMap<u64, UpgradeProposal>,
    next_proposal_id: u64,
}

impl ProtocolGovernanceEngine {
    pub fn new(initial_version: u32) -> Self {
        Self {
            active_protocol_version: initial_version,
            validator_stakes: HashMap::new(),
            proposals: HashMap::new(),
            next_proposal_id: 1,
        }
    }

    pub fn register_validator_stake(&mut self, validator_id: &str, stake_atomic: u128) {
        self.validator_stakes
            .insert(validator_id.to_string(), stake_atomic);
    }

    pub fn submit_upgrade_proposal(
        &mut self,
        target_version: u32,
        artifact_hash: [u8; 32],
        voting_deadline_height: u64,
        activation_delay_blocks: u64,
    ) -> Result<u64, RuntimeError> {
        if target_version <= self.active_protocol_version {
            return Err(RuntimeError::GovernanceError(
                "Target version must be strictly higher than active version".into(),
            ));
        }
        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        self.proposals.insert(
            id,
            UpgradeProposal {
                proposal_id: id,
                target_protocol_version: target_version,
                code_artifact_sha256: artifact_hash,
                voting_deadline_height,
                activation_delay_blocks: activation_delay_blocks.max(100),
                yes_stake_atomic: 0,
                no_stake_atomic: 0,
                voted_validators: HashSet::new(),
                state: ProposalState::VotingActive,
            },
        );
        Ok(id)
    }

    pub fn cast_vote(
        &mut self,
        proposal_id: u64,
        validator_id: &str,
        approve: bool,
        current_height: u64,
    ) -> Result<(), RuntimeError> {
        let stake = *self
            .validator_stakes
            .get(validator_id)
            .ok_or_else(|| RuntimeError::GovernanceError("Unregistered validator".into()))?;
        let prop = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| RuntimeError::GovernanceError("Proposal not found".into()))?;

        if prop.state != ProposalState::VotingActive || current_height > prop.voting_deadline_height
        {
            return Err(RuntimeError::GovernanceError("Voting period closed".into()));
        }
        if !prop.voted_validators.insert(validator_id.to_string()) {
            return Err(RuntimeError::GovernanceError(
                "Validator already voted on this proposal".into(),
            ));
        }

        if approve {
            prop.yes_stake_atomic += stake;
        } else {
            prop.no_stake_atomic += stake;
        }
        Ok(())
    }

    pub fn finalize_and_activate(
        &mut self,
        proposal_id: u64,
        current_height: u64,
    ) -> Result<ProposalState, RuntimeError> {
        let total_network_stake: u128 = self.validator_stakes.values().sum();
        if total_network_stake == 0 {
            return Err(RuntimeError::GovernanceError("Zero network stake".into()));
        }

        let prop = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| RuntimeError::GovernanceError("Proposal not found".into()))?;

        if prop.state == ProposalState::VotingActive {
            let yes_bps = ((prop.yes_stake_atomic * 10_000) / total_network_stake) as u64;
            if yes_bps >= GOVERNANCE_SUPERMAJORITY_BPS {
                let act_h = current_height + prop.activation_delay_blocks;
                prop.state = ProposalState::ApprovedTimelocked {
                    activation_height: act_h,
                };
            } else if current_height > prop.voting_deadline_height {
                prop.state = ProposalState::Rejected;
            }
        }

        if let ProposalState::ApprovedTimelocked { activation_height } = prop.state {
            if current_height >= activation_height {
                self.active_protocol_version = prop.target_protocol_version;
                prop.state = ProposalState::Executed;
            }
        }

        Ok(prop.state.clone())
    }
}

// ============================================================================
// MODULE 10: MANDATORY STRESS, FUZZ, PRUNING & GOVERNANCE TEST SUITE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module10_parallel_64_shard_50000_ops_load_and_stress_test() {
        let mut exec = ParallelShardExecutor::new();
        let mut batch = Vec::with_capacity(50_000);

        // 25,000 deposits followed by 25,000 withdrawals across 25,000 users
        for uid in 1..=25_000u64 {
            batch.push(ShardOperation {
                user_id: uid,
                op_nonce: 1,
                kind: ShardOpKind::CreditDeposit,
                amount_atomic: 1_000,
            });
            batch.push(ShardOperation {
                user_id: uid,
                op_nonce: 2,
                kind: ShardOpKind::DebitWithdrawal,
                amount_atomic: 400,
            });
        }

        let summary = exec.execute_parallel_batch(&batch).unwrap();
        assert_eq!(summary.total_operations_executed, 50_000);
        assert_eq!(summary.active_shards_used, SHARD_COUNT);
        assert_ne!(summary.global_state_merkle_root, [0u8; 32]);

        // Replay Attack Test: Re-submitting any operation with the same nonce must fail
        let replay_op = vec![ShardOperation {
            user_id: 1,
            op_nonce: 1,
            kind: ShardOpKind::CreditDeposit,
            amount_atomic: 1_000,
        }];
        assert!(matches!(
            exec.execute_parallel_batch(&replay_op),
            Err(RuntimeError::DuplicateOperationNonce { .. })
        ));
    }

    #[test]
    fn test_module10_real_state_pruning_bytes_freed_and_archive_recovery() {
        let mut pruner = StatePrunerAndArchiver::new();

        for i in 1..=500u64 {
            pruner.insert_record(HistoricalStateRecord {
                record_key: format!("UTXO_SPENT_{:05}", i),
                amount_atomic: 50_000,
                created_at_height: i,
                spent_at_height: Some(i + 10), // Spent between blocks 11..510
            });
        }
        // Add 100 unspent active records that must NOT be pruned
        for i in 501..=600u64 {
            pruner.insert_record(HistoricalStateRecord {
                record_key: format!("UTXO_UNSPENT_{:05}", i),
                amount_atomic: 100_000,
                created_at_height: i,
                spent_at_height: None,
            });
        }

        // Prune at finalized height 2,000 with retention window of 1,000 blocks (cutoff = 1,000)
        let report = pruner.prune_and_archive_spent_state(2_000, 1_000).unwrap();
        assert_eq!(report.records_pruned, 500);
        assert_eq!(report.remaining_active_records, 100);
        assert!(report.actual_bytes_freed > 10_000);

        // Verify archive restoration and tamper detection
        let mut blob = pruner.archives[0].clone();
        let restored = StatePrunerAndArchiver::verify_and_restore_archive(&blob).unwrap();
        assert_eq!(restored.len(), 500);

        blob.serialized_records[0] ^= 0xff;
        assert_eq!(
            StatePrunerAndArchiver::verify_and_restore_archive(&blob),
            Err(RuntimeError::ArchiveCorrupted)
        );
    }

    #[test]
    fn test_module10_protocol_governance_quorum_and_timelock_activation() {
        let mut gov = ProtocolGovernanceEngine::new(1);
        gov.register_validator_stake("val_1", 4_000);
        gov.register_validator_stake("val_2", 3_000);
        gov.register_validator_stake("val_3", 3_000);

        let prop_id = gov
            .submit_upgrade_proposal(2, [0xAAu8; 32], 1_000, 500)
            .unwrap();

        gov.cast_vote(prop_id, "val_1", true, 100).unwrap();
        gov.cast_vote(prop_id, "val_2", true, 110).unwrap(); // 7,000 / 10,000 = 70% (>= 67% quorum)

        let st_locked = gov.finalize_and_activate(prop_id, 200).unwrap();
        assert_eq!(
            st_locked,
            ProposalState::ApprovedTimelocked {
                activation_height: 700
            }
        );
        assert_eq!(gov.active_protocol_version, 1); // Not yet active before block 700

        // At block 700, timelock expires and protocol upgrades to v2
        let st_exec = gov.finalize_and_activate(prop_id, 700).unwrap();
        assert_eq!(st_exec, ProposalState::Executed);
        assert_eq!(gov.active_protocol_version, 2);
    }

    #[test]
    fn test_module10_deterministic_fuzz_boundary_and_underflow_invariants() {
        let mut exec = ParallelShardExecutor::new();
        let mut rng_state = 0x853c49e6748fea9bu64;

        // Deterministic PRNG Fuzzing over 2,000 randomized operations (including u128::MAX boundary values)
        for step in 0..2_000u64 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let rnd = rng_state.wrapping_mul(0x2545F4914F6CDD1D);

            let uid = (rnd % 128) + 1;
            let is_withdraw = (rnd & 1) == 1;
            let amt = if step % 50 == 0 {
                u128::MAX
            } else {
                (rnd % 10_000) as u128
            };

            let op = ShardOperation {
                user_id: uid,
                op_nonce: step + 1,
                kind: if is_withdraw {
                    ShardOpKind::DebitWithdrawal
                } else {
                    ShardOpKind::CreditDeposit
                },
                amount_atomic: amt,
            };

            // Must never panic or corrupt state regardless of fuzzed amounts
            let _ = exec.execute_parallel_batch(&[op]);
        }

        // Verify shard reserve equals exact sum of user balances across all 64 shards
        for shard in &exec.shards {
            let sum_users: u128 = shard
                .user_balances
                .values()
                .fold(0u128, |acc, &x| acc.saturating_add(x));
            assert_eq!(shard.total_reserve_atomic, sum_users);
        }
    }
}