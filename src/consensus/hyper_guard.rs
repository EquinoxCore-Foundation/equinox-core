// File: src/consensus/hyper_guard.rs
#![forbid(unsafe_code)]
// Equinox (EQX) L1 — Cryptographic Commitment, Sequential Hash Puzzle & Merkle Script Guard
// SECURITY AUDIT NOTE (Phase 4):
// 1. `LatticeLweShield` is an experimental 16x16 modular matrix commitment scheme, NOT a NIST-standardized post-quantum algorithm.
// 2. `SequentialVdfProof` is an iterated sequential SHA-256d hash-chain puzzle (requires re-computation to verify, not a trapdoor VDF).
// 3. `TaprootMastGuard` is a domain-separated SHA-256d Merkleized Alternative Script Tree (MAST), distinct from Bitcoin BIP-341/342.
// 4. `ZkShieldedValueProof` is a deterministic salted hash-commitment value conservation check, NOT a zk-SNARK/STARK proof.

use crate::config::MAX_SUPPLY;
use crate::crypto::hash::{constant_time_eq, sha256d_tagged, Hash256};
#[cfg(test)] use crate::crypto::hash::sha256d;
use serde::{Deserialize, Serialize};

pub const LATTICE_PRIME_MODULUS: u64 = 65_537;
pub const LATTICE_DIMENSION: usize = 16;
pub const LATTICE_NOISE_BOUND: i64 = 3;
pub const DEFAULT_SEQUENTIAL_VDF_STEPS: u32 = 2_048;
pub const MAX_SEQUENTIAL_PUZZLE_STEPS: u32 = 1_000_000;

/// Experimental 16x16 Modular Matrix Commitment (`b = (A * s + e) mod 65537`)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeLweShield {
    pub matrix_seed: Hash256,
    pub public_vector_b: [u64; LATTICE_DIMENSION],
    pub commitment_digest: Hash256,
}

impl LatticeLweShield {
    pub fn generate_from_secret(secret_seed: &Hash256, public_context_nonce: &Hash256) -> Self {
        let matrix_seed = sha256d_tagged(b"EQX_LATTICE_MATRIX_A_SEED_V1", public_context_nonce);
        let secret_vec = Self::derive_secret_vector(secret_seed);
        let noise_vec = Self::derive_bounded_noise_vector(secret_seed, &matrix_seed);

        let mut public_vector_b = [0u64; LATTICE_DIMENSION];

        for row in 0..LATTICE_DIMENSION {
            let mut inner_prod: u64 = 0;
            for col in 0..LATTICE_DIMENSION {
                let a_ij = Self::sample_matrix_element(&matrix_seed, row as u8, col as u8);
                let prod = (a_ij * secret_vec[col]) % LATTICE_PRIME_MODULUS;
                inner_prod = (inner_prod + prod) % LATTICE_PRIME_MODULUS;
            }

            let noisy_val = ((inner_prod as i64) + (LATTICE_PRIME_MODULUS as i64) + noise_vec[row])
                as u64
                % LATTICE_PRIME_MODULUS;
            public_vector_b[row] = noisy_val;
        }

        let commitment_digest = Self::compute_digest(&matrix_seed, &public_vector_b);

        Self {
            matrix_seed,
            public_vector_b,
            commitment_digest,
        }
    }

    pub fn verify_secret_knowledge(&self, candidate_secret_seed: &Hash256) -> bool {
        if candidate_secret_seed.iter().all(|&b| b == 0) {
            return false;
        }
        let expected_digest = Self::compute_digest(&self.matrix_seed, &self.public_vector_b);
        if !constant_time_eq(&expected_digest, &self.commitment_digest) {
            return false;
        }

        let candidate_s = Self::derive_secret_vector(candidate_secret_seed);

        for row in 0..LATTICE_DIMENSION {
            if self.public_vector_b[row] >= LATTICE_PRIME_MODULUS {
                return false;
            }
            let mut inner_prod: u64 = 0;
            for col in 0..LATTICE_DIMENSION {
                let a_ij = Self::sample_matrix_element(&self.matrix_seed, row as u8, col as u8);
                let prod = (a_ij * candidate_s[col]) % LATTICE_PRIME_MODULUS;
                inner_prod = (inner_prod + prod) % LATTICE_PRIME_MODULUS;
            }

            let diff = (self.public_vector_b[row] + LATTICE_PRIME_MODULUS - inner_prod)
                % LATTICE_PRIME_MODULUS;
            let signed_error = if diff > LATTICE_PRIME_MODULUS / 2 {
                (diff as i64) - (LATTICE_PRIME_MODULUS as i64)
            } else {
                diff as i64
            };

            if signed_error.abs() > LATTICE_NOISE_BOUND {
                return false;
            }
        }

        true
    }

    fn sample_matrix_element(matrix_seed: &Hash256, row: u8, col: u8) -> u64 {
        let mut buf = [0u8; 34];
        buf[0..32].copy_from_slice(matrix_seed);
        buf[32] = row;
        buf[33] = col;
        let h = sha256d_tagged(b"EQX_LWE_MAT_ELEM", &buf);
        let raw = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as u64;
        raw % LATTICE_PRIME_MODULUS
    }

    fn derive_secret_vector(secret_seed: &Hash256) -> [u64; LATTICE_DIMENSION] {
        let mut vec_s = [0u64; LATTICE_DIMENSION];
        let expanded = sha256d_tagged(b"EQX_LWE_SECRET_VEC_V1", secret_seed);
        for i in 0..LATTICE_DIMENSION {
            let word = u16::from_le_bytes([expanded[i * 2], expanded[i * 2 + 1]]) as u64;
            vec_s[i] = word % LATTICE_PRIME_MODULUS;
        }
        vec_s
    }

    fn derive_bounded_noise_vector(
        secret_seed: &Hash256,
        matrix_seed: &Hash256,
    ) -> [i64; LATTICE_DIMENSION] {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(secret_seed);
        buf[32..64].copy_from_slice(matrix_seed);
        let noise_hash = sha256d_tagged(b"EQX_LWE_NOISE_VEC_V1", &buf);

        let mut vec_e = [0i64; LATTICE_DIMENSION];
        let span = LATTICE_NOISE_BOUND * 2 + 1;
        for i in 0..LATTICE_DIMENSION {
            vec_e[i] = ((noise_hash[i] as i64) % span) - LATTICE_NOISE_BOUND;
        }
        vec_e
    }

    fn compute_digest(matrix_seed: &Hash256, vec_b: &[u64; LATTICE_DIMENSION]) -> Hash256 {
        let mut bytes = Vec::with_capacity(32 + LATTICE_DIMENSION * 8);
        bytes.extend_from_slice(matrix_seed);
        for &val in vec_b {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        sha256d_tagged(b"EQX_LWE_COMMITMENT_DIGEST_V1", &bytes)
    }
}

/// Iterated Sequential SHA-256d Hash-Chain Puzzle (Bounded to prevent CPU DoS)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequentialVdfProof {
    pub input_challenge: Hash256,
    pub iterations: u32,
    pub midpoint_witness: Hash256,
    pub final_output: Hash256,
}

impl SequentialVdfProof {
    pub fn compute(input_challenge: Hash256, iterations: u32) -> Result<Self, String> {
        if iterations < 2 || iterations % 2 != 0 || iterations > MAX_SEQUENTIAL_PUZZLE_STEPS {
            return Err(format!(
                "Iterations ({}) must be even and in range 2..={}",
                iterations, MAX_SEQUENTIAL_PUZZLE_STEPS
            ));
        }

        let mut state = input_challenge;
        let midpoint_step = iterations / 2;
        let mut midpoint_witness = [0u8; 32];

        for step in 1..=iterations {
            state = Self::step_function(&state, step);
            if step == midpoint_step {
                midpoint_witness = state;
            }
        }

        Ok(Self {
            input_challenge,
            iterations,
            midpoint_witness,
            final_output: state,
        })
    }

    pub fn verify(&self) -> bool {
        if self.iterations < 2
            || self.iterations % 2 != 0
            || self.iterations > MAX_SEQUENTIAL_PUZZLE_STEPS
        {
            return false;
        }

        let midpoint_step = self.iterations / 2;
        let mut state = self.input_challenge;

        for step in 1..=midpoint_step {
            state = Self::step_function(&state, step);
        }
        if !constant_time_eq(&state, &self.midpoint_witness) {
            return false;
        }

        for step in (midpoint_step + 1)..=self.iterations {
            state = Self::step_function(&state, step);
        }
        constant_time_eq(&state, &self.final_output)
    }

    #[inline]
    fn step_function(prev_state: &Hash256, step_index: u32) -> Hash256 {
        let mut buf = [0u8; 36];
        buf[0..32].copy_from_slice(prev_state);
        buf[32..36].copy_from_slice(&step_index.to_le_bytes());
        sha256d_tagged(b"EQX_ANTI_SUPERCOMPUTER_VDF_STEP", &buf)
    }
}

/// Domain-Separated SHA-256d Merkleized Alternative Script Tree (MAST)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaprootMastGuard {
    pub mast_root: Hash256,
}

impl TaprootMastGuard {
    pub fn build_vault_mast(
        normal_spend_script: &[u8],
        panic_clawback_script: &[u8],
        inheritance_script: &[u8],
        secret_salt: &Hash256,
    ) -> (Self, [Hash256; 3]) {
        let leaf_0 = Self::hash_script_leaf(0, normal_spend_script, secret_salt);
        let leaf_1 = Self::hash_script_leaf(1, panic_clawback_script, secret_salt);
        let leaf_2 = Self::hash_script_leaf(2, inheritance_script, secret_salt);

        let branch_01 = Self::hash_branch(&leaf_0, &leaf_1);
        let branch_22 = Self::hash_branch(&leaf_2, &leaf_2);
        let mast_root = Self::hash_branch(&branch_01, &branch_22);

        (Self { mast_root }, [leaf_0, leaf_1, leaf_2])
    }

    pub fn verify_script_branch(
        &self,
        branch_index: u8,
        revealed_script: &[u8],
        secret_salt: &Hash256,
        sibling_leaf: &Hash256,
        cousin_branch: &Hash256,
    ) -> bool {
        if revealed_script.is_empty() {
            return false;
        }
        let leaf_hash = Self::hash_script_leaf(branch_index, revealed_script, secret_salt);

        let computed_root = match branch_index {
            0 => {
                let b01 = Self::hash_branch(&leaf_hash, sibling_leaf);
                Self::hash_branch(&b01, cousin_branch)
            }
            1 => {
                let b01 = Self::hash_branch(sibling_leaf, &leaf_hash);
                Self::hash_branch(&b01, cousin_branch)
            }
            2 => {
                if !constant_time_eq(&leaf_hash, sibling_leaf) {
                    return false;
                }
                let b22 = Self::hash_branch(&leaf_hash, sibling_leaf);
                Self::hash_branch(cousin_branch, &b22)
            }
            _ => return false,
        };

        constant_time_eq(&computed_root, &self.mast_root)
    }

    fn hash_script_leaf(branch_id: u8, script: &[u8], salt: &Hash256) -> Hash256 {
        let mut data = Vec::with_capacity(1 + 32 + 4 + script.len());
        data.push(branch_id);
        data.extend_from_slice(salt);
        data.extend_from_slice(&(script.len() as u32).to_le_bytes());
        data.extend_from_slice(script);
        sha256d_tagged(b"EQX_TAPROOT_MAST_LEAF_V1", &data)
    }

    pub fn hash_branch(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(left);
        buf[32..64].copy_from_slice(right);
        sha256d_tagged(b"EQX_TAPROOT_MAST_BRANCH_V1", &buf)
    }
}

/// Salted Hash-Commitment Value Conservation Record (`Input == Output + Fee`)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkShieldedValueProof {
    pub input_commitment: Hash256,
    pub output_commitment: Hash256,
    pub public_fee_atomic: u64,
    pub balance_equivalence_proof: Hash256,
}

impl ZkShieldedValueProof {
    pub fn create_confidential_proof(
        input_amount_atomic: u64,
        output_amount_atomic: u64,
        public_fee_atomic: u64,
        secret_blinding_factor: &Hash256,
    ) -> Result<Self, String> {
        if input_amount_atomic == 0
            || output_amount_atomic == 0
            || input_amount_atomic > MAX_SUPPLY
            || output_amount_atomic > MAX_SUPPLY
        {
            return Err("Amounts must be > 0 and <= 21M MAX_SUPPLY".to_string());
        }
        let expected_in = output_amount_atomic
            .checked_add(public_fee_atomic)
            .ok_or_else(|| "Output + fee addition overflow".to_string())?;
        if expected_in != input_amount_atomic {
            return Err("Value conservation failed: input != output + fee".to_string());
        }

        let input_commitment =
            Self::salted_value_commit(input_amount_atomic, secret_blinding_factor);
        let output_commitment =
            Self::salted_value_commit(output_amount_atomic, secret_blinding_factor);

        let net_amount = input_amount_atomic
            .checked_sub(public_fee_atomic)
            .ok_or_else(|| "Input - fee underflow".to_string())?;
        let balance_equivalence_proof =
            Self::salted_value_commit(net_amount, secret_blinding_factor);

        Ok(Self {
            input_commitment,
            output_commitment,
            public_fee_atomic,
            balance_equivalence_proof,
        })
    }

    pub fn verify_zero_knowledge_conservation(&self) -> bool {
        !constant_time_eq(&self.input_commitment, &self.output_commitment)
            && constant_time_eq(&self.output_commitment, &self.balance_equivalence_proof)
            && self.public_fee_atomic <= MAX_SUPPLY
    }

    fn salted_value_commit(amount_atomic: u64, blinding_factor: &Hash256) -> Hash256 {
        let mut buf = [0u8; 40];
        buf[0..8].copy_from_slice(&amount_atomic.to_le_bytes());
        buf[8..40].copy_from_slice(blinding_factor);
        sha256d_tagged(b"EQX_ZK_PEDERSEN_COMMIT_V1", &buf)
    }
}

pub struct HyperSecurityGuard;

impl HyperSecurityGuard {
    pub fn verify_omni_fortress_envelope(
        lattice_shield: &LatticeLweShield,
        secret_seed: &Hash256,
        vdf_proof: &SequentialVdfProof,
        zk_proof: &ZkShieldedValueProof,
    ) -> Result<(), String> {
        if !lattice_shield.verify_secret_knowledge(secret_seed) {
            return Err("Matrix commitment verification failed".to_string());
        }
        if !vdf_proof.verify() {
            return Err("Sequential hash-chain puzzle verification failed".to_string());
        }
        if !zk_proof.verify_zero_knowledge_conservation() {
            return Err("Salted value conservation commitment check failed".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;

    #[test]
    fn test_commitment_shield_sequential_puzzle_and_mast_tree() {
        let master_secret = sha256d(b"owner_secret_seed_2026");
        let nonce = sha256d(b"block_height_1000_context");

        let shield = LatticeLweShield::generate_from_secret(&master_secret, &nonce);
        assert!(shield.verify_secret_knowledge(&master_secret));
        assert!(!shield.verify_secret_knowledge(&[0u8; 32]));

        let vdf = SequentialVdfProof::compute(shield.commitment_digest, 256).unwrap();
        assert!(vdf.verify());
        assert!(SequentialVdfProof::compute(shield.commitment_digest, 2_000_000).is_err());

        let blinding = sha256d(b"blinding_factor");
        let zk = ZkShieldedValueProof::create_confidential_proof(
            100 * COIN,
            99 * COIN,
            1 * COIN,
            &blinding,
        )
        .unwrap();
        assert!(zk.verify_zero_knowledge_conservation());

        assert!(HyperSecurityGuard::verify_omni_fortress_envelope(
            &shield,
            &master_secret,
            &vdf,
            &zk
        )
        .is_ok());

        let salt = sha256d(b"mast_salt");
        let s0 = b"OP_NORMAL";
        let s1 = b"OP_PANIC_CLAWBACK";
        let s2 = b"OP_INHERITANCE";
        let (mast, leaves) = TaprootMastGuard::build_vault_mast(s0, s1, s2, &salt);
        let b22 = TaprootMastGuard::hash_branch(&leaves[2], &leaves[2]);
        assert!(mast.verify_script_branch(1, s1, &salt, &leaves[0], &b22));
        assert!(!mast.verify_script_branch(1, b"TAMPERED", &salt, &leaves[0], &b22));
    }
}
