// File: src/consensus/validator.rs
#![forbid(unsafe_code)]

use crate::config::{calculate_capped_block_reward, MAX_SUPPLY, PREMINE_SUPPLY};
use crate::consensus::tokenomics::TokenomicsEngine;
use crate::crypto::hash::{constant_time_eq, Hash256, ZERO_HASH};
use crate::primitives::block::{Block, BlockHeader};
use crate::primitives::transaction::TxOutput;
use crate::state::outpoint::OutPoint;
use crate::state::utxo_set::UtxoSet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// চেইন রিঅর্গ (Reorg) হলে ব্লকের সমস্ত UTXO ও Key-Image পরিবর্তন পূর্বাবস্থায় ফিরিয়ে নেওয়ার আনডু রেকর্ড
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockUndoData {
    pub block_height: u64,
    pub block_hash: Hash256,
    pub previous_total_supply_atomic: u64,
    pub spent_utxos: Vec<(OutPoint, TxOutput)>,
    pub created_outpoints: Vec<OutPoint>,
    pub added_key_images: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockValidationOutcome {
    pub block_height: u64,
    pub block_hash: Hash256,
    pub total_inputs_atomic: u64,
    pub total_outputs_atomic: u64,
    pub total_fees_collected: u64,
    pub new_total_supply_atomic: u64,
    pub new_state_merkle_root: Hash256,
    pub undo_data: BlockUndoData,
}

pub struct ConsensusValidator;

impl ConsensusValidator {
    /// ব্লক যাচাই ও অ্যাটমিকভাবে UTXO লেজারে প্রয়োগ করে এবং রিঅর্গ রোলব্যাকের জন্য `BlockUndoData` তৈরি করে
    pub fn validate_and_apply_block(
        block: &Block,
        parent_header: Option<&BlockHeader>,
        utxo_set: &mut UtxoSet,
        spent_key_images: &mut HashSet<Hash256>,
        current_total_supply: u64,
    ) -> Result<BlockValidationOutcome, String> {
        block.verify_structural_integrity()?;
        let height = block.header.height;

        match parent_header {
            None => {
                if height != 0 || !constant_time_eq(&block.header.prev_block_hash, &ZERO_HASH) {
                    return Err(
                        "Genesis block must have height 0 and zero prev_block_hash".to_string(),
                    );
                }
            }
            Some(parent) => {
                let expected_h = parent
                    .height
                    .checked_add(1)
                    .ok_or_else(|| "Block height overflow".to_string())?;
                if height != expected_h {
                    return Err(format!(
                        "Non-sequential block height: parent #{}, block #{}",
                        parent.height, height
                    ));
                }
                if !constant_time_eq(&block.header.prev_block_hash, &parent.hash()) {
                    return Err("Block prev_block_hash does not match parent hash".to_string());
                }
                if block.header.timestamp < parent.timestamp {
                    return Err("Block timestamp is earlier than parent timestamp".to_string());
                }
            }
        }

        let mut staged_utxos = utxo_set.clone();
        let mut staged_key_images = spent_key_images.clone();

        let mut block_inputs_sum: u64 = 0;
        let mut block_outputs_sum: u64 = 0;
        let mut total_fees_collected: u64 = 0;

        let mut undo_spent_utxos: Vec<(OutPoint, TxOutput)> = Vec::new();
        let mut undo_created_outpoints: Vec<OutPoint> = Vec::new();
        let mut undo_added_key_images: Vec<Hash256> = Vec::new();

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let tx_out_sum = tx.total_output_amount()?;

            if tx_idx == 0 {
                if !tx.is_coinbase() || tx.fee != 0 {
                    return Err(
                        "First transaction must be a valid coinbase with zero fee".to_string(),
                    );
                }
            } else {
                if tx.is_coinbase() {
                    return Err(format!("Unexpected coinbase at transaction index #{}", tx_idx));
                }
                if !tx.verify_signatures() {
                    return Err(format!(
                        "Ed25519 signature verification failed on transaction #{}",
                        tx_idx
                    ));
                }

                let mut tx_in_sum: u64 = 0;
                for inp in &tx.inputs {
                    let ki = inp.key_image();
                    if staged_key_images.contains(&ki) {
                        return Err(format!(
                            "Double-spend prevented: Key-Image already spent in tx #{}",
                            tx_idx
                        ));
                    }

                    let prev_utxo = staged_utxos
                        .verify_utxo_spendable(&inp.prev_out, &inp.public_key, height)?
                        .clone();

                    staged_utxos.remove_utxo(&inp.prev_out);
                    staged_key_images.insert(ki);

                    undo_spent_utxos.push((inp.prev_out.clone(), prev_utxo.clone()));
                    undo_added_key_images.push(ki);

                    tx_in_sum = tx_in_sum
                        .checked_add(prev_utxo.amount)
                        .ok_or_else(|| "Transaction input sum overflow".to_string())?;
                }

                let required_tx_in = tx_out_sum
                    .checked_add(tx.fee)
                    .ok_or_else(|| "Transaction output + fee overflow".to_string())?;

                if tx_in_sum != required_tx_in {
                    return Err(format!(
                        "Conservation of value violated in tx #{}: inputs ({}) != outputs + fee ({})",
                        tx_idx, tx_in_sum, required_tx_in
                    ));
                }

                block_inputs_sum = block_inputs_sum
                    .checked_add(tx_in_sum)
                    .ok_or_else(|| "Block input sum overflow".to_string())?;
                total_fees_collected = total_fees_collected
                    .checked_add(tx.fee)
                    .ok_or_else(|| "Block fee sum overflow".to_string())?;
            }

            let txid = tx.txid();
            for (vout_idx, output) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint::new(txid, vout_idx as u32);
                if staged_utxos.get_utxo(&outpoint).is_some() {
                    return Err("Duplicate OutPoint collision in UTXO set".to_string());
                }
                staged_utxos.add_utxo_checked(outpoint.clone(), output.clone())?;
                undo_created_outpoints.push(outpoint);
            }

            block_outputs_sum = block_outputs_sum
                .checked_add(tx_out_sum)
                .ok_or_else(|| "Block output sum overflow".to_string())?;
        }

        let allowed_subsidy = if height == 0 {
            if current_total_supply != 0 {
                return Err("Supply prior to genesis must be 0".to_string());
            }
            PREMINE_SUPPLY
        } else {
            calculate_capped_block_reward(height, current_total_supply)
        };

        let coinbase_out_sum = block.transactions[0].total_output_amount()?;
        let max_allowed_coinbase = allowed_subsidy
            .checked_add(total_fees_collected)
            .ok_or_else(|| "Coinbase subsidy + fees overflow".to_string())?;

        if height == 0 && coinbase_out_sum != PREMINE_SUPPLY {
            return Err(format!(
                "Genesis coinbase output ({}) must equal PREMINE_SUPPLY ({})",
                coinbase_out_sum, PREMINE_SUPPLY
            ));
        }
        if coinbase_out_sum > max_allowed_coinbase {
            return Err(format!(
                "Invalid coinbase output ({}) > allowed subsidy + fees ({})",
                coinbase_out_sum, max_allowed_coinbase
            ));
        }

        if block_inputs_sum > MAX_SUPPLY || block_outputs_sum > MAX_SUPPLY {
            return Err("Block inputs or outputs exceed 21M MAX_SUPPLY".to_string());
        }

        let verified_new_supply = TokenomicsEngine::verify_block_conservation_of_value(
            current_total_supply,
            block_inputs_sum,
            block_outputs_sum,
            allowed_subsidy,
        )?;

        let ledger_supply_check = staged_utxos.verify_supply_invariant()?;
        if ledger_supply_check != verified_new_supply {
            return Err("Staged UTXO set sum does not match verified total supply".to_string());
        }

        let new_state_merkle_root = staged_utxos.compute_state_root();
        let block_hash = block.hash();

        *utxo_set = staged_utxos;
        *spent_key_images = staged_key_images;

        Ok(BlockValidationOutcome {
            block_height: height,
            block_hash,
            total_inputs_atomic: block_inputs_sum,
            total_outputs_atomic: block_outputs_sum,
            total_fees_collected,
            new_total_supply_atomic: verified_new_supply,
            new_state_merkle_root,
            undo_data: BlockUndoData {
                block_height: height,
                block_hash,
                previous_total_supply_atomic: current_total_supply,
                spent_utxos: undo_spent_utxos,
                created_outpoints: undo_created_outpoints,
                added_key_images: undo_added_key_images,
            },
        })
    }

    /// চেইন রিঅর্গ (Reorg) হলে একটি ব্লকের সমস্ত UTXO ও Key-Image অ্যাটমিকভাবে রোলব্যাক করে পূর্বের স্টেটে ফিরিয়ে নেয়
    pub fn rollback_block(
        undo: &BlockUndoData,
        utxo_set: &mut UtxoSet,
        spent_key_images: &mut HashSet<Hash256>,
    ) -> Result<u64, String> {
        let mut staged_utxos = utxo_set.clone();
        let mut staged_key_images = spent_key_images.clone();

        for created_op in undo.created_outpoints.iter().rev() {
            if staged_utxos.remove_utxo(created_op).is_none() {
                return Err("Rollback failed: expected created UTXO not found".to_string());
            }
        }

        for (spent_op, spent_out) in undo.spent_utxos.iter().rev() {
            staged_utxos.add_utxo_checked(spent_op.clone(), spent_out.clone())?;
        }

        for ki in &undo.added_key_images {
            if !staged_key_images.remove(ki) {
                return Err("Rollback failed: expected Key-Image not found".to_string());
            }
        }

        let restored_supply = staged_utxos.verify_supply_invariant()?;
        if restored_supply != undo.previous_total_supply_atomic {
            return Err("Rollback supply invariant mismatch".to_string());
        }

        *utxo_set = staged_utxos;
        *spent_key_images = staged_key_images;
        Ok(restored_supply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::COIN;
    use crate::crypto::keys::KeyPair;
    use crate::primitives::transaction::{Transaction, TxInput, TxOutput};
    use crate::wallet::address::pubkey_to_address;

    #[test]
    fn test_block_validation_and_atomic_reorg_utxo_rollback() {
        let kp_owner = KeyPair::generate();
        let kp_receiver = KeyPair::generate();
        let kp_miner = KeyPair::generate();

        let owner_addr = pubkey_to_address(&kp_owner.public_key());
        let receiver_addr = pubkey_to_address(&kp_receiver.public_key());
        let miner_addr = pubkey_to_address(&kp_miner.public_key());

        let mut utxo_set = UtxoSet::new();
        let mut spent_images = HashSet::new();

        let mut genesis = Block::genesis(&owner_addr, &miner_addr, &miner_addr, &miner_addr);
        genesis.mine(Some(50_000));

        let gen_out = ConsensusValidator::validate_and_apply_block(
            &genesis,
            None,
            &mut utxo_set,
            &mut spent_images,
            0,
        )
        .unwrap();
        let gen_state_root = utxo_set.compute_state_root();
        let owner_outpoint = OutPoint::new(genesis.transactions[0].txid(), 3);

        // Apply Block #1 spending owner's UTXO
        let mut tx1 = Transaction::new(
            vec![TxInput::new(owner_outpoint, kp_owner.public_key())],
            vec![
                TxOutput::new(50_000 * COIN, receiver_addr),
                TxOutput::new(150_000 * COIN - 20_000, owner_addr),
            ],
            genesis.header.timestamp + 15,
            20_000,
        );
        tx1.sign_input(0, &kp_owner).unwrap();

        let cb1 = Transaction::new_coinbase(1, miner_addr, 20_000, genesis.header.timestamp + 15);
        let mut blk1 = Block::new(
            1,
            genesis.hash(),
            vec![cb1, tx1],
            2,
            genesis.header.timestamp + 15,
        );
        blk1.mine(Some(50_000));

        let b1_out = ConsensusValidator::validate_and_apply_block(
            &blk1,
            Some(&genesis.header),
            &mut utxo_set,
            &mut spent_images,
            gen_out.new_total_supply_atomic,
        )
        .unwrap();
        assert_ne!(utxo_set.compute_state_root(), gen_state_root);

        // Rollback Block #1 and verify state root & supply return bit-for-bit to Genesis state
        let restored_supply = ConsensusValidator::rollback_block(
            &b1_out.undo_data,
            &mut utxo_set,
            &mut spent_images,
        )
        .unwrap();
        assert_eq!(restored_supply, gen_out.new_total_supply_atomic);
        assert_eq!(utxo_set.compute_state_root(), gen_state_root);
        assert!(spent_images.is_empty());
    }
}