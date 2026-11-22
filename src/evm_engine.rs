use revm::{
    db::InMemoryDB,
    primitives::{Address, Bytes, ExecutionResult, Output, TransactTo, U256},
    Evm,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single journal entry capturing an EVM state mutation for deterministic replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvmJournalEntry {
    Fund { address: [u8; 20], balance_wei: String },
    Deploy { caller: [u8; 20], init_bytecode: Vec<u8>, gas_limit: u64 },
    Call { caller: [u8; 20], contract: [u8; 20], calldata: Vec<u8>, value: String, gas_limit: u64 },
}

/// Hybrid EVM execution engine embedded directly inside Equinox Core.
#[derive(Debug, Default)]
pub struct EquinoxEvmEngine {
    pub chain_id: u64,
    pub db: InMemoryDB,
    pub journal: Vec<EvmJournalEntry>,
}

impl EquinoxEvmEngine {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            db: InMemoryDB::default(),
            journal: Vec::new(),
        }
    }

    /// Credits an EVM address with EQX-wei balance for gas and value transfers.
    pub fn fund_account(&mut self, addr: Address, balance_wei: U256) {
        self.journal.push(EvmJournalEntry::Fund {
            address: addr.0.into(),
            balance_wei: balance_wei.to_string(),
        });
        let mut info = self.db.accounts.get(&addr).map(|a| a.info.clone()).unwrap_or_default();
        info.balance = info.balance.saturating_add(balance_wei);
        self.db.insert_account_info(addr, info);
    }

    /// Deploys compiled Solidity/EVM init bytecode and returns (contract_address, gas_used).
    pub fn deploy_contract(
        &mut self,
        caller: Address,
        init_bytecode: Vec<u8>,
        gas_limit: u64,
    ) -> Result<(Address, u64), String> {
        self.journal.push(EvmJournalEntry::Deploy {
            caller: caller.0.into(),
            init_bytecode: init_bytecode.clone(),
            gas_limit,
        });
        let chain_id = self.chain_id;
        let result = {
            let mut evm = Evm::builder()
                .with_db(&mut self.db)
                .modify_cfg_env(|cfg| {
                    cfg.chain_id = chain_id;
                })
                .modify_tx_env(|tx| {
                    tx.caller = caller;
                    tx.transact_to = TransactTo::Create;
                    tx.data = Bytes::from(init_bytecode);
                    tx.value = U256::ZERO;
                    tx.gas_limit = gas_limit;
                })
                .build();

            evm.transact_commit()
                .map_err(|e| format!("EVM deploy error: {:?}", e))?
        };

        match result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(contract_addr)),
                gas_used,
                ..
            } => Ok((contract_addr, gas_used)),
            ExecutionResult::Success { .. } => Err("Contract creation did not return an address".to_string()),
            ExecutionResult::Revert { gas_used, output } => {
                Err(format!("Deploy reverted (gas {}): {:?}", gas_used, output))
            }
            ExecutionResult::Halt { reason, gas_used } => {
                Err(format!("Deploy halted (gas {}): {:?}", gas_used, reason))
            }
        }
    }

    /// Executes a call against a deployed smart contract and returns (output_bytes, gas_used).
    pub fn call_contract(
        &mut self,
        caller: Address,
        contract: Address,
        calldata: Vec<u8>,
        value: U256,
        gas_limit: u64,
    ) -> Result<(Vec<u8>, u64), String> {
        self.journal.push(EvmJournalEntry::Call {
            caller: caller.0.into(),
            contract: contract.0.into(),
            calldata: calldata.clone(),
            value: value.to_string(),
            gas_limit,
        });
        let chain_id = self.chain_id;
        let result = {
            let mut evm = Evm::builder()
                .with_db(&mut self.db)
                .modify_cfg_env(|cfg| {
                    cfg.chain_id = chain_id;
                })
                .modify_tx_env(|tx| {
                    tx.caller = caller;
                    tx.transact_to = TransactTo::Call(contract);
                    tx.data = Bytes::from(calldata);
                    tx.value = value;
                    tx.gas_limit = gas_limit;
                })
                .build();

            evm.transact_commit()
                .map_err(|e| format!("EVM call error: {:?}", e))?
        };

        match result {
            ExecutionResult::Success {
                output: Output::Call(bytes),
                gas_used,
                ..
            } => Ok((bytes.to_vec(), gas_used)),
            ExecutionResult::Success { gas_used, .. } => Ok((Vec::new(), gas_used)),
            ExecutionResult::Revert { gas_used, output } => {
                Err(format!("Call reverted (gas {}): {:?}", gas_used, output))
            }
            ExecutionResult::Halt { reason, gas_used } => {
                Err(format!("Call halted (gas {}): {:?}", gas_used, reason))
            }
        }
    }

    /// Deterministic journal persistence: writes the journal to a JSON file atomically.
    pub fn save_journal<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create data dir: {}", e))?;
        }
        let tmp_path = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(&self.journal)
            .map_err(|e| format!("Serialize error: {}", e))?;
        std::fs::write(&tmp_path, json.as_bytes())
            .map_err(|e| format!("Write tmp error: {}", e))?;
        std::fs::rename(&tmp_path, path)
            .map_err(|e| format!("Rename error: {}", e))?;
        Ok(())
    }

    /// Loads and replays a journal to reconstruct the EVM state deterministically.
    pub fn load_and_replay_journal<P: AsRef<Path>>(chain_id: u64, path: P) -> Result<Self, String> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Read error: {}", e))?;
        let entries: Vec<EvmJournalEntry> = serde_json::from_str(&data)
            .map_err(|e| format!("Deserialize error: {}", e))?;

        let mut engine = Self::new(chain_id);
        for entry in entries {
            match entry {
                EvmJournalEntry::Fund { address, balance_wei } => {
                    let addr = Address::from(address);
                    let wei = balance_wei.parse::<u128>().map_err(|e| format!("Parse wei: {}", e))?;
                    // Directly apply without re-journaling
                    let mut info = engine.db.accounts.get(&addr).map(|a| a.info.clone()).unwrap_or_default();
                    info.balance = info.balance.saturating_add(U256::from(wei));
                    engine.db.insert_account_info(addr, info);
                    engine.journal.push(EvmJournalEntry::Fund { address, balance_wei });
                }
                EvmJournalEntry::Deploy { caller, init_bytecode, gas_limit } => {
                    let addr = Address::from(caller);
                    engine.journal.push(EvmJournalEntry::Deploy { caller, init_bytecode: init_bytecode.clone(), gas_limit });
                    let chain_id = engine.chain_id;
                    let _ = {
                        let mut evm = Evm::builder()
                            .with_db(&mut engine.db)
                            .modify_cfg_env(|cfg| { cfg.chain_id = chain_id; })
                            .modify_tx_env(|tx| {
                                tx.caller = addr;
                                tx.transact_to = TransactTo::Create;
                                tx.data = Bytes::from(init_bytecode);
                                tx.value = U256::ZERO;
                                tx.gas_limit = gas_limit;
                            })
                            .build();
                        evm.transact_commit()
                    };
                }
                EvmJournalEntry::Call { caller, contract, calldata, value, gas_limit } => {
                    let caller_addr = Address::from(caller);
                    let contract_addr = Address::from(contract);
                    let val = value.parse::<u128>().map(U256::from).unwrap_or(U256::ZERO);
                    engine.journal.push(EvmJournalEntry::Call { caller, contract, calldata: calldata.clone(), value, gas_limit });
                    let chain_id = engine.chain_id;
                    let _ = {
                        let mut evm = Evm::builder()
                            .with_db(&mut engine.db)
                            .modify_cfg_env(|cfg| { cfg.chain_id = chain_id; })
                            .modify_tx_env(|tx| {
                                tx.caller = caller_addr;
                                tx.transact_to = TransactTo::Call(contract_addr);
                                tx.data = Bytes::from(calldata);
                                tx.value = val;
                                tx.gas_limit = gas_limit;
                            })
                            .build();
                        evm.transact_commit()
                    };
                }
            }
        }
        Ok(engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revm_deploy_and_call_smart_contract() {
        let mut engine = EquinoxEvmEngine::new(9333);
        let deployer = Address::from([0x11; 20]);
        engine.fund_account(deployer, U256::from(10_000_000_000_000_000_000u128));

        // Minimal EVM init bytecode that deploys a runtime contract returning uint256(42)
        // Runtime: PUSH1 0x2a, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        let init_bytecode: Vec<u8> = vec![
            0x69, 0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
            0x60, 0x00, 0x52, 0x60, 0x0a, 0x60, 0x16, 0xf3,
        ];

        let (contract_addr, deploy_gas) = engine
            .deploy_contract(deployer, init_bytecode, 500_000)
            .expect("smart contract deploy should succeed");
        assert!(deploy_gas > 0);

        let (ret_bytes, call_gas) = engine
            .call_contract(deployer, contract_addr, vec![], U256::ZERO, 100_000)
            .expect("smart contract call should succeed");
        assert!(call_gas > 0);
        assert_eq!(ret_bytes.len(), 32);
        assert_eq!(ret_bytes[31], 42);
    }

    #[test]
    fn test_evm_journal_persistence_and_replay() {
        let dir = std::env::temp_dir().join("eqx_evm_journal_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal_path = dir.join("evm_state.json");

        // Build and exercise an engine
        let mut engine = EquinoxEvmEngine::new(9333);
        let deployer = Address::from([0x44; 20]);
        engine.fund_account(deployer, U256::from(10_000_000_000_000_000_000u128));

        let init_bytecode: Vec<u8> = vec![
            0x69, 0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
            0x60, 0x00, 0x52, 0x60, 0x0a, 0x60, 0x16, 0xf3,
        ];
        let (contract_addr, _) = engine.deploy_contract(deployer, init_bytecode, 500_000).unwrap();
        let (original_ret, _) = engine.call_contract(deployer, contract_addr, vec![], U256::ZERO, 100_000).unwrap();

        // Persist journal
        engine.save_journal(&journal_path).expect("save_journal must succeed");
        assert!(journal_path.exists());
        assert!(!journal_path.with_extension("json.tmp").exists());

        // Replay from journal
        let replayed = EquinoxEvmEngine::load_and_replay_journal(9333, &journal_path).expect("replay");
        assert_eq!(replayed.journal.len(), engine.journal.len());

        // Verify the replayed engine has the same contract state
        let mut replayed = replayed;
        let (replayed_ret, _) = replayed.call_contract(deployer, contract_addr, vec![], U256::ZERO, 100_000).unwrap();
        assert_eq!(original_ret, replayed_ret);

        let _ = std::fs::remove_dir_all(&dir);
    }
}