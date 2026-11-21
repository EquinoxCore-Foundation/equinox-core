use revm::{
    db::InMemoryDB,
    primitives::{Address, Bytes, ExecutionResult, Output, TransactTo, U256},
    Evm,
};

/// Hybrid EVM execution engine embedded directly inside Equinox Core.
#[derive(Debug, Default)]
pub struct EquinoxEvmEngine {
    pub chain_id: u64,
    pub db: InMemoryDB,
}

impl EquinoxEvmEngine {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            db: InMemoryDB::default(),
        }
    }

    /// Credits an EVM address with EQX-wei balance for gas and value transfers.
    pub fn fund_account(&mut self, addr: Address, balance_wei: U256) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revm_deploy_and_call_smart_contract() {
        let mut engine = EquinoxEvmEngine::new(7777);
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
}