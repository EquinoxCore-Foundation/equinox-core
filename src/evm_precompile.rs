use std::sync::Arc;
use revm::{
    precompile::{Precompile, PrecompileError, PrecompileOutput, PrecompileResult},
    primitives::{Address, Bytes, U256},
    ContextPrecompile,
};
use crate::token_rpc::with_registry;

/// Fixed EVM Precompile Address: 0x0000000000000000000000000000000000000800
pub const NATIVE_TOKEN_PRECOMPILE_ADDR: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00,
]);

const GAS_BALANCE_OF: u64 = 2_000;
const GAS_TRANSFER: u64 = 5_000;

fn read_str<'a>(data: &'a [u8], cursor: &mut usize) -> Result<&'a str, PrecompileError> {
    if *cursor >= data.len() {
        return Err(PrecompileError::Other("Unexpected EOF reading length".into()));
    }
    let len = data[*cursor] as usize;
    *cursor += 1;
    if *cursor + len > data.len() {
        return Err(PrecompileError::Other("Unexpected EOF reading string".into()));
    }
    let s = std::str::from_utf8(&data[*cursor..*cursor + len])
        .map_err(|_| PrecompileError::Other("Invalid UTF-8 in precompile input".into()))?;
    *cursor += len;
    Ok(s)
}

/// Precompile ABI:
/// - Opcode 0x01 (balanceOf): [0x01][asset_len][asset_id][owner_len][owner] -> 32-byte BE u256 balance
/// - Opcode 0x02 (transfer):  [0x02][asset_len][asset_id][from_len][from][to_len][to][16-byte BE u128 amount] -> 32-byte BE 1
pub fn native_token_precompile(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let data = input.as_ref();
    if data.is_empty() {
        return Err(PrecompileError::Other("Empty precompile input".into()).into());
    }

    let op = data[0];
    let mut cursor = 1;

    match op {
        0x01 => {
            if gas_limit < GAS_BALANCE_OF {
                return Err(PrecompileError::OutOfGas.into());
            }
            let asset_id = read_str(data, &mut cursor)?;
            let owner = read_str(data, &mut cursor)?;

            let bal = with_registry(|reg| reg.balance_of(asset_id, owner))
                .map_err(|e| PrecompileError::Other(e))?;

            let out = U256::from(bal).to_be_bytes::<32>();
            Ok(PrecompileOutput::new(GAS_BALANCE_OF, Bytes::copy_from_slice(&out)))
        }
        0x02 => {
            if gas_limit < GAS_TRANSFER {
                return Err(PrecompileError::OutOfGas.into());
            }
            let asset_id = read_str(data, &mut cursor)?;
            let from = read_str(data, &mut cursor)?;
            let to = read_str(data, &mut cursor)?;

            if cursor + 16 > data.len() {
                return Err(PrecompileError::Other("Missing 16-byte amount".into()).into());
            }
            let mut amt_bytes = [0u8; 16];
            amt_bytes.copy_from_slice(&data[cursor..cursor + 16]);
            let amount = u128::from_be_bytes(amt_bytes);

            let res = with_registry(|reg| reg.transfer(asset_id, from, to, amount))
                .map_err(|e| PrecompileError::Other(e))?;

            match res {
                Ok(()) => {
                    let out = U256::from(1u64).to_be_bytes::<32>();
                    Ok(PrecompileOutput::new(GAS_TRANSFER, Bytes::copy_from_slice(&out)))
                }
                Err(e) => Err(PrecompileError::Other(format!("Native transfer failed: {:?}", e)).into()),
            }
        }
        _ => Err(PrecompileError::Other("Unknown precompile opcode".into()).into()),
    }
}

/// Registers the Equinox Native Token Bridge precompile inside any revm Handler.
pub fn register_equinox_precompiles<EXT, DB: revm::Database>(
    handler: &mut revm::Handler<'_, revm::Context<EXT, DB>, EXT, DB>,
) {
    let prev = handler.pre_execution.load_precompiles.clone();
    handler.pre_execution.load_precompiles = Arc::new(move || {
        let mut precompiles = prev();
        precompiles.extend([(
            NATIVE_TOKEN_PRECOMPILE_ADDR,
            ContextPrecompile::Ordinary(Precompile::Standard(native_token_precompile)),
        )]);
        precompiles
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{
        db::InMemoryDB,
        primitives::{ExecutionResult, Output, TransactTo},
        Evm,
    };

    fn encode_balance_call(asset_id: &str, owner: &str) -> Vec<u8> {
        let mut buf = vec![0x01];
        buf.push(asset_id.len() as u8);
        buf.extend_from_slice(asset_id.as_bytes());
        buf.push(owner.len() as u8);
        buf.extend_from_slice(owner.as_bytes());
        buf
    }

    fn encode_transfer_call(asset_id: &str, from: &str, to: &str, amount: u128) -> Vec<u8> {
        let mut buf = vec![0x02];
        buf.push(asset_id.len() as u8);
        buf.extend_from_slice(asset_id.as_bytes());
        buf.push(from.len() as u8);
        buf.extend_from_slice(from.as_bytes());
        buf.push(to.len() as u8);
        buf.extend_from_slice(to.as_bytes());
        buf.extend_from_slice(&amount.to_be_bytes());
        buf
    }

    #[test]
    fn test_evm_precompile_bridge_reads_and_transfers_native_token() {
        // 1. Deploy a native UTXO token in NativeTokenRegistry
        let asset_id = with_registry(|reg| {
            reg.deploy_token(
                "eqx1bridge_creator".to_string(),
                "Bridge Token".to_string(),
                "BRG".to_string(),
                6,
                1_000_000,
                99,
            )
            .map(|m| m.asset_id)
            .unwrap_or_else(|_| reg.ticker_index.get("BRG").cloned().unwrap())
        })
        .expect("registry lock");

        // 2. Call Precompile 0x0800 from inside revm to transfer 100_000 tokens
        let mut db = InMemoryDB::default();
        let caller = Address::from([0x33; 20]);
        let transfer_input = encode_transfer_call(&asset_id, "eqx1bridge_creator", "eqx1evm_user", 100_000);

        {
            let mut evm = Evm::builder()
                .with_db(&mut db)
                .append_handler_register(register_equinox_precompiles)
                .modify_tx_env(|tx| {
                    tx.caller = caller;
                    tx.transact_to = TransactTo::Call(NATIVE_TOKEN_PRECOMPILE_ADDR);
                    tx.data = Bytes::from(transfer_input);
                    tx.gas_limit = 100_000;
                })
                .build();

            let res = evm.transact_commit().expect("evm transfer call");
            assert!(matches!(res, ExecutionResult::Success { .. }));
        }

        // 3. Call Precompile 0x0800 from inside revm to read eqx1evm_user balance
        let bal_input = encode_balance_call(&asset_id, "eqx1evm_user");
        let mut evm = Evm::builder()
            .with_db(&mut db)
            .append_handler_register(register_equinox_precompiles)
            .modify_tx_env(|tx| {
                tx.caller = caller;
                tx.transact_to = TransactTo::Call(NATIVE_TOKEN_PRECOMPILE_ADDR);
                tx.data = Bytes::from(bal_input);
                tx.gas_limit = 100_000;
            })
            .build();

        let res = evm.transact_commit().expect("evm balance call");
        match res {
            ExecutionResult::Success { output: Output::Call(bytes), .. } => {
                let bal = U256::from_be_slice(&bytes);
                assert!(bal >= U256::from(100_000u64));
            }
            other => panic!("Expected success output, got {:?}", other),
        }
    }
}