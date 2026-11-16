#![allow(dead_code)]
// src/rpc/mod.rs
// Equinox (EQX) L1 — JSON-RPC 2.0 Web3/MetaMask API সার্ভার এবং CLI কমান্ড কন্ট্রোলার মডিউল।

pub mod cli_commands;
pub mod rpc_server;

pub use cli_commands::{CliCommandHandler, NodeCliCommand};
pub use rpc_server::{
    JsonRpcErrorObj, JsonRpcRequest, JsonRpcResponse, RpcServer, RpcSharedState,
    MAX_RPC_BODY_BYTES, MAX_RPC_REQUESTS_PER_MINUTE,
};
