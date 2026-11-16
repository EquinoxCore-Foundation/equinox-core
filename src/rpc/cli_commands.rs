#![allow(dead_code)]
// src/rpc/cli_commands.rs
// Equinox (EQX) L1 — Audit-Grade Terminal & CLI Command Parser and Dispatcher
// Features: Structured Command Parsing for Mining, Balance Lookup, Supply Audit & Node Control.

use crate::config::SYMBOL;
use crate::consensus::tokenomics::TokenomicsEngine;
use crate::rpc::rpc_server::{RpcServer, RpcSharedState};
use crate::wallet::address::is_valid_address;
use std::sync::{Arc, Mutex};

/// টার্মিনাল বা কমান্ড লাইন থেকে সমর্থিত কমান্ডসমূহ
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeCliCommand {
    Status,
    Mine { count: u64, address: Option<String> },
    Balance { address: String },
    Supply { height: Option<u64> },
    Help,
    Quit,
}

pub struct CliCommandHandler;

impl CliCommandHandler {
    /// ইউজারের টাইপ করা কমান্ড লাইন স্ট্রিং পার্স করে `NodeCliCommand`-এ রূপান্তর করে
    pub fn parse_command_line(input: &str) -> Result<NodeCliCommand, String> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Err("খালি কমান্ড".to_string());
        }

        match parts[0].to_ascii_lowercase().as_str() {
            "status" | "--status" => Ok(NodeCliCommand::Status),

            "mine" | "--mine" => {
                let count = parts
                    .get(1)
                    .map(|s| {
                        s.parse::<u64>()
                            .map_err(|_| "ব্লক সংখ্যা বৈধ পূর্ণসংখ্যা হতে হবে".to_string())
                    })
                    .transpose()?
                    .unwrap_or(1)
                    .max(1);

                let address = match parts.get(2) {
                    Some(addr) => {
                        if !is_valid_address(addr) {
                            return Err(format!("প্রদত্ত মাইনার অ্যাড্রেস বৈধ নয়: {}", addr));
                        }
                        Some((*addr).to_string())
                    }
                    None => None,
                };

                Ok(NodeCliCommand::Mine { count, address })
            }

            "balance" | "--balance" => {
                let addr = parts
                    .get(1)
                    .ok_or_else(|| "ব্যালেন্স জানতে ওয়ালেট অ্যাড্রেস দিন: balance <address>".to_string())?;
                if !is_valid_address(addr) {
                    return Err(format!("অবৈধ Equinox ওয়ালেট অ্যাড্রেস: {}", addr));
                }
                Ok(NodeCliCommand::Balance {
                    address: (*addr).to_string(),
                })
            }

            "supply" | "--supply" => {
                let height = parts
                    .get(1)
                    .map(|s| {
                        s.parse::<u64>()
                            .map_err(|_| "ব্লক হাইট বৈধ পূর্ণসংখ্যা হতে হবে".to_string())
                    })
                    .transpose()?;
                Ok(NodeCliCommand::Supply { height })
            }

            "help" | "--help" | "?" => Ok(NodeCliCommand::Help),

            "quit" | "exit" | "q" => Ok(NodeCliCommand::Quit),

            other => Err(format!(
                "অপরিচিত কমান্ড '{}'। সহায়তার জন্য 'help' লিখুন।",
                other
            )),
        }
    }

    /// ব্যালেন্স এবং সাপ্লাই কুয়েরি সরাসরি `RpcSharedState` থেকে এক্সিকিউট করে আউটপুট স্ট্রিং দেয়
    pub fn execute_readonly_query(
        cmd: &NodeCliCommand,
        shared_state: &Arc<Mutex<RpcSharedState>>,
    ) -> Result<String, String> {
        let state = shared_state
            .lock()
            .map_err(|_| "নোড স্টেট লক ত্রুটি".to_string())?;

        match cmd {
            NodeCliCommand::Balance { address } => {
                let (spendable, locked, count) =
                    state.utxo_set.get_balance_with_count(address, state.best_height);
                Ok(format!(
                    "অ্যাড্রেস: {}\n  খরচযোগ্য (Spendable): {} {}\n  টাইম-লকড (Locked)   : {} {}\n  মোট UTXO নোট       : {} টি",
                    address,
                    RpcServer::format_atomic_to_eqx(spendable),
                    SYMBOL,
                    RpcServer::format_atomic_to_eqx(locked),
                    SYMBOL,
                    count
                ))
            }
            NodeCliCommand::Supply { height } => {
                let target_h = height.unwrap_or(state.best_height);
                let rep = TokenomicsEngine::get_supply_report_at_height(target_h);
                Ok(format!(
                    "ব্লক #{} সাপ্লাই অডিট রিপোর্ট:\n  মোট মিন্টেড সাপ্লাই   : {} {}\n  সার্কুলেটিং সাপ্লাই    : {} {}\n  ওনার লকড সাপ্লাই     : {} {}\n  বর্তমান ব্লক রিওয়ার্ড  : {} {}",
                    rep.block_height,
                    RpcServer::format_atomic_to_eqx(rep.total_minted_supply),
                    SYMBOL,
                    RpcServer::format_atomic_to_eqx(rep.circulating_supply),
                    SYMBOL,
                    RpcServer::format_atomic_to_eqx(rep.locked_owner_supply),
                    SYMBOL,
                    RpcServer::format_atomic_to_eqx(rep.current_block_reward),
                    SYMBOL
                ))
            }
            NodeCliCommand::Help => Ok(
                "সমর্থিত কমান্ড তালিকা:\n  status                 - নোডের বর্তমান ব্লক হাইট, পিয়ার ও সাপ্লাই স্ট্যাটাস\n  mine [count] [address] - নতুন ব্লক মাইন ও ডিস্কে সেভ করা\n  balance <address>      - নির্দিষ্ট ওয়ালেটের লাইভ UTXO ব্যালেন্স দেখা\n  supply [height]        - নির্দিষ্ট ব্লক হাইটের ২১ মিলিয়ন টোকেনোমিক্স অডিট\n  quit / exit            - নিরাপদে নোড বন্ধ করা"
                    .to_string(),
            ),
            _ => Ok(String::new()),
        }
    }
}
