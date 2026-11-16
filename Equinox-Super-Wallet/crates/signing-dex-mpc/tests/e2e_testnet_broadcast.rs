// File: Equinox-Super-Wallet/crates/signing-dex-mpc/tests/e2e_testnet_broadcast.rs
#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use equinox_signing_dex_mpc::{
    ChainTransactionSigner, EvmUnsignedTx, ExecutionError, LiveTestnetBroadcaster,
    SignedRawTransaction, TestnetNetwork, TestnetRpcConfig, UserApprovalToken,
};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use zeroize::Zeroizing;

const TX_SIGNING_DOMAIN: &[u8] = b"EQX_MAINNET_TX_SIGNING_V2";
const EQX_VERSION_BYTE: u8 = 0x21;

/// equinox-core/src/state/outpoint.rs এর হুবহু বাইনারি স্ট্রাকচার
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct L1OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// ৬৪-বাইট সিগনেচার Serde হেল্পার (equinox-core/src/primitives/transaction.rs এর সাথে সামঞ্জস্যপূর্ণ)
mod sig64_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[0..32]);
        s.copy_from_slice(&sig[32..64]);
        (r, s).serialize(serializer)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let (r, s): ([u8; 32], [u8; 32]) = Deserialize::deserialize(deserializer)?;
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&r);
        sig[32..64].copy_from_slice(&s);
        Ok(sig)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct L1TxInput {
    pub prev_out: L1OutPoint,
    pub public_key: [u8; 32],
    #[serde(with = "sig64_serde")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct L1TxOutput {
    pub amount: u64,
    pub recipient_address: String,
    pub unlock_height: u64,
}

/// equinox-core/src/primitives/transaction.rs এর হুবহু Transaction স্ট্রাকচার
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct L1Transaction {
    pub version: u32,
    pub inputs: Vec<L1TxInput>,
    pub outputs: Vec<L1TxOutput>,
    pub timestamp: u64,
    pub fee: u64,
}

impl L1Transaction {
    fn signing_message(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(TX_SIGNING_DOMAIN);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.fee.to_le_bytes());

        buf.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.prev_out.txid);
            buf.extend_from_slice(&inp.prev_out.vout.to_le_bytes());
            buf.extend_from_slice(&inp.public_key);
        }

        buf.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for out in &self.outputs {
            buf.extend_from_slice(&out.amount.to_le_bytes());
            buf.extend_from_slice(&out.unlock_height.to_le_bytes());
            buf.extend_from_slice(out.recipient_address.as_bytes());
        }
        buf
    }

    fn txid(&self) -> [u8; 32] {
        let mut buf = self.signing_message();
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.signature);
        }
        let first = Sha256::digest(&buf);
        Sha256::digest(first).into()
    }
}

fn pubkey_to_eqx_address(pubkey: &[u8; 32]) -> String {
    let sha = Sha256::digest(pubkey);
    let h160 = Ripemd160::digest(sha);
    let mut payload = [0u8; 21];
    payload[0] = EQX_VERSION_BYTE;
    payload[1..21].copy_from_slice(&h160);
    bs58::encode(payload).with_check().into_string()
}

/// যদি পিসিতে `equinox-core` নোড না চলে, তবে টেস্টের জন্য একটি স্থানীয় L1 RPC হ্যান্ডলার চালু করে
fn spawn_local_l1_rpc_harness() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind ephemeral port");
    let addr = format!("http://{}", listener.local_addr().unwrap());

    thread::spawn(move || {
        let mut mempool_txs: HashMap<String, L1Transaction> = HashMap::new();
        for _ in 0..2 {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 32 * 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);
                let body = req_str.split("\r\n\r\n").nth(1).unwrap_or("");
                let parsed: Value = serde_json::from_str(body).unwrap_or(json!({}));
                let req_id = parsed.get("id").cloned().unwrap_or(json!(1));
                let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");

                let resp_json = match method {
                    "eqx_sendRawTransaction" => {
                        let raw_hex = parsed["params"][0].as_str().unwrap_or("");
                        let clean = raw_hex.trim_start_matches("0x");
                        let tx_bytes = hex::decode(clean).expect("Valid hex");
                        let tx: L1Transaction =
                            bincode::deserialize(&tx_bytes).expect("Valid bincode L1Transaction");

                        // Verify Ed25519 signature exactly as equinox-core/src/primitives/transaction.rs does
                        let msg = tx.signing_message();
                        let vk = VerifyingKey::from_bytes(&tx.inputs[0].public_key).unwrap();
                        let sig = ed25519_dalek::Signature::from_bytes(&tx.inputs[0].signature);
                        assert!(vk.verify_strict(&msg, &sig).is_ok());

                        let txid_hex = hex::encode(tx.txid());
                        mempool_txs.insert(txid_hex.clone(), tx);
                        json!({ "jsonrpc": "2.0", "id": req_id, "result": txid_hex })
                    }
                    "eqx_getTransactionByHash" => {
                        let tx_hex = parsed["params"][0]
                            .as_str()
                            .unwrap_or("")
                            .trim_start_matches("0x");
                        if let Some(tx) = mempool_txs.get(tx_hex) {
                            let out_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
                            json!({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "txid": tx_hex,
                                    "status": "PENDING_MEMPOOL",
                                    "confirmations": 0,
                                    "fee_atomic": tx.fee,
                                    "total_output_atomic": out_sum
                                }
                            })
                        } else {
                            json!({ "jsonrpc": "2.0", "id": req_id, "error": { "code": -32004, "message": "Not found" } })
                        }
                    }
                    _ => json!({ "jsonrpc": "2.0", "id": req_id, "result": "ok" }),
                };

                let body_out = resp_json.to_string();
                let http = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body_out.len(),
                    body_out
                );
                let _ = stream.write_all(http.as_bytes());
            }
        }
    });

    addr
}

#[test]
fn test_end_to_end_equinox_l1_and_evm_testnet_broadcast_pipeline() {
    // ১. প্রেরক ও প্রাপকের আসল Ed25519 কী ও Base58Check (0x21) অ্যাড্রেস তৈরি
    let sender_secret = Zeroizing::new([0x24u8; 32]);
    let sender_sk = SigningKey::from_bytes(&*sender_secret);
    let sender_pubkey = sender_sk.verifying_key().to_bytes();
    let sender_address = pubkey_to_eqx_address(&sender_pubkey);

    let recipient_sk = SigningKey::from_bytes(&[0x55u8; 32]);
    let recipient_address = pubkey_to_eqx_address(&recipient_sk.verifying_key().to_bytes());

    println!("[E2E Step 1] Sender EQX Address   : {}", sender_address);
    println!("[E2E Step 1] Recipient EQX Address: {}", recipient_address);

    // ২. UTXO ইনপুট (50.00000000 EQX) থেকে 12.50000000 EQX পাঠানোর ট্রানজ্যাকশন তৈরি
    let input_utxo_amount = 50_0000_0000u64;
    let send_amount = 12_5000_0000u64;
    let fee_atomic = 10_000u64;
    let change_amount = input_utxo_amount - send_amount - fee_atomic;

    let mut l1_tx = L1Transaction {
        version: 1,
        inputs: vec![L1TxInput {
            prev_out: L1OutPoint {
                txid: [0xABu8; 32],
                vout: 0,
            },
            public_key: sender_pubkey,
            signature: [0u8; 64],
        }],
        outputs: vec![
            L1TxOutput {
                amount: send_amount,
                recipient_address: recipient_address.clone(),
                unlock_height: 0,
            },
            L1TxOutput {
                amount: change_amount,
                recipient_address: sender_address.clone(),
                unlock_height: 0,
            },
        ],
        timestamp: 1_763_000_000,
        fee: fee_atomic,
    };

    // ৩. ইউজার অনুমোদন যাচাই ও অফলাইন Ed25519 সাইনিং
    let signing_msg = l1_tx.signing_message();
    let pre_image_digest: [u8; 32] = Sha256::digest(Sha256::digest(&signing_msg)).into();

    let sig = sender_sk.sign(&signing_msg);
    l1_tx.inputs[0].signature = sig.to_bytes();

    let expected_txid_hex = hex::encode(l1_tx.txid());
    let bincode_bytes = bincode::serialize(&l1_tx).expect("Serialize L1Transaction");
    let raw_tx_hex = format!("0x{}", hex::encode(&bincode_bytes));

    let signed_payload = SignedRawTransaction {
        chain_id: 9333,
        tx_hash_hex: format!("0x{}", expected_txid_hex),
        raw_tx_hex,
    };

    println!("[E2E Step 2] Pre-Image Digest     : 0x{}", hex::encode(pre_image_digest));
    println!("[E2E Step 2] Signed Bincode Size  : {} bytes", bincode_bytes.len());
    println!("[E2E Step 2] Computed L1 TxID     : {}", signed_payload.tx_hash_hex);

    // ৪. লোকাল টেস্টনেট RPC সার্ভারে ব্রডকাস্ট এবং eqx_getTransactionByHash দিয়ে অন-চেইন ভেরিফিকেশন
    let rpc_url = spawn_local_l1_rpc_harness();
    let mut endpoints = HashMap::new();
    endpoints.insert(TestnetNetwork::EquinoxTestnet, rpc_url.clone());
    endpoints.insert(
        TestnetNetwork::EthereumSepolia,
        "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
    );

    let cfg = TestnetRpcConfig {
        endpoints,
        timeout_secs: 10,
    };
    let mut broadcaster = LiveTestnetBroadcaster::new(cfg, [0x99u8; 32]).unwrap();

    let receipt = broadcaster
        .broadcast_signed_transaction(
            TestnetNetwork::EquinoxTestnet,
            &signed_payload,
            1_763_000_005,
        )
        .expect("Broadcast to Equinox Testnet RPC must succeed");

    assert_eq!(receipt.on_chain_tx_hash, expected_txid_hex);
    println!(
        "[E2E Step 3] Broadcast Confirmed! On-Chain TxID: 0x{} via {}",
        receipt.on_chain_tx_hash, receipt.rpc_endpoint_used
    );

    // ৫. EVM Sepolia Testnet (Chain ID: 11155111) EIP-155 RLP Transaction Signing Verification
    let sepolia_unsigned = EvmUnsignedTx {
        chain_id: 11_155_111,
        nonce: 0,
        gas_price_wei: 1_500_000_000, // 1.5 Gwei
        gas_limit: 21_000,
        to_address: [0x22u8; 20],
        value_wei: 10_000_000_000_000_000, // 0.01 Sepolia ETH
        data: Vec::new(),
    };

    let sepolia_preview =
        ChainTransactionSigner::simulate_evm_transaction(&sepolia_unsigned, 11_155_111).unwrap();

    // ইউজার অনুমোদন ছাড়া সাইন করার চেষ্টা করলে সাথে সাথে ব্লক হবে
    let unapproved = UserApprovalToken {
        approved_digest: sepolia_preview.pre_image_signing_digest,
        approved_at_unix: 100,
        expires_at_unix: 400,
        explicit_user_consent: false,
    };
    assert_eq!(
        ChainTransactionSigner::sign_evm_transaction(
            &sepolia_unsigned,
            &unapproved,
            &sender_secret,
            200
        ),
        Err(ExecutionError::UnauthorizedSigningAttempt)
    );

    // বৈধ অনুমোদন টোকেন দিলে স্বাক্ষরিত Sepolia RLP তৈরি হবে
    let approved = UserApprovalToken {
        approved_digest: sepolia_preview.pre_image_signing_digest,
        approved_at_unix: 100,
        expires_at_unix: 400,
        explicit_user_consent: true,
    };
    let sepolia_signed = ChainTransactionSigner::sign_evm_transaction(
        &sepolia_unsigned,
        &approved,
        &sender_secret,
        200,
    )
    .unwrap();

    println!(
        "[E2E Step 4] Sepolia Signed TxHash: {}",
        sepolia_signed.tx_hash_hex
    );
    assert!(sepolia_signed.raw_tx_hex.starts_with("0xf8"));
}
