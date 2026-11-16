# 🌌 Equinox Network — Layer-1 Hybrid UTXO Blockchain & Super Wallet

[![Chain ID](https://img.shields.io/badge/Chain_ID-9333_(0x2475)-f5b041?style=for-the-badge)](#)
[![Max Supply](https://img.shields.io/badge/Max_Supply-21,000,000_EQX-10b981?style=for-the-badge)](#)
[![Built with Rust](https://img.shields.io/badge/Core-Rust_100%25_Safe-00e5ff?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](#)

**Equinox Network (EQX)** is a high-security, zero-dependency Layer-1 blockchain implemented in pure Rust, paired with **Equinox Super Wallet**—a multi-chain non-custodial desktop and web suite featuring pre-sign transaction simulation, hardware-grade keystore encryption, and a native Constant-Product AMM DEX.

---

## ⚡ Core Architecture Highlights

### 1. Equinox Core L1 Node (`equinox-core`)
* **Hardcoded Monetary Policy:** Strictly capped at **21,000,000 EQX** (`2,100,000,000,000,000` atomic units, 8 decimals).
* **ASERT PoW Difficulty Adjustment:** Exponential per-block difficulty targeting that resists hash-rate oscillation and timestamp manipulation.
* **Protocol Royalty Split:** Deterministic coinbase split allocating **98.3%** to PoW miners and **1.7%** to the protocol development & bug bounty vault.
* **Double-Spend & Replay Immunity:** Enforced via deterministic `spent_key_images` tracking and strict UTXO dust guards (`1,000` atomic threshold).
* **Flat-File Persistence:** Ultra-fast, zero-dependency disk storage (`chain_state.dat`, `dex_state.dat`) with cryptographic integrity checks.

### 2. Equinox Super Wallet (`Equinox-Super-Wallet`)
* **Multi-Chain HD Derivation (BIP-39 / BIP-44):** Single 24-word CSPRNG mnemonic derives native **EQX**, **BTC (Native SegWit `bc1q`)**, **ETH/BNB/Arbitrum/Polygon (`0x`)**, **Solana (`SPL`)**, **TRON (`TRC-20`)**, and **TON** addresses.
* **Strict Cryptographic Checksums:**
  * **Equinox & TRON:** 25-byte `Base58Check` with 4-byte `SHA-256d` checksum verification.
  * **Bitcoin:** Full BIP-173 `Bech32` polynomial (`polymod`) checksum verification.
* **2-Step Pre-Sign Security Simulation:** Every outgoing transfer generates a `TransactionPlan` and a 32-byte `Pre-Image Signing Digest`, displaying exact `MINUS`/`PLUS` balance deltas and risk warnings before requesting the keystore password.
* **RAM Zeroization:** Decrypted seeds are wiped from memory (`\0` overwrite) the millisecond offline signing completes.
* **Decentralized Payment Gateway & Native AMM:** Built-in `x * y = k` liquidity pool router (`0.30%` LP fee) with slippage protection and anti-replay merchant invoice verification.

---

## 🚀 Quickstart Guide (Testnet & Desktop App)

### 1. Run Equinox L1 Testnet Node
```powershell
# Clone repository
git clone [https://github.com/equinox-network/equinox-core.git](https://github.com/equinox-network/equinox-core.git)
cd equinox-core

# Run full unit & integration test suite
cargo test

# Initialize a new encrypted testnet wallet
cargo run --release -- --testnet --new-wallet YourStrongPassword2026

# Start the live Testnet Node & JSON-RPC Server (Port 8545 / 9332)
cargo run --release -- --testnet