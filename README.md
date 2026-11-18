# ⚡ Equinox Core (`EQX`) — Layer-1 Hybrid PoW + BFT UTXO Blockchain

> ### 💻 Got a Normal Laptop or PC? Mine Free `EQX` in 1 Click (Public Testnet Live!)
> **No expensive GPU required!** Download **`Equinox-Core-v0.2.0-Windows-x64.zip`** from our [**Official Releases**](https://github.com/EquinoxCore-Foundation/equinox-core/releases), extract it, and double-click **`Launch_Equinox.bat`**. You will start mining blocks every **15 seconds** on `Chain ID: 9333` and earn automatic **Mainnet Genesis (`Block #0`) Allocations**!

---

## 📊 Genesis Premine Allocation (`2,000,000 EQX` Total — 100% Transparent)

Out of the `21,000,000 EQX` hard-capped supply, `19,000,000 EQX` is strictly reserved for public Proof-of-Work miners over a 120-year decay schedule. The `2,000,000 EQX` Genesis Premine is cryptographically partitioned across 4 dedicated vaults:

| Vault Name | Allocation (`EQX`) | Share of Premine | Purpose & Lock Policy |
| :--- | :--- | :--- | :--- |
| **1. Founder & Core Protocol Vault** | `1,200,000 EQX` | **60%** (`12 Lakh`) | Protected by a 5-Year Cryptographic Block-Height Time-Lock (`src/consensus/`). |
| **2. Exchange & On-Chain DEX Liquidity Pool** | `400,000 EQX` | **20%** (`4 Lakh`) | Reserved strictly for CEX/DEX market-making and `dex.rs` AMM liquidity seeding. |
| **3. Open-Source Developer & Bug Bounty Fund** | `200,000 EQX` | **10%** (`2 Lakh`) | Distributed to GitHub contributors, security auditors (`SECURITY.md`), and EIP maintainers. |
| **4. Community Airdrop, Testnet Miners & Marketing** | `200,000 EQX` | **10%** (`2 Lakh`) | Fixed pro-rata pool for Testnet node runners, YouTubers, and referral quests. |

---
## Key Protocol Specifications
- **Ticker Symbol:** `EQX`
- **Chain ID:** `9333` (`0x2475`)
- **Maximum Total Supply:** `21,000,000 EQX` (Hard-Capped)
- **Atomic Decimals:** `8` (`1 EQX = 100,000,000 Atomic Units`)
- **Target Block Time:** `15 Seconds` (`2,102,400 Blocks/Year`)
- **Genesis Premine:** `2,000,000 EQX` (with 5-Year Cryptographic Block-Height Time-Lock on Owner Vault)
- **Mineable Supply:** `19,000,000 EQX` (120-Year Smooth Decay Schedule)
- **Cryptography:** Ed25519 Canonical Signatures, SHA-256d, RIPEMD-160 (`Base58Check`), AES-256-GCM + PBKDF2-HMAC-SHA256 (600,000 Rounds), BIP-39 (2048 Words), SLIP-0010 HD Derivation.

## Build & Run Commands
```bash
# Run full cryptographic & consensus test suite
cargo test

# Start the Mainnet Full Node & JSON-RPC 2.0 Server
cargo run --release
