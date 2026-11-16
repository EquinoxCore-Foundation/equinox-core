# Equinox Core (`EQX`) — Layer-1 Hybrid PoW + BFT UTXO Blockchain

Equinox (`EQX`) is an audit-grade, zero-floating-point Layer-1 blockchain written in Rust.

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