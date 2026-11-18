# 🚀 Equinox Core (EQX) — Open-Source Developer Bounty Board

All bounties listed below are paid **automatically in EQX** via the Genesis Snapshot (`Block #0`) and the algorithmic DAO Treasury upon PR merge.

---

### 🟢 Bounty #1: Zero-Fee Instant QR Merchant POS Mode (`1,500 EQX`)
- **Goal:** Expand `Equinox-Super-Wallet` (`index.html` & `apps/mobile_flutter`) with a dedicated **"Merchant POS Mode"**.
- **Specs:** Allow shopkeepers to input an invoice amount in local currency or `EQX`, generate a dynamic `equinox:E...?amount=X` payment QR code, and trigger an instant audio/visual confirmation chime within 3 seconds of mempool/block detection.

### 🟢 Bounty #2: Automated On-Chain Holder Dividends & Micro-LP Farming UI (`2,500 EQX`)
- **Goal:** Connect `src/dividend.rs` and `src/dex.rs` directly to the Super-Wallet Swap & Earn tab.
- **Specs:** Enable small miners ($5–$20 value) to lock `EQX` in the Constant-Product AMM pool and automatically claim their proportional `0.30%` swap fee + protocol dividend rewards per epoch.

### 🟢 Bounty #3: Hardware & Offline Air-Gapped QR Transaction Signing (`3,000 EQX`)
- **Goal:** Implement cold-storage offline transaction signing in `Equinox-Super-Wallet` and `lib/main.dart`.
- **Specs:** An online watch-only wallet generates an unsigned UTXO payload QR $\rightarrow$ An offline air-gapped phone/PC scans it, signs with `Ed25519` private key (`src/wallet/signer.rs`), and displays the signed raw hex QR $\rightarrow$ Online device scans and broadcasts via `eqx_sendRawTransaction`.

### 🟢 Bounty #4: Decentralized DNS Seeder & PEX Crawler (`2,000 EQX`)
- **Goal:** Enhance `equinox-network` peer exchange (`PEX`) so new nodes joining `Chain ID: 9333` automatically discover and sync with active global miner IPs without relying on centralized servers.
