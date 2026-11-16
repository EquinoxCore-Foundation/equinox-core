---

### ২. অফিশিয়াল বাগ বাউন্টি ও সিকিউরিটি পলিসি: `SECURITY.md`
আপনার প্রজেক্টের মূল ফোল্ডারে `SECURITY.md` নামে আরেকটি ফাইল তৈরি করে নিচের কোডটুকু পেস্ট করুন:

```markdown
# 🛡️ Equinox Network Security Policy & Bug Bounty Program

The Equinox Network core team and community take cryptographic and consensus security seriously. Every crate in `equinox-core` and `Equinox-Super-Wallet` enforces `#![forbid(unsafe_code)]`, strict integer overflow protection, and immediate RAM zeroization.

---

## 📌 Supported Versions

| Component | Version | Security Status |
| :--- | :--- | :--- |
| `equinox-core` (L1 Node) | `0.2.x-testnet` | ✅ Actively Audited & Supported |
| `Equinox-Super-Wallet` (Desktop/Web) | `0.2.x` | ✅ Actively Audited & Supported |
| `EquinoxScan` & Merchant Gateway | `0.2.x` | ✅ Actively Audited & Supported |

---

## 🏆 Official Bug Bounty Rewards (Paid in Mainnet EQX)

Valid, previously unreported vulnerabilities that affect consensus finality, UTXO accounting, or keystore cryptography are eligible for rewards from the **Equinox Protocol Security Reserve**:

| Severity Level | Vulnerability Category | Bounty Reward |
| :--- | :--- | :--- |
| **Critical (P1)** | L1 Consensus split, 21M supply inflation bypass, `spent_key_images` double-spend, or remote private key extraction. | **5,000 – 10,000 EQX** |
| **High (P2)** | JSON-RPC remote crash (DoS bypass), AMM DEX reserve manipulation, or Pre-Sign Simulation bypass. | **2,000 – 4,000 EQX** |
| **Medium (P3)** | Address checksum validation edge cases (`Base58Check` / `Bech32`), replay guard issues in merchant invoices. | **500 – 1,000 EQX** |
| **Low (P4)** | UI/UX state desynchronization, minor RPC rate-limiter improvements, or documentation fixes. | **100 – 300 EQX** |

---

## 🎯 In-Scope Targets

1. **Layer-1 Consensus & Tokenomics (`src/pow.rs`, `src/tokenomics.rs`):**
   * ASERT difficulty calculation under extreme timestamp drift.
   * 21,000,000 EQX hard cap enforcement and 98.3% / 1.7% integer math rounding.
2. **UTXO & Keystore Cryptography (`crates/wallet-engine`, `crates/key-vault`):**
   * `SecretSeedBuffer` RAM zeroization on drop.
   * Deterministic coin selection, dust change merging, and `Pre-Image Signing Digest` integrity.
3. **On-Chain Deposit & Merchant Gateway (`js/gateway.js`, `js/ui-patch.js`):**
   * Anti-replay `TxHash` verification and multi-peer RPC failover state machine.

---

## 📩 How to Report a Vulnerability (Responsible Disclosure)

**DO NOT open a public GitHub Issue for security vulnerabilities.**

1. Navigate to the **Security** tab of this GitHub repository.
2. Click **"Report a vulnerability"** to open a **Private Security Advisory**.
3. Provide:
   * A clear description of the vulnerability and affected file/line numbers.
   * A reproducible Proof-of-Concept (PoC) or Cargo unit test (`#[test]`).
   * Your Equinox Mainnet/Testnet address (`E...`) for bounty payout credit.

### Response Timeline
* **Initial Acknowledgment:** Within **24 hours**.
* **Triage & reproduction:** Within **72 hours**.
* **Patch Release & Bounty Award:** Within **7 days** of verification.