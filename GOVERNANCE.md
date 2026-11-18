# 🏛️ Equinox Core (EQX) — Decentralized Open-Source Governance Charter

Equinox Core (`Chain ID: 9333`) is a sovereign, community-governed Layer-1 UTXO public utility licensed under the **MIT License**. Like Bitcoin, the protocol operates without a CEO, central company, or venture capital control.

---

## 1. The EIP Process (Equinox Improvement Proposals)
Anyone in the global community can propose protocol upgrades, consensus optimizations, or Super-Wallet features by opening an **EIP Issue or Pull Request**:
1. **Drafting:** Submit a PR with deterministic Rust code (`#![forbid(unsafe_code)]`).
2. **Automated CI Audit:** All 64+ cryptographic and consensus unit tests (`cargo test`) must pass with zero warnings.
3. **Peer Review:** Requires approval from at least **2 Core Maintainers** before merging into `main`.
4. **Miner & Node Consensus:** Major consensus changes require adoption by >51% of active PoW hashpower and BFT validator nodes.

---

## 2. How to Become a Core Maintainer
Maintainer status is earned purely through **Proof-of-Merit**:
- Developers who successfully resolve **3+ High/Medium Issues** or contribute major infrastructure (P2P, RPC, DEX, Mobile Wallet) are nominated to the `EquinoxCore-Foundation` Maintainer Council.
- Active maintainers share governance keys for the Community Bounty Treasury.

---

## 3. Immortal Infrastructure Policy
- **Zero Single Point of Failure:** Anyone can fork, mirror, compile, and host the Equinox Super-Wallet and Block Explorer on IPFS, GitHub Pages, or local hardware.
- **Self-Sustaining Economy:** On-chain 0.30% AMM DEX LP fees and the 120-year PoW decay schedule ensure permanent economic incentives for miners and liquidity providers without central intervention.
