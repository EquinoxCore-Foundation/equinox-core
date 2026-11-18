// File: apps/desktop/src/js/tauri-bridge.js
// Strict Zero-Secret Frontend IPC Bridge (Rule #8: Never expose private keys or mnemonics to JS)
// Replaces all demo passwords, hardcoded PINs, fake balances, and client-side XOR crypto.

"use strict";

const EQX_TAURI_BRIDGE = Object.freeze({
  async invokeBackend(command, payload) {
    if (!window.__TAURI__ || typeof window.__TAURI__.invoke !== "function") {
      throw new Error("Tauri native backend IPC is required. Browser demo mode is disabled.");
    }
    const allowedCommands = new Set([
      "unlock_vault_with_totp",
      "lock_vault_session",
      "get_verified_balances",
      "simulate_transaction_preview",
      "approve_and_sign_transaction",
      "verify_onchain_deposit_receipt",
      "build_onchain_dex_swap"
    ]);
    if (!allowedCommands.has(command)) {
      throw new Error("Blocked unauthorized IPC command: " + command);
    }
    return await window.__TAURI__.invoke(command, payload || {});
  },

  async loginWithTotp(password, totpCode) {
    // Returns only opaque SessionTicket { session_id_hex, expires_at_unix, addresses }
    // Never returns PIN, password hash, or mnemonic seed to JavaScript
    return await this.invokeBackend("unlock_vault_with_totp", {
      password: String(password || ""),
      totpCode: String(totpCode || "").trim()
    });
  },

  async requestPreSignSimulation(sessionId, unsignedTxRequest) {
    // Step 1: Simulation only (cannot sign or broadcast)
    return await this.invokeBackend("simulate_transaction_preview", {
      sessionId: String(sessionId),
      txRequest: unsignedTxRequest
    });
  },

  async approveAndBroadcastTransaction(sessionId, approvedDigestHex, explicitUserConsent) {
    if (explicitUserConsent !== true) {
      throw new Error("Explicit user approval is mandatory before signing.");
    }
    // Step 2: Signing occurs strictly inside Rust Zeroizing memory
    return await this.invokeBackend("approve_and_sign_transaction", {
      sessionId: String(sessionId),
      approvedDigestHex: String(approvedDigestHex),
      explicitUserConsent: true
    });
  }
});