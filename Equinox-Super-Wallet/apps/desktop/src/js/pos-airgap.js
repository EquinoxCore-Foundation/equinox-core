// Equinox Core (EQX) — Zero-Fee Merchant POS & Air-Gapped Offline Signing Engine
window.EquinoxMerchantPOS = {
    generateInvoiceURI: function(address, amountEQX, memo) {
        const cleanMemo = encodeURIComponent(memo || "Equinox_POS");
        return `equinox:${address}?amount=${amountEQX}&memo=${cleanMemo}&chain=9333`;
    },
    createOfflineUnsignedPayload: function(fromAddr, toAddr, amountEQX, nonce) {
        return JSON.stringify({
            protocol: "EQX_AIRGAP_V1",
            chain_id: 9333,
            from: fromAddr,
            to: toAddr,
            amount_atomic: Math.round(parseFloat(amountEQX) * 100000000),
            nonce: nonce || Date.now(),
            status: "UNSIGNED_RAW_UTXO"
        }, null, 2);
    }
};
console.log("[EQX] Merchant POS & Air-Gapped Signing Module Loaded.");
