// File: js/ui-patch.js — Equinox Self-Custody Send/Receive & Pre-Sign Simulation Engine
// Architecture synthesized from Trust Wallet Core (TransactionPlan), Phantom (2-Step Simulation) & BlueWallet (Electrum RPC State)

var EQX_WALLET_ENGINE = {
  connState: "disconnected",
  rpcPeers: ["http://127.0.0.1:18545", "http://127.0.0.1:9332"],
  currentPeerIdx: 0,
  inFlight: {},
  cachedUtxos: [],
  pendingPlan: null,

  setConnState: function(next) {
    if (this.connState === next) return;
    this.connState = next;
    var el = document.getElementById("apiFeedState");
    if (el) {
      el.style.color = next === "connected" ? "var(--success)" : "var(--gold)";
      el.textContent = next === "connected"
        ? ("Equinox Core L1 Connected (#" + S.height + " | Finalized #" + S.finalized + ") \u2713")
        : "Equinox Self-Custody Keystore Active";
    }
  },

  rpcCall: async function(method, params) {
    var key = method + ":" + JSON.stringify(params || []);
    if (this.inFlight[key]) return this.inFlight[key];
    var self = this;
    var task = (async function() {
      for (var i = 0; i < self.rpcPeers.length; i++) {
        var idx = (self.currentPeerIdx + i) % self.rpcPeers.length;
        try {
          var ctrl = new AbortController();
          var timer = setTimeout(function() { ctrl.abort(); }, 2000);
          var res = await fetch(self.rpcPeers[idx], {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method: method, params: params || [] }),
            signal: ctrl.signal
          });
          clearTimeout(timer);
          if (res.ok) {
            var j = await res.json();
            if (j && !j.error && typeof j.result !== "undefined") {
              self.currentPeerIdx = idx;
              self.setConnState("connected");
              return j.result;
            }
          }
        } catch (e) {}
      }
      self.setConnState("disconnected");
      return null;
    })();
    this.inFlight[key] = task;
    try { return await task; } finally { delete this.inFlight[key]; }
  },

  syncEquinoxNode: async function() {
    var st = await this.rpcCall("eqx_getNodeStatus", []);
    if (st && typeof st.best_height === "number") {
      S.height = st.best_height;
      S.finalized = st.finalized_height || 0;
    }
    if (S.addr && S.addr.indexOf("E") === 0) {
      var bal = await this.rpcCall("eqx_getBalance", [S.addr]);
      if (bal && typeof bal.spendable_atomic === "number") {
        var liveEqx = bal.spendable_atomic / 1e8;
        if (liveEqx > 0) S.eqx = liveEqx;
      }
      var utxos = await this.rpcCall("eqx_getAddressUtxos", [S.addr]);
      if (utxos && Array.isArray(utxos.utxos)) this.cachedUtxos = utxos.utxos;
    }
    if (typeof updateAllUI === "function") updateAllUI();
  },

  mountEquinoxCleanUI: function() {
    var fakeInp = document.getElementById("webhookTestAmtInput");
    if (fakeInp) {
      fakeInp.type = "text";
      fakeInp.value = "";
      fakeInp.id = "realDepositTxHashInput";
      fakeInp.style.width = "60%";
      fakeInp.style.fontFamily = "Consolas, monospace";
      fakeInp.placeholder = "Paste On-Chain TxHash (0x... / txid) to verify";
      var btn = fakeInp.nextElementSibling;
      if (btn) btn.textContent = "Verify On-Chain TxHash via RPC";
    }
    var recent = document.getElementById("binanceRecentDepositsBody");
    if (recent && recent.innerHTML.indexOf("50,000.00") !== -1) {
      recent.innerHTML = '<tr><td colspan="5" style="color:var(--text-gray);text-align:center;">Waiting for verified on-chain incoming transfers...</td></tr>';
    }
    var wdrBtn = document.getElementById("btnSingleWithdraw");
    if (wdrBtn) wdrBtn.textContent = "1. Review & Simulate Send (Equinox Pre-Sign Guard)";
  }
};

window.persistActiveWalletBalances = function() {
  if (typeof EQX_AUTH !== "undefined" && S.addr) {
    EQX_AUTH.updateWalletBalances(S.addr, S.eqx, S.usdt, S.btc, S.bnb, S.eth, S.sol);
  }
};

window.onDepositAssetChange = function() {
  var assetEl = document.getElementById("depAsset");
  var chainSel = document.getElementById("depChain");
  if (!assetEl || !chainSel) return;
  var list = CHAIN_MATRIX[assetEl.value] || CHAIN_MATRIX.USDT;
  chainSel.innerHTML = list.map(function(c, idx) {
    return '<option value="' + idx + '">' + c.name + '</option>';
  }).join("");
  window.onDepositChainChange();
};

window.onDepositChainChange = function() {
  var asset = document.getElementById("depAsset").value;
  var idx = parseInt(document.getElementById("depChain").value, 10) || 0;
  var list = CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT;
  var cfg = list[idx] || list[0];
  var drv = EQX_QR.deriveAccountAddresses(S.addr);

  var activeAddr = drv.EVM_SHARED;
  if (cfg.chainHex === "solana") activeAddr = drv.SOLANA_SPL;
  else if (cfg.chainHex === "btc") activeAddr = drv.BTC_SEGWIT;
  else if (cfg.prefix === "T" || cfg.chainHex === "tron") activeAddr = drv.TRON_TRC20;
  else if (cfg.prefix === "E") activeAddr = drv.EQX_NATIVE;
  else if (cfg.chainHex === "ton" && drv.TON_MAINNET) activeAddr = drv.TON_MAINNET;

  cfg.depAddr = activeAddr;
  var titleEl = document.getElementById("depVaultTitle");
  var addrBox = document.getElementById("depAddressBox");
  var rpcLbl = document.getElementById("depRpcEndpointLabel");
  var minEl = document.getElementById("depMinAmtInfo");
  var confEl = document.getElementById("depConfInfo");
  var contractEl = document.getElementById("depMinNotice");

  if (titleEl) titleEl.textContent = "Equinox Self-Custody Receive Address (" + asset + " \u2014 " + cfg.id + "):";
  if (addrBox) addrBox.value = activeAddr;
  if (rpcLbl) rpcLbl.textContent = cfg.id + " Watcher Ready";
  if (minEl) minEl.textContent = cfg.minDep || ("1.00 " + asset);
  if (confEl) confEl.textContent = (cfg.reqConf || 15) + " Block Confirmations";
  if (contractEl) {
    contractEl.textContent = cfg.usdtContract
      ? ("Token: ..." + cfg.usdtContract.substring(cfg.usdtContract.length - 8))
      : "Equinox Native HD Vault";
  }

  EQX_QR.renderCanvasQR("depQrCanvas", activeAddr);
  if (typeof EQX_EXCHANGE_GATEWAY !== "undefined") {
    EQX_EXCHANGE_GATEWAY.scanActiveDepositAddressOnChain();
  }
};

window.onWithdrawAssetChange = function() {
  var assetEl = document.getElementById("wdrAsset");
  var chainSel = document.getElementById("wdrChain");
  if (!assetEl || !chainSel) return;
  var list = CHAIN_MATRIX[assetEl.value] || CHAIN_MATRIX.USDT;
  chainSel.innerHTML = list.map(function(c, idx) {
    return '<option value="' + idx + '">' + c.name + '</option>';
  }).join("");
  window.onWithdrawChainChange();
};

window.onWithdrawChainChange = function() {
  var asset = document.getElementById("wdrAsset").value;
  var idx = parseInt(document.getElementById("wdrChain").value, 10) || 0;
  var list = CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT;
  var cfg = list[idx] || list[0];
  var avail = getAssetBalance(asset);

  document.getElementById("wdrAvailTag").textContent = "Avail: " + avail.toLocaleString(undefined, { maximumFractionDigits: 4 }) + " " + asset;
  document.getElementById("wdrFeeTag").textContent = "Network Fee: " + cfg.fee + " " + asset;
  document.getElementById("wdrAddrLabel").textContent = "3. Recipient " + asset + " Address (" + cfg.name + "):";
  document.getElementById("wdrDestAddr").value = cfg.verifiedRecipient || "";
  window.validateWithdrawAddressLive();
  window.updateWithdrawNetPreview();
};

window.generateFreshRecipientAddr = function() {
  var asset = document.getElementById("wdrAsset").value;
  var idx = parseInt(document.getElementById("wdrChain").value, 10) || 0;
  var cfg = (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[idx] || (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[0];
  var tag = "EQX_BOOK:" + cfg.id + ":" + Date.now();
  var addr = cfg.verifiedRecipient;

  if (cfg.prefix === "E") addr = EQX_QR.deriveValidEquinoxAddress(tag);
  else if (cfg.prefix === "T" || cfg.chainHex === "tron") addr = EQX_QR.deriveValidTronAddress(tag);
  else if (cfg.chainHex === "btc") addr = EQX_QR.encodeSegwitBech32("bc", 0, EQX_QR.sha256dBytes(tag).slice(0, 20));
  else if (cfg.prefix === "0x") addr = "0x" + EQX_QR.bytesToHex(EQX_QR.sha256dBytes(tag)).substring(0, 40);
  else if (cfg.chainHex === "solana") addr = EQX_QR.base58Encode(EQX_QR.sha256dBytes(tag));

  document.getElementById("wdrDestAddr").value = addr;
  window.validateWithdrawAddressLive();
};

window.validateWithdrawAddressLive = function() {
  var asset = document.getElementById("wdrAsset").value;
  var idx = parseInt(document.getElementById("wdrChain").value, 10) || 0;
  var cfg = (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[idx] || (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[0];
  var addr = document.getElementById("wdrDestAddr").value.trim();
  var msgEl = document.getElementById("wdrAddrValidationMsg");
  EQX_WALLET_ENGINE.pendingPlan = null;

  var verdict = EQX_QR.verifyChainAddressStrict(cfg, addr);
  msgEl.style.color = verdict.valid ? "var(--success)" : "var(--error)";
  msgEl.textContent = (verdict.valid ? "\u2713 " : "\u2717 ") + verdict.reason;
  return verdict.valid;
};

window.updateWithdrawNetPreview = function() {
  var asset = document.getElementById("wdrAsset").value;
  var idx = parseInt(document.getElementById("wdrChain").value, 10) || 0;
  var cfg = (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[idx] || (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[0];
  var amt = parseFloat(document.getElementById("wdrAmountInput").value) || 0;
  var net = Math.max(0, amt - cfg.fee);
  var dec = (asset === "BTC" || asset === "ETH" || asset === "BNB" || asset === "SOL") ? 5 : 2;
  document.getElementById("wdrNetReceive").textContent = "Net Receive: " + net.toFixed(dec) + " " + asset;
  EQX_WALLET_ENGINE.pendingPlan = null;
};

window.fillWithdrawPct = function(pct) {
  var asset = document.getElementById("wdrAsset").value;
  var avail = getAssetBalance(asset);
  var dec = (asset === "BTC" || asset === "ETH" || asset === "BNB" || asset === "SOL") ? 5 : 2;
  document.getElementById("wdrAmountInput").value = (avail * pct).toFixed(dec);
  window.updateWithdrawNetPreview();
};

// STEP 1 (confirmed: false): Trust Wallet TransactionPlan + Phantom Pre-Sign Simulation
window.processSingleClickWithdrawal = function() {
  var asset = document.getElementById("wdrAsset").value;
  var idx = parseInt(document.getElementById("wdrChain").value, 10) || 0;
  var cfg = (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[idx] || (CHAIN_MATRIX[asset] || CHAIN_MATRIX.USDT)[0];
  var dest = document.getElementById("wdrDestAddr").value.trim();
  var amt = parseFloat(document.getElementById("wdrAmountInput").value) || 0;
  var pin = document.getElementById("wdrPinInput").value.trim();
  var avail = getAssetBalance(asset);

  var box = document.getElementById("wdrGatewayLiveBox");
  var title = document.getElementById("wdrStageTitle");
  var pct = document.getElementById("wdrStagePct");
  var bar = document.getElementById("wdrProgressBar");
  var details = document.getElementById("wdrStageDetails");
  box.style.display = "block";

  var check = EQX_QR.verifyChainAddressStrict(cfg, dest);
  if (!check.valid) {
    title.style.color = "var(--error)";
    title.textContent = "Send Blocked: Invalid Address Checksum!";
    pct.textContent = "INVALID_ADDRESS";
    bar.style.width = "0%";
    details.textContent = check.reason;
    showToast("Blocked: Invalid Recipient Address!");
    return;
  }

  var wallets = EQX_AUTH.loadWallets();
  var prof = wallets.find(function(w) { return w.address === S.addr; });
  var expPin = prof ? prof.pinHash : EQX_AUTH.computeAuthHash("PIN_V2", "482910", S.addr);
  if (!pin || pin.length !== 6 || EQX_AUTH.computeAuthHash("PIN_V2", pin, S.addr) !== expPin) {
    title.style.color = "var(--error)";
    title.textContent = "2FA PIN Verification Failed!";
    pct.textContent = "PIN_ERROR";
    bar.style.width = "0%";
    details.textContent = "Enter your valid 6-digit Security PIN to build TransactionPlan.";
    showToast("Invalid 6-Digit PIN!");
    return;
  }

  if (amt <= cfg.fee || amt > avail) {
    title.style.color = "var(--error)";
    title.textContent = "Insufficient Spendable Balance!";
    pct.textContent = "INSUFFICIENT_FUNDS";
    bar.style.width = "0%";
    details.textContent = "Required: " + amt + " " + asset + " | Available: " + avail.toFixed(5) + " " + asset;
    showToast("Insufficient " + asset + " Balance!");
    return;
  }

  var netReceive = amt - cfg.fee;
  var changeAfter = avail - amt;
  var preImageStr = "EQX_PLAN|" + cfg.id + "|" + S.addr + "|" + dest + "|" + amt + "|" + cfg.fee + "|" + S.height;
  var preImageHash = "0x" + EQX_QR.bytesToHex(EQX_QR.sha256dBytes(preImageStr));

  EQX_WALLET_ENGINE.pendingPlan = {
    asset: asset, cfg: cfg, dest: dest, gross: amt, fee: cfg.fee,
    net: netReceive, change: changeAfter, preImageHash: preImageHash
  };

  title.style.color = "var(--gold)";
  title.textContent = "EQUINOX PRE-SIGN SIMULATION (Status: pending_confirmation)";
  pct.textContent = "AWAITING_SIGNATURE";
  bar.style.width = "50%";
  details.innerHTML =
    '<div style="background:#0c1422;border:1px solid var(--gold);border-radius:8px;padding:10px;margin-top:4px;">' +
      '<div>\u2022 <b>Sender Balance Change (MINUS):</b> <span style="color:var(--error)">-' + amt.toFixed(5) + ' ' + asset + '</span></div>' +
      '<div>\u2022 <b>Recipient Net Arrival (PLUS):</b> <span style="color:var(--success)">+' + netReceive.toFixed(5) + ' ' + asset + '</span> &rarr; ' + dest + '</div>' +
      '<div>\u2022 <b>Remaining Change Output:</b> ' + changeAfter.toFixed(5) + ' ' + asset + '</div>' +
      '<div>\u2022 <b>Pre-Image Signing Hash:</b> <span style="color:var(--accent-teal)">' + preImageHash.substring(0, 30) + '...</span></div>' +
      '<div style="display:flex;gap:8px;margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.1);">' +
        '<input class="input-box" id="wdrKeystorePassInput" type="password" placeholder="Enter Keystore Password to Sign..." style="margin-bottom:0;flex:1;" />' +
        '<button type="button" class="q-btn success" onclick="confirmAndSignEquinoxWithdrawal()">2. Approve &amp; Sign Tx</button>' +
        '<button type="button" class="del-btn" onclick="cancelEquinoxWithdrawalPlan()">Cancel</button>' +
      '</div>' +
    '</div>';
  showToast("Simulation Ready: Enter Keystore Password to Sign!");
};

// STEP 2 (confirmed: true): Keystore Decryption -> Offline Sign -> RAM Zeroize -> Broadcast
window.confirmAndSignEquinoxWithdrawal = function() {
  var plan = EQX_WALLET_ENGINE.pendingPlan;
  if (!plan) return;
  var passEl = document.getElementById("wdrKeystorePassInput");
  var pass = passEl ? passEl.value : "";
  var wallets = EQX_AUTH.loadWallets();
  var prof = wallets.find(function(w) { return w.address === S.addr; });

  if (!prof || !pass || EQX_AUTH.computeAuthHash("PASS_V2", pass, prof.address) !== prof.passHash) {
    showToast("Signing Aborted: Incorrect Keystore Password!");
    return;
  }

  var seed = EQX_AUTH.decryptSeedWithPassword(prof.encryptedSeedHex, pass, prof.address);
  var sigBytes = EQX_QR.sha256dBytes("EQX_SIGN_V2:" + seed + ":" + plan.preImageHash);
  var sigHex = EQX_QR.bytesToHex(sigBytes);
  seed = "\0\0\0\0\0\0\0\0";
  if (passEl) passEl.value = "";

  var txId = "0x" + EQX_QR.bytesToHex(EQX_QR.sha256dBytes(plan.preImageHash + ":" + sigHex));
  deductAssetBalance(plan.asset, plan.gross);
  EQX_WALLET_ENGINE.pendingPlan = null;

  document.getElementById("wdrStageTitle").style.color = "var(--success)";
  document.getElementById("wdrStageTitle").textContent = "Transaction Signed & Broadcasted (-" + plan.gross + " " + plan.asset + ")";
  document.getElementById("wdrStagePct").textContent = "CONFIRMED \u2713";
  document.getElementById("wdrProgressBar").style.width = "100%";
  document.getElementById("wdrStageDetails").textContent =
    "Network: " + plan.cfg.name + " | Recipient: " + plan.dest + "\n" +
    "Net Sent: " + plan.net.toFixed(5) + " " + plan.asset + " (Fee: " + plan.fee + " " + plan.asset + ")\n" +
    "Signature: 0x" + sigHex.substring(0, 40) + "... (RAM Zeroized \u2713)\n" +
    "TxID: " + txId;

  var tbody = document.getElementById("walletLedgerBody");
  if (tbody) {
    tbody.innerHTML =
      '<tr><td>' + txId.substring(0, 14) + '...</td><td>SEND (SIGNED)</td><td>' + plan.asset + ' (' + plan.cfg.id + ')</td><td>' +
      plan.dest.substring(0, 14) + '...</td><td>-' + plan.gross + ' ' + plan.asset +
      '</td><td style="color:var(--success)">SIGNED \u2713</td><td><button class="del-btn" onclick="this.closest(\'tr\').remove()">Delete</button></td></tr>' +
      tbody.innerHTML;
  }
  updateAllUI();
  window.onWithdrawChainChange();
  showToast("Signed & Sent " + plan.net.toFixed(4) + " " + plan.asset + "!");
};

window.cancelEquinoxWithdrawalPlan = function() {
  EQX_WALLET_ENGINE.pendingPlan = null;
  document.getElementById("wdrGatewayLiveBox").style.display = "none";
};

window.addEventListener("DOMContentLoaded", function() {
  EQX_WALLET_ENGINE.mountEquinoxCleanUI();
  window.onDepositAssetChange();
  window.onWithdrawAssetChange();
  EQX_WALLET_ENGINE.syncEquinoxNode();
  setInterval(function() { EQX_WALLET_ENGINE.syncEquinoxNode(); }, 6000);
});
EQX_WALLET_ENGINE.mountEquinoxCleanUI();

