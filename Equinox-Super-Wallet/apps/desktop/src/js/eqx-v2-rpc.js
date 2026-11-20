(function () {
  "use strict";

  var DEFAULT_RPC = "http://127.0.0.1:18545";

  async function rpcCall(method, params, endpoint) {
    var url = (endpoint || DEFAULT_RPC).trim();
    var res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: method,
        params: params || [],
        id: Date.now()
      })
    });
    if (!res.ok) {
      throw new Error("HTTP " + res.status + " from " + url);
    }
    var json = await res.json();
    if (json.error) {
      throw new Error(json.error.message || JSON.stringify(json.error));
    }
    return json.result;
  }

  async function sha256File(file) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("WebCrypto unavailable on this origin; paste 64-char SHA-256 manually.");
    }
    var buf = await file.arrayBuffer();
    var digest = await window.crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(digest))
      .map(function (b) { return b.toString(16).padStart(2, "0"); })
      .join("");
  }

  window.EQX_V2_RPC = {
    call: rpcCall,
    resolveName: function (name, ep) { return rpcCall("eqx_resolveName", [name], ep); },
    getBalance: function (addrOrHandle, ep) { return rpcCall("eqx_getBalance", [addrOrHandle], ep); },
    verifyProof: function (hashHex, ep) { return rpcCall("eqx_verifyProof", [hashHex], ep); },
    getMetrics: function (ep) { return rpcCall("eqx_getMetrics", [], ep); },
    sendRawTransaction: function (rawHex, ep) { return rpcCall("eqx_sendRawTransaction", [rawHex], ep); },
    sha256File: sha256File
  };

  function mountWidget() {
    if (document.getElementById("eqx-v2-rpc-fab")) return;

    var fab = document.createElement("button");
    fab.id = "eqx-v2-rpc-fab";
    fab.type = "button";
    fab.textContent = "EQX v2 • @name & Proof";
    fab.style.cssText = [
      "position:fixed", "right:18px", "bottom:18px", "z-index:99998",
      "background:linear-gradient(135deg,#00e5a0,#38bdf8)", "color:#071019",
      "border:none", "border-radius:999px", "padding:10px 16px",
      "font-family:system-ui,sans-serif", "font-size:12px", "font-weight:700",
      "box-shadow:0 8px 24px rgba(0,229,160,0.3)", "cursor:pointer"
    ].join(";");

    var panel = document.createElement("div");
    panel.id = "eqx-v2-rpc-panel";
    panel.style.cssText = [
      "display:none", "position:fixed", "right:18px", "bottom:68px", "z-index:99999",
      "width:370px", "max-width:calc(100vw - 36px)", "max-height:80vh", "overflow-y:auto",
      "background:#0d1117", "color:#e6edf3", "border:1px solid #30363d",
      "border-radius:16px", "padding:16px", "font-family:system-ui,sans-serif",
      "box-shadow:0 18px 48px rgba(0,0,0,0.65)"
    ].join(";");

    panel.innerHTML = [
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">',
      '  <strong style="font-size:14px;color:#00e5a0;">Equinox v2 Live RPC</strong>',
      '  <button id="eqx-v2-close" type="button" style="background:none;border:none;color:#8b949e;font-size:18px;cursor:pointer;">&times;</button>',
      '</div>',
      '<input id="eqx-v2-url" value="' + DEFAULT_RPC + '" style="width:100%;box-sizing:border-box;padding:8px;border-radius:8px;border:1px solid #30363d;background:#161b22;color:#fff;font-size:12px;margin-bottom:10px;"/>',
      '<div style="display:flex;gap:6px;margin-bottom:12px;">',
      '  <button data-tab="name" class="eqx-v2-tab" style="flex:1;padding:7px;border:none;border-radius:8px;background:#00e5a0;color:#000;font-weight:700;font-size:11px;cursor:pointer;">@name.eqx</button>',
      '  <button data-tab="proof" class="eqx-v2-tab" style="flex:1;padding:7px;border:none;border-radius:8px;background:#161b22;color:#c9d1d9;font-weight:700;font-size:11px;cursor:pointer;">Proof Verify</button>',
      '  <button data-tab="metrics" class="eqx-v2-tab" style="flex:1;padding:7px;border:none;border-radius:8px;background:#161b22;color:#c9d1d9;font-weight:700;font-size:11px;cursor:pointer;">Node & TX</button>',
      '</div>',
      '<div id="eqx-v2-body-name">',
      '  <input id="eqx-v2-name-in" placeholder="@alice_dev.eqx or E... address" style="width:100%;box-sizing:border-box;padding:8px;border-radius:8px;border:1px solid #30363d;background:#161b22;color:#fff;font-size:12px;margin-bottom:8px;"/>',
      '  <button id="eqx-v2-name-btn" type="button" style="width:100%;padding:9px;border:none;border-radius:8px;background:#00e5a0;color:#000;font-weight:700;font-size:12px;cursor:pointer;">Resolve & Check Balance</button>',
      '</div>',
      '<div id="eqx-v2-body-proof" style="display:none;">',
      '  <input id="eqx-v2-file-in" type="file" style="width:100%;font-size:11px;color:#8b949e;margin-bottom:8px;"/>',
      '  <input id="eqx-v2-proof-in" placeholder="64-char SHA-256 / pHash hex" style="width:100%;box-sizing:border-box;padding:8px;border-radius:8px;border:1px solid #30363d;background:#161b22;color:#fff;font-size:12px;margin-bottom:8px;"/>',
      '  <button id="eqx-v2-proof-btn" type="button" style="width:100%;padding:9px;border:none;border-radius:8px;background:#38bdf8;color:#000;font-weight:700;font-size:12px;cursor:pointer;">Verify On-Chain Proof</button>',
      '</div>',
      '<div id="eqx-v2-body-metrics" style="display:none;">',
      '  <button id="eqx-v2-metrics-btn" type="button" style="width:100%;padding:9px;border:none;border-radius:8px;background:#f59e0b;color:#000;font-weight:700;font-size:12px;cursor:pointer;margin-bottom:10px;">Fetch Live Metrics</button>',
      '  <textarea id="eqx-v2-tx-in" rows="2" placeholder="Paste signed v2 raw TX hex" style="width:100%;box-sizing:border-box;padding:8px;border-radius:8px;border:1px solid #30363d;background:#161b22;color:#fff;font-size:11px;margin-bottom:8px;"></textarea>',
      '  <button id="eqx-v2-tx-btn" type="button" style="width:100%;padding:8px;border:1px solid #00e5a0;border-radius:8px;background:transparent;color:#00e5a0;font-weight:700;font-size:12px;cursor:pointer;">Broadcast Raw TX</button>',
      '</div>',
      '<pre id="eqx-v2-out" style="margin-top:12px;padding:10px;border-radius:8px;background:#161b22;border:1px solid #30363d;color:#7ee787;font-size:11px;white-space:pre-wrap;word-break:break-all;min-height:48px;">Ready — Start equinox_node on port 18545.</pre>'
    ].join("\n");

    document.body.appendChild(fab);
    document.body.appendChild(panel);

    var outEl = document.getElementById("eqx-v2-out");
    var urlEl = document.getElementById("eqx-v2-url");

    function showOut(obj, isErr) {
      outEl.style.color = isErr ? "#ff7b72" : "#7ee787";
      outEl.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
    }

    fab.onclick = function () {
      panel.style.display = panel.style.display === "none" ? "block" : "none";
    };
    document.getElementById("eqx-v2-close").onclick = function () {
      panel.style.display = "none";
    };

    var tabs = panel.querySelectorAll(".eqx-v2-tab");
    tabs.forEach(function (btn) {
      btn.onclick = function () {
        var target = btn.getAttribute("data-tab");
        ["name", "proof", "metrics"].forEach(function (k) {
          document.getElementById("eqx-v2-body-" + k).style.display = (k === target) ? "block" : "none";
        });
        tabs.forEach(function (b) {
          var active = b === btn;
          b.style.background = active ? "#00e5a0" : "#161b22";
          b.style.color = active ? "#000" : "#c9d1d9";
        });
      };
    });

    document.getElementById("eqx-v2-name-btn").onclick = async function () {
      try {
        var q = document.getElementById("eqx-v2-name-in").value.trim();
        if (!q) return;
        showOut("Querying node...", false);
        var res = (q.startsWith("@") || q.endsWith(".eqx"))
          ? await window.EQX_V2_RPC.resolveName(q, urlEl.value)
          : await window.EQX_V2_RPC.getBalance(q, urlEl.value);
        showOut(res, false);
      } catch (e) {
        showOut("Error: " + e.message, true);
      }
    };

    document.getElementById("eqx-v2-file-in").onchange = async function (ev) {
      var file = ev.target.files && ev.target.files[0];
      if (!file) return;
      try {
        showOut("Hashing " + file.name + " locally (never uploaded)...", false);
        var digest = await sha256File(file);
        document.getElementById("eqx-v2-proof-in").value = digest;
        var res = await window.EQX_V2_RPC.verifyProof(digest, urlEl.value);
        showOut(res, false);
      } catch (e) {
        showOut("Error: " + e.message, true);
      }
    };

    document.getElementById("eqx-v2-proof-btn").onclick = async function () {
      try {
        var h = document.getElementById("eqx-v2-proof-in").value.trim();
        if (!h) return;
        showOut("Verifying proof on-chain...", false);
        var res = await window.EQX_V2_RPC.verifyProof(h, urlEl.value);
        showOut(res, false);
      } catch (e) {
        showOut("Error: " + e.message, true);
      }
    };

    document.getElementById("eqx-v2-metrics-btn").onclick = async function () {
      try {
        showOut("Fetching live metrics...", false);
        var res = await window.EQX_V2_RPC.getMetrics(urlEl.value);
        showOut(res, false);
      } catch (e) {
        showOut("Error: " + e.message, true);
      }
    };

    document.getElementById("eqx-v2-tx-btn").onclick = async function () {
      try {
        var hex = document.getElementById("eqx-v2-tx-in").value.trim();
        if (!hex) return;
        showOut("Broadcasting signed transaction...", false);
        var res = await window.EQX_V2_RPC.sendRawTransaction(hex, urlEl.value);
        showOut(res, false);
      } catch (e) {
        showOut("Error: " + e.message, true);
      }
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountWidget);
  } else {
    mountWidget();
  }
})();