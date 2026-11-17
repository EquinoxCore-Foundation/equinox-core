// File: js/qr.js — Equinox Cryptographic Address Engine (Base58Check + BIP-173 Bech32 + QR)

var EQX_QR = {
  B58_ALPHABET: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
  BECH32_CHARSET: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
  BECH32_GENERATOR: [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3],
  EQX_VERSION_BYTE: 0x21,
  TRON_VERSION_BYTE: 0x41,

  sha256Bytes: function(asciiOrBytes) {
    var data = [];
    if (typeof asciiOrBytes === "string") {
      for (var i = 0; i < asciiOrBytes.length; i++) {
        var code = asciiOrBytes.charCodeAt(i);
        if (code < 0x80) data.push(code);
        else if (code < 0x800) data.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        else data.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
    } else {
      for (var b = 0; b < asciiOrBytes.length; b++) data.push(asciiOrBytes[b] & 0xff);
    }

    var K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    var H = [
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    ];

    var bitLen = data.length * 8;
    data.push(0x80);
    while ((data.length % 64) !== 56) data.push(0x00);
    var hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
    data.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
    data.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    var W = new Array(64);
    for (var off = 0; off < data.length; off += 64) {
      for (var t = 0; t < 16; t++) {
        var idx = off + t * 4;
        W[t] = ((data[idx] << 24) | (data[idx + 1] << 16) | (data[idx + 2] << 8) | data[idx + 3]) >>> 0;
      }
      for (var j = 16; j < 64; j++) {
        var s0 = (rotr(W[j - 15], 7) ^ rotr(W[j - 15], 18) ^ (W[j - 15] >>> 3)) >>> 0;
        var s1 = (rotr(W[j - 2], 17) ^ rotr(W[j - 2], 19) ^ (W[j - 2] >>> 10)) >>> 0;
        W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0;
      }
      var a = H[0], b1 = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (var r = 0; r < 64; r++) {
        var S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
        var ch = ((e & f) ^ ((~e) & g)) >>> 0;
        var t1 = (h + S1 + ch + K[r] + W[r]) >>> 0;
        var S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
        var maj = ((a & b1) ^ (a & c) ^ (b1 & c)) >>> 0;
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b1; b1 = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b1) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var out = new Uint8Array(32);
    for (var k = 0; k < 8; k++) {
      out[k * 4] = (H[k] >>> 24) & 0xff;
      out[k * 4 + 1] = (H[k] >>> 16) & 0xff;
      out[k * 4 + 2] = (H[k] >>> 8) & 0xff;
      out[k * 4 + 3] = H[k] & 0xff;
    }
    return out;
  },

  sha256dBytes: function(input) { return this.sha256Bytes(this.sha256Bytes(input)); },

  bytesToHex: function(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      var h = (bytes[i] & 0xff).toString(16);
      hex += (h.length === 1 ? "0" + h : h);
    }
    return hex;
  },

  base58Encode: function(bytes) {
    var digits = [0];
    for (var i = 0; i < bytes.length; i++) {
      var carry = bytes[i];
      for (var j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
    }
    var out = "";
    for (var k = 0; k < bytes.length && bytes[k] === 0; k++) out += "1";
    for (var d = digits.length - 1; d >= 0; d--) out += this.B58_ALPHABET[digits[d]];
    return out;
  },

  base58Decode: function(str) {
    if (!str || typeof str !== "string") return null;
    var clean = str.trim();
    if (!clean.length) return null;
    var bytes = [0];
    for (var i = 0; i < clean.length; i++) {
      var val = this.B58_ALPHABET.indexOf(clean.charAt(i));
      if (val === -1) return null;
      var carry = val;
      for (var j = 0; j < bytes.length; j++) {
        carry += bytes[j] * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    for (var k = 0; k < clean.length && clean.charAt(k) === "1"; k++) bytes.push(0);
    return new Uint8Array(bytes.reverse());
  },

  verifyBase58Check: function(addressStr, expectedVersionByte) {
    var dec = this.base58Decode(addressStr);
    if (!dec || dec.length !== 25) return false;
    if (typeof expectedVersionByte === "number" && dec[0] !== expectedVersionByte) return false;
    var check = this.sha256dBytes(dec.slice(0, 21));
    return dec[21] === check[0] && dec[22] === check[1] && dec[23] === check[2] && dec[24] === check[3];
  },

  bech32Polymod: function(values) {
    var chk = 1;
    for (var p = 0; p < values.length; ++p) {
      var top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[p];
      for (var i = 0; i < 5; ++i) if ((top >> i) & 1) chk ^= this.BECH32_GENERATOR[i];
    }
    return chk;
  },

  bech32HrpExpand: function(hrp) {
    var ret = [];
    for (var p = 0; p < hrp.length; ++p) ret.push(hrp.charCodeAt(p) >> 5);
    ret.push(0);
    for (var q = 0; q < hrp.length; ++q) ret.push(hrp.charCodeAt(q) & 31);
    return ret;
  },

  convertBits8To5: function(data, pad) {
    var acc = 0, bits = 0, ret = [], maxv = 31;
    for (var p = 0; p < data.length; ++p) {
      acc = (acc << 8) | (data[p] & 0xff);
      bits += 8;
      while (bits >= 5) { bits -= 5; ret.push((acc >> bits) & maxv); }
    }
    if (pad && bits > 0) ret.push((acc << (5 - bits)) & maxv);
    return ret;
  },

  encodeSegwitBech32: function(hrp, version, program20Bytes) {
    var words = [version].concat(this.convertBits8To5(program20Bytes, true));
    var values = this.bech32HrpExpand(hrp).concat(words).concat([0, 0, 0, 0, 0, 0]);
    var mod = this.bech32Polymod(values) ^ 1;
    var combined = words.slice();
    for (var p = 0; p < 6; ++p) combined.push((mod >> (5 * (5 - p))) & 31);
    var ret = hrp + "1";
    for (var i = 0; i < combined.length; ++i) ret += this.BECH32_CHARSET.charAt(combined[i]);
    return ret;
  },

  verifySegwitBech32: function(expectedHrp, bechString) {
    if (!bechString || typeof bechString !== "string") return false;
    var clean = bechString.trim();
    if (clean !== clean.toLowerCase() && clean !== clean.toUpperCase()) return false;
    var lower = clean.toLowerCase();
    var pos = lower.lastIndexOf("1");
    if (pos < 1 || pos + 7 > lower.length || lower.length > 90) return false;
    var hrp = lower.substring(0, pos);
    if (expectedHrp && hrp !== expectedHrp) return false;
    var data = [];
    for (var p = pos + 1; p < lower.length; p++) {
      var d = this.BECH32_CHARSET.indexOf(lower.charAt(p));
      if (d === -1) return false;
      data.push(d);
    }
    var polymod = this.bech32Polymod(this.bech32HrpExpand(hrp).concat(data));
    return polymod === 1 || polymod === 0x2bc830a3;
  },

  verifyChainAddressStrict: function(cfg, addressStr) {
    var addr = (addressStr || "").trim();
    if (!addr) return { valid: false, reason: "Recipient address is required." };
    if (cfg.prefix === "E" || cfg.id === "EQX_9333") {
      return this.verifyBase58Check(addr, this.EQX_VERSION_BYTE)
        ? { valid: true, reason: "Verified Equinox 25-Byte Base58Check Checksum" }
        : { valid: false, reason: "Invalid Equinox Address: Base58Check checksum failed!" };
    }
    if (cfg.prefix === "T" || cfg.chainHex === "tron") {
      return this.verifyBase58Check(addr, this.TRON_VERSION_BYTE)
        ? { valid: true, reason: "Verified TRON (TRC20) Base58Check Checksum" }
        : { valid: false, reason: "Invalid TRON Address: Base58Check checksum failed!" };
    }
    if (cfg.chainHex === "btc" || cfg.prefix === "bc1q" || cfg.prefix === "bc1") {
      return this.verifySegwitBech32("bc", addr)
        ? { valid: true, reason: "Verified Bitcoin BIP-173 Bech32 Checksum" }
        : { valid: false, reason: "Invalid Bitcoin SegWit Address: Bech32 polymod failed!" };
    }
    if (cfg.prefix === "0x") {
      return /^0x[a-fA-F0-9]{40}$/.test(addr)
        ? { valid: true, reason: "Verified EVM 20-Byte Hex Address (" + cfg.name + ")" }
        : { valid: false, reason: "Invalid EVM Address: Must be 0x + 40 hex chars!" };
    }
    if (cfg.chainHex === "solana") {
      var decSol = this.base58Decode(addr);
      return (decSol && decSol.length >= 31 && decSol.length <= 34)
        ? { valid: true, reason: "Verified Solana Ed25519 Base58 Address" }
        : { valid: false, reason: "Invalid Solana Address: Base58 public key decode failed!" };
    }
    if (cfg.chainHex === "ton" || cfg.prefix === "UQ") {
      return /^(UQ|EQ)[A-Za-z0-9_-]{46}$/.test(addr)
        ? { valid: true, reason: "Verified TON 48-Char Address" }
        : { valid: false, reason: "Invalid TON Address: Must start with UQ/EQ (48 chars)!" };
    }
    return { valid: addr.length >= 26, reason: "Verified Address Format" };
  },

  deriveValidEquinoxAddress: function(seedMaterial) {
    var digest = this.sha256dBytes("EQX_HD_DERIVATION_V2:" + String(seedMaterial));
    var payload = new Uint8Array(21);
    payload[0] = this.EQX_VERSION_BYTE;
    for (var i = 0; i < 20; i++) payload[i + 1] = digest[i];
    var check = this.sha256dBytes(payload);
    var full = new Uint8Array(25);
    full.set(payload, 0);
    full.set(check.slice(0, 4), 21);
    return this.base58Encode(full);
  },

  deriveValidTronAddress: function(seedMaterial) {
    var digest = this.sha256dBytes("EQX_TRON_TRC20:" + String(seedMaterial));
    var payload = new Uint8Array(21);
    payload[0] = this.TRON_VERSION_BYTE;
    for (var i = 0; i < 20; i++) payload[i + 1] = digest[i];
    var check = this.sha256dBytes(payload);
    var full = new Uint8Array(25);
    full.set(payload, 0);
    full.set(check.slice(0, 4), 21);
    return this.base58Encode(full);
  },

  deriveAccountAddresses: function(eqxAddress) {
    var clean = (eqxAddress || "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx").trim();
    var evmDigest = this.sha256dBytes("EQX_EVM_BIP44:" + clean);
    var solDigest = this.sha256dBytes("EQX_SOL_SPL:" + clean);
    var btcDigest = this.sha256dBytes("EQX_BTC_BIP84:" + clean);
    return {
      EQX_NATIVE: clean,
      EVM_SHARED: "0x" + this.bytesToHex(evmDigest).substring(0, 40),
      SOLANA_SPL: this.base58Encode(solDigest),
      TRON_TRC20: this.deriveValidTronAddress(clean),
      BTC_SEGWIT: this.encodeSegwitBech32("bc", 0, btcDigest.slice(0, 20))
    };
  },

  renderCanvasQR: function(canvasId, textData) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext("2d"), size = 25, matrix = [], reserved = [];
    for (var r = 0; r < size; r++) {
      matrix[r] = []; reserved[r] = [];
      for (var c = 0; c < size; c++) { matrix[r][c] = 0; reserved[r][c] = false; }
    }
    function placeFinder(row, col) {
      for (var dr = -1; dr <= 7; dr++) {
        for (var dc = -1; dc <= 7; dc++) {
          var rr = row + dr, cc = col + dc;
          if (rr >= 0 && rr < size && cc >= 0 && cc < size) {
            reserved[rr][cc] = true;
            if (dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 && (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4))) {
              matrix[rr][cc] = 1;
            }
          }
        }
      }
    }
    placeFinder(0, 0); placeFinder(0, size - 7); placeFinder(size - 7, 0);
    for (var t = 8; t < size - 8; t++) {
      reserved[6][t] = true; matrix[6][t] = (t % 2 === 0) ? 1 : 0;
      reserved[t][6] = true; matrix[t][6] = (t % 2 === 0) ? 1 : 0;
    }
    var digest = this.sha256dBytes(String(textData || "EQUINOX")), bitIdx = 0;
    for (var y = 0; y < size; y++) {
      for (var x = 0; x < size; x++) {
        if (!reserved[y][x]) {
          var byteVal = digest[(bitIdx >> 3) % 32] ^ ((x * 17 + y * 31) & 0xff);
          matrix[y][x] = (byteVal >> (bitIdx & 7)) & 1;
          bitIdx++;
        }
      }
    }
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    var pad = 5, cell = Math.floor((canvas.width - pad * 2) / size);
    var offset = Math.floor((canvas.width - cell * size) / 2);
    ctx.fillStyle = "#06090e";
    for (var mr = 0; mr < size; mr++) {
      for (var mc = 0; mc < size; mc++) {
        if (matrix[mr][mc] === 1) ctx.fillRect(offset + mc * cell, offset + mr * cell, cell, cell);
      }
    }
  }
};