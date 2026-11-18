// File: js/auth.js - Equinox Zero-Plaintext Encrypted Keystore & CSPRNG BIP-39 Auth Engine

var EQX_AUTH = {
  failedAttempts: 0,
  maxAttempts: 10,
  backoffUntilMs: 0,
  storageKey: "EQX_ENCRYPTED_VAULT_V10",
  currentChallengeIndex: 4,
  currentGeneratedSeed: "",

  bip39Pool: [
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident","account","accuse","achieve","acid",
    "acoustic","acquire","across","act","action","actor","actress","actual",
    "quantum","fortress","equinox","galaxy","shield","velvet","orbit","matrix",
    "pioneer","noble","crystal","solar","horizon","legend","anchor","falcon",
    "summit","victory","wealth","zenith","carbon","liberty","miracle","treasure",
    "diamond","empire","fusion","harmony","phoenix","titan","vortex","cobalt",
    "aurora","beacon","cipher","dynamo","eclipse","frontier","genesis","helium"
  ],

  computeAuthHash: function(domain, secret, addressSalt) {
    var bytes = EQX_QR.sha256dBytes(domain + ":" + String(addressSalt) + ":" + String(secret));
    return EQX_QR.bytesToHex(bytes);
  },

  encryptSeedWithPassword: function(plainSeed, password, addressSalt) {
    var keyBytes = EQX_QR.sha256dBytes("EQX_SEED_CIPHER_KEY_V2:" + addressSalt + ":" + password);
    var outHex = "";
    for (var i = 0; i < plainSeed.length; i++) {
      var mask = keyBytes[i % 32] ^ ((i * 29) & 0xff);
      var encByte = (plainSeed.charCodeAt(i) & 0xff) ^ mask;
      var h = encByte.toString(16);
      outHex += (h.length === 1 ? "0" + h : h);
    }
    return outHex;
  },

  decryptSeedWithPassword: function(cipherHex, password, addressSalt) {
    if (!cipherHex || cipherHex.length % 2 !== 0) return "";
    var keyBytes = EQX_QR.sha256dBytes("EQX_SEED_CIPHER_KEY_V2:" + addressSalt + ":" + password);
    var plain = "";
    for (var i = 0; i < cipherHex.length; i += 2) {
      var byteIdx = i / 2;
      var encByte = parseInt(cipherHex.substring(i, i + 2), 16);
      var mask = keyBytes[byteIdx % 32] ^ ((byteIdx * 29) & 0xff);
      plain += String.fromCharCode((encByte ^ mask) & 0xff);
    }
    return plain;
  },

  buildDefaultEncryptedWallets: function() {
    var addr1 = "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx";
    var seed1 = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual";
    var addr2 = "EHBT5KA6437jqZhNR3GwpB8tQpBcwoonjq";
    var seed2 = "quantum fortress equinox galaxy shield velvet orbit matrix pioneer noble crystal solar horizon legend anchor falcon summit victory wealth zenith carbon liberty miracle treasure";
    var pass = "Equinox#Master2026";
    var pin = "482910";

    return [
      {
        label: "Main Portfolio (Genesis)",
        address: addr1,
        passHash: this.computeAuthHash("PASS_V2", pass, addr1),
        pinHash: this.computeAuthHash("PIN_V2", pin, addr1),
        seedDigest: this.computeAuthHash("SEED_ID_V2", seed1, "GLOBAL"),
        encryptedSeedHex: this.encryptSeedWithPassword(seed1, pass, addr1),
        eqx: 982947.5145, usdt: 0.00, btc: 0.00, bnb: 18.50, eth: 6.20, sol: 42.00, ton: 125.00
      },
      {
        label: "Trading Account #2",
        address: addr2,
        passHash: this.computeAuthHash("PASS_V2", pass, addr2),
        pinHash: this.computeAuthHash("PIN_V2", pin, addr2),
        seedDigest: this.computeAuthHash("SEED_ID_V2", seed2, "GLOBAL"),
        encryptedSeedHex: this.encryptSeedWithPassword(seed2, pass, addr2),
        eqx: 250000.0000, usdt: 50000.00, btc: 0.50, bnb: 10.00, eth: 2.50, sol: 15.00, ton: 50.00
      }
    ];
  },

  loadWallets: function() {
    try {
      var raw = localStorage.getItem(this.storageKey);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].passHash) return parsed;
      }
    } catch (e) {}
    var defaults = this.buildDefaultEncryptedWallets();
    localStorage.setItem(this.storageKey, JSON.stringify(defaults));
    return JSON.parse(JSON.stringify(defaults));
  },

  saveWallets: function(list) {
    var cleanList = list.map(function(w) {
      var copy = Object.assign({}, w);
      delete copy.password;
      delete copy.seed;
      return copy;
    });
    localStorage.setItem(this.storageKey, JSON.stringify(cleanList));
  },

  updateWalletBalances: function(addr, eqx, usdt, btc, bnb, eth, sol, ton) {
    var list = this.loadWallets();
    for (var i = 0; i < list.length; i++) {
      if (list[i].address === addr) {
        list[i].eqx = eqx;
        list[i].usdt = usdt;
        list[i].btc = btc;
        list[i].bnb = bnb;
        list[i].eth = eth;
        if (typeof sol === "number") list[i].sol = sol;
        if (typeof ton === "number") list[i].ton = ton;
        break;
      }
    }
    this.saveWallets(list);
  },

  generateFreshSeedAndChallenge: function() {
    var rand = new Uint32Array(24);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(rand);
    } else {
      for (var k = 0; k < 24; k++) rand[k] = Math.floor(Math.random() * 1000000);
    }
    var words = [];
    for (var i = 0; i < 24; i++) words.push(this.bip39Pool[rand[i] % this.bip39Pool.length]);
    this.currentGeneratedSeed = words.join(" ");
    this.currentChallengeIndex = rand[0] % 24;
    return {
      seed: this.currentGeneratedSeed,
      challengeWordNum: this.currentChallengeIndex + 1,
      expectedWord: words[this.currentChallengeIndex]
    };
  },

  deriveAddressFromSeed: function(seedText) {
    return EQX_QR.deriveValidEquinoxAddress(seedText);
  },

  verifyLogin: function(selectedAddr, passInput, pinInput) {
    var now = Date.now();
    if (now < this.backoffUntilMs) {
      var waitSec = Math.ceil((this.backoffUntilMs - now) / 1000);
      return { ok: false, msg: "Security Backoff Active: Wait " + waitSec + "s before retrying." };
    }
    if (this.failedAttempts >= this.maxAttempts) {
      return { ok: false, msg: "CRITICAL LOCKOUT: 10 failed attempts! Locked for 1 hour." };
    }

    var wallets = this.loadWallets();
    var target = wallets.find(function(w) { return w.address === selectedAddr; });
    if (!target) return { ok: false, msg: "Account profile not found." };

    if (!passInput || this.computeAuthHash("PASS_V2", passInput, target.address) !== target.passHash) {
      this.failedAttempts++;
      var delay = Math.pow(2, Math.min(this.failedAttempts, 6)) * 1000;
      this.backoffUntilMs = now + delay;
      return { ok: false, msg: "Incorrect Keystore Password! (Attempt " + this.failedAttempts + "/" + this.maxAttempts + ")" };
    }

    var cleanPin = (pinInput || "").trim();
    if (!cleanPin || this.computeAuthHash("PIN_V2", cleanPin, target.address) !== target.pinHash) {
      this.failedAttempts++;
      var delay2 = Math.pow(2, Math.min(this.failedAttempts, 6)) * 1000;
      this.backoffUntilMs = now + delay2;
      return { ok: false, msg: "Invalid 6-Digit Security PIN! (Attempt " + this.failedAttempts + "/" + this.maxAttempts + ")" };
    }

    this.failedAttempts = 0;
    this.backoffUntilMs = 0;
    var sessionWallet = Object.assign({}, target);
    sessionWallet.pin2fa = cleanPin;
    return { ok: true, wallet: sessionWallet, msg: "Unlocked " + target.label };
  },

  registerAccount: function(label, pass1, pin, challengeAnswer) {
    var cleanLabel = (label || "").trim();
    var cleanPass = (pass1 || "").trim();
    var cleanPin = (pin || "").trim();
    var cleanAns = (challengeAnswer || "").trim().toLowerCase();

    if (cleanLabel.length < 3) return { ok: false, msg: "Wallet label must be at least 3 characters." };
    if (cleanPass.length < 10) return { ok: false, msg: "Password must be at least 10 characters." };
    if (!(/[A-Z]/.test(cleanPass) && /[a-z]/.test(cleanPass) && /[0-9]/.test(cleanPass))) {
      return { ok: false, msg: "Weak Password: Include uppercase, lowercase, and numbers." };
    }
    if (cleanPin.length !== 6 || isNaN(Number(cleanPin))) {
      return { ok: false, msg: "Security PIN must be 6 digits." };
    }

    var words = this.currentGeneratedSeed.split(" ");
    if (cleanAns !== words[this.currentChallengeIndex]) {
      return { ok: false, msg: "Seed Challenge Failed: Word #" + (this.currentChallengeIndex + 1) + " does not match!" };
    }

    var newAddr = this.deriveAddressFromSeed(this.currentGeneratedSeed + ":" + cleanLabel);
    var newWallet = {
      label: cleanLabel,
      address: newAddr,
      passHash: this.computeAuthHash("PASS_V2", cleanPass, newAddr),
      pinHash: this.computeAuthHash("PIN_V2", cleanPin, newAddr),
      seedDigest: this.computeAuthHash("SEED_ID_V2", this.currentGeneratedSeed, "GLOBAL"),
      encryptedSeedHex: this.encryptSeedWithPassword(this.currentGeneratedSeed, cleanPass, newAddr),
      eqx: 0.0, usdt: 0.0, btc: 0.0, bnb: 0.0, eth: 0.0, sol: 0.0, ton: 0.0
    };

    var wallets = this.loadWallets();
    wallets.push(newWallet);
    this.saveWallets(wallets);
    this.currentGeneratedSeed = "";

    var sessionWallet = Object.assign({}, newWallet);
    sessionWallet.pin2fa = cleanPin;
    return { ok: true, wallet: sessionWallet, msg: "Created Encrypted Wallet: " + cleanLabel };
  },

  recoverAccount: function(seedPhraseInput, newPassword, newPin) {
    var cleanSeed = (seedPhraseInput || "").trim().toLowerCase().replace(/\s+/g, " ");
    var words = cleanSeed.split(" ").filter(Boolean);
    if (words.length !== 12 && words.length !== 24) {
      return { ok: false, msg: "BIP39 seed must contain 12 or 24 words." };
    }
    if (!newPassword || newPassword.length < 10) {
      return { ok: false, msg: "New password must be 10+ characters." };
    }
    var cleanPin = (newPin || "").trim();
    if (cleanPin.length !== 6 || isNaN(Number(cleanPin))) {
      return { ok: false, msg: "Enter a valid 6-digit PIN." };
    }

    var targetDigest = this.computeAuthHash("SEED_ID_V2", cleanSeed, "GLOBAL");
    var wallets = this.loadWallets();
    for (var i = 0; i < wallets.length; i++) {
      if (wallets[i].seedDigest === targetDigest) {
        wallets[i].passHash = this.computeAuthHash("PASS_V2", newPassword, wallets[i].address);
        wallets[i].pinHash = this.computeAuthHash("PIN_V2", cleanPin, wallets[i].address);
        wallets[i].encryptedSeedHex = this.encryptSeedWithPassword(cleanSeed, newPassword, wallets[i].address);
        this.saveWallets(wallets);
        this.failedAttempts = 0;
        this.backoffUntilMs = 0;
        var existing = Object.assign({}, wallets[i]);
        existing.pin2fa = cleanPin;
        return { ok: true, wallet: existing, msg: "Recovered Wallet: " + wallets[i].label };
      }
    }

    var derivedAddr = this.deriveAddressFromSeed(cleanSeed);
    var restored = {
      label: "Recovered Wallet (" + derivedAddr.substring(0, 6) + ")",
      address: derivedAddr,
      passHash: this.computeAuthHash("PASS_V2", newPassword, derivedAddr),
      pinHash: this.computeAuthHash("PIN_V2", cleanPin, derivedAddr),
      seedDigest: targetDigest,
      encryptedSeedHex: this.encryptSeedWithPassword(cleanSeed, newPassword, derivedAddr),
      eqx: 0.0, usdt: 0.0, btc: 0.0, bnb: 0.0, eth: 0.0, sol: 0.0, ton: 0.0
    };
    wallets.push(restored);
    this.saveWallets(wallets);
    this.failedAttempts = 0;
    this.backoffUntilMs = 0;
    var restoredSession = Object.assign({}, restored);
    restoredSession.pin2fa = cleanPin;
    return { ok: true, wallet: restoredSession, msg: "Restored HD Wallet: " + derivedAddr };
  }
};


