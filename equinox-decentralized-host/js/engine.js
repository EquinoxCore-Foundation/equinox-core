// File: js/engine.js
// Open-Source Decentralized Payment Engine & API Host

var PaymentStatus = {
  Pending: "PENDING",
  Confirmed: "CONFIRMED",
  Expired: "EXPIRED",
  Failed: "FAILED"
};

var PaymentEngine = {
  seq: 9201,
  activeInvoice: null,
  settledInvoices: {},

  Adapters: {
    "BSC": EQX_ADAPTERS.makeAdapter(
      "BSC",
      "https://bsc-dataseed.binance.org"
    ),
    "Ethereum": EQX_ADAPTERS.makeAdapter(
      "Ethereum",
      "https://eth.llamarpc.com"
    ),
    "Bitcoin": EQX_ADAPTERS.makeAdapter(
      "Bitcoin",
      "https://mempool.space/api"
    ),
    "Solana": EQX_ADAPTERS.makeAdapter(
      "Solana",
      "https://api.mainnet-beta.solana.com"
    ),
    "TRON": EQX_ADAPTERS.makeAdapter(
      "TRON",
      "https://api.trongrid.io"
    ),
    "EQX_AEGIS": EQX_ADAPTERS.makeAdapter(
      "EQX_AEGIS",
      "http://127.0.0.1:18545"
    )
  },

  // API: POST /api/v1/invoices
  NewInvoice: function(ch, ast, net, amt, adr) {
    var inv = {
      ID: "INV-" + (this.seq++),
      Chain: ch,
      Asset: ast,
      Network: net,
      Amount: String(amt),
      ReceiveAddress: adr,
      Status: PaymentStatus.Pending,
      TxHash: "",
      Confirmations: 0,
      BlockHash: "",
      ExpiresAt: Date.now() + 900000
    };
    this.activeInvoice = inv;
    return inv;
  },

  // API: POST /api/v1/invoices/{id}/verify
  Verify: async function(invoice) {
    var adapter = this.Adapters[invoice.Chain];
    if (!adapter) {
      throw new Error("unsupported blockchain");
    }

    if (Date.now() > invoice.ExpiresAt) {
      invoice.Status = PaymentStatus.Expired;
      return invoice;
    }

    if (this.settledInvoices[invoice.ID]) {
      // Create a fresh invoice automatically if user clicks again
      invoice = this.NewInvoice(
        invoice.Chain,
        invoice.Asset,
        invoice.Network,
        invoice.Amount,
        invoice.ReceiveAddress
      );
    }

    var result = await adapter.VerifyPayment(invoice);

    if (!result.Valid || result.Amount !== invoice.Amount) {
      invoice.Status = PaymentStatus.Failed;
      throw new Error("payment verification failed");
    }

    invoice.TxHash = result.TxHash;
    invoice.Confirmations = result.Confirmations;
    invoice.BlockHash = result.BlockHash;

    if (result.Confirmations >= 1) {
      invoice.Status = PaymentStatus.Confirmed;
      this.settledInvoices[invoice.ID] = true;
    }

    return invoice;
  }
};
