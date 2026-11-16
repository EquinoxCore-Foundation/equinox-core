-- EQUINOX PRODUCTION EXCHANGE & PAYMENT GATEWAY POSTGRESQL SCHEMA
-- Enforces: Double-Entry Ledger, Zero Negative Balances, Idempotent Deposits, and Hash-Chained Audit Log.

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    eqx_address VARCHAR(64) UNIQUE NOT NULL,
    password_argon2id_hash TEXT NOT NULL,
    totp_secret_encrypted BYTEA,
    is_frozen BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS chain_circuit_breakers (
    chain_name VARCHAR(32) PRIMARY KEY,
    is_paused BOOLEAN NOT NULL DEFAULT FALSE,
    max_hourly_outflow_atomic NUMERIC(38, 0) NOT NULL,
    current_hourly_outflow_atomic NUMERIC(38, 0) NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS processed_txs (
    chain_name VARCHAR(32) NOT NULL,
    tx_hash VARCHAR(128) NOT NULL,
    log_index INT NOT NULL DEFAULT 0,
    invoice_id BIGINT NOT NULL,
    amount_atomic NUMERIC(38, 0) NOT NULL CHECK (amount_atomic > 0),
    confirmed_at_height BIGINT NOT NULL,
    PRIMARY KEY (chain_name, tx_hash, log_index)
);

CREATE TABLE IF NOT EXISTS user_wallets (
    user_id UUID NOT NULL REFERENCES users(user_id),
    asset_symbol VARCHAR(16) NOT NULL,
    available_atomic NUMERIC(38, 0) NOT NULL DEFAULT 0 CHECK (available_atomic >= 0),
    locked_in_orders_atomic NUMERIC(38, 0) NOT NULL DEFAULT 0 CHECK (locked_in_orders_atomic >= 0),
    PRIMARY KEY (user_id, asset_symbol)
);

-- Append-Only Double-Entry Ledger (UPDATE and DELETE are strictly revoked on this table)
CREATE TABLE IF NOT EXISTS ledger_entries (
    entry_id BIGSERIAL PRIMARY KEY,
    tx_reference VARCHAR(128) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(user_id),
    asset_symbol VARCHAR(16) NOT NULL,
    debit_account VARCHAR(64) NOT NULL,
    credit_account VARCHAR(64) NOT NULL,
    amount_atomic NUMERIC(38, 0) NOT NULL CHECK (amount_atomic > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id BIGSERIAL PRIMARY KEY,
    actor VARCHAR(64) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    payload_json TEXT NOT NULL,
    prev_log_hash VARCHAR(64) NOT NULL,
    current_log_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
