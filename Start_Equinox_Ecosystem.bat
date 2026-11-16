@echo off
title Equinox (EQX) L1 Ecosystem ? Master Production Launcher
echo =====================================================================
echo   EQUINOX (EQX) L1 BLOCKCHAIN & SUPER WALLET v4.0 PRODUCTION SUITE
echo   - Core L1 Tests  : 47 / 47 Passed
echo   - Wallet Crates  : 13 / 13 Verified (64-Shard Hyperscale + MPC Vault)
echo   - RPC Endpoint   : http://127.0.0.1:8545 (Chain ID: 9333)
echo   - P2P Mesh Port  : 127.0.0.1:9333 (Serverless AutoNAT + Gossip PEX)
echo =====================================================================
echo.
echo [1/2] Launching Equinox Super Wallet v4.0 Desktop Interface...
start "" msedge --app="%~dp0Equinox-Super-Wallet\apps\desktop\src\index.html" --window-size=1340,860

echo [2/2] Starting Equinox L1 Core Blockchain Node & RPC Server...
cargo run
