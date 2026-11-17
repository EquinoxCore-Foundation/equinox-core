@echo off
title Equinox Core L1 Node & Super-Wallet (v0.2.0-testnet)
echo Starting Equinox Core Layer-1 Node on Port 18545...
start "Equinox L1 Node" "%~dp0equinox-core.exe" --testnet
timeout /t 2 >nul
start "" "%~dp0wallet-ui\index.html"
