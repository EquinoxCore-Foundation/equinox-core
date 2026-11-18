// File: src-tauri/src/main.rs — Tauri Desktop Launcher for Equinox Super Wallet
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Equinox Super Wallet desktop application");
}