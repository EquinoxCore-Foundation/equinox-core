#![allow(dead_code)]
// Section 15: Local SQLite Database Guard (Forbids Plaintext Private Keys/Mnemonics)

pub struct StorageGuard;
impl StorageGuard {
    pub fn is_safe_for_sqlite_storage(column_name: &str, payload: &str) -> bool {
        let lower = column_name.to_lowercase();
        if lower.contains("private_key") || lower.contains("mnemonic") || lower.contains("raw_seed") {
            return false;
        }
        !payload.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sqlite_plaintext_secret_rejection() {
        assert!(!StorageGuard::is_safe_for_sqlite_storage("raw_private_key", "secret"));
        assert!(!StorageGuard::is_safe_for_sqlite_storage("user_mnemonic", "twenty four words"));
        assert!(StorageGuard::is_safe_for_sqlite_storage("wallet_address", "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx"));
    }
}
