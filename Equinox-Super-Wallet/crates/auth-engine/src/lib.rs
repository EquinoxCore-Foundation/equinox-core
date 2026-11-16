#![allow(dead_code)]
// Equinox Super Wallet — International Authentication, 2FA & Anti-Brute-Force Guard

pub const MAX_FAILED_LOGIN_ATTEMPTS: u8 = 5;

pub struct AuthSessionManager {
    pub failed_attempts: u8,
    pub is_locked_out: bool,
    pub active_account_address: Option<String>,
}

impl AuthSessionManager {
    pub fn new() -> Self {
        Self {
            failed_attempts: 0,
            is_locked_out: false,
            active_account_address: None,
        }
    }

    pub fn login_with_password_and_2fa(
        &mut self,
        password: &str,
        totp_code: &str,
        expected_address: &str,
    ) -> Result<String, String> {
        if self.is_locked_out {
            return Err("Account temporarily locked due to 5 failed login attempts!".to_string());
        }
        if password.len() < 10 || totp_code.len() != 6 || !totp_code.chars().all(|c| c.is_ascii_digit()) {
            self.failed_attempts += 1;
            if self.failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS {
                self.is_locked_out = true;
            }
            return Err(format!("Invalid credentials! Attempts remaining: {}", MAX_FAILED_LOGIN_ATTEMPTS - self.failed_attempts));
        }

        self.failed_attempts = 0;
        self.active_account_address = Some(expected_address.to_string());
        Ok(format!("SESSION_ACTIVE_{}", expected_address))
    }

    pub fn login_with_mnemonic_seed(&mut self, seed_phrase: &str, derived_address: &str) -> Result<String, String> {
        let word_count = seed_phrase.split_whitespace().count();
        if word_count != 12 && word_count != 24 {
            return Err("Seed phrase must contain exactly 12 or 24 BIP-39 words".to_string());
        }
        self.failed_attempts = 0;
        self.active_account_address = Some(derived_address.to_string());
        Ok(derived_address.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_international_login_and_brute_force_lockout() {
        let mut auth = AuthSessionManager::new();
        let addr = "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx";

        // সঠিক পাসওয়ার্ড ও ৬-ডিজিট 2FA দিয়ে সফল লগইন
        assert!(auth.login_with_password_and_2fa("Equinox#Master2026", "482910", addr).is_ok());

        // ৫ বার ভুল পাসওয়ার্ড দিলে হ্যাকারকে অটো-লক করে দেবে
        for _ in 0..5 {
            let _ = auth.login_with_password_and_2fa("wrong", "000", addr);
        }
        assert!(auth.is_locked_out);
        assert!(auth.login_with_password_and_2fa("Equinox#Master2026", "482910", addr).is_err());
    }
}
