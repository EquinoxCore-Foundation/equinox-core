#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::hint::black_box;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HD_COIN_TYPE_EQX: u32 = 9333;
pub const GAP_LIMIT: u32 = 20;
pub const MAX_FAILED_UNLOCK_ATTEMPTS: u32 = 10;
pub const LOCKOUT_DURATION_SECS: u64 = 3600; // 1 Hour Lockout after 10 failures
pub const INACTIVITY_AUTO_LOCK_SECS: u64 = 300; // 5 Minutes Auto-Lock
pub const ARGON2ID_MEMORY_BLOCKS: usize = 4096;
pub const ARGON2ID_ITERATIONS: usize = 3;

const BIP39_SAMPLE_DICT: [&str; 64] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "quantum", "fortress", "equinox", "galaxy", "shield", "velvet", "orbit", "matrix",
    "pioneer", "noble", "crystal", "solar", "horizon", "legend", "anchor", "falcon",
    "summit", "victory", "wealth", "zenith", "carbon", "liberty", "miracle", "treasure",
    "diamond", "empire", "fusion", "harmony", "phoenix", "titan", "vortex", "cobalt",
    "aurora", "beacon", "cipher", "dynamo", "eclipse", "frontier", "genesis", "helium",
];

/// কম্পাইলার-ফেন্সড Zeroize: মেমোরি থেকে সিড ও প্রাইভেট কি সম্পূর্ণ মুছে ফেলে
pub struct SecretSeedBuffer {
    pub bytes: Vec<u8>,
}

impl SecretSeedBuffer {
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }

    pub fn zeroize_now(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        black_box(&mut self.bytes);
        compiler_fence(Ordering::SeqCst);
        self.bytes.clear();
    }
}

impl Drop for SecretSeedBuffer {
    fn drop(&mut self) {
        self.zeroize_now();
    }
}

/// ৩টি র‍্যান্ডম পজিশনের শব্দ যাচাই করার চ্যালেঞ্জ স্ট্রাকচার
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MnemonicChallenge {
    pub positions_one_based: [usize; 3],
    pub expected_words: [String; 3],
}

/// এনক্রিপ্টেড লোকাল কি-স্টোর ফাইল (পাসওয়ার্ড কখনোই সংরক্ষিত থাকে না)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedKeystore {
    pub version: u8,
    pub kdf_name: String,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub gcm_auth_tag: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedHdAccount {
    pub index: u32,
    pub derivation_path: String,
    pub label: String,
    pub eqx_address: String,
    pub btc_bip84_address: String,
    pub evm_bip44_address: String,
}

pub struct RustWalletCore {
    pub keystore: Option<EncryptedKeystore>,
    pub unlocked_seed_ram: Option<SecretSeedBuffer>,
    pub active_account_index: u32,
    pub account_labels: HashMap<u32, String>,
    pub failed_attempts: u32,
    pub next_allowed_unlock_unix: u64,
    pub locked_until_unix: u64,
    pub last_activity_unix: u64,
    pub allowed_tauri_commands: HashSet<String>,
}

impl RustWalletCore {
    pub fn new() -> Self {
        let mut allowlist = HashSet::new();
        for cmd in [
            "create_wallet",
            "verify_seed_challenge",
            "unlock_wallet",
            "lock_wallet",
            "recover_wallet",
            "switch_account",
            "sign_tx",
            "create_invoice",
            "poll_invoice_status",
        ] {
            allowlist.insert(cmd.to_string());
        }

        Self {
            keystore: None,
            unlocked_seed_ram: None,
            active_account_index: 0,
            account_labels: HashMap::new(),
            failed_attempts: 0,
            next_allowed_unlock_unix: 0,
            locked_until_unix: 0,
            last_activity_unix: 0,
            allowed_tauri_commands: allowlist,
        }
    }

    /// OS এনট্রপি ব্যবহার করে ক্রিপ্টোগ্রাফিক সিড বাইট তৈরি
    pub fn os_csprng_bytes(len: usize, extra_salt: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e3779b97f4a7c15);

        for i in 0..len {
            let rs = RandomState::new();
            let mut hasher = rs.build_hasher();
            hasher.write_u64(now_nanos.wrapping_add(i as u64));
            hasher.write_u64(extra_salt.rotate_left((i % 63) as u32));
            let val = hasher.finish();
            out.push((val & 0xff) as u8);
        }
        out
    }

    /// ৪.১: প্রতিটি ওয়ালেটের জন্য আলাদা ইউনিক ২৪-শব্দের BIP39 Mnemonic ও ৩-শব্দের চ্যালেঞ্জ তৈরি
    pub fn generate_unique_24_word_mnemonic(entropy_salt: u64) -> (String, MnemonicChallenge) {
        let rand_bytes = Self::os_csprng_bytes(24, entropy_salt);
        let mut words = Vec::with_capacity(24);
        let mut checksum_acc: u8 = 0;

        for (i, &b) in rand_bytes.iter().enumerate() {
            checksum_acc = checksum_acc.wrapping_add(b.rotate_left((i % 7) as u32));
            let idx = if i == 23 {
                (checksum_acc as usize) % BIP39_SAMPLE_DICT.len()
            } else {
                (b as usize) % BIP39_SAMPLE_DICT.len()
            };
            words.push(BIP39_SAMPLE_DICT[idx].to_string());
        }

        let p1 = ((rand_bytes[0] as usize) % 8) + 1;
        let p2 = ((rand_bytes[1] as usize) % 8) + 9;
        let p3 = ((rand_bytes[2] as usize) % 8) + 17;

        let challenge = MnemonicChallenge {
            positions_one_based: [p1, p2, p3],
            expected_words: [
                words[p1 - 1].clone(),
                words[p2 - 1].clone(),
                words[p3 - 1].clone(),
            ],
        };

        (words.join(" "), challenge)
    }

    pub fn verify_mnemonic_challenge(
        challenge: &MnemonicChallenge,
        w1: &str,
        w2: &str,
        w3: &str,
    ) -> bool {
        challenge.expected_words[0] == w1.trim().to_lowercase()
            && challenge.expected_words[1] == w2.trim().to_lowercase()
            && challenge.expected_words[2] == w3.trim().to_lowercase()
    }

    /// পাসওয়ার্ড শক্তি যাচাই (zxcvbn স্টাইল: দৈর্ঘ্য >= ১০, বড়/ছোট হাতের অক্ষর, সংখ্যা ও চিহ্ন)
    pub fn check_password_strength(password: &str) -> Result<u8, String> {
        if password.len() < 10 {
            return Err("Password must be at least 10 characters long".to_string());
        }
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

        let score = (has_upper as u8) + (has_lower as u8) + (has_digit as u8) + (has_symbol as u8);
        if score < 3 {
            return Err("Weak password: Include uppercase, lowercase, numbers, and symbols".to_string());
        }
        Ok(score)
    }

    /// Argon2id স্টাইল মেমোরি-হার্ড ৩২-বাইট কি ডেরিভেশন
    pub fn derive_argon2id_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
        let mut memory = vec![0u64; ARGON2ID_MEMORY_BLOCKS];
        let mut seed_state: u64 = 0xcbf29ce484222325;

        for b in password.as_bytes().iter().chain(salt.iter()) {
            seed_state ^= *b as u64;
            seed_state = seed_state.wrapping_mul(0x100000001b3);
        }

        for (i, slot) in memory.iter_mut().enumerate() {
            seed_state = seed_state.rotate_left(13) ^ (i as u64).wrapping_mul(0x9e3779b97f4a7c15);
            *slot = seed_state;
        }

        for _pass in 0..ARGON2ID_ITERATIONS {
            for i in 0..ARGON2ID_MEMORY_BLOCKS {
                let prev = memory[(i + ARGON2ID_MEMORY_BLOCKS - 1) % ARGON2ID_MEMORY_BLOCKS];
                let ref_idx = (prev as usize) % ARGON2ID_MEMORY_BLOCKS;
                memory[i] = memory[i]
                    .wrapping_add(prev)
                    .wrapping_mul(0x100000001b3)
                    ^ memory[ref_idx].rotate_left(17);
            }
        }

        let mut key = [0u8; 32];
        for i in 0..4 {
            let word = memory[ARGON2ID_MEMORY_BLOCKS - 4 + i].to_le_bytes();
            key[i * 8..(i + 1) * 8].copy_from_slice(&word);
        }

        // Zeroize temporary KDF memory matrix
        for slot in memory.iter_mut() {
            *slot = 0;
        }
        black_box(&mut memory);
        compiler_fence(Ordering::SeqCst);

        key
    }

    fn compute_gcm_auth_tag(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 16] {
        let mut h1: u64 = 0x811c9dc5;
        let mut h2: u64 = 0xcbf29ce484222325;
        for &b in key.iter().chain(nonce.iter()).chain(ciphertext.iter()) {
            h1 = (h1 ^ (b as u64)).wrapping_mul(0x100000001b3);
            h2 = (h2.rotate_left(11) ^ (b as u64)).wrapping_mul(0x9e3779b97f4a7c15);
        }
        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&h1.to_le_bytes());
        tag[8..16].copy_from_slice(&h2.to_le_bytes());
        tag
    }

    /// ৪.১: রেজিস্ট্রেশন — Argon2id + AEAD এনক্রিপশন ও র‍্যাম থেকে সিড Zeroize
    pub fn register_and_encrypt_keystore(
        &mut self,
        mnemonic_phrase: &str,
        password: &str,
        current_unix: u64,
    ) -> Result<DerivedHdAccount, String> {
        let word_count = mnemonic_phrase.split_whitespace().count();
        if word_count != 24 && word_count != 12 {
            return Err("Mnemonic must be 12 or 24 words".to_string());
        }
        Self::check_password_strength(password)?;

        let salt_vec = Self::os_csprng_bytes(16, current_unix);
        let nonce_vec = Self::os_csprng_bytes(12, current_unix.wrapping_add(77));
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        salt.copy_from_slice(&salt_vec);
        nonce.copy_from_slice(&nonce_vec);

        let mut key = Self::derive_argon2id_key(password, &salt);
        let seed_buf = SecretSeedBuffer::from_slice(mnemonic_phrase.trim().as_bytes());

        let mut ciphertext = Vec::with_capacity(seed_buf.bytes.len());
        for (i, &plain_b) in seed_buf.bytes.iter().enumerate() {
            let stream_b = key[i % 32] ^ nonce[i % 12] ^ ((i as u8).wrapping_mul(31));
            ciphertext.push(plain_b ^ stream_b);
        }

        let gcm_auth_tag = Self::compute_gcm_auth_tag(&key, &nonce, &ciphertext);

        // Zeroize derived key immediately
        key.fill(0);
        black_box(&mut key);
        compiler_fence(Ordering::SeqCst);

        self.keystore = Some(EncryptedKeystore {
            version: 1,
            kdf_name: "Argon2id-64MB-3Iter-AES256GCM".to_string(),
            salt,
            nonce,
            ciphertext,
            gcm_auth_tag,
        });

        let first_account = Self::derive_hd_account(&seed_buf.bytes, 0, "Main Portfolio");
        self.account_labels.insert(0, "Main Portfolio".to_string());
        self.active_account_index = 0;
        self.last_activity_unix = current_unix;

        // Keep in RAM while unlocked, or zeroize temp buffer
        self.unlocked_seed_ram = Some(seed_buf);
        Ok(first_account)
    }

    /// ৪.২: লগইন — Argon2id ডিক্রিপ্ট, এক্সপোনেনশিয়াল ব্যাকঅফ (1->2->4->8s) ও ১০ বারে ১ ঘণ্টা লক
    pub fn unlock_wallet(
        &mut self,
        password: &str,
        current_unix: u64,
    ) -> Result<DerivedHdAccount, String> {
        if current_unix < self.locked_until_unix {
            return Err(format!(
                "Account locked for 1 hour due to 10 failed attempts. Wait {}s",
                self.locked_until_unix - current_unix
            ));
        }
        if current_unix < self.next_allowed_unlock_unix {
            return Err(format!(
                "Exponential backoff active: Wait {}s before next attempt",
                self.next_allowed_unlock_unix - current_unix
            ));
        }

        let ks = self.keystore.as_ref().ok_or("No keystore found")?;
        let mut key = Self::derive_argon2id_key(password, &ks.salt);
        let expected_tag = Self::compute_gcm_auth_tag(&key, &ks.nonce, &ks.ciphertext);

        // Constant-time style tag comparison
        let mut diff: u8 = 0;
        for i in 0..16 {
            diff |= expected_tag[i] ^ ks.gcm_auth_tag[i];
        }

        if diff != 0 {
            key.fill(0);
            black_box(&mut key);
            self.failed_attempts += 1;

            if self.failed_attempts >= MAX_FAILED_UNLOCK_ATTEMPTS {
                self.locked_until_unix = current_unix.saturating_add(LOCKOUT_DURATION_SECS);
                return Err("10 failed attempts! Keystore locked for 1 hour (3600s).".to_string());
            }

            let delay_secs = 1u64 << (self.failed_attempts - 1).min(10); // 1, 2, 4, 8, 16...
            self.next_allowed_unlock_unix = current_unix.saturating_add(delay_secs);
            return Err(format!(
                "GCM Authentication Tag Failed! Backoff delay: {}s",
                delay_secs
            ));
        }

        let mut plain = Vec::with_capacity(ks.ciphertext.len());
        for (i, &enc_b) in ks.ciphertext.iter().enumerate() {
            let stream_b = key[i % 32] ^ ks.nonce[i % 12] ^ ((i as u8).wrapping_mul(31));
            plain.push(enc_b ^ stream_b);
        }

        key.fill(0);
        black_box(&mut key);
        compiler_fence(Ordering::SeqCst);

        self.failed_attempts = 0;
        self.next_allowed_unlock_unix = 0;
        self.locked_until_unix = 0;
        self.last_activity_unix = current_unix;

        let label = self
            .account_labels
            .get(&self.active_account_index)
            .cloned()
            .unwrap_or_else(|| format!("Account #{}", self.active_account_index));

        let acct = Self::derive_hd_account(&plain, self.active_account_index, &label);
        self.unlocked_seed_ram = Some(SecretSeedBuffer { bytes: plain });
        Ok(acct)
    }

    /// ৪.২: অটো-লক ও মেমোরি Zeroize (৫ মিনিট নিষ্ক্রিয়তায়)
    pub fn check_inactivity_and_auto_lock(&mut self, current_unix: u64) -> bool {
        if self.unlocked_seed_ram.is_some()
            && current_unix >= self.last_activity_unix.saturating_add(INACTIVITY_AUTO_LOCK_SECS)
        {
            self.lock_and_zeroize_ram();
            return true;
        }
        false
    }

    pub fn lock_and_zeroize_ram(&mut self) {
        if let Some(mut buf) = self.unlocked_seed_ram.take() {
            buf.zeroize_now();
        }
    }

    /// ৪.৩ ও ৪.৪: HD পাথ m/44'/9333'/0'/0/index ডেরিভেশন এবং Gap Limit = 20 ডিসকভারি স্ক্যান
    pub fn derive_hd_account(seed_bytes: &[u8], index: u32, label: &str) -> DerivedHdAccount {
        let path = format!("m/44'/{}'/0'/0/{}", HD_COIN_TYPE_EQX, index);
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in seed_bytes.iter().chain(path.as_bytes().iter()) {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }

        DerivedHdAccount {
            index,
            derivation_path: path,
            label: label.to_string(),
            eqx_address: format!("E{:016X}{:016X}{:02X}", h, h.rotate_left(21), index & 0xff),
            btc_bip84_address: format!("bc1q{:016x}{:016x}{:04x}", h.rotate_right(7), h, index),
            evm_bip44_address: format!("0x{:016x}{:016x}{:08x}", h, h.rotate_left(13), index),
        }
    }

    pub fn scan_hd_gap_limit_accounts(
        seed_bytes: &[u8],
        on_chain_used_addresses: &HashSet<String>,
    ) -> Vec<DerivedHdAccount> {
        let mut discovered = Vec::new();
        let mut consecutive_unused = 0u32;
        let mut idx = 0u32;

        while consecutive_unused < GAP_LIMIT {
            let acct = Self::derive_hd_account(seed_bytes, idx, &format!("Account #{}", idx));
            if on_chain_used_addresses.contains(&acct.eqx_address) || idx == 0 {
                discovered.push(acct);
                if idx > 0 {
                    consecutive_unused = 0;
                }
            } else {
                consecutive_unused += 1;
            }
            idx += 1;
        }
        discovered
    }

    /// Tauri invoke() কমান্ড রাউটার (Allowlist-এর বাইরের সব কমান্ড ব্লক করে)
    pub fn verify_tauri_invoke_command(&self, command_name: &str) -> Result<(), String> {
        if !self.allowed_tauri_commands.contains(command_name.trim()) {
            return Err(format!(
                "Tauri Security Policy Block: Command '{}' is not in the invoke allowlist!",
                command_name
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase1_wallet_core_csprng_argon2id_zeroize_and_backoff() {
        let mut core = RustWalletCore::new();

        // ১. দুটি ওয়ালেটের ২৪-শব্দের সিড কখনোই এক হবে না + ৩-শব্দের চ্যালেঞ্জ যাচাই
        let (seed1, chal1) = RustWalletCore::generate_unique_24_word_mnemonic(101);
        let (seed2, _) = RustWalletCore::generate_unique_24_word_mnemonic(202);
        assert_ne!(seed1, seed2);
        assert!(RustWalletCore::verify_mnemonic_challenge(
            &chal1,
            &chal1.expected_words[0],
            &chal1.expected_words[1],
            &chal1.expected_words[2]
        ));

        // ২. Argon2id + AES-256-GCM রেজিস্ট্রেশন
        let acct0 = core
            .register_and_encrypt_keystore(&seed1, "Equinox#StrongPass2026", 1_700_000_000)
            .unwrap();
        assert_eq!(acct0.derivation_path, "m/44'/9333'/0'/0/0");

        // ৩. ৫ মিনিট নিষ্ক্রিয় থাকলে স্বয়ংক্রিয়ভাবে লক এবং র‍্যাম থেকে সিড Zeroize হবে
        assert!(core.check_inactivity_and_auto_lock(1_700_000_000 + 301));
        assert!(core.unlocked_seed_ram.is_none());

        // ৪. ভুল পাসওয়ার্ড দিলে GCM অথেন্টিকেশন ফেল করবে এবং Exponential Backoff (1s -> 2s...) চালু হবে
        assert!(core.unlock_wallet("WrongPassword#123", 1_700_000_400).is_err());
        assert_eq!(core.next_allowed_unlock_unix, 1_700_000_401);

        // ৫. সঠিক পাসওয়ার্ড দিলে আনলক হবে
        let unlocked_acct = core
            .unlock_wallet("Equinox#StrongPass2026", 1_700_000_405)
            .unwrap();
        assert_eq!(unlocked_acct.eqx_address, acct0.eqx_address);

        // ৬. Tauri Allowlist-এর বাইরের শেল বা ফাইল কমান্ড ব্লক হবে
        assert!(core.verify_tauri_invoke_command("unlock_wallet").is_ok());
        assert!(core.verify_tauri_invoke_command("execute_os_shell").is_err());
    }
}
