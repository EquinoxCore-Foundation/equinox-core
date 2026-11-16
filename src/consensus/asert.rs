// File: src/consensus/asert.rs
#![forbid(unsafe_code)]

use crate::config::TARGET_BLOCK_TIME_SECS;
use crate::crypto::hash::Hash256;
use std::cmp::Ordering;

/// ASERT অর্ধ-জীবন (Half-Life): ৯০০ সেকেন্ড (১৫ মিনিট)
pub const ASERT_HALF_LIFE_SECS: i128 = 900;

/// ১৬-বিট ফিক্সড-পয়েন্ট র‍্যাডিক্স (2^16 = 65,536)
const RADIX_16: u128 = 65_536;

/// মেইননেটের সর্বনিম্ন ডিফিকাল্টি / সর্বোচ্চ সহজ কম্প্যাক্ট টার্গেট সীমা
pub const MAX_COMPACT_NBITS: u32 = 0x1f0f_ffff;

/// সর্বোচ্চ ডিফিকাল্টি / সর্বনিম্ন কম্প্যাক্ট টার্গেট সীমা
pub const MIN_COMPACT_NBITS: u32 = 0x0301_0000;

/// এক্সপোনেন্ট ওভারফ্লো/আন্ডারফ্লো রোধে সর্বোচ্চ অনুমোদিত শিফট ব্যবধান
const MAX_ASERT_SHIFT_HALVINGS: i128 = 62;

/// পূর্ণ ২৫৬-বিট আনসাইন্ড ইন্টিজার (`limbs[0]` = সর্বনিম্ন ৬৪ বিট, `limbs[3]` = সর্বোচ্চ ৬৪ বিট)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TargetU256 {
    pub limbs: [u64; 4],
}

impl PartialOrd for TargetU256 {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TargetU256 {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl TargetU256 {
    pub const ZERO: Self = Self { limbs: [0; 4] };
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0],
    };
    pub const MAX: Self = Self {
        limbs: [u64::MAX; 4],
    };

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&w| w == 0)
    }

    pub fn from_u128(val: u128) -> Self {
        Self {
            limbs: [val as u64, (val >> 64) as u64, 0, 0],
        }
    }

    pub fn to_u128_saturating(&self) -> u128 {
        if self.limbs[3] != 0 || self.limbs[2] != 0 {
            u128::MAX
        } else {
            (self.limbs[0] as u128) | ((self.limbs[1] as u128) << 64)
        }
    }

    pub fn from_be_bytes(bytes: &Hash256) -> Self {
        let l3 = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let l2 = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let l1 = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        let l0 = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
        Self {
            limbs: [l0, l1, l2, l3],
        }
    }

    pub fn to_be_bytes(&self) -> Hash256 {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.limbs[3].to_be_bytes());
        out[8..16].copy_from_slice(&self.limbs[2].to_be_bytes());
        out[16..24].copy_from_slice(&self.limbs[1].to_be_bytes());
        out[24..32].copy_from_slice(&self.limbs[0].to_be_bytes());
        out
    }

    /// লিডিং জিরো বিট সংখ্যা (`1..=256`) থেকে ২৫৬-বিট টার্গেট (`MAX >> bits`) তৈরি করে
    pub fn from_leading_zero_bits(bits: u32) -> Result<Self, String> {
        if bits == 0 || bits > 256 {
            return Err(format!("Invalid leading-zero difficulty bits: {}", bits));
        }
        if bits == 256 {
            return Ok(Self::ONE);
        }
        Ok(Self::MAX.shr_bits(bits))
    }

    #[inline]
    pub fn bit(&self, index: usize) -> bool {
        if index >= 256 {
            return false;
        }
        let word = index / 64;
        let bit = index % 64;
        ((self.limbs[word] >> bit) & 1) != 0
    }

    #[inline]
    pub fn set_bit(&mut self, index: usize) {
        if index < 256 {
            self.limbs[index / 64] |= 1u64 << (index % 64);
        }
    }

    pub fn bit_not(&self) -> Self {
        Self {
            limbs: [
                !self.limbs[0],
                !self.limbs[1],
                !self.limbs[2],
                !self.limbs[3],
            ],
        }
    }

    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            out[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 {
            None
        } else {
            Some(Self { limbs: out })
        }
    }

    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self < other {
            return None;
        }
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        Some(Self { limbs: out })
    }

    pub fn shr_bits(&self, shift: u32) -> Self {
        if shift == 0 {
            return *self;
        }
        if shift >= 256 {
            return Self::ZERO;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;
        let mut out = [0u64; 4];

        for i in 0..(4 - word_shift) {
            out[i] = self.limbs[i + word_shift] >> bit_shift;
            if bit_shift > 0 && (i + word_shift + 1) < 4 {
                out[i] |= self.limbs[i + word_shift + 1] << (64 - bit_shift);
            }
        }
        Self { limbs: out }
    }

    /// ২৫৬-বিট পূর্ণসংখ্যার সঠিক ভাগফল (`self / divisor`) নির্ণয় করে
    pub fn checked_div(&self, divisor: &Self) -> Option<Self> {
        if divisor.is_zero() {
            return None;
        }
        if self < divisor {
            return Some(Self::ZERO);
        }
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;

        for i in (0..256).rev() {
            // remainder = (remainder << 1) | self.bit(i)
            let mut carry = u64::from(self.bit(i));
            for w in 0..4 {
                let next_carry = remainder.limbs[w] >> 63;
                remainder.limbs[w] = (remainder.limbs[w] << 1) | carry;
                carry = next_carry;
            }
            if &remainder >= divisor {
                remainder = remainder.checked_sub(divisor).unwrap();
                quotient.set_bit(i);
            }
        }
        Some(quotient)
    }

    /// ৩২০-বিট ইন্টারমিডিয়েট বাফার ব্যবহার করে `(self * factor_u64) >> right_shift` বা `<< left_shift` হিসাব করে
    pub fn mul_u64_and_shift(&self, factor: u64, shift: i32) -> Option<Self> {
        let mut prod = [0u64; 5];
        let mut carry = 0u128;

        for i in 0..4 {
            let p = (self.limbs[i] as u128) * (factor as u128) + carry;
            prod[i] = p as u64;
            carry = p >> 64;
        }
        prod[4] = carry as u64;

        if shift == 0 {
            if prod[4] != 0 {
                return None;
            }
            return Some(Self {
                limbs: [prod[0], prod[1], prod[2], prod[3]],
            });
        }

        if shift < 0 {
            let rshift = (-shift) as u32;
            if rshift >= 320 {
                return Some(Self::ZERO);
            }
            let word_shift = (rshift / 64) as usize;
            let bit_shift = rshift % 64;
            let mut shifted = [0u64; 5];

            for i in 0..(5 - word_shift) {
                shifted[i] = prod[i + word_shift] >> bit_shift;
                if bit_shift > 0 && (i + word_shift + 1) < 5 {
                    shifted[i] |= prod[i + word_shift + 1] << (64 - bit_shift);
                }
            }
            if shifted[4] != 0 {
                return None;
            }
            Some(Self {
                limbs: [shifted[0], shifted[1], shifted[2], shifted[3]],
            })
        } else {
            let lshift = shift as u32;
            if lshift >= 64 {
                // Check if shifting left overflows 256 bits
                let word_shift = (lshift / 64) as usize;
                let bit_shift = lshift % 64;
                if word_shift >= 4 || prod[4] != 0 {
                    return None;
                }
                for i in (4 - word_shift)..4 {
                    if prod[i] != 0 {
                        return None;
                    }
                }
                let mut out = [0u64; 4];
                for i in (word_shift..4).rev() {
                    let src = i - word_shift;
                    if bit_shift > 0 && (prod[src] >> (64 - bit_shift)) != 0 && i == 3 {
                        return None;
                    }
                    out[i] = prod[src] << bit_shift;
                    if bit_shift > 0 && src > 0 {
                        out[i] |= prod[src - 1] >> (64 - bit_shift);
                    }
                }
                Some(Self { limbs: out })
            } else {
                let bit_shift = lshift;
                if prod[4] != 0 || (prod[3] >> (64 - bit_shift)) != 0 {
                    return None;
                }
                let mut out = [0u64; 4];
                for i in (0..4).rev() {
                    out[i] = prod[i] << bit_shift;
                    if i > 0 {
                        out[i] |= prod[i - 1] >> (64 - bit_shift);
                    }
                }
                Some(Self { limbs: out })
            }
        }
    }
}

pub struct AsertDifficultyEngine;

impl AsertDifficultyEngine {
    /// কম্প্যাক্ট `nBits` ফরম্যাটের বৈধতা পরীক্ষা করে এবং ২৫৬-বিট `TargetU256`-এ রূপান্তর করে।
    /// শূন্য, নেগেটিভ (`0x00800000`), নন-ক্যানোনিকাল এবং ওভারসাইজড টার্গেট কঠোরভাবে রিজেক্ট করে।
    pub fn validate_and_decode_compact_nbits(nbits: u32) -> Result<TargetU256, String> {
        let exponent = ((nbits >> 24) & 0xFF) as usize;
        let is_negative = (nbits & 0x0080_0000) != 0;
        let mantissa = nbits & 0x007F_FFFF;

        if exponent == 0 || exponent > 32 {
            return Err(format!("Invalid compact nBits exponent: {}", exponent));
        }
        if is_negative {
            return Err("Negative compact target (0x00800000 bit set) is forbidden".to_string());
        }
        if mantissa == 0 {
            return Err("Zero mantissa in compact nBits is forbidden".to_string());
        }
        

        let mut target_be = [0u8; 32];
        if exponent <= 3 {
            let shift = 3 - exponent;
            let shifted = mantissa >> (8 * shift);
            if shifted == 0 {
                return Err("Target underflowed to zero".to_string());
            }
            target_be[31] = (shifted & 0xFF) as u8;
            if exponent >= 2 {
                target_be[30] = ((shifted >> 8) & 0xFF) as u8;
            }
            if exponent == 3 {
                target_be[29] = ((shifted >> 16) & 0xFF) as u8;
            }
        } else {
            let start_pos = 32 - exponent;
            target_be[start_pos] = ((mantissa >> 16) & 0xFF) as u8;
            target_be[start_pos + 1] = ((mantissa >> 8) & 0xFF) as u8;
            target_be[start_pos + 2] = (mantissa & 0xFF) as u8;
        }

        let decoded = TargetU256::from_be_bytes(&target_be);
        if decoded.is_zero() {
            return Err("Decoded 256-bit target is zero".to_string());
        }
        Ok(decoded)
    }

    /// ২৫৬-বিট `TargetU256`-কে ক্যানোনিকাল ৩২-বিট কম্প্যাক্ট `nBits` ফরম্যাটে রূপান্তর করে
    pub fn target256_to_compact_nbits(target: &TargetU256) -> u32 {
        if target.is_zero() {
            return MIN_COMPACT_NBITS;
        }
        let be = target.to_be_bytes();
        let first_nz = be.iter().position(|&b| b != 0).unwrap_or(31);
        let mut size = 32 - first_nz;

        let mut mantissa: u32 = if size <= 3 {
            let b0 = be[29] as u32;
            let b1 = be[30] as u32;
            let b2 = be[31] as u32;
            ((b0 << 16) | (b1 << 8) | b2) << (8 * (3 - size))
        } else {
            let b0 = be[first_nz] as u32;
            let b1 = be[first_nz + 1] as u32;
            let b2 = be[first_nz + 2] as u32;
            (b0 << 16) | (b1 << 8) | b2
        };

        // If the 0x00800000 sign bit is set, shift right by 1 byte and increment exponent
        if (mantissa & 0x0080_0000) != 0 {
            mantissa >>= 8;
            size += 1;
        }

        let nbits = ((size as u32) << 24) | (mantissa & 0x007F_FFFF);
        nbits.clamp(MIN_COMPACT_NBITS, MAX_COMPACT_NBITS)
    }

    /// পুরনো API সামঞ্জস্যতার জন্য `compact_nbits_to_target256` (অবৈধ ইনপুটে শূন্য হ্যাশ রিটার্ন করে যাতে কোনো ব্লক পাস না করে)
    pub fn compact_nbits_to_target256(nbits: u32) -> Hash256 {
        match Self::validate_and_decode_compact_nbits(nbits) {
            Ok(t) => t.to_be_bytes(),
            Err(_) => [0u8; 32],
        }
    }

    #[inline]
    pub fn hash_meets_compact_target(block_hash: &Hash256, compact_nbits: u32) -> bool {
        let Ok(target) = Self::validate_and_decode_compact_nbits(compact_nbits) else {
            return false;
        };
        let hash_u256 = TargetU256::from_be_bytes(block_hash);
        hash_u256 <= target
    }

    /// পূর্ণ ২৫৬-বিট ইন্টিজার ASERT অ্যালগরিদম:
    /// `next_target = anchor_target * 2^((actual_time - ideal_time) / ASERT_HALF_LIFE_SECS)`
    pub fn calculate_next_asert_target_256(
        anchor_target: &TargetU256,
        anchor_height: u64,
        anchor_timestamp: u64,
        current_height: u64,
        current_timestamp: u64,
    ) -> Result<TargetU256, String> {
        if anchor_target.is_zero() {
            return Err("Anchor 256-bit target cannot be zero".to_string());
        }
        if current_height <= anchor_height {
            return Err("Current height must be strictly greater than anchor height".to_string());
        }

        let max_target = Self::validate_and_decode_compact_nbits(MAX_COMPACT_NBITS)?;
        let min_target = Self::validate_and_decode_compact_nbits(MIN_COMPACT_NBITS)?;

        let height_diff = (current_height - anchor_height) as i128;
        let ideal_time = height_diff.saturating_mul(TARGET_BLOCK_TIME_SECS as i128);
        let actual_time = (current_timestamp as i128).saturating_sub(anchor_timestamp as i128);

        let time_delta = actual_time.saturating_sub(ideal_time);
        let exponent_fp16 = time_delta
            .saturating_mul(RADIX_16 as i128)
            / ASERT_HALF_LIFE_SECS;

        let unclamped_shifts = exponent_fp16 >> 16;
        let shifts = unclamped_shifts.clamp(-MAX_ASERT_SHIFT_HALVINGS, MAX_ASERT_SHIFT_HALVINGS);
        let frac = (exponent_fp16 & 0xFFFF) as u128;

        // Cubic polynomial in 16-bit fixed point: factor_fp16 in [65536, 131071]
        let f1 = 195_766_423_245_049u128.saturating_mul(frac);
        let f2 = 971_821_376u128.saturating_mul(frac).saturating_mul(frac);
        let f3 = 5_127u128
            .saturating_mul(frac)
            .saturating_mul(frac)
            .saturating_mul(frac);

        let poly_add = (f1.saturating_add(f2).saturating_add(f3).saturating_add(1u128 << 47)) >> 48;
        let factor_fp16 = (RADIX_16 + poly_add) as u64;

        let net_shift = (shifts as i32) - 16;
        let computed = match anchor_target.mul_u64_and_shift(factor_fp16, net_shift) {
            Some(t) => t,
            None => max_target,
        };

        Ok(computed.clamp(min_target, max_target))
    }

    /// পুরনো API সামঞ্জস্যতার জন্য `calculate_next_asert_target_u128`
    pub fn calculate_next_asert_target_u128(
        anchor_target: u128,
        anchor_height: u64,
        anchor_timestamp: u64,
        current_height: u64,
        current_timestamp: u64,
    ) -> u128 {
        if current_height <= anchor_height || anchor_target == 0 {
            return anchor_target.max(1);
        }
        let height_diff = (current_height - anchor_height) as i128;
        let ideal_time = height_diff.saturating_mul(TARGET_BLOCK_TIME_SECS as i128);
        let actual_time = (current_timestamp as i128).saturating_sub(anchor_timestamp as i128);

        let exponent_fp16 = ((actual_time - ideal_time).saturating_mul(RADIX_16 as i128))
            / ASERT_HALF_LIFE_SECS;
        let mut shifts = (exponent_fp16 >> 16).clamp(-62, 62);
        let frac = (exponent_fp16 & 0xFFFF) as u128;

        let f1 = 195_766_423_245_049u128.saturating_mul(frac);
        let f2 = 971_821_376u128.saturating_mul(frac).saturating_mul(frac);
        let f3 = 5_127u128
            .saturating_mul(frac)
            .saturating_mul(frac)
            .saturating_mul(frac);
        let poly_add = (f1.saturating_add(f2).saturating_add(f3).saturating_add(1u128 << 47)) >> 48;
        let factor_fp16 = RADIX_16.saturating_add(poly_add);

        let mut next = anchor_target.saturating_mul(factor_fp16);
        shifts -= 16;

        if shifts >= 0 {
            let s = (shifts as u32).min(63);
            next = next.saturating_mul(1u128 << s);
        } else {
            let s = ((-shifts) as u32).min(127);
            next >>= s;
        }
        next.clamp(1, u128::MAX / 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_256bit_asert_schedule_and_compact_nbits_validation() {
        // 1. Negative bit (0x00800000), zero mantissa, and oversized exponent must be rejected
        assert!(AsertDifficultyEngine::validate_and_decode_compact_nbits(0x1d80_ffff).is_err());
        assert!(AsertDifficultyEngine::validate_and_decode_compact_nbits(0x1d00_0000).is_err());
        assert!(AsertDifficultyEngine::validate_and_decode_compact_nbits(0x2101_0000).is_err());

        // 2. Valid 256-bit target roundtrip and ASERT exact halving/doubling
        let anchor_256 =
            AsertDifficultyEngine::validate_and_decode_compact_nbits(0x1d00_ffff).unwrap();

        let steady = AsertDifficultyEngine::calculate_next_asert_target_256(
            &anchor_256,
            0,
            1_000_000,
            10,
            1_000_000 + 10 * TARGET_BLOCK_TIME_SECS,
        )
        .unwrap();
        assert_eq!(steady, anchor_256);

        // One half-life (+900s) behind schedule doubles the 256-bit target (halves difficulty)
        let easier = AsertDifficultyEngine::calculate_next_asert_target_256(
            &anchor_256,
            0,
            1_000_000,
            10,
            1_000_000 + 10 * TARGET_BLOCK_TIME_SECS + (ASERT_HALF_LIFE_SECS as u64),
        )
        .unwrap();
        let expected_double = anchor_256.checked_add(&anchor_256).unwrap();
        assert_eq!(easier, expected_double);

        // One half-life (-900s) ahead of schedule halves the 256-bit target (doubles difficulty)
        let harder = AsertDifficultyEngine::calculate_next_asert_target_256(
            &anchor_256,
            0,
            1_000_000,
            100,
            1_000_000 + 100 * TARGET_BLOCK_TIME_SECS - (ASERT_HALF_LIFE_SECS as u64),
        )
        .unwrap();
        assert_eq!(harder, anchor_256.shr_bits(1));
    }
}
