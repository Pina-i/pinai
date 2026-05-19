//! Numeric one-time-passcode utility for signup email verification.

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Default OTP length used everywhere in the signup flow.
pub const OTP_LEN: usize = 6;

/// Cryptographically random numeric OTP. Each digit is drawn uniformly from
/// `0..=9` via rejection sampling on `OsRng` bytes — biased modulo would skew
/// digits and shrink the effective entropy.
pub fn generate_numeric_otp(len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 1];
    while out.len() < len {
        OsRng.fill_bytes(&mut buf);
        let b = buf[0];
        if b < 250 {
            out.push(char::from(b'0' + (b % 10)));
        }
    }
    out
}

/// HMAC-SHA256(pepper, code). Pepper lives in env, never in the DB — a leaked
/// table can't be brute-forced offline without it.
pub fn hash(code: &str, pepper: &[u8]) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(code.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time compare; rejects length mismatch up front.
pub fn verify(code: &str, expected_hash: &[u8], pepper: &[u8]) -> bool {
    let got = hash(code, pepper);
    if got.len() != expected_hash.len() {
        return false;
    }
    got.ct_eq(expected_hash).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_requested_length_of_digits() {
        for _ in 0..50 {
            let otp = generate_numeric_otp(OTP_LEN);
            assert_eq!(otp.len(), OTP_LEN);
            assert!(otp.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn hash_is_deterministic_for_same_input() {
        let pepper = b"super-secret-pepper-of-at-least-32-bytes!";
        assert_eq!(hash("123456", pepper), hash("123456", pepper));
        assert_ne!(hash("123456", pepper), hash("123457", pepper));
    }

    #[test]
    fn hash_changes_with_pepper() {
        let h1 = hash("123456", b"pepper-a");
        let h2 = hash("123456", b"pepper-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_round_trips() {
        let pepper = b"pepper-pepper-pepper-pepper-pepper-pepper";
        let h = hash("987654", pepper);
        assert!(verify("987654", &h, pepper));
        assert!(!verify("987653", &h, pepper));
        assert!(!verify("", &h, pepper));
        assert!(!verify("987654", &h, b"different-pepper"));
    }

    #[test]
    fn verify_rejects_length_mismatched_hash() {
        let pepper = b"pepper";
        let h = hash("123456", pepper);
        let truncated = &h[..h.len() - 1];
        assert!(!verify("123456", truncated, pepper));
    }
}
