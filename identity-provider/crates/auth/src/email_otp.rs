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
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
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
mod tests;
