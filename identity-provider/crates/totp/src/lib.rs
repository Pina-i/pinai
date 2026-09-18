//! Pure TOTP + recovery-code primitives used by the auth crate.
//!
//! No DB, no HTTP — every public function is a small deterministic operation
//! testable in isolation.

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use totp_rs::{Algorithm, TOTP};

type HmacSha256 = Hmac<Sha256>;

/// Authenticator-compatible defaults — every popular app speaks these.
pub const TOTP_DIGITS: usize = 6;
pub const TOTP_STEP_SECS: u64 = 30;
/// Allow ±1 time-step (±30 s) so phones that drift slightly still verify.
pub const TOTP_SKEW: u8 = 1;
/// 160-bit secret per RFC 4226. Anything larger and older authenticator apps
/// start choking on the QR payload.
pub const TOTP_SECRET_BYTES: usize = 20;

pub const RECOVERY_CODES_PER_USER: usize = 10;
pub const RECOVERY_CODE_LEN: usize = 10;
/// Crockford-ish alphabet minus visually-ambiguous characters. 30 chars → ~49
/// bits of entropy per code; with 10 codes and per-attempt rate limits, brute
/// force is not a credible threat.
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid TOTP secret length: expected {expected}, got {got}")]
    BadSecret { expected: usize, got: usize },
    #[error("system time error")]
    Time,
    #[error("totp library error: {0}")]
    Library(String),
}

/// Fresh authenticator secret. Returned as raw bytes — base32-encode at the
/// UI boundary only.
pub fn generate_secret() -> Vec<u8> {
    let mut buf = vec![0u8; TOTP_SECRET_BYTES];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Base32 (no padding) for the manual-entry fallback ("can't scan the QR?").
pub fn secret_to_base32(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
}

/// `otpauth://totp/...` URL the QR code encodes. `account` is what the user
/// sees in their authenticator app entry.
pub fn provisioning_url(secret: &[u8], issuer: &str, account: &str) -> Result<String, TotpError> {
    let totp = build_totp(secret, issuer, account)?;
    Ok(totp.get_url())
}

/// True when `code` matches the current TOTP window (or ±`TOTP_SKEW`).
pub fn verify_code(secret: &[u8], code: &str) -> Result<bool, TotpError> {
    // Strip whitespace — users paste codes with stray spaces all the time.
    let clean: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != TOTP_DIGITS || !clean.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }
    let totp = build_totp(secret, "", "")?;
    totp.check_current(&clean).map_err(|_| TotpError::Time)
}

fn build_totp(secret: &[u8], issuer: &str, account: &str) -> Result<TOTP, TotpError> {
    if secret.len() != TOTP_SECRET_BYTES {
        return Err(TotpError::BadSecret {
            expected: TOTP_SECRET_BYTES,
            got: secret.len(),
        });
    }
    let issuer_opt = if issuer.is_empty() {
        None
    } else {
        Some(issuer.to_string())
    };
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP_SECS,
        secret.to_vec(),
        issuer_opt,
        account.to_string(),
    )
    .map_err(|e| TotpError::Library(e.to_string()))
}

/// Generate `RECOVERY_CODES_PER_USER` plaintext recovery codes formatted as
/// `XXXXX-XXXXX`. The plaintext is shown once at enrollment / regeneration
/// and never stored — only the HMAC-SHA256 hash is persisted.
pub fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES_PER_USER)
        .map(|_| generate_one_recovery_code())
        .collect()
}

fn generate_one_recovery_code() -> String {
    let mut buf = [0u8; RECOVERY_CODE_LEN];
    OsRng.fill_bytes(&mut buf);
    let raw: String = buf
        .iter()
        .map(|b| RECOVERY_ALPHABET[(*b as usize) % RECOVERY_ALPHABET.len()] as char)
        .collect();
    // XXXXX-XXXXX — the dash is presentational; verify() strips it.
    format!("{}-{}", &raw[..5], &raw[5..])
}

/// Strip whitespace + dashes and uppercase. Both `abcde-12345` and
/// `ABCDE12345` map to the same canonical form.
pub fn normalize_recovery_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

pub fn hash_recovery_code(code: &str, pepper: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(normalize_recovery_code(code).as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn verify_recovery_code(code: &str, expected_hash: &[u8], pepper: &[u8]) -> bool {
    let got = hash_recovery_code(code, pepper);
    if got.len() != expected_hash.len() {
        return false;
    }
    got.ct_eq(expected_hash).into()
}

#[cfg(test)]
mod tests;
