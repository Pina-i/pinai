use base64ct::{Base64UrlUnpadded, Encoding};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::JwtUtilsError;

/// Generate a cryptographically random code_verifier.
/// RFC 7636 §4.1: 43–128 unreserved characters [A-Z a-z 0-9 - . _ ~].
/// We use 64 alphanumeric characters for simplicity.
pub fn generate_code_verifier() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Compute the S256 code_challenge from a code_verifier.
/// challenge = BASE64URL-NOPAD(SHA256(ASCII(verifier)))
pub fn compute_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    Base64UrlUnpadded::encode_string(&hash)
}

/// Verify that SHA256(code_verifier) matches the stored code_challenge.
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_pkce(code_verifier: &str, stored_challenge: &str) -> Result<(), JwtUtilsError> {
    let computed = compute_code_challenge(code_verifier);
    if computed.as_bytes().ct_eq(stored_challenge.as_bytes()).into() {
        Ok(())
    } else {
        Err(JwtUtilsError::PkceVerificationFailed)
    }
}
