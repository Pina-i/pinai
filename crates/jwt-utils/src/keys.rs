use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{DecodingKey, EncodingKey};
use std::path::Path;

use crate::JwtUtilsError;

/// Holds both the jsonwebtoken encoding/decoding keys and the raw public key
/// bytes needed to serialize the JWKS endpoint.
pub struct EdKeyPair {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    /// Raw 32-byte compressed Ed25519 public key for JWK serialization.
    pub verifying_key_bytes: [u8; 32],
    /// Key ID from config, e.g. "key-2025-01".
    pub kid: String,
    /// Raw Ed25519 signing key — used for HTTP Signatures on outgoing AP requests.
    pub signing_key: SigningKey,
    /// PKCS#8 SubjectPublicKeyInfo PEM of the verifying key.
    /// Included in the Actor document's `publicKey.publicKeyPem` field.
    pub public_key_pem: String,
}

/// Load an Ed25519 PKCS#8 private key from a PEM file and derive the keypair.
///
/// The PEM file must start with `-----BEGIN PRIVATE KEY-----` (PKCS#8 format).
/// Generate with: `openssl genpkey -algorithm ed25519 -out keys/ed25519.pem`
///
/// Only one file is needed at runtime — the public key is derived from it.
pub fn load_ed_keypair_from_pem(
    pem_path: &Path,
    kid: impl Into<String>,
) -> Result<EdKeyPair, JwtUtilsError> {
    let pem = std::fs::read(pem_path)
        .map_err(|e| JwtUtilsError::Key(format!("cannot read key file: {e}")))?;

    // jsonwebtoken v9: EncodingKey::from_ed_pem expects PKCS#8 private key PEM
    let encoding_key = EncodingKey::from_ed_pem(&pem)
        .map_err(|e| JwtUtilsError::Key(format!("invalid private key PEM: {e}")))?;

    // Use ed25519-dalek to extract the verifying (public) key so we can:
    // (a) derive the public PEM for DecodingKey, and
    // (b) get the raw bytes for JWK serialization.
    let signing_key = parse_pkcs8_pem_to_signing_key(&pem)?;
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let verifying_key_bytes = verifying_key.to_bytes();

    // Serialize the verifying key to PKCS#8 SubjectPublicKeyInfo PEM so that
    // jsonwebtoken's DecodingKey::from_ed_pem can parse it.
    // Note: DecodingKey::from_ed_pem requires PUBLIC key PEM, not private.
    use ed25519_dalek::pkcs8::EncodePublicKey;
    let public_pem = verifying_key
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| JwtUtilsError::Key(format!("public key PEM encode failed: {e}")))?;

    let decoding_key = DecodingKey::from_ed_pem(public_pem.as_bytes())
        .map_err(|e| JwtUtilsError::Key(format!("invalid public key PEM: {e}")))?;

    Ok(EdKeyPair {
        encoding_key,
        decoding_key,
        verifying_key_bytes,
        kid: kid.into(),
        signing_key,
        public_key_pem: public_pem,
    })
}

fn parse_pkcs8_pem_to_signing_key(pem: &[u8]) -> Result<SigningKey, JwtUtilsError> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem)
        .map_err(|_| JwtUtilsError::Key("PEM is not valid UTF-8".into()))?;
    SigningKey::from_pkcs8_pem(pem_str)
        .map_err(|e| JwtUtilsError::Key(format!("PKCS8 parse failed: {e}")))
}
