//! HTTP Signatures for ActivityPub delivery.
//!
//! Implements the Cavage draft (draft-cavage-http-signatures) used by Mastodon
//! and most ActivityPub servers.  We sign/verify with Ed25519 (`hs2019`).
//!
//! # Signed headers
//! POST requests sign: `(request-target) host date digest`
//! GET  requests sign: `(request-target) host date`

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc2822;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("Failed to build signature string: {0}")]
    Build(String),
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Missing required header: {0}")]
    MissingHeader(String),
    #[error("Invalid Signature header format")]
    InvalidFormat,
    #[error("Failed to parse public key: {0}")]
    KeyParse(String),
    #[error("Signature verification failed")]
    BadSignature,
    #[error("Base64 decode error")]
    Base64,
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/// Parameters required to sign an outgoing HTTP request.
pub struct SignParams<'a> {
    /// HTTP method in lowercase, e.g. `"post"`.
    pub method: &'a str,
    /// Request path + query string, e.g. `"/users/alex-7G4K/inbox"`.
    pub path: &'a str,
    /// Value of the `Host` header.
    pub host: &'a str,
    /// Value of the `Date` header (RFC 2822).
    pub date: &'a str,
    /// SHA-256 digest of the body (`"SHA-256=<base64>"`), `None` for GET.
    pub digest: Option<&'a str>,
    /// ActivityPub key ID, e.g. `"https://example.com/users/alex-7G4K#main-key"`.
    pub key_id: &'a str,
    /// Ed25519 signing key.
    pub signing_key: &'a SigningKey,
}

/// Produce the value for the `Signature:` header.
pub fn sign_request(p: SignParams<'_>) -> Result<String, SignError> {
    let (header_names, sig_string) = build_signature_string(p.method, p.path, p.host, p.date, p.digest);
    let sig: Signature = p.signing_key.sign(sig_string.as_bytes());
    let sig_b64 = Base64::encode_string(sig.to_bytes().as_ref());
    Ok(format!(
        r#"keyId="{}",algorithm="hs2019",headers="{}",signature="{}""#,
        p.key_id, header_names, sig_b64
    ))
}

/// Compute the `Date` header value (RFC 2822 / HTTP-date format).
pub fn http_date_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_string())
}

/// Compute `SHA-256=<base64>` for use as the `Digest` header value.
pub fn sha256_digest(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    format!("SHA-256={}", Base64::encode_string(&hash))
}

// ─── Verification ─────────────────────────────────────────────────────────────

/// A parsed `Signature` header.
pub struct ParsedSignature {
    pub key_id: String,
    pub headers: Vec<String>,
    pub signature_bytes: Vec<u8>,
}

/// Parse the value of a `Signature:` header.
pub fn parse_signature_header(value: &str) -> Result<ParsedSignature, VerifyError> {
    let mut key_id = None;
    let mut headers = None;
    let mut signature = None;

    for part in value.split(',') {
        let part = part.trim();
        if let Some(v) = strip_quoted(part, "keyId") {
            key_id = Some(v.to_string());
        } else if let Some(v) = strip_quoted(part, "headers") {
            headers = Some(v.split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>());
        } else if let Some(v) = strip_quoted(part, "signature") {
            signature = Some(Base64::decode_vec(v).map_err(|_| VerifyError::Base64)?);
        }
    }

    Ok(ParsedSignature {
        key_id: key_id.ok_or(VerifyError::InvalidFormat)?,
        headers: headers.ok_or(VerifyError::InvalidFormat)?,
        signature_bytes: signature.ok_or(VerifyError::InvalidFormat)?,
    })
}

/// Verify an incoming signed request.
///
/// `get_header` — closure that looks up a request header by (lowercase) name.
/// `public_key_pem` — Ed25519 public key in PEM format (fetched from sender's Actor).
pub fn verify_request(
    method: &str,
    path: &str,
    sig_header: &str,
    get_header: impl Fn(&str) -> Option<String>,
    public_key_pem: &str,
) -> Result<(), VerifyError> {
    use ed25519_dalek::pkcs8::DecodePublicKey;

    let parsed = parse_signature_header(sig_header)?;

    // Re-build the signature string using the header names listed in the Signature header.
    let mut lines: Vec<String> = Vec::new();
    for name in &parsed.headers {
        let line = match name.as_str() {
            "(request-target)" => format!("(request-target): {} {}", method.to_lowercase(), path),
            other => {
                let val = get_header(other).ok_or_else(|| VerifyError::MissingHeader(other.to_string()))?;
                format!("{}: {}", other, val)
            }
        };
        lines.push(line);
    }
    let sig_string = lines.join("\n");

    // Decode the public key.
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| VerifyError::KeyParse(e.to_string()))?;

    // Deserialise and verify the signature.
    let sig_bytes: [u8; 64] = parsed
        .signature_bytes
        .try_into()
        .map_err(|_| VerifyError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(sig_string.as_bytes(), &signature)
        .map_err(|_| VerifyError::BadSignature)
}

// ─── Internals ────────────────────────────────────────────────────────────────

fn build_signature_string(
    method: &str,
    path: &str,
    host: &str,
    date: &str,
    digest: Option<&str>,
) -> (String, String) {
    let mut names = vec!["(request-target)", "host", "date"];
    let mut lines = vec![
        format!("(request-target): {} {}", method.to_lowercase(), path),
        format!("host: {}", host),
        format!("date: {}", date),
    ];
    if let Some(d) = digest {
        names.push("digest");
        lines.push(format!("digest: {}", d));
    }
    (names.join(" "), lines.join("\n"))
}

fn strip_quoted<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{}=\"", key);
    input
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix('"'))
}
