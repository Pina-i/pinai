//! Ed25519 attestation signing. The IdP signs
//! `(actor_uri, device_id, drk_pub, expires_at, kid)`; peer clients verify
//! against the issuer's JWKS. See `specs/05-e2ee.md` for the wire format.

use base64ct::{Base64, Encoding as _};
use ed25519_dalek::{Signature, Signer, SigningKey};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

/// Canonical signed-message bytes for an IdP device attestation. The
/// `IDP-ATTEST-v1` tag prevents the signature from validating in any other
/// context using the same key.
pub fn canonical_attestation_bytes(
    actor_uri: &str,
    device_id: &Uuid,
    drk_pub: &[u8],
    expires_at: OffsetDateTime,
    kid: &str,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("IDP-ATTEST-v1\n");
    out.push_str(actor_uri);
    out.push('\n');
    out.push_str(&device_id.to_string());
    out.push('\n');
    out.push_str(&Base64::encode_string(drk_pub));
    out.push('\n');
    out.push_str(
        &expires_at
            .format(&Rfc3339)
            .expect("RFC3339 format never fails for OffsetDateTime"),
    );
    out.push('\n');
    out.push_str(kid);
    out.into_bytes()
}

/// Sign canonical attestation bytes with the IdP's Ed25519 key.
pub fn sign_attestation(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

#[cfg(test)]
mod tests;
