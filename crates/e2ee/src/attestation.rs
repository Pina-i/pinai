//! Ed25519 attestation signing for the per-device identity refactor.
//!
//! The IdP signs `(actor_uri, device_id, drk_pub, expires_at, kid)` once per
//! device on first registration (and on every renewal). Peer clients fetch
//! the IdP's JWKS, verify this signature, then trust the Device Root Key
//! contained in the attestation.
//!
//! See `docs/plans/2026-05-14-per-device-identity-design.md` § 3 for the
//! wire format.

use base64ct::{Base64, Encoding as _};
use ed25519_dalek::{Signature, Signer, SigningKey};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

/// Build the canonical signed-message bytes for an IdP device attestation.
///
/// **Format (UTF-8):**
/// ```text
/// IDP-ATTEST-v1\n
/// <actor_uri>\n
/// <device_id>\n
/// <base64(drk_pub)>\n
/// <iso8601(expires_at)>\n
/// <kid>
/// ```
///
/// Domain-separation tag `IDP-ATTEST-v1` keeps an attestation signature
/// from ever validating as some other Ed25519 use of the same key.
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
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use rand::RngCore;

    fn fresh_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    /// Golden-vector test for canonical byte ordering. If a future
    /// refactor reorders the fields or changes the separators, this
    /// test breaks loudly — that's a wire-format break and needs a
    /// version bump.
    #[test]
    fn canonical_bytes_are_stable() {
        let actor = "https://idp.alice.com/users/alice_xK9mP";
        let device = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let drk = [0u8; 32];
        let expires = OffsetDateTime::parse(
            "2027-05-14T00:00:00Z",
            &Rfc3339,
        ).unwrap();
        let kid = "key-2026-01";

        let bytes = canonical_attestation_bytes(actor, &device, &drk, expires, kid);
        let expected: &[u8] = b"IDP-ATTEST-v1\n\
            https://idp.alice.com/users/alice_xK9mP\n\
            550e8400-e29b-41d4-a716-446655440000\n\
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
            2027-05-14T00:00:00Z\n\
            key-2026-01";
        assert_eq!(bytes, expected);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = fresh_signing_key();
        let msg = b"hello-attestation";
        let sig = sign_attestation(&key, msg);
        assert!(key.verifying_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn tampering_breaks_verify() {
        let key = fresh_signing_key();
        let sig = sign_attestation(&key, b"original");
        assert!(key.verifying_key().verify(b"tampered", &sig).is_err());
    }
}
