use super::*;
use ed25519_dalek::Verifier;
use rand::RngCore;

fn fresh_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

/// Wire-format golden vector — a break here means bumping the version tag.
#[test]
fn canonical_bytes_are_stable() {
    let actor = "https://idp.alice.com/users/alice_xK9mP";
    let device = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let drk = [0u8; 32];
    let expires = OffsetDateTime::parse("2027-05-14T00:00:00Z", &Rfc3339).unwrap();
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
