use ed25519_dalek::{Signature, Verifier};
use jwt_utils::load_ed_keypair;

use super::*;

// Minted for these tests only.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF1VRwFuAo+gfSZtIUeF2VmNnVy0VePE+L7/D1UTTV6/
-----END PRIVATE KEY-----
";

fn attester() -> Ed25519DeviceAttester {
    let path = std::env::temp_dir().join(format!("pinai-attester-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, TEST_KEY).unwrap();
    let keypair = load_ed_keypair(&path, Some("key-2026-01")).unwrap();
    std::fs::remove_file(&path).unwrap();
    Ed25519DeviceAttester::new(Arc::new(keypair))
}

fn expires() -> OffsetDateTime {
    OffsetDateTime::parse("2027-05-14T00:00:00Z", &Rfc3339).unwrap()
}

/// The wire format's golden vector: a break here means a new version tag.
#[test]
fn the_signed_bytes_are_the_documented_canonical_form() {
    let device = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

    let bytes = canonical_bytes(
        "https://idp.alice.com/users/alice_xK9mP",
        device.into(),
        &[0; 32],
        expires(),
        "key-2026-01",
    );

    let expected: &[u8] = b"IDP-ATTEST-v1\n\
        https://idp.alice.com/users/alice_xK9mP\n\
        550e8400-e29b-41d4-a716-446655440000\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
        2027-05-14T00:00:00Z\n\
        key-2026-01";
    assert_eq!(bytes, expected);
}

#[test]
fn an_attestation_verifies_under_the_instance_key_and_only_for_its_bytes() {
    let attester = attester();
    let actor = ActorUri::parse("https://idp.alice.com/users/alice_xK9mP").unwrap();
    let key = DeviceRootKey::parse(&[3; 32]).unwrap();

    let signed = attester.attest(&actor, DeviceId::generate(), &key, expires());

    let verifying = attester.keypair.signing_key.verifying_key();
    let signature = Signature::from_slice(&signed.signature).unwrap();
    assert_eq!(signed.kid, "key-2026-01");
    assert!(verifying.verify(&signed.signed_message, &signature).is_ok());
    assert!(verifying.verify(b"tampered", &signature).is_err());
    assert!(
        signed
            .signed_message
            .starts_with(b"IDP-ATTEST-v1\nhttps://idp.alice.com/users/alice_xK9mP\n")
    );
}
