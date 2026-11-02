use super::*;
use crate::e2ee::testing::{PlainEd25519Verifier, hpke_key, plain_signature};

fn label(name: &str, kind: DeviceKind) -> DeviceLabel {
    DeviceLabel {
        name: name.to_owned(),
        kind,
    }
}

fn from(user_agent: &str) -> DeviceLabel {
    DeviceLabel::from_user_agent(Some(user_agent))
}

fn key(byte: u8) -> DeviceRootKey {
    DeviceRootKey::parse(&[byte; 32]).unwrap()
}

fn device(attested: Option<DeviceRootKey>) -> Device {
    let at = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
    Device {
        id: DeviceId::generate(),
        owner: UserId::generate(),
        label: DeviceLabel::unknown(),
        paired_at: at,
        last_seen_at: at,
        revoked_at: None,
        attestation: attested.map(|root_key| Attestation {
            root_key,
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: at,
            expires_at: at + ATTESTATION_LIFETIME,
        }),
        hpke_key: None,
        history_generation: None,
    }
}

#[test]
fn a_root_key_is_an_ed25519_public_key() {
    assert_eq!(key(1).as_bytes(), &[1; 32]);
    for len in [0, 31, 33, 64] {
        assert!(DeviceRootKey::parse(&vec![1; len]).is_err(), "{len} bytes");
    }
}

#[test]
fn a_device_without_a_user_agent_is_a_web_client() {
    assert_eq!(
        DeviceLabel::from_user_agent(None),
        label("Web client", DeviceKind::Unknown)
    );
    assert_eq!(
        DeviceLabel::from_user_agent(Some("")),
        label("Web client", DeviceKind::Unknown)
    );
    assert_eq!(
        from("WeirdCustomBot/1.0"),
        label("Web client", DeviceKind::Unknown)
    );
}

#[test]
fn apple_mobiles_are_named_before_safari_is() {
    assert_eq!(
        from(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
        ),
        label("Safari on iOS", DeviceKind::Phone)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
        ),
        label("Safari on iPadOS", DeviceKind::Tablet)
    );
}

#[test]
fn an_android_is_a_phone_only_when_it_says_mobile() {
    assert_eq!(
        from(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
        ),
        label("Chrome on Android", DeviceKind::Phone)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        label("Chrome on Android", DeviceKind::Tablet)
    );
}

#[test]
fn a_desktop_is_named_by_its_most_specific_browser() {
    assert_eq!(
        from(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0"
        ),
        label("Firefox on macOS", DeviceKind::Laptop)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        label("Chrome on Windows", DeviceKind::Laptop)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
        ),
        label("Edge on Windows", DeviceKind::Laptop)
    );
}

#[test]
fn a_kind_reads_back_as_it_is_stored() {
    for kind in [
        DeviceKind::Laptop,
        DeviceKind::Phone,
        DeviceKind::Tablet,
        DeviceKind::Unknown,
    ] {
        assert_eq!(kind.as_str().parse::<DeviceKind>().unwrap(), kind);
    }
    assert!("desktop".parse::<DeviceKind>().is_err());
}

#[test]
fn a_device_never_attested_registers_for_the_first_time() {
    assert_eq!(
        Registration::of(None, UserId::generate(), &key(1)).unwrap(),
        Registration::FirstTime
    );
    let unattested = device(None);
    assert_eq!(
        Registration::of(Some(&unattested), unattested.owner, &key(1)).unwrap(),
        Registration::FirstTime
    );
}

#[test]
fn an_attested_device_renews_its_key_or_rotates_to_another() {
    let attested = device(Some(key(1)));

    assert_eq!(
        Registration::of(Some(&attested), attested.owner, &key(1)).unwrap(),
        Registration::Renewal
    );
    assert_eq!(
        Registration::of(Some(&attested), attested.owner, &key(2)).unwrap(),
        Registration::Rotation
    );
}

#[test]
fn a_revoked_device_registers_no_key() {
    let mut revoked = device(Some(key(1)));
    revoked.revoked_at = Some(revoked.paired_at);

    let renewal = Registration::of(Some(&revoked), revoked.owner, &key(1));
    let rotation = Registration::of(Some(&revoked), revoked.owner, &key(2));

    assert!(
        matches!(renewal, Err(KeyDirectoryError::DeviceRevoked)),
        "{renewal:?}"
    );
    assert!(
        matches!(rotation, Err(KeyDirectoryError::DeviceRevoked)),
        "{rotation:?}"
    );
}

#[test]
fn a_device_id_another_account_holds_registers_no_key() {
    for held in [device(None), device(Some(key(1)))] {
        let taken = Registration::of(Some(&held), UserId::generate(), &key(1));

        assert!(
            matches!(taken, Err(KeyDirectoryError::DeviceTaken)),
            "{taken:?}"
        );
    }
}

#[test]
fn an_hpke_key_is_an_x25519_public_key_and_its_signature_an_ed25519_one() {
    assert_eq!(HpkePublicKey::parse(&[1; 32]).unwrap().as_bytes(), &[1; 32]);
    assert_eq!(
        Ed25519Signature::parse("signature", &[2; 64])
            .unwrap()
            .as_bytes(),
        &[2; 64]
    );
    for len in [0, 31, 33, 64] {
        assert!(HpkePublicKey::parse(&vec![1; len]).is_err(), "{len} bytes");
    }
    for len in [0, 32, 63, 65] {
        let refused = Ed25519Signature::parse("hpke_key_signature", &vec![1; len]).unwrap_err();
        assert_eq!(refused.field, "hpke_key_signature", "{len} bytes");
    }
}

#[test]
fn an_hpke_key_comes_with_its_signature_or_not_at_all() {
    let (key, signature) = (hpke_key(1).key().clone(), hpke_key(1).signature().clone());

    assert_eq!(
        UnverifiedHpkeKey::from_parts(Some(key.clone()), Some(signature.clone())).unwrap(),
        Some(UnverifiedHpkeKey::new(key.clone(), signature.clone()))
    );
    assert_eq!(UnverifiedHpkeKey::from_parts(None, None).unwrap(), None);
    assert!(UnverifiedHpkeKey::from_parts(Some(key), None).is_err());
    assert!(UnverifiedHpkeKey::from_parts(None, Some(signature)).is_err());
}

/// The wire format's golden vector: a break here means a new version tag.
#[test]
fn the_bytes_a_root_key_signs_over_its_hpke_key_are_the_documented_canonical_form() {
    let actor = ActorUri::parse("https://idp.alice.com/users/alice_xK9mP").unwrap();
    let device: DeviceId = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
        .unwrap()
        .into();

    let bytes = HpkePublicKey::parse(&[0; 32])
        .unwrap()
        .canonical_bytes(&actor, device);

    let expected: &[u8] = b"PINAI-DEVICE-HPKE-v1\n\
        https://idp.alice.com/users/alice_xK9mP\n\
        550e8400-e29b-41d4-a716-446655440000\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert_eq!(bytes, expected);
}

#[test]
fn an_hpke_key_verifies_only_under_its_root_key_for_its_device_and_account() {
    let alice = ActorUri::parse("https://idp.alice.com/users/alice_xK9mP").unwrap();
    let bob = ActorUri::parse("https://idp.alice.com/users/bob_k2m9x").unwrap();
    let (device, hpke) = (
        DeviceId::generate(),
        HpkePublicKey::parse(&[9; 32]).unwrap(),
    );
    let signed_for = |root: u8, actor: &ActorUri, device: DeviceId, over: &HpkePublicKey| {
        UnverifiedHpkeKey::new(
            hpke.clone(),
            plain_signature(&key(root), &over.canonical_bytes(actor, device)),
        )
    };
    let verify = |brought: UnverifiedHpkeKey| {
        brought.verified(&key(1), &alice, device, &PlainEd25519Verifier)
    };

    let verified = verify(signed_for(1, &alice, device, &hpke)).unwrap();

    assert_eq!(verified.key(), &hpke);
    for forged in [
        signed_for(2, &alice, device, &hpke),
        signed_for(1, &bob, device, &hpke),
        signed_for(1, &alice, DeviceId::generate(), &hpke),
        signed_for(1, &alice, device, &HpkePublicKey::parse(&[8; 32]).unwrap()),
    ] {
        let refused = verify(forged);
        assert!(
            matches!(refused, Err(KeyDirectoryError::HpkeKeyUnsigned)),
            "{refused:?}"
        );
    }
}

#[test]
fn a_registration_bringing_an_hpke_key_sets_it_whatever_it_is() {
    for registration in [
        Registration::FirstTime,
        Registration::Renewal,
        Registration::Rotation,
    ] {
        assert_eq!(
            registration.hpke_key(Some(hpke_key(2))),
            HpkeKeyWrite::Set(hpke_key(2)),
            "{registration:?}"
        );
    }
}

#[test]
fn a_renewal_keeps_the_hpke_key_held_and_a_rotation_clears_it() {
    assert_eq!(Registration::Renewal.hpke_key(None), HpkeKeyWrite::Keep);
    assert_eq!(Registration::Rotation.hpke_key(None), HpkeKeyWrite::Clear);
    assert_eq!(Registration::FirstTime.hpke_key(None), HpkeKeyWrite::Clear);
}

#[test]
fn an_attestation_is_issued_in_utc_and_whole_seconds() {
    let in_tahiti = OffsetDateTime::from_unix_timestamp_nanos(1_788_000_000_123_456_789)
        .unwrap()
        .to_offset(time::UtcOffset::from_hms(-10, 0, 0).unwrap());

    let (issued_at, expires_at) = attestation_period(in_tahiti);

    assert_eq!(issued_at.offset(), time::UtcOffset::UTC);
    assert_eq!(
        issued_at,
        OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap()
    );
    assert_eq!(expires_at.at(), issued_at + ATTESTATION_LIFETIME);
    assert_eq!(expires_at.at().offset(), time::UtcOffset::UTC);
}

#[test]
fn a_session_registers_and_names_only_the_device_it_declared() {
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());

    assert!(may_register(None, phone).is_ok());
    assert!(may_register(Some(laptop), laptop).is_ok());
    assert!(matches!(
        may_register(Some(laptop), phone),
        Err(KeyDirectoryError::NotTheSessionsDevice)
    ));
    assert!(may_name(None, phone).is_ok());
    assert!(may_name(Some(laptop), laptop).is_ok());
    assert!(matches!(
        may_name(Some(laptop), phone),
        Err(AuthError::DeviceMismatch)
    ));
}

#[test]
fn only_a_label_that_says_something_replaces_the_unknown_one() {
    let chrome = from("Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36");

    assert!(chrome.replaces(&DeviceLabel::unknown()));
    assert!(!DeviceLabel::unknown().replaces(&DeviceLabel::unknown()));
    assert!(!chrome.replaces(&label("Firefox on Linux", DeviceKind::Laptop)));
}
