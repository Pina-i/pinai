use super::*;

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
