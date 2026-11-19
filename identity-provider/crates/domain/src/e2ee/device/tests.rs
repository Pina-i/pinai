use super::*;
use crate::e2ee::testing::{PlainEd25519Verifier, hpke_key, plain_signature};

fn label(name: &str, kind: DeviceKind, client: DeviceClient) -> DeviceLabel {
    DeviceLabel {
        name: AutomaticName::parse(name).unwrap(),
        kind,
        client,
    }
}

fn browser(name: &str, kind: DeviceKind) -> DeviceLabel {
    label(name, kind, DeviceClient::Browser)
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
        chosen_name: None,
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
    let unknown = label("Web client", DeviceKind::Unknown, DeviceClient::Unknown);

    assert_eq!(DeviceLabel::from_user_agent(None), unknown);
    assert_eq!(DeviceLabel::from_user_agent(Some("")), unknown);
    assert_eq!(from("WeirdCustomBot/1.0"), unknown);
}

#[test]
fn apple_mobiles_are_named_before_safari_is() {
    assert_eq!(
        from(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
        ),
        browser("Safari on iOS", DeviceKind::Phone)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
        ),
        browser("Safari on iPadOS", DeviceKind::Tablet)
    );
}

#[test]
fn an_android_is_a_phone_only_when_it_says_mobile() {
    assert_eq!(
        from(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
        ),
        browser("Chrome on Android", DeviceKind::Phone)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        browser("Chrome on Android", DeviceKind::Tablet)
    );
}

#[test]
fn a_desktop_is_named_by_its_most_specific_browser() {
    assert_eq!(
        from(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0"
        ),
        browser("Firefox on macOS", DeviceKind::Laptop)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        browser("Chrome on Windows", DeviceKind::Laptop)
    );
    assert_eq!(
        from(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
        ),
        browser("Edge on Windows", DeviceKind::Laptop)
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
fn a_session_registers_only_the_device_it_declared() {
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());

    assert!(may_register(None, phone).is_ok());
    assert!(may_register(Some(laptop), laptop).is_ok());
    assert!(matches!(
        may_register(Some(laptop), phone),
        Err(KeyDirectoryError::NotTheSessionsDevice)
    ));
}

#[test]
fn a_label_from_the_user_agent_names_only_a_device_recorded_unnamed() {
    let chrome = "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36";
    let (unnamed, mut named) = (device(None), device(None));
    named.label = browser("Firefox on Linux", DeviceKind::Laptop);
    let guessed = BroughtLabel::of(None, Some(chrome));
    let chrome = browser("Chrome on Linux", DeviceKind::Laptop);

    assert_eq!(guessed, BroughtLabel::FromUserAgent(chrome.clone()));
    assert_eq!(
        guessed.write(Some(&unnamed), Some(unnamed.id)),
        LabelWrite::Always(chrome.clone())
    );
    assert_eq!(
        BroughtLabel::of(None, None).write(Some(&unnamed), Some(unnamed.id)),
        LabelWrite::IfNew(DeviceLabel::unknown())
    );
    assert_eq!(
        guessed.write(Some(&named), Some(named.id)),
        LabelWrite::IfNew(chrome.clone())
    );
    assert_eq!(guessed.write(None, None), LabelWrite::IfNew(chrome));
}

#[test]
fn a_label_the_client_composed_replaces_the_one_held_at_each_request() {
    let composed = label("Pixel 8", DeviceKind::Phone, DeviceClient::Browser);
    let (unnamed, mut named) = (device(None), device(None));
    named.label = label("Pixel 7", DeviceKind::Phone, DeviceClient::Browser);

    let brought = BroughtLabel::of(Some(composed.clone()), Some("Firefox/130.0"));

    assert_eq!(brought, BroughtLabel::Composed(composed.clone()));
    for known in [&unnamed, &named] {
        assert_eq!(
            brought.write(Some(known), Some(known.id)),
            LabelWrite::Always(composed.clone())
        );
    }
    assert_eq!(brought.write(None, None), LabelWrite::IfNew(composed));
}

/// Device ids are listed, and a renewal takes any session of the owner's: only the device's own
/// session speaks for it.
#[test]
fn a_known_device_is_relabelled_only_from_a_session_that_named_it() {
    let known = device(None);
    let composed = BroughtLabel::Composed(label("Pixel 8", DeviceKind::Phone, DeviceClient::App));
    let guessed = BroughtLabel::of(None, Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"));

    for named in [None, Some(DeviceId::generate())] {
        for brought in [&composed, &guessed] {
            assert!(
                !brought.write(Some(&known), named).replaces(),
                "{brought:?} from {named:?}"
            );
        }
    }
}

#[test]
fn a_client_composes_a_name_a_kind_and_whether_it_is_the_app() {
    assert_eq!(
        DeviceLabel::from_client(
            "  ThinkPad X1 Carbon Gen 9 (alice-thinkpad) ",
            "laptop",
            "app"
        )
        .unwrap(),
        label(
            "ThinkPad X1 Carbon Gen 9 (alice-thinkpad)",
            DeviceKind::Laptop,
            DeviceClient::App
        )
    );
    assert_eq!(
        DeviceLabel::from_client(&"é".repeat(100), "unknown", "browser")
            .unwrap()
            .name
            .as_str()
            .chars()
            .count(),
        100,
        "characters, not bytes"
    );
    assert_eq!(
        AutomaticName::parse("\u{1F469}\u{200D}\u{1F4BB} laptop")
            .unwrap()
            .as_str(),
        "\u{1F469}\u{200D}\u{1F4BB} laptop",
        "a joiner inside an emoji sequence stays"
    );
}

#[test]
fn a_composed_label_names_the_rule_it_breaks() {
    let refused = |name: &str, kind: &str, client: &str| {
        DeviceLabel::from_client(name, kind, client)
            .unwrap_err()
            .to_string()
    };

    assert_eq!(refused("  ", "phone", "app"), "label.name: cannot be blank");
    assert_eq!(
        refused(&"a".repeat(101), "phone", "app"),
        "label.name: at most 100 characters"
    );
    assert_eq!(
        refused("Pixel\u{0}8", "phone", "app"),
        "label.name: no control characters"
    );
    assert_eq!(
        refused("Pixel\n8", "phone", "app"),
        "label.name: no control characters"
    );
    for invisible in [
        '\u{200B}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2060}', '\u{2066}',
        '\u{2069}', '\u{FEFF}', '\u{2028}', '\u{2029}',
    ] {
        assert_eq!(
            refused(&format!("Pixel{invisible}8"), "phone", "app"),
            "label.name: no invisible characters",
            "{invisible:?}"
        );
    }
    assert_eq!(
        refused(" \u{200D}\u{200C} ", "phone", "app"),
        "label.name: cannot be blank",
        "joiners alone name nothing"
    );
    assert_eq!(
        refused("Pixel 8", "desktop", "app"),
        "label.kind: laptop, phone, tablet or unknown"
    );
    for client in ["unknown", "Electron", ""] {
        assert_eq!(
            refused("Pixel 8", "phone", client),
            "label.client: app or browser"
        );
    }
}

#[test]
fn the_client_is_read_from_the_user_agent_the_app_before_any_browser() {
    let client = |ua| from(ua).client;

    assert_eq!(
        client(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Pinai/0.5.0 Chrome/130.0.6723.191 Electron/33.2.1 Safari/537.36"
        ),
        DeviceClient::App
    );
    assert_eq!(
        client("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"),
        DeviceClient::Browser
    );
    assert_eq!(
        client(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) CriOS/130.0 Mobile/15E148"
        ),
        DeviceClient::Browser
    );
    assert_eq!(client("Electron/33.2.1"), DeviceClient::App);
    assert_eq!(client("WeirdCustomBot/1.0"), DeviceClient::Unknown);
    assert_eq!(
        DeviceLabel::from_user_agent(None).client,
        DeviceClient::Unknown
    );
}

#[test]
fn a_client_reads_back_as_it_is_stored() {
    for client in [
        DeviceClient::App,
        DeviceClient::Browser,
        DeviceClient::Unknown,
    ] {
        assert_eq!(client.as_str().parse::<DeviceClient>().unwrap(), client);
    }
    assert!("desktop".parse::<DeviceClient>().is_err());
}

#[test]
fn a_device_is_shown_by_the_name_its_user_chose_else_its_automatic_one() {
    let mut named = device(None);

    let automatic = named.shown_name().to_owned();
    named.chosen_name = Some(ChosenName::parse("Alice's laptop").unwrap());

    assert_eq!(automatic, "Web client");
    assert_eq!(named.shown_name(), "Alice's laptop");
}

#[test]
fn a_character_that_draws_nothing_is_refused_in_either_name() {
    for (group, invisible) in [
        ("the Arabic letter mark", vec!['\u{061C}']),
        ("the soft hyphen", vec!['\u{00AD}']),
        ("the Mongolian vowel separator", vec!['\u{180E}']),
        (
            "the invisible operators",
            vec!['\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}'],
        ),
        (
            "the Hangul fillers",
            vec!['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}'],
        ),
        ("the blank braille pattern", vec!['\u{2800}']),
    ] {
        for c in invisible {
            assert_eq!(
                ChosenName::or_none(Some(&c.to_string()))
                    .unwrap_err()
                    .to_string(),
                "name: no invisible characters",
                "{group}: {c:?} alone"
            );
            assert_eq!(
                AutomaticName::parse(&format!("Pixel{c}8"))
                    .unwrap_err()
                    .to_string(),
                "label.name: no invisible characters",
                "{group}: {c:?}"
            );
        }
    }
}

#[test]
fn a_chosen_name_equal_to_the_automatic_one_leaves_none() {
    let device = device(None);
    let after =
        |raw: &str| device.chosen_name_after(ChosenName::or_none(Some(raw)).unwrap().as_ref());

    assert_eq!(after("  Web client "), None);
    assert_eq!(after(""), None);
    assert_eq!(
        after("Work laptop"),
        Some(ChosenName::parse("Work laptop").unwrap())
    );
    assert_eq!(
        after("web client"),
        Some(ChosenName::parse("web client").unwrap()),
        "the very name only"
    );
}

#[test]
fn a_chosen_name_is_trimmed_and_holds_50_characters() {
    let chosen = |raw: &str| ChosenName::or_none(Some(raw)).unwrap().unwrap();

    assert_eq!(chosen("  Work laptop ").as_str(), "Work laptop");
    assert_eq!(
        chosen(&"é".repeat(50)).as_str().chars().count(),
        50,
        "characters, not bytes"
    );
    assert_eq!(
        ChosenName::or_none(Some(&"é".repeat(51)))
            .unwrap_err()
            .to_string(),
        "name: at most 50 characters"
    );
}

#[test]
fn no_name_or_an_empty_one_gives_the_automatic_name_back() {
    for raw in [None, Some(""), Some("   "), Some("\t\n")] {
        assert_eq!(ChosenName::or_none(raw).unwrap(), None, "{raw:?}");
    }
}

#[test]
fn a_chosen_name_names_the_rule_it_breaks() {
    let refused = |raw: &str| ChosenName::or_none(Some(raw)).unwrap_err().to_string();

    assert_eq!(refused("Work\u{0}laptop"), "name: no control characters");
    assert_eq!(
        refused("Work\u{200B}laptop"),
        "name: no invisible characters"
    );
    assert_eq!(
        refused("Work\u{202E}laptop"),
        "name: no invisible characters"
    );
    assert_eq!(
        refused(" \u{200D} "),
        "name: cannot be blank",
        "a joiner alone names nothing"
    );
    assert_eq!(
        ChosenName::parse("\u{1F469}\u{200D}\u{1F4BB} laptop")
            .unwrap()
            .as_str(),
        "\u{1F469}\u{200D}\u{1F4BB} laptop"
    );
}

#[test]
fn a_first_key_or_the_same_one_again_comes_from_any_session_of_the_owners() {
    let id = DeviceId::generate();

    for registration in [Registration::FirstTime, Registration::Renewal] {
        assert!(
            registration.may_come_from(None, id).is_ok(),
            "{registration:?}"
        );
        assert!(registration.may_come_from(Some(id), id).is_ok());
    }
}

#[test]
fn another_root_key_takes_a_session_that_named_that_very_device() {
    let id = DeviceId::generate();

    assert!(Registration::Rotation.may_come_from(Some(id), id).is_ok());
    for named in [None, Some(DeviceId::generate())] {
        assert!(
            matches!(
                Registration::Rotation.may_come_from(named, id),
                Err(KeyDirectoryError::DeviceRequired(_))
            ),
            "{named:?}"
        );
    }
}
