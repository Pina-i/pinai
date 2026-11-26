use time::OffsetDateTime;

use super::*;
use crate::auth::SessionKind;
use crate::auth::testing::web_client;
use crate::e2ee::{
    ATTESTATION_LIFETIME, Approval, Approver, Attestation, DeviceLabel, DeviceRequired,
    DeviceRootKey, Ed25519Signature, HistoryGeneration,
};
use crate::{ApprovalRequestId, SessionId};

fn device(owner: UserId, revoked: bool) -> Device {
    let now = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        chosen_name: None,
        paired_at: now,
        last_seen_at: now,
        revoked_at: revoked.then_some(now),
        attestation: None,
        hpke_key: None,
        history_generation: None,
    }
}

#[test]
fn a_relay_is_an_https_address_or_http_on_this_machine() {
    for fine in [
        "https://exp.host/--/api/v2/push/send",
        "https://push.example.org:8443/send?app=pinai",
        "http://localhost:4000/send",
        "http://127.0.0.1:4000/send",
        "http://[::1]:4000/send",
    ] {
        assert!(PushRelay::parse(fine).is_ok(), "{fine}");
    }
    for refused in [
        "",
        "exp.host/--/api/v2/push/send",
        "http://exp.host/--/api/v2/push/send",
        "http://10.0.0.2/send",
        "ftp://push.example.org/send",
        "https://user:secret@push.example.org/send",
        "https://push.example.org/send#here",
        &format!(
            "https://push.example.org/{}",
            "a".repeat(PUSH_FIELD_MAX_BYTES)
        ),
    ] {
        assert_eq!(
            PushRelay::parse(refused).map_err(|e| e.field),
            Err("relay"),
            "{refused}"
        );
    }
}

#[test]
fn a_relay_is_kept_as_its_url_reads() {
    let relay = PushRelay::parse("HTTPS://Exp.Host/--/api/v2/push/send").unwrap();

    assert_eq!(relay.as_str(), "https://exp.host/--/api/v2/push/send");
}

#[test]
fn a_token_is_printable_ascii_without_spaces() {
    let expo = "ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]";
    assert_eq!(PushToken::parse(expo).unwrap().as_str(), expo);
    assert!(PushToken::parse(&"a".repeat(PUSH_FIELD_MAX_BYTES)).is_ok());
    for refused in [
        String::new(),
        "a b".to_owned(),
        "tab\tbed".to_owned(),
        "jeton·é".to_owned(),
        "a".repeat(PUSH_FIELD_MAX_BYTES + 1),
    ] {
        assert_eq!(
            PushToken::parse(&refused).map_err(|e| e.field),
            Err("token"),
            "{refused}"
        );
    }
}

#[test]
fn a_token_never_shows_in_a_log() {
    let token = PushToken::parse("ExponentPushToken[secret]").unwrap();

    assert_eq!(format!("{token:?}"), "PushToken(…)");
}

#[test]
fn a_device_registers_its_own_pushes() {
    let alice = UserId::generate();
    let phone = device(alice, false);

    let registered = may_register_push(Some(phone.id), alice, phone.id, Some(&phone));

    assert!(registered.is_ok(), "{registered:?}");
}

#[test]
fn a_session_naming_no_device_or_another_registers_nothing() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, false), device(alice, false));

    let unnamed = may_register_push(None, alice, phone.id, Some(&phone));
    let anothers = may_register_push(Some(laptop.id), alice, phone.id, Some(&phone));

    assert!(
        matches!(
            unnamed,
            Err(KeyDirectoryError::DeviceRequired(DeviceRequired))
        ),
        "{unnamed:?}"
    );
    assert!(
        matches!(anothers, Err(KeyDirectoryError::NotTheSessionsDevice)),
        "{anothers:?}"
    );
}

#[test]
fn only_an_unrevoked_device_of_the_callers_registers() {
    let (alice, bob) = (UserId::generate(), UserId::generate());
    let (bobs, revoked) = (device(bob, false), device(alice, true));
    let register =
        |id: DeviceId, device: Option<&Device>| may_register_push(Some(id), alice, id, device);

    let unknown = register(DeviceId::generate(), None);
    let anothers = register(bobs.id, Some(&bobs));
    let gone = register(revoked.id, Some(&revoked));

    for refused in [unknown, anothers] {
        assert!(
            matches!(refused, Err(KeyDirectoryError::DeviceNotFound)),
            "{refused:?}"
        );
    }
    assert!(
        matches!(gone, Err(KeyDirectoryError::DeviceRevoked)),
        "{gone:?}"
    );
}

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap()
}

fn attested(owner: UserId, root: u8) -> Device {
    Device {
        attestation: Some(Attestation {
            root_key: DeviceRootKey::parse(&[root; 32]).unwrap(),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: at(),
            expires_at: at() + ATTESTATION_LIFETIME,
        }),
        ..device(owner, false)
    }
}

fn by_the_words(device: &Device) -> Approval {
    Approval {
        device: device.id,
        root_key: device.attestation.as_ref().unwrap().root_key.clone(),
        approver: Approver::Passphrase(HistoryGeneration::FIRST),
        signature: Ed25519Signature::parse("signature", &[9; 64]).unwrap(),
        created_at: at(),
    }
}

fn session(user: UserId, device: DeviceId, revoked: bool) -> Session {
    Session {
        id: SessionId::generate(),
        user,
        kind: SessionKind::App(web_client().id),
        device: Some(device),
        created_at: at(),
        last_used_at: at(),
        authenticated_at: at(),
        revoked_at: revoked.then(at),
    }
}

fn registration(token: &str) -> PushRegistration {
    PushRegistration {
        relay: PushRelay::parse("https://exp.host/--/api/v2/push/send").unwrap(),
        token: PushToken::parse(token).unwrap(),
    }
}

/// Alice's phone and tablet approved, the tablet signed out; a laptop nobody approved yet.
struct Account {
    alice: UserId,
    phone: Device,
    tablet: Device,
    laptop: Device,
    trust: DeviceTrust,
}

fn account() -> Account {
    let alice = UserId::generate();
    let (phone, tablet, laptop) = (attested(alice, 1), attested(alice, 2), attested(alice, 3));
    let trust = DeviceTrust {
        approvals: vec![by_the_words(&phone), by_the_words(&tablet)],
        devices: vec![phone.clone(), tablet.clone(), laptop.clone()],
        current: Some(HistoryGeneration::FIRST),
    };
    Account {
        alice,
        phone,
        tablet,
        laptop,
        trust,
    }
}

#[test]
fn a_notice_says_nothing_of_the_account_and_one_of_a_kind_replaces_the_last() {
    let alert = |what| {
        PushAlert {
            owner: UserId::generate(),
            device: DeviceId::generate(),
            what,
        }
        .notice()
    };

    assert_eq!(alert(Happened::Arrived), PushNotice::DeviceWaiting);
    assert_eq!(alert(Happened::AsksACode), PushNotice::DeviceWaiting);
    assert_eq!(alert(Happened::AsksToStartOver), PushNotice::StartOver);
    assert_eq!(PushNotice::DeviceWaiting.title(), "Is this you?");
    assert_eq!(PushNotice::StartOver.tag(), "start_over");
    assert_ne!(PushNotice::DeviceWaiting.tag(), PushNotice::StartOver.tag());
}

#[test]
fn the_approved_devices_signed_in_with_a_registration_are_told_never_the_one_concerned() {
    let a = account();
    let held = vec![
        (a.phone.id, registration("ExponentPushToken[phone]")),
        (a.tablet.id, registration("ExponentPushToken[tablet]")),
        (a.laptop.id, registration("ExponentPushToken[laptop]")),
    ];
    let sessions = vec![
        session(a.alice, a.phone.id, false),
        session(a.alice, a.tablet.id, true),
        session(a.alice, a.laptop.id, false),
    ];

    let about_the_laptop = push_recipients(&a.trust, &held, &sessions, a.laptop.id, at());
    let about_the_phone = push_recipients(&a.trust, &held, &sessions, a.phone.id, at());

    assert_eq!(about_the_laptop, vec![&held[0]]);
    assert!(about_the_phone.is_empty());
}

#[test]
fn nobody_is_told_before_the_account_has_a_history_key() {
    let a = account();
    let trust = DeviceTrust {
        current: None,
        ..a.trust
    };
    let held = vec![(a.phone.id, registration("ExponentPushToken[phone]"))];
    let sessions = vec![session(a.alice, a.phone.id, false)];

    assert!(push_recipients(&trust, &held, &sessions, a.laptop.id, at()).is_empty());
}

#[test]
fn an_arrival_waits_while_unapproved_unrevoked_and_asking_no_code() {
    let a = account();
    let asking = ApprovalRequest {
        id: ApprovalRequestId::generate(),
        owner: a.alice,
        device: a.laptop.id,
        approver: None,
        created_at: at(),
        expires_at: at() + time::Duration::minutes(10),
        closed_at: None,
    };
    let mut revoked = a.trust.clone();
    revoked.devices[2].revoked_at = Some(at());

    assert!(arrival_still_waits(&a.trust, a.laptop.id, &[]));
    assert!(!arrival_still_waits(&a.trust, a.laptop.id, &[asking]));
    assert!(!arrival_still_waits(&a.trust, a.phone.id, &[]));
    assert!(!arrival_still_waits(&revoked, a.laptop.id, &[]));
    assert!(!arrival_still_waits(&a.trust, DeviceId::generate(), &[]));
}
