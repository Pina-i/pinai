use time::OffsetDateTime;

use super::*;
use crate::e2ee::{DeviceLabel, DeviceRequired};

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
