use crate::SessionId;
use crate::auth::SessionKind;
use crate::e2ee::{
    ATTESTATION_LIFETIME, Approval, Approver, Attestation, DeviceLabel, DeviceRootKey,
    Ed25519Signature,
};

use super::*;

fn generation(raw: i64) -> HistoryGeneration {
    HistoryGeneration::parse(raw).unwrap()
}

/// The clock: everything below is an offset from it.
fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap()
}

fn device(owner: UserId, root: Option<u8>) -> Device {
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        paired_at: t0(),
        last_seen_at: t0(),
        revoked_at: None,
        attestation: root.map(|byte| Attestation {
            root_key: DeviceRootKey::parse(&[byte; 32]).unwrap(),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: t0(),
            expires_at: t0() + ATTESTATION_LIFETIME,
        }),
        hpke_key: None,
        history_generation: None,
    }
}

fn by_words(device: &Device, generation: HistoryGeneration) -> Approval {
    Approval {
        device: device.id,
        root_key: device.attestation.as_ref().unwrap().root_key.clone(),
        approver: Approver::Passphrase(generation),
        signature: Ed25519Signature::parse("signature", &[9; 64]).unwrap(),
        created_at: t0(),
    }
}

/// A session of `device`'s, last used `used`.
fn used(owner: UserId, device: DeviceId, used: OffsetDateTime) -> Session {
    Session {
        id: SessionId::generate(),
        user: owner,
        kind: SessionKind::Browser,
        device: Some(device),
        created_at: used - Duration::days(30),
        last_used_at: used,
        authenticated_at: used - Duration::days(30),
        revoked_at: None,
    }
}

/// Under generation 1: the laptop approved, a fresh device not.
struct Account {
    alice: UserId,
    laptop: Device,
    fresh: Device,
    trust: DeviceTrust,
}

fn account() -> Account {
    let alice = UserId::generate();
    let (laptop, fresh) = (device(alice, Some(1)), device(alice, Some(2)));
    Account {
        trust: DeviceTrust {
            devices: vec![laptop.clone(), fresh.clone()],
            approvals: vec![by_words(&laptop, generation(1))],
            current: Some(generation(1)),
        },
        alice,
        laptop,
        fresh,
    }
}

fn opened(a: &Account, at: OffsetDateTime) -> StartOverRequest {
    StartOverRequest::open_for(&a.fresh, &a.trust, at).unwrap()
}

#[test]
fn a_device_not_approved_asks_to_replace_the_current_generation() {
    let a = account();

    let request = opened(&a, t0());

    assert_eq!(
        (request.owner, request.device, request.generation),
        (a.alice, a.fresh.id, generation(1))
    );
    assert_eq!((request.created_at, request.ended), (t0(), None));
}

#[test]
fn an_approved_device_a_device_without_a_root_key_or_an_account_without_a_key_asks_nothing() {
    let a = account();
    let keyless = device(a.alice, None);
    let mut no_key_yet = a.trust.clone();
    no_key_yet.current = None;

    assert!(matches!(
        StartOverRequest::open_for(&a.laptop, &a.trust, t0()),
        Err(KeyDirectoryError::StartOver(
            StartOverRefusal::AlreadyApproved
        ))
    ));
    assert!(matches!(
        StartOverRequest::open_for(&keyless, &a.trust, t0()),
        Err(KeyDirectoryError::NoRootKey)
    ));
    assert!(matches!(
        StartOverRequest::open_for(&a.fresh, &no_key_yet, t0()),
        Err(KeyDirectoryError::StartOver(StartOverRefusal::NoHistoryKey))
    ));
}

#[test]
fn a_request_matures_a_week_after_it_opened_when_no_approved_device_is_used_since() {
    let a = account();
    let request = opened(&a, t0());
    let long_unused = [used(a.alice, a.laptop.id, t0() - Duration::days(30))];

    assert_eq!(
        request.ready_at(&a.trust, &long_unused),
        t0() + START_OVER_WAIT
    );
    assert_eq!(request.ready_at(&a.trust, &[]), t0() + START_OVER_WAIT);
}

#[test]
fn each_use_of_an_approved_device_pushes_the_request_back_a_week_from_that_use() {
    let a = account();
    let request = opened(&a, t0());

    for days in [1, 6, 13] {
        let in_use = [used(a.alice, a.laptop.id, t0() + Duration::days(days))];
        assert_eq!(
            request.ready_at(&a.trust, &in_use),
            t0() + Duration::days(days) + START_OVER_WAIT,
            "used on day {days}"
        );
    }
}

#[test]
fn only_the_approved_devices_uses_count_the_latest_of_them() {
    let a = account();
    let phone = device(a.alice, Some(3));
    let mut trust = a.trust.clone();
    trust.devices.push(phone.clone());
    trust.approvals.push(by_words(&phone, generation(1)));
    let request = StartOverRequest::open_for(&a.fresh, &trust, t0()).unwrap();
    let sessions = [
        used(a.alice, a.laptop.id, t0() + Duration::days(2)),
        used(a.alice, phone.id, t0() + Duration::days(3)),
        used(a.alice, a.fresh.id, t0() + Duration::days(5)),
    ];

    assert_eq!(
        request.ready_at(&trust, &sessions),
        t0() + Duration::days(3) + START_OVER_WAIT
    );
}

#[test]
fn with_no_approved_device_left_a_request_is_ready_at_once() {
    let mut a = account();
    a.trust.approvals.clear();
    let request = opened(&a, t0());

    assert_eq!(
        request.ready_at(&a.trust, &[used(a.alice, a.laptop.id, t0())]),
        t0()
    );
}

#[test]
fn a_revoked_device_no_longer_counts_as_approved() {
    let mut a = account();
    let request = opened(&a, t0());
    a.trust.devices[0].revoked_at = Some(t0());

    assert_eq!(
        request.ready_at(&a.trust, &[used(a.alice, a.laptop.id, t0())]),
        t0()
    );
}

#[test]
fn the_maturity_rule_is_the_later_of_opening_and_last_use_plus_a_week() {
    let approved = [DeviceId::generate()];

    assert_eq!(ready_at(t0(), &[], Some(t0())), t0());
    assert_eq!(ready_at(t0(), &approved, None), t0() + START_OVER_WAIT);
    assert_eq!(
        ready_at(t0(), &approved, Some(t0() - Duration::days(1))),
        t0() + START_OVER_WAIT
    );
    assert_eq!(
        ready_at(t0(), &approved, Some(t0() + Duration::hours(1))),
        t0() + Duration::hours(1) + START_OVER_WAIT
    );
}

#[test]
fn an_account_has_one_open_request_and_the_device_asking_again_gets_its_own() {
    let a = account();
    let request = opened(&a, t0());
    let other = StartOverRequest {
        id: StartOverRequestId::generate(),
        device: DeviceId::generate(),
        ..request.clone()
    };

    assert_eq!(
        may_open_start_over(&request, None, 0),
        Ok(StartOverOpening::Open)
    );
    assert_eq!(
        may_open_start_over(&opened(&a, t0()), Some(&request), 1),
        Ok(StartOverOpening::Existing(request.clone()))
    );
    assert_eq!(
        may_open_start_over(&other, Some(&request), 1),
        Err(StartOverRefusal::Pending)
    );
}

#[test]
fn an_account_opens_three_requests_a_day() {
    let a = account();
    let request = opened(&a, t0());

    assert_eq!(
        may_open_start_over(&request, None, START_OVER_REQUESTS_PER_WINDOW - 1),
        Ok(StartOverOpening::Open)
    );
    assert_eq!(
        may_open_start_over(&request, None, START_OVER_REQUESTS_PER_WINDOW),
        Err(StartOverRefusal::TooMany)
    );
    assert_eq!(START_OVER_REQUESTS_PER_WINDOW, 3);
    assert_eq!(start_over_window(t0()), t0() - Duration::days(1));
}

#[test]
fn the_asker_withdraws_an_approved_device_cancels_and_nobody_else_ends_a_request() {
    let a = account();
    let request = opened(&a, t0());
    let other = device(a.alice, Some(4));

    assert_eq!(
        request.may_end(a.fresh.id, &a.trust).unwrap(),
        StartOverEnd::Withdrawn
    );
    assert_eq!(
        request.may_end(a.laptop.id, &a.trust).unwrap(),
        StartOverEnd::Cancelled
    );
    assert!(matches!(
        request.may_end(other.id, &a.trust),
        Err(KeyDirectoryError::ApprovalRequired(_))
    ));
}

#[test]
fn a_request_that_ended_ends_no_more() {
    let a = account();
    let mut request = opened(&a, t0());
    request.ended = Some(StartOverEnding {
        how: StartOverEnd::Cancelled,
        at: t0(),
    });

    assert!(matches!(
        request.may_end(a.laptop.id, &a.trust),
        Err(KeyDirectoryError::StartOver(StartOverRefusal::Ended))
    ));
}

#[test]
fn the_asker_and_the_approved_devices_read_a_request_and_hear_it_ended() {
    let a = account();
    let request = opened(&a, t0());
    let other = device(a.alice, Some(4));

    assert_eq!(request.may_read(a.fresh.id, &a.trust), Ok(()));
    assert_eq!(request.may_read(a.laptop.id, &a.trust), Ok(()));
    assert_eq!(request.may_read(other.id, &a.trust), Err(ApprovalRequired));
    assert_eq!(
        request.audience(&a.trust),
        Audience::Devices(vec![a.fresh.id, a.laptop.id])
    );
}

#[test]
fn how_a_request_ended_is_written_one_way() {
    for end in [
        StartOverEnd::Cancelled,
        StartOverEnd::Withdrawn,
        StartOverEnd::Used,
        StartOverEnd::Superseded,
        StartOverEnd::Revoked,
        StartOverEnd::Approved,
    ] {
        assert_eq!(end.as_str().parse::<StartOverEnd>().ok(), Some(end));
    }
    assert!("expired".parse::<StartOverEnd>().is_err());
}

#[test]
fn a_request_that_ended_is_kept_past_the_day_it_counts_in() {
    assert_eq!(start_over_sweep_before(t0()), t0() - Duration::days(7));
    assert!(START_OVER_KEPT > START_OVER_WINDOW);
}
