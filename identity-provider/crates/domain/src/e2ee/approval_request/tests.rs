use super::*;
use crate::auth::SessionKind;
use crate::e2ee::{ATTESTATION_LIFETIME, Attestation, DeviceLabel, DeviceRootKey};

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap()
}

fn device(owner: UserId, attested: bool) -> Device {
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        paired_at: now(),
        last_seen_at: now(),
        revoked_at: None,
        attestation: attested.then(|| Attestation {
            root_key: DeviceRootKey::parse(&[1; 32]).unwrap(),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: now(),
            expires_at: now() + ATTESTATION_LIFETIME,
        }),
        hpke_key: None,
        history_generation: None,
    }
}

/// An open request of a new device's, and another attested device of the same account.
fn request_and_another() -> (ApprovalRequest, Device) {
    let owner = UserId::generate();
    let asking = device(owner, true);
    (
        ApprovalRequest::open_for(&asking, now()).unwrap(),
        device(owner, true),
    )
}

fn asking(request: &ApprovalRequest) -> Device {
    Device {
        id: request.device,
        ..device(request.owner, true)
    }
}

fn session(user: UserId, device: Option<DeviceId>, live: bool) -> Session {
    Session {
        id: SessionId::generate(),
        user,
        kind: SessionKind::Browser,
        device,
        created_at: now(),
        last_used_at: now(),
        authenticated_at: now(),
        revoked_at: (!live).then(now),
    }
}

#[test]
fn a_message_body_is_1_to_4096_bytes() {
    assert!(ApprovalMessageBody::parse(vec![1]).is_ok());
    assert!(ApprovalMessageBody::parse(vec![1; 4096]).is_ok());
    for len in [0, 4097] {
        assert_eq!(
            ApprovalMessageBody::parse(vec![1; len]).map_err(|e| e.to_string()),
            Err("body: must be 1 to 4096 bytes".to_owned()),
            "{len}"
        );
    }
}

#[test]
fn messages_are_read_after_a_place_from_0() {
    assert_eq!(MessageSeq::parse(0).unwrap(), MessageSeq::START);
    assert_eq!(MessageSeq::parse(12).unwrap().value(), 12);
    for raw in [-1, i64::from(i32::MAX) + 1] {
        assert!(MessageSeq::parse(raw).is_err(), "{raw}");
    }
}

#[test]
fn a_device_with_a_root_key_opens_a_request_for_ten_minutes() {
    let owner = UserId::generate();
    let laptop = device(owner, true);

    let opened = ApprovalRequest::open_for(&laptop, now()).unwrap();
    let unattested = ApprovalRequest::open_for(&device(owner, false), now());

    assert_eq!(
        (
            opened.owner,
            opened.device,
            opened.approver,
            opened.closed_at
        ),
        (owner, laptop.id, None, None)
    );
    assert_eq!(opened.expires_at, now() + Duration::minutes(10));
    assert!(opened.is_open(now() + Duration::seconds(599)));
    assert!(!opened.is_open(now() + Duration::minutes(10)));
    assert!(matches!(unattested, Err(KeyDirectoryError::NoRootKey)));
}

#[test]
fn a_closed_request_is_no_longer_open() {
    let (open, _) = request_and_another();
    let closed = ApprovalRequest {
        closed_at: Some(now()),
        ..open
    };

    assert!(!closed.is_open(now()));
}

#[test]
fn an_account_opens_ten_requests_an_hour() {
    assert_eq!(may_open_request(9), Ok(()));
    assert_eq!(may_open_request(10), Err(RequestRefusal::TooMany));
    assert_eq!(window_start(now()), now() - Duration::hours(1));
}

#[test]
fn any_device_of_the_account_takes_part_until_one_answers() {
    let (open, other) = request_and_another();
    let approver = DeviceId::generate();
    let bound = ApprovalRequest {
        approver: Some(approver),
        ..open.clone()
    };

    assert_eq!(open.may_take_part(open.device, now()), Ok(()));
    assert_eq!(open.may_take_part(other.id, now()), Ok(()));
    assert_eq!(bound.may_take_part(bound.device, now()), Ok(()));
    assert_eq!(bound.may_take_part(approver, now()), Ok(()));
    assert_eq!(
        bound.may_take_part(other.id, now()),
        Err(RequestRefusal::Taken)
    );
}

#[test]
fn nobody_posts_to_or_closes_a_request_that_ended() {
    let (open, other) = request_and_another();
    let closed = ApprovalRequest {
        closed_at: Some(now()),
        ..open.clone()
    };

    assert_eq!(
        open.may_take_part(open.device, open.expires_at),
        Err(RequestRefusal::Ended)
    );
    assert_eq!(
        closed.may_take_part(open.device, now()),
        Err(RequestRefusal::Ended)
    );
    assert_eq!(
        open.may_post(&other, 0, open.expires_at),
        Err(RequestRefusal::Ended)
    );
}

#[test]
fn the_two_sides_read_until_the_sweep_and_a_third_device_never() {
    let (open, other) = request_and_another();
    let approver = DeviceId::generate();
    let bound_and_closed = ApprovalRequest {
        approver: Some(approver),
        closed_at: Some(now()),
        ..open.clone()
    };
    let later = open.expires_at + Duration::minutes(5);

    assert_eq!(open.may_read(other.id, now()), Ok(()));
    assert_eq!(open.may_read(open.device, later), Ok(()));
    assert_eq!(open.may_read(other.id, later), Err(RequestRefusal::Ended));
    assert_eq!(bound_and_closed.may_read(open.device, later), Ok(()));
    assert_eq!(bound_and_closed.may_read(approver, later), Ok(()));
    assert_eq!(
        bound_and_closed.may_read(other.id, now()),
        Err(RequestRefusal::Taken)
    );
}

#[test]
fn the_first_message_from_another_device_binds_the_request_to_it() {
    let (open, other) = request_and_another();
    let bound = ApprovalRequest {
        approver: Some(other.id),
        ..open.clone()
    };

    assert_eq!(
        open.may_post(&asking(&open), 0, now()),
        Ok(Posting {
            seq: MessageSeq(1),
            binds: false
        })
    );
    assert_eq!(
        open.may_post(&other, 1, now()),
        Ok(Posting {
            seq: MessageSeq(2),
            binds: true
        })
    );
    assert_eq!(
        bound.may_post(&other, 2, now()),
        Ok(Posting {
            seq: MessageSeq(3),
            binds: false
        })
    );
    assert_eq!(
        bound.may_post(&device(open.owner, true), 3, now()),
        Err(RequestRefusal::Taken)
    );
}

#[test]
fn a_device_without_a_root_key_never_answers_a_request() {
    let (open, _) = request_and_another();
    let unattested = device(open.owner, false);

    assert_eq!(
        open.may_post(&unattested, 1, now()),
        Err(RequestRefusal::NoRootKey)
    );
}

#[test]
fn a_request_holds_twelve_messages() {
    let (open, _) = request_and_another();
    let asking = asking(&open);

    assert_eq!(
        open.may_post(&asking, 11, now()).unwrap().seq,
        MessageSeq(12)
    );
    assert_eq!(open.may_post(&asking, 12, now()), Err(RequestRefusal::Full));
}

#[test]
fn a_message_reaches_the_other_side_every_other_device_until_one_answers() {
    let (open, other) = request_and_another();
    let bound = ApprovalRequest {
        approver: Some(other.id),
        ..open.clone()
    };

    assert_eq!(
        open.counterpart(open.device),
        Audience::AllBut(vec![open.device])
    );
    assert_eq!(
        bound.counterpart(bound.device),
        Audience::Devices(vec![other.id])
    );
    assert_eq!(
        bound.counterpart(other.id),
        Audience::Devices(vec![bound.device])
    );
}

#[test]
fn an_end_reaches_both_sides_and_an_answer_tells_the_others_it_is_taken() {
    let (open, other) = request_and_another();
    let bound = ApprovalRequest {
        approver: Some(other.id),
        ..open.clone()
    };

    assert_eq!(open.parties(), Audience::AllBut(vec![]));
    assert_eq!(
        bound.parties(),
        Audience::Devices(vec![bound.device, other.id])
    );
    assert_eq!(
        bound.bystanders(),
        Audience::AllBut(vec![bound.device, other.id])
    );
}

#[test]
fn an_audience_is_the_live_sessions_of_its_devices_and_never_one_that_named_none() {
    let alice = UserId::generate();
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
    let on_laptop = session(alice, Some(laptop), true);
    let on_phone = session(alice, Some(phone), true);
    let unnamed = session(alice, None, true);
    let ended = session(alice, Some(phone), false);
    let sessions = [on_laptop.clone(), on_phone.clone(), unnamed, ended];

    assert_eq!(
        Audience::AllBut(vec![]).sessions(&sessions, now()),
        vec![on_laptop.id, on_phone.id]
    );
    assert_eq!(
        Audience::AllBut(vec![laptop]).sessions(&sessions, now()),
        vec![on_phone.id]
    );
    assert_eq!(
        Audience::Devices(vec![laptop, phone]).sessions(&sessions, now()),
        vec![on_laptop.id, on_phone.id]
    );
}

#[test]
fn a_third_device_hears_a_request_is_anothers_before_it_hears_it_ended() {
    let (open, other) = request_and_another();
    let bound_and_ended = ApprovalRequest {
        approver: Some(DeviceId::generate()),
        closed_at: Some(now()),
        ..open
    };

    assert_eq!(
        bound_and_ended.may_take_part(other.id, now()),
        Err(RequestRefusal::Taken)
    );
    assert_eq!(
        bound_and_ended.may_read(other.id, now()),
        Err(RequestRefusal::Taken)
    );
    assert_eq!(
        bound_and_ended.may_post(&other, 0, now()),
        Err(RequestRefusal::Taken)
    );
}
