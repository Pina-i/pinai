use time::Duration;

use super::*;
use crate::SessionId;
use crate::e2ee::DeviceLabel;

fn generation(raw: i64) -> HistoryGeneration {
    HistoryGeneration::parse(raw).unwrap()
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap()
}

fn signed_in(minutes_ago: i64) -> Bearer {
    Bearer {
        user: UserId::generate(),
        session: SessionId::generate(),
        authenticated_at: now() - Duration::minutes(minutes_ago),
    }
}

fn device(owner: UserId, revoked: bool) -> Device {
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        paired_at: now(),
        last_seen_at: now(),
        revoked_at: revoked.then(now),
        attestation: None,
        hpke_key: None,
        history_generation: None,
    }
}

#[test]
fn a_generation_is_a_positive_32_bit_number() {
    assert_eq!(generation(1), HistoryGeneration::FIRST);
    assert_eq!(generation(i64::from(i32::MAX)).value(), i32::MAX);
    for raw in [0, -1, i64::from(i32::MAX) + 1] {
        assert_eq!(
            HistoryGeneration::parse(raw).map_err(|e| e.to_string()),
            Err("generation: must be from 1 to 2147483647".to_owned()),
            "{raw}"
        );
    }
}

#[test]
fn a_salt_is_16_bytes_a_check_value_32_and_an_approval_key_32() {
    assert_eq!(HistorySalt::parse(&[1; 16]).unwrap().as_bytes(), &[1; 16]);
    assert_eq!(
        HistoryCheckValue::parse(&[2; 32]).unwrap().as_bytes(),
        &[2; 32]
    );
    assert_eq!(
        ApprovalPublicKey::parse(&[3; 32]).unwrap().as_bytes(),
        &[3; 32]
    );
    for len in [0, 15, 17, 32] {
        assert!(HistorySalt::parse(&vec![1; len]).is_err(), "salt of {len}");
    }
    for len in [0, 16, 31, 33] {
        assert_eq!(
            HistoryCheckValue::parse(&vec![1; len]).map_err(|e| e.to_string()),
            Err("check_value: must be 32 bytes (HMAC-SHA256)".to_owned()),
            "check value of {len}"
        );
        assert_eq!(
            ApprovalPublicKey::parse(&vec![1; len]).map_err(|e| e.to_string()),
            Err("approval_public_key: must be 32 bytes (Ed25519)".to_owned()),
            "approval key of {len}"
        );
    }
}

#[test]
fn only_the_generation_right_after_the_current_one_follows_it() {
    assert!(generation(1).follows(None));
    assert!(generation(2).follows(Some(generation(1))));
    assert!(generation(8).follows(Some(generation(7))));

    assert!(!generation(2).follows(None), "none skipped");
    assert!(
        !generation(1).follows(Some(generation(1))),
        "none taken twice"
    );
    assert!(!generation(3).follows(Some(generation(1))));
    assert!(
        !generation(1).follows(Some(generation(2))),
        "none gone back to"
    );
}

#[test]
fn a_session_that_named_its_device_sets_the_first_generation_without_a_recent_password() {
    let laptop = DeviceId::generate();

    let set_by = may_set_history_key(
        HistoryGeneration::FIRST,
        &signed_in(60),
        Some(laptop),
        now(),
    );

    assert_eq!(set_by.unwrap(), laptop, "the session's device sets it");
}

#[test]
fn any_later_generation_takes_a_recent_password() {
    let laptop = Some(DeviceId::generate());

    assert!(may_set_history_key(generation(2), &signed_in(10), laptop, now()).is_ok());
    for later in [2, 3, 40] {
        let refused = may_set_history_key(generation(later), &signed_in(11), laptop, now());
        assert!(
            matches!(refused, Err(ArchiveError::RecentSignInRequired)),
            "{later}: {refused:?}"
        );
    }
}

#[test]
fn a_session_that_named_no_device_sets_no_generation() {
    for raw in [1, 2] {
        let refused = may_set_history_key(generation(raw), &signed_in(0), None, now());
        assert!(
            matches!(refused, Err(ArchiveError::DeviceRequired(DeviceRequired))),
            "{raw}: {refused:?}"
        );
    }
}

#[test]
fn only_the_current_generation_is_written_under() {
    assert_eq!(
        check_history_generation(generation(2), Some(generation(2))),
        Ok(())
    );
    assert_eq!(
        check_history_generation(generation(1), Some(generation(2))),
        Err(StaleHistoryKey),
        "a generation already replaced"
    );
    assert_eq!(
        check_history_generation(generation(3), Some(generation(2))),
        Err(StaleHistoryKey)
    );
    assert_eq!(
        check_history_generation(HistoryGeneration::FIRST, None),
        Err(StaleHistoryKey),
        "none set yet"
    );
}

#[test]
fn a_device_of_the_callers_reports_the_current_generation_from_its_own_session() {
    let alice = UserId::generate();
    let laptop = device(alice, false);

    let reported = may_report_history_key(
        Some(laptop.id),
        alice,
        laptop.id,
        Some(&laptop),
        generation(3),
        Some(generation(3)),
    );

    assert!(reported.is_ok(), "{reported:?}");
}

#[test]
fn a_report_from_a_session_naming_no_device_or_another_is_refused_before_anything_else() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, false), device(alice, false));
    let report =
        |named| may_report_history_key(named, alice, phone.id, Some(&phone), generation(1), None);

    let unnamed = report(None);
    let anothers = report(Some(laptop.id));

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
fn only_an_unrevoked_device_of_the_callers_reports_and_only_the_current_generation() {
    let (alice, bob) = (UserId::generate(), UserId::generate());
    let (bobs, revoked, laptop) = (
        device(bob, false),
        device(alice, true),
        device(alice, false),
    );
    let current = Some(generation(2));
    let report = |id: DeviceId, device: Option<&Device>, generation, current| {
        may_report_history_key(Some(id), alice, id, device, generation, current)
    };

    let unknown = report(DeviceId::generate(), None, generation(2), current);
    let anothers = report(bobs.id, Some(&bobs), generation(2), current);
    let gone = report(revoked.id, Some(&revoked), generation(2), current);
    let replaced = report(laptop.id, Some(&laptop), generation(1), current);
    let none_set = report(laptop.id, Some(&laptop), generation(1), None);

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
    for refused in [replaced, none_set] {
        assert!(
            matches!(refused, Err(KeyDirectoryError::StaleHistoryKey(_))),
            "{refused:?}"
        );
    }
}

mod replacing {
    use super::*;
    use crate::auth::{Session, SessionKind};
    use crate::e2ee::{
        ATTESTATION_LIFETIME, Approval, Approver, Attestation, DeviceRootKey, Ed25519Signature,
        START_OVER_WAIT, StartOverEnd, StartOverEnding,
    };

    fn key(raw: i64, byte: u8) -> HistoryKey {
        HistoryKey {
            generation: generation(raw),
            salt: HistorySalt::parse(&[byte; 16]).unwrap(),
            check_value: HistoryCheckValue::parse(&[byte; 32]).unwrap(),
            approval_public_key: ApprovalPublicKey::parse(&[byte; 32]).unwrap(),
        }
    }

    fn attested(owner: UserId, root: u8) -> Device {
        let mut device = device(owner, false);
        device.attestation = Some(Attestation {
            root_key: DeviceRootKey::parse(&[root; 32]).unwrap(),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: now(),
            expires_at: now() + ATTESTATION_LIFETIME,
        });
        device
    }

    /// Under generation 1: the laptop approved by its words, a fresh device not, and the fresh
    /// device's request opened a week ago.
    struct Account {
        laptop: Device,
        fresh: Device,
        trust: DeviceTrust,
        request: StartOverRequest,
    }

    fn account() -> Account {
        let alice = UserId::generate();
        let (laptop, fresh) = (attested(alice, 1), attested(alice, 2));
        let trust = DeviceTrust {
            devices: vec![laptop.clone(), fresh.clone()],
            approvals: vec![Approval {
                device: laptop.id,
                root_key: laptop.attestation.as_ref().unwrap().root_key.clone(),
                approver: Approver::Passphrase(generation(1)),
                signature: Ed25519Signature::parse("signature", &[9; 64]).unwrap(),
                created_at: now(),
            }],
            current: Some(generation(1)),
        };
        let request = StartOverRequest::open_for(&fresh, &trust, now() - START_OVER_WAIT).unwrap();
        Account {
            laptop,
            fresh,
            trust,
            request,
        }
    }

    fn laptop_used(a: &Account, at: OffsetDateTime) -> Session {
        Session {
            id: SessionId::generate(),
            user: a.laptop.owner,
            kind: SessionKind::Browser,
            device: Some(a.laptop.id),
            created_at: at,
            last_used_at: at,
            authenticated_at: at,
            revoked_at: None,
        }
    }

    fn gate(
        a: &Account,
        next: &HistoryKey,
        setter: DeviceId,
        request: Option<&StartOverRequest>,
        sessions: &[Session],
    ) -> Result<KeyGate, ArchiveError> {
        may_replace_history_key(
            next,
            setter,
            Some(&key(1, 1)),
            &a.trust,
            request,
            sessions,
            now(),
        )
    }

    #[test]
    fn the_key_held_is_a_retry_before_any_other_check() {
        let a = account();

        assert_eq!(
            gate(&a, &key(1, 1), a.fresh.id, None, &[]).unwrap(),
            KeyGate::AlreadySet
        );
    }

    #[test]
    fn a_generation_that_does_not_follow_is_a_conflict_before_the_approval_is_looked_at() {
        let a = account();

        for (next, setter) in [(key(3, 3), a.fresh.id), (key(1, 9), a.laptop.id)] {
            assert!(matches!(
                gate(&a, &next, setter, None, &[]),
                Err(ArchiveError::KeyConflict { current: Some(g) }) if g == generation(1)
            ));
        }
    }

    #[test]
    fn the_first_generation_is_written_by_any_device() {
        let a = account();

        let first = may_replace_history_key(
            &key(1, 1),
            a.fresh.id,
            None,
            &DeviceTrust::default(),
            None,
            &[],
            now(),
        );

        assert_eq!(first.unwrap(), KeyGate::Write(None));
    }

    #[test]
    fn a_device_approved_under_the_generation_replaced_writes_at_once() {
        let a = account();

        assert_eq!(
            gate(&a, &key(2, 2), a.laptop.id, None, &[laptop_used(&a, now())]).unwrap(),
            KeyGate::Write(None)
        );
    }

    #[test]
    fn a_device_not_approved_needs_a_request_of_its_own() {
        let a = account();
        let mut withdrawn = a.request.clone();
        withdrawn.ended = Some(StartOverEnding {
            how: StartOverEnd::Withdrawn,
            at: now(),
        });
        let anothers = StartOverRequest {
            device: DeviceId::generate(),
            ..a.request.clone()
        };

        for request in [None, Some(&withdrawn), Some(&anothers)] {
            assert!(matches!(
                gate(&a, &key(2, 2), a.fresh.id, request, &[]),
                Err(ArchiveError::StartOver(StartOverRefusal::Required))
            ));
        }
    }

    #[test]
    fn a_request_not_matured_says_when_it_will_be() {
        let a = account();
        let yesterday = now() - Duration::days(1);

        let refused = gate(
            &a,
            &key(2, 2),
            a.fresh.id,
            Some(&a.request),
            &[laptop_used(&a, yesterday)],
        );

        assert!(matches!(
            refused,
            Err(ArchiveError::StartOver(StartOverRefusal::NotReady { ready_at }))
                if ready_at == yesterday + START_OVER_WAIT
        ));
    }

    #[test]
    fn a_matured_request_writes_the_next_generation_and_names_what_it_relied_on() {
        let a = account();
        let unused = laptop_used(&a, now() - Duration::days(8));

        let KeyGate::Write(Some(matured)) = gate(
            &a,
            &key(2, 2),
            a.fresh.id,
            Some(&a.request),
            std::slice::from_ref(&unused),
        )
        .unwrap() else {
            panic!("a matured request");
        };

        assert_eq!(
            (matured.request(), matured.device(), matured.generation()),
            (a.request.id, a.fresh.id, generation(1))
        );
    }
}
