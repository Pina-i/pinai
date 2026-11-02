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
