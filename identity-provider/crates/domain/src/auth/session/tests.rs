use super::*;

fn used_at(at: OffsetDateTime) -> Session {
    Session {
        id: SessionId::generate(),
        user: UserId::generate(),
        kind: SessionKind::Browser,
        device: None,
        created_at: at,
        last_used_at: at,
        authenticated_at: at,
        revoked_at: None,
    }
}

#[test]
fn a_session_lives_until_ninety_days_without_use() {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let session = used_at(at);

    assert!(session.is_live(at));
    assert!(session.is_live(at + SESSION_IDLE - Duration::days(1)));
    assert!(!session.is_live(at + SESSION_IDLE));
    assert!(!session.is_live(at + SESSION_IDLE + Duration::days(1)));
}

#[test]
fn a_revoked_session_is_over_at_once() {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let session = Session {
        revoked_at: Some(at),
        ..used_at(at)
    };

    assert!(!session.is_live(at));
}

#[test]
fn a_device_was_last_active_at_its_live_sessions_last_use_and_is_signed_out_without_one() {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let device = DeviceId::generate();
    let on = |session: Session| Session {
        device: Some(device),
        ..session
    };
    let earlier = on(used_at(at - Duration::days(2)));
    let latest = on(used_at(at - Duration::hours(3)));
    let ended = Session {
        revoked_at: Some(at),
        ..on(used_at(at - Duration::minutes(5)))
    };
    let elsewhere = used_at(at - Duration::minutes(1));

    assert_eq!(
        last_active(
            &[earlier.clone(), latest, ended.clone(), elsewhere.clone()],
            device,
            at
        ),
        Some(at - Duration::hours(3))
    );
    assert_eq!(last_active(&[ended, elsewhere], device, at), None);
    assert_eq!(
        last_active(&[earlier], device, at + SESSION_IDLE),
        None,
        "idle 90 days is signed out"
    );
}
