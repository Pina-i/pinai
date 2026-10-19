use super::*;

fn used_at(at: OffsetDateTime) -> Session {
    Session {
        id: SessionId::generate(),
        user: UserId::generate(),
        kind: SessionKind::Browser,
        created_at: at,
        last_used_at: at,
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
