use super::*;

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn fresh() -> Invitation {
    Invitation {
        id: InvitationId::generate(),
        created_by: UserId::generate(),
        created_at: at(),
        expires_at: at() + INVITATION_TTL,
        used_at: None,
        revoked_at: None,
    }
}

#[test]
fn an_invitation_unused_unrevoked_and_unexpired_is_open() {
    assert!(fresh().is_open(at()));
}

#[test]
fn an_invitation_is_open_until_the_second_it_expires() {
    let invitation = fresh();
    let expiry = invitation.expires_at;

    assert!(invitation.is_open(expiry - Duration::seconds(1)));
    assert!(!invitation.is_open(expiry));
    assert!(!invitation.is_open(expiry + Duration::seconds(1)));
}

#[test]
fn a_used_or_revoked_invitation_is_closed() {
    let used = Invitation {
        used_at: Some(at()),
        ..fresh()
    };
    let revoked = Invitation {
        revoked_at: Some(at()),
        ..fresh()
    };

    assert!(!used.is_open(at() + Duration::minutes(1)));
    assert!(!revoked.is_open(at() + Duration::minutes(1)));
}

#[test]
fn an_invitation_ends_when_used_revoked_or_expired_whichever_came_first() {
    let used = Invitation {
        used_at: Some(at() + Duration::days(1)),
        ..fresh()
    };
    let revoked = Invitation {
        revoked_at: Some(at() + Duration::days(2)),
        ..fresh()
    };

    assert_eq!(used.ended_at(), at() + Duration::days(1));
    assert_eq!(revoked.ended_at(), at() + Duration::days(2));
    assert_eq!(fresh().ended_at(), at() + INVITATION_TTL);
}
