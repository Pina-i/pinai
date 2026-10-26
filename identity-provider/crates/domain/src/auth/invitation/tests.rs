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

#[test]
fn a_token_is_256_bits_in_url_safe_base64_without_padding() {
    let token = InvitationToken::from_bytes([0xfb; 32]);

    assert_eq!(token.as_str().len(), InvitationToken::LEN);
    assert!(
        !token.as_str().contains(['+', '/', '=']),
        "{}",
        token.as_str()
    );
    assert_eq!(InvitationToken::parse(token.as_str()).unwrap(), token);
}

#[test]
fn a_token_of_another_shape_names_no_invitation() {
    let token = InvitationToken::from_bytes([7; 32]);
    for refused in [
        "",
        &token.as_str()[1..],
        &format!("{}A", token.as_str()),
        &format!("{}=", &token.as_str()[..42]),
        &token
            .as_str()
            .replace(|c: char| c.is_ascii_alphanumeric(), "+"),
        "<script>alert(1)</script>",
    ] {
        assert!(InvitationToken::parse(refused).is_err(), "{refused:?}");
    }
}

#[test]
fn a_token_never_shows_in_debug_output() {
    let token = InvitationToken::from_bytes([42; 32]);

    let shown = format!("{token:?}");

    assert_eq!(shown, "InvitationToken(..)");
    assert!(!shown.contains(token.as_str()));
}
