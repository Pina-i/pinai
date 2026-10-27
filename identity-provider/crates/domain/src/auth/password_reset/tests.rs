use super::*;
use crate::auth::testing::signed_up;

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn fresh() -> PasswordReset {
    PasswordReset {
        member: UserId::generate(),
        created_by: Some(UserId::generate()),
        created_at: at(),
        expires_at: at() + RESET_TTL,
        used_at: None,
        replaced_at: None,
    }
}

#[test]
fn a_link_unused_not_replaced_and_unexpired_is_open() {
    assert!(fresh().is_open(at()));
}

#[test]
fn a_link_is_open_for_a_day_until_the_second_it_expires() {
    let reset = fresh();
    let expiry = reset.expires_at;

    assert_eq!(expiry - reset.created_at, Duration::hours(24));
    assert!(reset.is_open(expiry - Duration::seconds(1)));
    assert!(!reset.is_open(expiry));
    assert!(!reset.is_open(expiry + Duration::seconds(1)));
}

#[test]
fn a_used_or_replaced_link_is_closed() {
    let used = PasswordReset {
        used_at: Some(at()),
        ..fresh()
    };
    let replaced = PasswordReset {
        replaced_at: Some(at()),
        ..fresh()
    };

    assert!(!used.is_open(at() + Duration::minutes(1)));
    assert!(!replaced.is_open(at() + Duration::minutes(1)));
}

#[test]
fn a_link_ends_when_used_replaced_or_expired_whichever_came_first() {
    let used = PasswordReset {
        used_at: Some(at() + Duration::hours(1)),
        ..fresh()
    };
    let replaced = PasswordReset {
        replaced_at: Some(at() + Duration::hours(2)),
        ..fresh()
    };

    assert_eq!(used.ended_at(), at() + Duration::hours(1));
    assert_eq!(replaced.ended_at(), at() + Duration::hours(2));
    assert_eq!(fresh().ended_at(), at() + RESET_TTL);
}

#[test]
fn a_member_who_is_no_admin_may_get_a_link_confirmed_or_admitted() {
    let alice = signed_up("alice");
    let invited = SignInAccount {
        email_verified: false,
        admitted: true,
        ..signed_up("hoku")
    };

    for member in [alice, invited] {
        assert_eq!(reset_target(Some(member.clone())).unwrap(), member);
    }
}

#[test]
fn an_account_still_to_confirm_its_address_is_as_unknown_as_none() {
    let signing_up = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };

    assert!(matches!(
        reset_target(Some(signing_up)),
        Err(AuthError::UnknownUser)
    ));
}

#[test]
fn an_admin_or_an_unknown_account_gets_no_link() {
    let admin = SignInAccount {
        admin: true,
        ..signed_up("root")
    };

    assert!(matches!(
        reset_target(Some(admin)),
        Err(AuthError::AdminNotResettable)
    ));
    assert!(matches!(reset_target(None), Err(AuthError::UnknownUser)));
}

#[test]
fn a_new_password_follows_the_rule_and_is_typed_the_same_twice() {
    let set = NewPassword::parse("correct horse", "correct horse").unwrap();

    assert_eq!(set.as_str(), "correct horse");
    assert!(matches!(
        NewPassword::parse("short", "short"),
        Err(AuthError::PasswordTooShort)
    ));
    assert!(matches!(
        NewPassword::parse("correct horse", "correct house"),
        Err(AuthError::PasswordMismatch)
    ));
}

#[test]
fn a_new_password_never_shows_in_debug_output() {
    let set = NewPassword::parse("correct horse", "correct horse").unwrap();

    assert_eq!(format!("{set:?}"), "NewPassword(..)");
}

#[test]
fn a_link_with_no_admin_behind_it_went_through_the_mailbox() {
    let requested = PasswordReset {
        created_by: None,
        ..fresh()
    };

    assert_eq!(requested.by(), ResetBy::Mailbox);
    assert_eq!(fresh().by(), ResetBy::Admin);
}

#[test]
fn a_link_asked_for_by_mail_is_open_for_thirty_minutes_an_admins_for_a_day() {
    assert_eq!(REQUESTED_RESET_TTL, Duration::minutes(30));
    assert_eq!(RESET_TTL, Duration::hours(24));
    let requested = PasswordReset {
        created_by: None,
        expires_at: at() + REQUESTED_RESET_TTL,
        ..fresh()
    };

    assert!(requested.is_open(at() + Duration::minutes(30) - Duration::seconds(1)));
    assert!(!requested.is_open(at() + Duration::minutes(30)));
}

#[test]
fn whoever_has_the_address_confirmed_or_admitted_admins_included_may_ask_for_a_link() {
    let confirmed = signed_up("alice");
    let admitted = SignInAccount {
        email_verified: false,
        admitted: true,
        ..signed_up("hoku")
    };
    let admin = SignInAccount {
        admin: true,
        ..signed_up("root")
    };

    for account in [confirmed, admitted, admin] {
        assert_eq!(reset_requester(Some(account.clone())), Some(account));
    }
}

#[test]
fn an_account_still_to_confirm_its_address_or_none_gets_no_link_asked_for() {
    let signing_up = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };

    assert_eq!(reset_requester(Some(signing_up)), None);
    assert_eq!(reset_requester(None), None);
}

#[test]
fn five_links_may_be_asked_for_in_an_hour_and_no_more() {
    assert_eq!(RESET_REQUEST_WINDOW, Duration::hours(1));
    for asked in 0..5 {
        assert!(may_request_reset(asked), "{asked}");
    }
    for asked in [5, 6, 50] {
        assert!(!may_request_reset(asked), "{asked}");
    }
}

#[test]
fn a_reset_link_opens_its_page_on_the_instance() {
    let origin = InstanceOrigin::parse("https://chat.example.org").unwrap();
    let token = ResetToken::from_bytes([1; 32]);

    assert_eq!(reset_path(&token), format!("/r/{}", token.as_str()));
    assert!(reset_path(&token).starts_with(RESET_PATH_PREFIX));
    assert_eq!(
        reset_link(&origin, &token),
        format!("https://chat.example.org/r/{}", token.as_str())
    );
}

#[test]
fn a_reset_mail_never_shows_its_link_or_its_address_in_debug_output() {
    let token = ResetToken::from_bytes([1; 32]);
    let mail = ResetMail {
        to: "alice@idp.test".to_owned(),
        name: "alice".to_owned(),
        instance: "Aotearoa".to_owned(),
        link: format!("https://chat.example.org/r/{}", token.as_str()),
        valid_for: REQUESTED_RESET_TTL,
    };

    let shown = format!("{mail:?}");
    assert!(!shown.contains(token.as_str()), "{shown}");
    assert!(!shown.contains("alice@idp.test"), "{shown}");
}

#[test]
fn an_open_link_never_shows_its_address_in_debug_output() {
    let open = OpenReset {
        member: UserId::generate(),
        display_name: Some("alice".to_owned()),
        email: "alice@idp.test".to_owned(),
        by: ResetBy::Mailbox,
        expires_at: at(),
    };

    let shown = format!("{open:?}");
    assert!(!shown.contains("alice@idp.test"), "{shown}");
}
