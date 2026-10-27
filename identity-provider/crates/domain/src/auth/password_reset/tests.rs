use super::*;
use crate::auth::testing::signed_up;

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn fresh() -> PasswordReset {
    PasswordReset {
        member: UserId::generate(),
        created_by: UserId::generate(),
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
