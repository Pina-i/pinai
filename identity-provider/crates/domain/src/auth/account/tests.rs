use super::*;
use crate::auth::testing::signed_up;

#[test]
fn only_an_account_neither_confirmed_nor_admitted_needs_a_code() {
    let confirmed = signed_up("alice");
    let admitted = SignInAccount {
        email_verified: false,
        admitted: true,
        ..signed_up("bob")
    };
    let neither = SignInAccount {
        email_verified: false,
        ..signed_up("carol")
    };

    assert!(!confirmed.needs_code());
    assert!(!admitted.needs_code());
    assert!(neither.needs_code());
}

#[test]
fn a_mail_calls_an_account_by_its_display_name_else_its_handle() {
    let named = signed_up("alice");
    let unnamed = SignInAccount {
        display_name: None,
        ..signed_up("bob")
    };
    let blank = SignInAccount {
        display_name: Some(String::new()),
        ..signed_up("carol")
    };

    assert_eq!(named.addressed_as(), "alice");
    assert_eq!(unnamed.addressed_as(), "bob_t3st0");
    assert_eq!(blank.addressed_as(), "carol_t3st0");
}
