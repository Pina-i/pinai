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
