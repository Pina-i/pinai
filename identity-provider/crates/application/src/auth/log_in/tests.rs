use domain::auth::testing::{Mail, a_request, signed_up};
use domain::auth::{ClientId, ClientSignIn, Grant, SignInAccount};
use time::Duration;

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn the_right_password_ends_in_a_code_answering_the_request() {
    let w = world().await;

    let outcome = w
        .log_in
        .execute(&w.alice.email, "alice-password", &a_request(), now())
        .await
        .unwrap();

    let issued = w.codes.issued();
    assert_eq!(
        outcome,
        LoginOutcome::SignedIn {
            user: w.alice.id,
            code: issued[0].0.clone(),
        }
    );
    assert_eq!(issued[0].1, Grant::answering(w.alice.id, &a_request()));
    assert_eq!(
        w.sign_ins.remembered(),
        vec![ClientSignIn::of(w.alice.id, &a_request())],
        "the app is remembered for the account"
    );
}

#[tokio::test]
async fn a_wrong_password_and_an_unknown_email_are_refused_alike() {
    let w = world().await;

    let wrong = w
        .log_in
        .execute(&w.alice.email, "bob-password", &a_request(), now())
        .await
        .unwrap();
    let unknown = w
        .log_in
        .execute("nobody@idp.test", "alice-password", &a_request(), now())
        .await
        .unwrap();

    assert_eq!(
        (wrong, unknown),
        (LoginOutcome::Refused, LoginOutcome::Refused)
    );
    assert!(w.codes.issued().is_empty());
}

#[tokio::test]
async fn an_unconfirmed_address_is_mailed_a_code_instead_of_signing_in() {
    let w = world().await;
    let bob = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;

    let outcome = w
        .log_in
        .execute(&bob.email, "bob-password", &a_request(), now())
        .await
        .unwrap();

    let issued = w.signup_codes.issued();
    assert_eq!(
        outcome,
        LoginOutcome::Unverified {
            user: bob.id,
            email: bob.email.clone(),
        }
    );
    assert_eq!(
        (issued[0].0, issued[0].2),
        (bob.id, now() + Duration::minutes(10))
    );
    assert_eq!(
        w.mailer.sent(),
        vec![Mail {
            to: bob.email.clone(),
            name: "bob".to_owned(),
            code: issued[0].1.clone(),
        }]
    );
    assert!(w.codes.issued().is_empty());
}

#[tokio::test]
async fn a_mail_that_cannot_leave_still_sends_the_account_to_confirm_its_address() {
    let w = world().await;
    let bob = SignInAccount {
        email_verified: false,
        display_name: None,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;
    w.mailer.break_down();

    let outcome = w
        .log_in
        .execute(&bob.email, "bob-password", &a_request(), now())
        .await
        .unwrap();

    assert!(
        matches!(outcome, LoginOutcome::Unverified { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_account_with_an_authenticator_is_given_a_ticket_instead_of_a_code() {
    let w = world().await;
    let bob = SignInAccount {
        totp_enabled: true,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;

    let outcome = w
        .log_in
        .execute(&bob.email, "bob-password", &a_request(), now())
        .await
        .unwrap();

    let opened = w.tickets.opened();
    assert_eq!(outcome, LoginOutcome::SecondFactor(opened[0].0));
    assert_eq!(
        (opened[0].1, &opened[0].2, opened[0].3),
        (bob.id, &a_request(), now() + Duration::minutes(5))
    );
    assert!(w.codes.issued().is_empty());
}

#[tokio::test]
async fn a_request_from_an_unknown_client_or_to_an_unregistered_redirect_is_refused_first() {
    let w = world().await;
    let stranger = AuthorizationRequest {
        client: ClientId::parse("http://localhost:5173/stranger.json").unwrap(),
        ..a_request()
    };
    let elsewhere = AuthorizationRequest {
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..a_request()
    };

    let unknown = w
        .log_in
        .execute(&w.alice.email, "alice-password", &stranger, now())
        .await;
    let unregistered = w
        .log_in
        .execute(&w.alice.email, "alice-password", &elsewhere, now())
        .await;

    assert!(
        matches!(unknown, Err(AuthError::UnknownClient)),
        "{unknown:?}"
    );
    assert!(
        matches!(unregistered, Err(AuthError::UnregisteredRedirect)),
        "{unregistered:?}"
    );
    assert_eq!(w.hasher.verifications(), 0);
    assert!(w.codes.issued().is_empty());
}

#[tokio::test]
async fn an_unknown_email_costs_the_same_password_check_as_a_wrong_password() {
    let w = world().await;

    w.log_in
        .execute("nobody@idp.test", "alice-password", &a_request(), now())
        .await
        .unwrap();
    let unknown = w.hasher.verifications();
    w.log_in
        .execute(&w.alice.email, "not-it", &a_request(), now())
        .await
        .unwrap();

    assert_eq!((unknown, w.hasher.verifications()), (1, 2));
}

#[tokio::test]
async fn an_address_mailed_to_its_limit_is_not_mailed_again_on_signing_in() {
    let w = world().await;
    let bob = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;
    for _ in 0..domain::auth::RESEND_LIMIT {
        w.resend.execute(bob.id, now()).await.unwrap();
    }
    let mailed = w.mailer.sent().len();

    let outcome = w
        .log_in
        .execute(&bob.email, "bob-password", &a_request(), now())
        .await
        .unwrap();

    assert!(
        matches!(outcome, LoginOutcome::Unverified { .. }),
        "{outcome:?}"
    );
    assert_eq!(w.mailer.sent().len(), mailed);
    assert_eq!(w.signup_codes.issued().len(), mailed);
}

#[tokio::test]
async fn an_address_signs_in_whatever_its_case() {
    let w = world().await;

    let outcome = w
        .log_in
        .execute(" ALICE@idp.test", "alice-password", &a_request(), now())
        .await
        .unwrap();

    assert!(
        matches!(outcome, LoginOutcome::SignedIn { .. }),
        "{outcome:?}"
    );
}
