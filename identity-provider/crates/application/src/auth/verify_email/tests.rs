use domain::auth::testing::a_request;
use domain::auth::{
    AuthorizationRequest, ClientId, ClientSignIn, Grant, SIGNUP_CODE_TTL, SignInAccount,
};

use crate::auth::world::{World, now, world};

use super::*;

/// Bob, registered: his code is the first one mailed.
async fn bob(w: &World) -> (UserId, String) {
    let registered = w
        .register
        .execute(
            crate::auth::RegisterCommand {
                display_name: "Bob".to_owned(),
                email: "bob@idp.test".to_owned(),
                password: "bob-password".to_owned(),
            },
            Some(&a_request()),
            now(),
        )
        .await
        .unwrap();
    let code = w.signup_codes.issued()[0].1.as_str().to_owned();
    (registered.user, code)
}

#[tokio::test]
async fn the_mailed_code_confirms_the_address_and_signs_in() {
    let w = world().await;
    let (bob, code) = bob(&w).await;

    let verified = w
        .verify
        .execute(bob, &code, &a_request(), None, now())
        .await
        .unwrap();

    let issued = w.codes.issued();
    assert_eq!(
        verified,
        Verification::SignedIn {
            user: bob,
            session: w.sessions.all()[0].id,
            code: issued[0].0.clone(),
        }
    );
    assert_eq!(
        issued[0].1,
        Grant::answering(bob, w.sessions.all()[0].id, &a_request())
    );
    let account: SignInAccount = w.accounts.by_id(bob).await.unwrap().unwrap();
    assert!(account.email_verified);
    assert_eq!(
        w.sign_ins.remembered(),
        vec![ClientSignIn::of(bob, &a_request())]
    );
}

#[tokio::test]
async fn a_wrong_code_counts_down_a_malformed_one_is_not_tried_and_an_old_one_is_gone() {
    let w = world().await;
    let (bob, code) = bob(&w).await;
    let wrong = if code == "999999" { "111111" } else { "999999" };

    let malformed = w
        .verify
        .execute(bob, "12 34", &a_request(), None, now())
        .await
        .unwrap();
    let guessed = w
        .verify
        .execute(bob, wrong, &a_request(), None, now())
        .await
        .unwrap();
    let late = w
        .verify
        .execute(bob, &code, &a_request(), None, now() + SIGNUP_CODE_TTL)
        .await
        .unwrap();

    assert_eq!(malformed, Verification::Malformed);
    assert_eq!(
        guessed,
        Verification::Refused(CodeAttempt::Wrong { left: 4 })
    );
    assert_eq!(late, Verification::Refused(CodeAttempt::NoCode));
}

#[tokio::test]
async fn a_confirmed_account_is_sent_to_sign_in_and_an_unknown_one_refused() {
    let w = world().await;

    let confirmed = w
        .verify
        .execute(w.alice.id, "123456", &a_request(), None, now())
        .await
        .unwrap();
    let unknown = w
        .verify
        .execute(UserId::generate(), "123456", &a_request(), None, now())
        .await;

    assert_eq!(confirmed, Verification::AlreadyConfirmed);
    assert!(
        matches!(unknown, Err(AuthError::UnknownUser)),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn a_request_not_from_a_client_is_refused_before_the_code_is_tried() {
    let w = world().await;
    let (bob, code) = bob(&w).await;
    let stranger = AuthorizationRequest {
        client: ClientId::parse("http://localhost:5173/stranger.json").unwrap(),
        ..a_request()
    };
    let elsewhere = AuthorizationRequest {
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..a_request()
    };

    let unknown = w.verify.execute(bob, &code, &stranger, None, now()).await;
    let unregistered = w.verify.execute(bob, &code, &elsewhere, None, now()).await;
    let fine = w
        .verify
        .execute(bob, &code, &a_request(), None, now())
        .await
        .unwrap();

    assert!(
        matches!(unknown, Err(AuthError::UnknownClient)),
        "{unknown:?}"
    );
    assert!(
        matches!(unregistered, Err(AuthError::UnregisteredRedirect)),
        "{unregistered:?}"
    );
    assert!(matches!(fine, Verification::SignedIn { .. }), "{fine:?}");
}
