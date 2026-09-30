use domain::auth::testing::{CHALLENGE, REDIRECT_URI, a_request};

use crate::auth::world::{now, world};

use super::*;

fn command() -> AuthorizeCommand {
    let request = a_request();
    AuthorizeCommand {
        response_type: "code".to_owned(),
        client_id: request.client.as_str().to_owned(),
        redirect_uri: REDIRECT_URI.to_owned(),
        scope: request.scope,
        state: request.state,
        code_challenge: CHALLENGE.to_owned(),
        code_challenge_method: "S256".to_owned(),
        nonce: request.nonce,
    }
}

#[tokio::test]
async fn a_browser_signed_in_already_is_handed_a_code_at_once() {
    let w = world().await;

    let authorized = w
        .authorize
        .execute(command(), Some(w.alice.id), now())
        .await
        .unwrap();

    let issued = w.codes.issued();
    assert_eq!(
        authorized,
        Authorized::Code {
            request: a_request(),
            code: issued[0].0.clone(),
        }
    );
    assert_eq!(issued[0].1, Grant::answering(w.alice.id, &a_request()));
}

#[tokio::test]
async fn a_browser_without_a_session_is_sent_to_sign_in() {
    let w = world().await;

    let anonymous = w.authorize.execute(command(), None, now()).await.unwrap();
    let vanished = w
        .authorize
        .execute(command(), Some(UserId::generate()), now())
        .await
        .unwrap();

    assert_eq!(anonymous, Authorized::SignIn(a_request()));
    assert_eq!(vanished, Authorized::SignIn(a_request()));
    assert!(w.codes.issued().is_empty());
}

#[tokio::test]
async fn a_request_is_refused_for_another_flow_an_unknown_client_or_an_unregistered_redirect() {
    let w = world().await;
    let refused = async |command: AuthorizeCommand| {
        w.authorize
            .execute(command, Some(w.alice.id), now())
            .await
            .unwrap_err()
    };

    let token = refused(AuthorizeCommand {
        response_type: "token".to_owned(),
        ..command()
    })
    .await;
    let plain = refused(AuthorizeCommand {
        code_challenge_method: "plain".to_owned(),
        ..command()
    })
    .await;
    let stranger = refused(AuthorizeCommand {
        client_id: "stranger".to_owned(),
        ..command()
    })
    .await;
    let elsewhere = refused(AuthorizeCommand {
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..command()
    })
    .await;

    assert!(
        matches!(token, AuthError::UnsupportedResponseType),
        "{token:?}"
    );
    assert!(matches!(plain, AuthError::BadChallengeMethod), "{plain:?}");
    assert!(matches!(stranger, AuthError::UnknownClient), "{stranger:?}");
    assert!(
        matches!(elsewhere, AuthError::UnregisteredRedirect),
        "{elsewhere:?}"
    );
    assert!(w.codes.issued().is_empty());
}

#[tokio::test]
async fn the_client_and_its_redirect_are_checked_before_the_flow_so_an_error_can_go_back_to_it() {
    let w = world().await;

    let stranger = w
        .authorize
        .execute(
            AuthorizeCommand {
                client_id: "stranger".to_owned(),
                response_type: "token".to_owned(),
                ..command()
            },
            None,
            now(),
        )
        .await;
    let elsewhere = w
        .authorize
        .execute(
            AuthorizeCommand {
                redirect_uri: "https://evil.test/callback".to_owned(),
                code_challenge_method: "plain".to_owned(),
                ..command()
            },
            None,
            now(),
        )
        .await;

    assert!(
        matches!(stranger, Err(AuthError::UnknownClient)),
        "{stranger:?}"
    );
    assert!(
        matches!(elsewhere, Err(AuthError::UnregisteredRedirect)),
        "{elsewhere:?}"
    );
}
