use domain::UserId;
use domain::auth::testing::{REDIRECT_URI, VERIFIER, a_request};
use domain::auth::{AuthorizationCodes, Grant};
use time::Duration;

use crate::auth::world::{World, now, world};

use super::*;

async fn a_code(w: &World) -> AuthorizationCode {
    w.codes
        .issue(
            &Grant::answering(w.alice.id, &a_request()),
            now() + Duration::minutes(10),
        )
        .await
        .unwrap()
}

fn command(code: &AuthorizationCode) -> TokenCommand {
    TokenCommand {
        grant_type: "authorization_code".to_owned(),
        code: code.as_str().to_owned(),
        redirect_uri: REDIRECT_URI.to_owned(),
        client_id: "web-client".to_owned(),
        code_verifier: VERIFIER.to_owned(),
    }
}

#[tokio::test]
async fn a_code_is_exchanged_once_for_the_accounts_tokens() {
    let w = world().await;
    let code = a_code(&w).await;

    let tokens = w.exchange.execute(command(&code), now()).await.unwrap();
    let again = w.exchange.execute(command(&code), now()).await;

    assert_eq!(
        tokens,
        Tokens {
            access_token: format!("access:{}:web-client", w.alice.id),
            id_token: format!("id:{}:web-client:{}:the-nonce", w.alice.id, w.alice.email),
            expires_in: Duration::hours(1),
        }
    );
    assert!(matches!(again, Err(AuthError::CodeUnusable)), "{again:?}");
}

#[tokio::test]
async fn an_exchange_is_refused_for_another_grant_client_or_redirect_and_a_wrong_verifier() {
    let w = world().await;
    let refused = async |change: fn(TokenCommand) -> TokenCommand| {
        let code = a_code(&w).await;
        w.exchange
            .execute(change(command(&code)), now())
            .await
            .unwrap_err()
    };

    let grant = refused(|c| TokenCommand {
        grant_type: "password".to_owned(),
        ..c
    })
    .await;
    let stranger = refused(|c| TokenCommand {
        client_id: "stranger".to_owned(),
        ..c
    })
    .await;
    let elsewhere = refused(|c| TokenCommand {
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..c
    })
    .await;
    let guessed = refused(|c| TokenCommand {
        code_verifier: "a-guess".to_owned(),
        ..c
    })
    .await;
    let unknown = refused(|c| TokenCommand {
        code: "no-such-code".to_owned(),
        ..c
    })
    .await;

    assert!(
        matches!(grant, AuthError::UnsupportedGrantType),
        "{grant:?}"
    );
    assert!(matches!(stranger, AuthError::UnknownClient), "{stranger:?}");
    assert!(
        matches!(elsewhere, AuthError::RedirectMismatch),
        "{elsewhere:?}"
    );
    assert!(
        matches!(guessed, AuthError::VerifierMismatch),
        "{guessed:?}"
    );
    assert!(matches!(unknown, AuthError::CodeUnusable), "{unknown:?}");
}

#[tokio::test]
async fn a_refused_verifier_still_spends_the_code() {
    let w = world().await;
    let code = a_code(&w).await;

    let guessed = w
        .exchange
        .execute(
            TokenCommand {
                code_verifier: "a-guess".to_owned(),
                ..command(&code)
            },
            now(),
        )
        .await;
    let after = w.exchange.execute(command(&code), now()).await;

    assert!(matches!(guessed, Err(AuthError::VerifierMismatch)));
    assert!(matches!(after, Err(AuthError::CodeUnusable)), "{after:?}");
}

#[tokio::test]
async fn a_code_whose_account_is_gone_is_unusable() {
    let w = world().await;
    let code = w
        .codes
        .issue(
            &Grant::answering(UserId::generate(), &a_request()),
            now() + Duration::minutes(10),
        )
        .await
        .unwrap();

    let refused = w.exchange.execute(command(&code), now()).await;

    assert!(
        matches!(refused, Err(AuthError::CodeUnusable)),
        "{refused:?}"
    );
}
