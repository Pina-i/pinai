use domain::auth::testing::{CLIENT_ID, a_request};
use domain::auth::{RefreshTokens, RevokedReason, SessionKind, Sessions};

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn revoking_a_refresh_token_ends_its_session() {
    let w = world().await;
    let session = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now())
        .await
        .unwrap();
    let token = w
        .refresh_tokens
        .start(session, &a_request().client, now())
        .await
        .unwrap();

    w.revoke_token
        .execute(CLIENT_ID, token.as_str(), now())
        .await
        .unwrap();

    assert_eq!(w.sessions.reason(session), Some(RevokedReason::SignOut));
    assert_eq!(w.ended.ended(), vec![session], "its sockets close");
}

#[tokio::test]
async fn an_unknown_token_or_another_clients_ends_nothing_and_is_answered_alike() {
    let w = world().await;
    let session = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now())
        .await
        .unwrap();
    let token = w
        .refresh_tokens
        .start(session, &a_request().client, now())
        .await
        .unwrap();

    let unknown = w.revoke_token.execute(CLIENT_ID, "a-guess", now()).await;
    let by_another = w
        .revoke_token
        .execute(w.desktop.id.as_str(), token.as_str(), now())
        .await;
    let malformed = w
        .revoke_token
        .execute("stranger", token.as_str(), now())
        .await;

    assert!(unknown.is_ok() && by_another.is_ok());
    assert!(
        matches!(malformed, Err(AuthError::UnknownClient)),
        "{malformed:?}"
    );
    assert!(
        w.sessions
            .find(session)
            .await
            .unwrap()
            .unwrap()
            .is_live(now())
    );
}
