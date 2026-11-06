use domain::auth::testing::{CLIENT_ID, a_request, another_web_app};
use domain::auth::{ClientId, RefreshTokens, RevokedReason, Sessions};

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn revoking_a_web_apps_refresh_token_ends_its_session_alone() {
    let w = world().await;
    let browser = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let under = async |client: &ClientId| {
        w.sessions
            .open_under(browser, client, now())
            .await
            .unwrap()
            .unwrap()
            .id
    };
    let session = under(&a_request().client).await;
    let beside = under(&another_web_app().id).await;
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
    for kept in [browser, beside] {
        assert_eq!(
            w.sessions.reason(kept),
            None,
            "the browser session and its other web app stay"
        );
    }
}

#[tokio::test]
async fn an_unknown_token_or_another_clients_ends_nothing_and_is_answered_alike() {
    let w = world().await;
    let session = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
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
