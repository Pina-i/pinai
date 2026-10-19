use domain::SessionId;
use domain::auth::testing::{CLIENT_ID, a_request};
use domain::auth::{
    REFRESH_GRACE, RefreshToken, RefreshTokens, RevokedReason, SESSION_IDLE, SessionKind, Sessions,
};
use time::Duration;

use crate::auth::world::{World, now, world};

use super::*;

/// A browser session of Alice's, and the web client's first refresh token under it.
async fn signed_in(w: &World) -> (SessionId, RefreshToken) {
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
    (session, token)
}

fn command(token: &RefreshToken) -> RefreshCommand {
    RefreshCommand {
        client_id: CLIENT_ID.to_owned(),
        refresh_token: token.as_str().to_owned(),
    }
}

#[tokio::test]
async fn a_refresh_token_is_traded_for_an_access_token_and_its_successor() {
    let w = world().await;
    let (session, first) = signed_in(&w).await;
    let later = now() + Duration::minutes(48);

    let tokens = w.refresh.execute(command(&first), later).await.unwrap();
    let next = w
        .refresh
        .execute(
            command(&tokens.refresh_token),
            later + Duration::minutes(48),
        )
        .await
        .unwrap();

    assert_eq!(
        tokens,
        Tokens {
            access_token: format!("access:{}:{session}:{CLIENT_ID}", w.alice.id),
            refresh_token: RefreshToken::new("refresh-2".to_owned()),
            id_token: None,
            expires_in: Duration::hours(1),
        }
    );
    assert_eq!(
        next.refresh_token,
        RefreshToken::new("refresh-3".to_owned())
    );
    assert_eq!(
        w.sessions
            .find(session)
            .await
            .unwrap()
            .unwrap()
            .last_used_at,
        later + Duration::minutes(48),
        "used: its 90 days start over"
    );
}

#[tokio::test]
async fn a_rotated_token_presented_again_ends_its_session() {
    let w = world().await;
    let (session, first) = signed_in(&w).await;
    let second = w
        .refresh
        .execute(command(&first), now())
        .await
        .unwrap()
        .refresh_token;
    let copied = now() + REFRESH_GRACE + Duration::seconds(1);

    let reused = w.refresh.execute(command(&first), copied).await;
    let after = w.refresh.execute(command(&second), copied).await;

    assert!(
        matches!(reused, Err(AuthError::RefreshUnusable)),
        "{reused:?}"
    );
    assert!(
        matches!(after, Err(AuthError::RefreshUnusable)),
        "the head goes with its session: {after:?}"
    );
    assert_eq!(w.sessions.reason(session), Some(RevokedReason::Reuse));
    assert_eq!(w.ended.ended(), vec![session], "its sockets close");
}

#[tokio::test]
async fn an_answer_lost_on_its_way_is_given_again_within_the_grace() {
    let w = world().await;
    let (session, first) = signed_in(&w).await;
    w.refresh.execute(command(&first), now()).await.unwrap();

    let again = w
        .refresh
        .execute(command(&first), now() + Duration::seconds(20))
        .await
        .unwrap();

    assert_eq!(
        again.refresh_token,
        RefreshToken::new("refresh-3".to_owned())
    );
    assert!(
        w.sessions
            .find(session)
            .await
            .unwrap()
            .unwrap()
            .is_live(now())
    );
    assert!(w.ended.ended().is_empty());
}

#[tokio::test]
async fn a_token_of_an_ended_or_idle_session_is_refused() {
    let w = world().await;
    let (signed_out, first) = signed_in(&w).await;
    w.sessions
        .revoke(signed_out, RevokedReason::SignOut, now())
        .await
        .unwrap();
    let (_, idle) = signed_in(&w).await;

    let ended = w.refresh.execute(command(&first), now()).await;
    let unused = w
        .refresh
        .execute(command(&idle), now() + SESSION_IDLE)
        .await;

    assert!(
        matches!(ended, Err(AuthError::RefreshUnusable)),
        "{ended:?}"
    );
    assert!(
        matches!(unused, Err(AuthError::RefreshUnusable)),
        "{unused:?}"
    );
}

#[tokio::test]
async fn an_unknown_token_or_another_clients_is_refused_and_ends_nothing() {
    let w = world().await;
    let (session, first) = signed_in(&w).await;

    let unknown = w
        .refresh
        .execute(command(&RefreshToken::new("a-guess".to_owned())), now())
        .await;
    let by_another = w
        .refresh
        .execute(
            RefreshCommand {
                client_id: w.desktop.id.as_str().to_owned(),
                ..command(&first)
            },
            now(),
        )
        .await;
    let malformed = w
        .refresh
        .execute(
            RefreshCommand {
                client_id: "stranger".to_owned(),
                ..command(&first)
            },
            now(),
        )
        .await;

    assert!(
        matches!(unknown, Err(AuthError::RefreshUnusable)),
        "{unknown:?}"
    );
    assert!(
        matches!(by_another, Err(AuthError::RefreshUnusable)),
        "{by_another:?}"
    );
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
    assert!(w.refresh.execute(command(&first), now()).await.is_ok());
}
