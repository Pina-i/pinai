use domain::UserId;
use domain::auth::testing::web_client;
use domain::auth::{RevokedReason, SessionKind, Sessions};
use domain::identity::Bearer;

use crate::auth::world::{now, world};

#[tokio::test]
async fn every_other_session_of_the_account_ends_and_this_one_stays() {
    let w = world().await;
    let open =
        async |user: UserId, kind: SessionKind| w.sessions.open(user, &kind, now()).await.unwrap();
    let current = open(w.alice.id, SessionKind::Browser).await;
    let other_browser = open(w.alice.id, SessionKind::Browser).await;
    let desktop = open(w.alice.id, SessionKind::App(web_client().id)).await;
    let bobs = open(UserId::generate(), SessionKind::Browser).await;

    let ended = w
        .sign_out_others
        .execute(
            Bearer {
                user: w.alice.id,
                session: current,
                authenticated_at: now(),
            },
            now(),
        )
        .await
        .unwrap();

    assert_eq!(ended, 2);
    for gone in [other_browser, desktop] {
        assert_eq!(
            w.sessions.reason(gone),
            Some(RevokedReason::SignedOutElsewhere)
        );
    }
    assert_eq!(
        w.ended.ended(),
        vec![other_browser, desktop],
        "their sockets close"
    );
    for kept in [current, bobs] {
        assert!(w.sessions.find(kept).await.unwrap().unwrap().is_live(now()));
    }
}
