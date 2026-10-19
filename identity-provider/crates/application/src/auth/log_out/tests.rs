use domain::auth::SessionKind;
use domain::auth::Sessions;
use domain::auth::testing::{CLIENT_ID, POST_LOGOUT_URI};

use crate::auth::world::{now, world};

#[tokio::test]
async fn after_signing_out_a_browser_goes_back_only_where_its_client_listed() {
    let w = world().await;

    assert_eq!(
        w.log_out
            .execute(None, Some(CLIENT_ID), Some(POST_LOGOUT_URI), now())
            .await
            .unwrap(),
        Some(POST_LOGOUT_URI.to_owned())
    );
    for elsewhere in [
        "http://localhost:5173",
        "http://localhost:5173/home",
        "https://evil.test/",
        "javascript:alert(1)",
    ] {
        assert_eq!(
            w.log_out
                .execute(None, Some(CLIENT_ID), Some(elsewhere), now())
                .await
                .unwrap(),
            None,
            "{elsewhere}"
        );
    }
}

#[tokio::test]
async fn a_logout_naming_no_known_client_stays_here() {
    let w = world().await;

    for client in [
        None,
        Some("web-client"),
        Some("http://localhost:5173/nobody.json"),
    ] {
        assert_eq!(
            w.log_out
                .execute(None, client, Some(POST_LOGOUT_URI), now())
                .await
                .unwrap(),
            None,
            "{client:?}"
        );
    }
    assert_eq!(
        w.log_out
            .execute(None, Some(CLIENT_ID), None, now())
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn signing_out_ends_the_browsers_session_and_what_hangs_on_it_once() {
    let w = world().await;
    let session = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now())
        .await
        .unwrap();

    w.log_out
        .execute(Some(session), None, None, now())
        .await
        .unwrap();
    w.log_out
        .execute(Some(session), None, None, now())
        .await
        .unwrap();

    assert_eq!(
        w.sessions.reason(session),
        Some(domain::auth::RevokedReason::SignOut)
    );
    assert_eq!(w.ended.ended(), vec![session], "its sockets closed once");
}
