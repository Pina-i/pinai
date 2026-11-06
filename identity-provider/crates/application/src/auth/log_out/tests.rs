use domain::auth::testing::{CLIENT_ID, POST_LOGOUT_URI, another_web_app, web_client};
use domain::auth::{RevokedReason, Sessions};

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
async fn signing_out_ends_the_browsers_session_and_its_web_apps_once_never_a_desktops() {
    let w = world().await;
    let session = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let under = async |client: &domain::auth::ClientId| {
        w.sessions
            .open_under(session, client, now())
            .await
            .unwrap()
            .unwrap()
            .id
    };
    let web = under(&web_client().id).await;
    let other = under(&another_web_app().id).await;
    let (_, desktop) = w.on_the_desktop(w.alice.id).await;

    w.log_out
        .execute(Some(session), None, None, now())
        .await
        .unwrap();
    w.log_out
        .execute(Some(session), None, None, now())
        .await
        .unwrap();

    for ended in [session, web, other] {
        assert_eq!(w.sessions.reason(ended), Some(RevokedReason::SignOut));
    }
    let mut told = w.ended.ended();
    told.sort();
    let mut expected = vec![session, web, other];
    expected.sort();
    assert_eq!(told, expected, "their sockets closed once");
    assert_eq!(w.sessions.reason(desktop), None, "the desktop's own stays");
}
