use domain::auth::testing::{CLIENT_ID, POST_LOGOUT_URI};

use crate::auth::world::world;

#[tokio::test]
async fn after_signing_out_a_browser_goes_back_only_where_its_client_listed() {
    let w = world().await;

    assert_eq!(
        w.log_out
            .execute(Some(CLIENT_ID), Some(POST_LOGOUT_URI))
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
                .execute(Some(CLIENT_ID), Some(elsewhere))
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
                .execute(client, Some(POST_LOGOUT_URI))
                .await
                .unwrap(),
            None,
            "{client:?}"
        );
    }
    assert_eq!(
        w.log_out.execute(Some(CLIENT_ID), None).await.unwrap(),
        None
    );
}
