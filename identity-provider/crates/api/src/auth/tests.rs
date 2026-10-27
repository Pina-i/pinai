use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::UserId;
use domain::auth::testing::{SignInSeeds, signed_up};
use time::{Duration, OffsetDateTime};

use crate::testing::TestApp;

#[tokio::test]
async fn a_missing_or_bad_bearer_token_is_challenged_as_rfc_6750_says() {
    let app = TestApp::with([], []);
    let with = |token: &str| {
        Request::builder()
            .method(Method::GET)
            .uri("/api/friends")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let without = Request::builder()
        .method(Method::GET)
        .uri("/api/friends")
        .body(Body::empty())
        .unwrap();

    let missing = app.respond(without).await;
    let forged = app.respond(with("forged")).await;
    let fine = app.respond(with(&app.token(UserId::generate()))).await;

    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        forged.headers()[header::WWW_AUTHENTICATE],
        r#"Bearer error="invalid_token""#
    );
    assert!(!fine.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn a_sensitive_action_takes_a_password_typed_in_the_last_ten_minutes() {
    let app = TestApp::with([], []);
    let alice = signed_up("alice");
    app.sign_in.accounts.sign_up(&alice).await;
    let alice = alice.id;
    let now = OffsetDateTime::now_utc();
    let (stale, fresh) = (
        app.token_signed_in_at(alice, now - Duration::minutes(11)),
        app.token_signed_in_at(alice, now - Duration::minutes(9)),
    );
    let request = |method: Method, uri: String, token: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let sensitive = [
        (
            Method::POST,
            format!("/api/keys/devices/{}/revoke", uuid::Uuid::new_v4()),
        ),
        (Method::POST, "/api/totp/enroll".to_owned()),
        (Method::DELETE, "/api/history/messages".to_owned()),
        (
            Method::POST,
            format!("/api/admin/members/{}/password-reset", uuid::Uuid::new_v4()),
        ),
        // Last: done, it ends the session the stale token is from.
        (Method::DELETE, "/api/sessions?keep=current".to_owned()),
    ];

    let ordinary = app
        .respond(request(Method::GET, "/api/friends".to_owned(), &stale))
        .await;
    assert_eq!(ordinary.status(), StatusCode::OK);
    for (method, uri) in sensitive {
        let refused = app
            .respond(request(method.clone(), uri.clone(), &stale))
            .await;
        let done = app.respond(request(method, uri.clone(), &fresh)).await;

        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(
            refused.headers()[header::WWW_AUTHENTICATE],
            r#"Bearer error="insufficient_user_authentication", max_age="600""#,
            "{uri}"
        );
        assert_ne!(done.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
}
