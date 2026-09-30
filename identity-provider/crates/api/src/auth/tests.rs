use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::UserId;

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
