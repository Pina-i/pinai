use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn the_health_endpoint_answers_200() {
    let response = router(AppState::default())
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_refusal_carries_its_code_and_description() {
    let response = ApiError::bad_request("Cannot befriend yourself").into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await,
        json!({ "error": "invalid_request", "error_description": "Cannot befriend yourself" })
    );
}

#[tokio::test]
async fn an_internal_error_never_shows_its_cause() {
    let cause = anyhow::anyhow!("connection refused: 10.0.0.4:5432");

    let response = ApiError::internal(cause).into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        json_body(response).await,
        json!({ "error": "server_error", "error_description": "internal error" })
    );
}

#[tokio::test]
async fn extra_fields_sit_beside_the_error() {
    let response = ApiError::new(StatusCode::CONFLICT, "conflict", "Epoch already taken")
        .with("winning_commit", json!({ "epoch": 4 }))
        .into_response();

    assert_eq!(
        json_body(response).await["winning_commit"],
        json!({ "epoch": 4 })
    );
}
