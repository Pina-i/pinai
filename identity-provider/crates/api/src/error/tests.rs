use super::*;
use http_body_util::BodyExt;
use serde_json::json;

async fn json_body(response: Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
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

#[tokio::test]
async fn a_validation_error_is_a_400_naming_the_field() {
    let response =
        ApiError::from(ValidationError::new("handle", "3–32 characters")).into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await,
        json!({ "error": "invalid_request", "error_description": "handle: 3–32 characters" })
    );
}

#[tokio::test]
async fn a_peer_that_failed_to_answer_is_a_bad_gateway_without_its_cause() {
    let cause = anyhow::anyhow!("peer returned 500: {{\"detail\":\"db password hunter2\"}}");

    let response = ApiError::upstream(cause).into_response();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(response).await,
        json!({ "error": "bad_gateway", "error_description": "the account's instance did not answer" })
    );
}
