use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use domain::ValidationError;
use serde_json::{Map, Value};

/// The one error type handlers return. Each context's `impl From<XError> for ApiError`
/// is its status-code policy; the body is `{ "error", "error_description", ..extra }`.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    description: String,
    source: Option<anyhow::Error>,
    extra: Map<String, Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            code,
            description: description.into(),
            source: None,
            extra: Map::new(),
        }
    }

    pub fn bad_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn not_found(description: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", description)
    }

    /// A 401 for a missing or unusable bearer token — the code the IdP answered before
    /// `invalid_token` (RFC 6750); it changes with the auth context.
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    /// A 500 whose cause goes to the logs, never to the client.
    pub fn internal(source: anyhow::Error) -> Self {
        Self {
            source: Some(source),
            ..Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            )
        }
    }

    /// A 502 for another instance that failed to answer; the cause goes to the logs.
    pub fn upstream(source: anyhow::Error) -> Self {
        Self {
            source: Some(source),
            ..Self::new(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                "the account's instance did not answer",
            )
        }
    }

    /// An extra top-level body field, e.g. the winning commit of a 409.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.extra.insert(key.to_owned(), value.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Logged once, here, where the error is handled.
        match &self.source {
            Some(source) if self.status.is_server_error() => {
                tracing::error!(error = ?source, "request failed")
            }
            _ => tracing::debug!(status = %self.status, code = self.code, "request refused"),
        }
        let mut body = self.extra;
        body.insert("error".into(), self.code.into());
        body.insert("error_description".into(), self.description.into());
        (self.status, Json(body)).into_response()
    }
}

impl From<ValidationError> for ApiError {
    fn from(error: ValidationError) -> Self {
        Self::bad_request(error.to_string())
    }
}

#[cfg(test)]
mod tests;
