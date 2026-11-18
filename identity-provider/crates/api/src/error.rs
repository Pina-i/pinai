use axum::Json;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use domain::ValidationError;
use serde_json::{Map, Value};
use tracing::Level;

/// The one error type handlers return. Each context's `impl From<XError> for ApiError`
/// is its status-code policy; the body is `{ "error", "error_description", ..extra }`.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    description: String,
    /// The cause, for the log only, and the level it is logged at.
    source: Option<(anyhow::Error, Level)>,
    extra: Map<String, Value>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            code,
            description: description.into(),
            source: None,
            extra: Map::new(),
            headers: Vec::new(),
        }
    }

    pub fn bad_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn not_found(description: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", description)
    }

    /// A 401 for a client this instance does not know — RFC 6749 § 5.2.
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    /// A 401 for a bearer token that is missing (`presented: false`) or unusable, with the
    /// challenge RFC 6750 § 3 asks for.
    pub fn invalid_token(description: impl Into<String>, presented: bool) -> Self {
        let challenge = if presented {
            r#"Bearer error="invalid_token""#
        } else {
            "Bearer"
        };
        Self::new(StatusCode::UNAUTHORIZED, "invalid_token", description).with_header(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(challenge),
        )
    }

    /// A 401 for a password typed longer than `max_age` ago, with the challenge RFC 9470 § 3
    /// asks for: the client has the password typed again, then asks again.
    pub fn insufficient_user_authentication(max_age: time::Duration) -> Self {
        let challenge = format!(
            r#"Bearer error="insufficient_user_authentication", max_age="{}""#,
            max_age.whole_seconds()
        );
        Self::new(
            StatusCode::UNAUTHORIZED,
            "insufficient_user_authentication",
            "Type your password again to do this",
        )
        .with_header(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&challenge).expect("an ASCII challenge"),
        )
    }

    /// A 429 for a requester past its rate limit.
    pub fn rate_limited() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "rate limit exceeded",
        )
    }

    /// A 403 for an instance the peer request policy keeps this one from asking. The reason may
    /// name what the instance's address resolves to, so it goes to the log only.
    pub fn peer_not_allowed(reason: String) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "That address can't be reached from this instance",
        )
        .refused_because(reason)
    }

    /// A 500 whose cause goes to the logs at error level, never to the client: this instance
    /// failed.
    pub fn internal(source: anyhow::Error) -> Self {
        Self {
            source: Some((source, Level::ERROR)),
            ..Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            )
        }
    }

    /// A 502 for another instance that failed to answer. Its cause goes to the logs at warn
    /// level: the peer failed, not this instance, and anyone can name a dead one.
    pub fn upstream(source: anyhow::Error) -> Self {
        Self {
            source: Some((source, Level::WARN)),
            ..Self::bad_gateway()
        }
    }

    /// A 502, as [`Self::upstream`], for an instance the peer request policy keeps this one from
    /// asking, where the caller is told no more than that it didn't answer; the reason is logged
    /// as [`Self::peer_not_allowed`]'s.
    pub fn upstream_not_allowed(reason: String) -> Self {
        Self::bad_gateway().refused_because(reason)
    }

    fn bad_gateway() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "bad_gateway",
            "the account's instance did not answer",
        )
    }

    /// The reason for a refusal, for the log at debug level only: it may name what the
    /// requester must not learn, and anyone can make it.
    pub fn refused_because(mut self, reason: impl Into<String>) -> Self {
        self.source = Some((anyhow::anyhow!(reason.into()), Level::DEBUG));
        self
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
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
            Some((source, level)) if *level == Level::ERROR => {
                tracing::error!(error = ?source, "request failed")
            }
            Some((source, level)) if *level == Level::WARN => {
                tracing::warn!(status = %self.status, error = %format_args!("{source:#}"), "a peer failed to answer")
            }
            Some((source, _)) => {
                tracing::debug!(status = %self.status, code = self.code, error = %source, "request refused")
            }
            None => tracing::debug!(status = %self.status, code = self.code, "request refused"),
        }
        let mut body = self.extra;
        body.insert("error".into(), self.code.into());
        body.insert("error_description".into(), self.description.into());
        let mut response = (self.status, Json(body)).into_response();
        response.headers_mut().extend(self.headers);
        response
    }
}

impl From<ValidationError> for ApiError {
    fn from(error: ValidationError) -> Self {
        Self::bad_request(error.to_string())
    }
}

#[cfg(test)]
mod tests;
