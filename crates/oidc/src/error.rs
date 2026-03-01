use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct OidcErrorBody {
    pub error: String,
    pub error_description: String,
}

/// OIDC/OAuth2 error response per RFC 6749 §5.2.
#[derive(Debug)]
pub struct OidcError {
    pub status: StatusCode,
    pub error: &'static str,
    pub error_description: String,
}

impl OidcError {
    pub fn invalid_request(desc: impl Into<String>) -> Self {
        let desc = desc.into();
        tracing::warn!(error = "invalid_request", description = %desc);
        Self { status: StatusCode::BAD_REQUEST, error: "invalid_request", error_description: desc }
    }

    pub fn invalid_client(desc: impl Into<String>) -> Self {
        let desc = desc.into();
        tracing::warn!(error = "invalid_client", description = %desc);
        Self { status: StatusCode::UNAUTHORIZED, error: "invalid_client", error_description: desc }
    }

    pub fn invalid_grant(desc: impl Into<String>) -> Self {
        let desc = desc.into();
        tracing::warn!(error = "invalid_grant", description = %desc);
        Self { status: StatusCode::BAD_REQUEST, error: "invalid_grant", error_description: desc }
    }

    pub fn unauthorized_client(desc: impl Into<String>) -> Self {
        let desc = desc.into();
        tracing::warn!(error = "unauthorized_client", description = %desc);
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized_client",
            error_description: desc,
        }
    }

    pub fn access_denied(desc: impl Into<String>) -> Self {
        let desc = desc.into();
        tracing::warn!(error = "access_denied", description = %desc);
        Self { status: StatusCode::FORBIDDEN, error: "access_denied", error_description: desc }
    }

    pub fn server_error(desc: impl Into<String>) -> Self {
        let desc = desc.into();
        tracing::error!(error = "server_error", description = %desc);
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            error_description: desc,
        }
    }
}

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        let body = OidcErrorBody {
            error: self.error.to_owned(),
            error_description: self.error_description,
        };
        (self.status, Json(body)).into_response()
    }
}
