use serde::Serialize;
use thiserror::Error;

/// HTTP status code as a plain u16 — keeps this crate framework-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const CONFLICT: Self = Self(409);
    pub const UNPROCESSABLE: Self = Self(422);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
}

/// Standard error envelope returned by all Pina-i services.
#[derive(Debug, Clone, Error, Serialize)]
#[error("{message}")]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,    // machine-readable, e.g. "invalid_grant"
    pub message: String, // human-readable
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }
}
