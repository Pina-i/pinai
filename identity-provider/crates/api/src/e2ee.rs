//! What the history and key-directory routes share: their base64 fields, and the refusals both
//! give about the account's history key.

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::ValidationError;

use crate::ApiError;

/// The standard base64 in `field`, parsed into its domain type.
pub(crate) fn base64_field<T>(
    field: &'static str,
    raw: &str,
    parse: impl FnOnce(&[u8]) -> Result<T, ValidationError>,
) -> Result<T, ValidationError> {
    let bytes = B64
        .decode(raw)
        .map_err(|_| ValidationError::new(field, "must be base64"))?;
    parse(&bytes)
}

/// An upload or a report naming a generation the account's key is no longer — or not yet — at:
/// the device reads the key again.
pub(crate) fn stale_history_key() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "stale_history_key",
        "Not the account's current history key",
    )
}

/// Setting or holding the history key from a session that hasn't named its device.
pub(crate) fn device_required() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "device_required",
        "Name this session's device first",
    )
}
