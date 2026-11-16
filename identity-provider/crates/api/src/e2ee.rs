//! What the history and key-directory routes share: their base64 fields, and the refusals both
//! give about the account's history key and starting it over.

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::ValidationError;
use domain::e2ee::StartOverRefusal;
use time::format_description::well_known::Rfc3339;

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

/// Setting or holding the history key, or committing a device into a group by itself, from a
/// session that hasn't named its device.
pub(crate) fn device_required() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "device_required",
        "Name this session's device first",
    )
}

/// What only a device approved under the current generation does: revoke an approved device,
/// read or cancel another device's start over, turn the second factor on, save to or clear the
/// history backup, sign the other devices out, commit itself into a group.
pub(crate) fn approval_required() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "approval_required",
        "This takes a device approved under the current history key",
    )
}

pub(crate) fn start_over_refused(refusal: StartOverRefusal) -> ApiError {
    match refusal {
        StartOverRefusal::NoHistoryKey => ApiError::new(
            StatusCode::CONFLICT,
            "no_history_key",
            "The account has no history key to start over from",
        ),
        StartOverRefusal::AlreadyApproved => ApiError::new(
            StatusCode::CONFLICT,
            "already_approved",
            "An approved device replaces the history key itself",
        ),
        StartOverRefusal::Pending => ApiError::new(
            StatusCode::CONFLICT,
            "start_over_pending",
            "Another device of the account is starting over",
        ),
        StartOverRefusal::TooMany => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many start over requests in the last day",
        ),
        StartOverRefusal::NotFound => ApiError::not_found("Start over request not found"),
        StartOverRefusal::Ended => ApiError::new(
            StatusCode::GONE,
            "start_over_ended",
            "The start over request has ended",
        ),
        StartOverRefusal::Required => ApiError::new(
            StatusCode::FORBIDDEN,
            "start_over_required",
            "A device not approved starts over through a request",
        ),
        StartOverRefusal::NotReady { ready_at } => {
            let refused = ApiError::new(
                StatusCode::FORBIDDEN,
                "start_over_not_ready",
                "No approved device may be used for a week first",
            );
            match ready_at.format(&Rfc3339) {
                Ok(at) => refused.with("ready_at", at),
                Err(e) => ApiError::internal(e.into()),
            }
        }
    }
}
