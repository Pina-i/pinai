//! Dev-only smoke endpoint. Mounted only when `IDP_ENV=development`.

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use tracing::{info, instrument};

use crate::{AppState, OidcError};

#[derive(Debug, Deserialize)]
pub struct SendTestEmailRequest {
    pub to: String,
    #[serde(default = "default_display_name")]
    pub display_name: String,
}

fn default_display_name() -> String {
    "Tester".to_string()
}

/// `POST /dev/send-test-email` — fires a hardcoded signup OTP email at `to`
/// so a developer can verify the SMTP path / Mailpit pickup in one click.
#[instrument(skip_all, fields(to = %body.to))]
pub async fn post_send_test_email(
    State(state): State<AppState>,
    Json(body): Json<SendTestEmailRequest>,
) -> Result<StatusCode, OidcError> {
    state
        .email
        .send_signup_otp(&body.to, &body.display_name, "123456")
        .await
        .map_err(|e| OidcError::server_error(format!("email send failed: {e}")))?;
    info!("dev test email dispatched");
    Ok(StatusCode::NO_CONTENT)
}
