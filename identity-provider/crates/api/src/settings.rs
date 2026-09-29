//! `PATCH /api/settings` — see identity-provider/specs/01-identity-federation.md § 1.6.

use std::sync::Arc;

use application::settings::UpdateSettings;
use axum::Json;
use axum::extract::State;
use domain::settings::{SettingsError, SettingsPatch};
use serde_json::Value;

use crate::ApiError;
use crate::auth::Authenticated;

pub async fn update_settings(
    State(update): State<Arc<UpdateSettings>>,
    Authenticated(user): Authenticated,
    Json(change): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let patch = SettingsPatch::parse(change).map_err(|e| ApiError::bad_request(e.reason))?;
    let merged = update.execute(user, patch).await?;
    tracing::info!(user_id = %user, "settings updated");
    Ok(Json(merged.as_value().clone()))
}

impl From<SettingsError> for ApiError {
    fn from(error: SettingsError) -> Self {
        match error {
            SettingsError::TooLarge => ApiError::bad_request("settings are too large"),
            SettingsError::Unexpected(e) => ApiError::internal(e),
        }
    }
}
