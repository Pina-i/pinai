//! User settings — `PATCH /api/settings`, read back on `/userinfo`.
//!
//! The account's settings are one JSON document owned by the client. Each
//! top-level key is a section (`appearance`, …); the server checks the shape
//! — an object of objects, within a size cap — and stores it without
//! interpreting a section, so a client that doesn't know a section never
//! drops it. Settings that belong to one device stay on that device.
//!
//! ### API contract
//!
//! - Body: an object of sections, e.g. `{ "appearance": { "family": "lagoon", "motif": "raranga" } }`.
//!   Each section named replaces the stored one whole; the others are kept.
//! - Response: the merged document. The user's other sessions receive it as
//!   a `settings_updated` WebSocket event.

use axum::{extract::State, http::HeaderMap, Json};
use serde_json::Value;
use uuid::Uuid;

use idp_db::repos::user_settings;
use idp_federation::auth::require_auth;
use idp_realtime::{SettingsPayload, WsEvent};

use crate::{AppState, OidcError};

/// Postgres `check_violation` — the table's size cap.
const CHECK_VIOLATION: &str = "23514";

/// PATCH /api/settings
#[tracing::instrument(skip_all)]
pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    validate_sections(&body)?;

    let merged = user_settings::merge_sections(&state.pool, user_id, &body.to_string())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.code().as_deref() == Some(CHECK_VIOLATION) => {
                OidcError::invalid_request("settings are too large")
            }
            _ => OidcError::server_error(e.to_string()),
        })?;
    let merged: Value =
        serde_json::from_str(&merged).map_err(|e| OidcError::server_error(e.to_string()))?;

    state.hub.send_to_user(
        &user_id,
        WsEvent::SettingsUpdated(SettingsPayload {
            settings: merged.clone(),
        }),
    );

    tracing::info!(user_id = %user_id, "settings updated");
    Ok(Json(merged))
}

/// The user's settings document, `{}` when they never saved any.
pub async fn load_settings(state: &AppState, user_id: Uuid) -> Result<Value, OidcError> {
    let stored = user_settings::get(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    match stored {
        Some(text) => {
            serde_json::from_str(&text).map_err(|e| OidcError::server_error(e.to_string()))
        }
        None => Ok(Value::Object(Default::default())),
    }
}

/// A change is a non-empty object whose every value is itself an object: a
/// section is replaced whole, so a scalar there would erase a section's shape.
fn validate_sections(body: &Value) -> Result<(), OidcError> {
    let sections = body
        .as_object()
        .ok_or_else(|| OidcError::invalid_request("settings must be a JSON object"))?;
    if sections.is_empty() {
        return Err(OidcError::invalid_request("settings change is empty"));
    }
    if let Some((name, _)) = sections.iter().find(|(_, section)| !section.is_object()) {
        return Err(OidcError::invalid_request(format!(
            "settings section `{name}` must be an object"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
