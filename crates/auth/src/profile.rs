//! Profile editing — `PATCH /api/profile`.
//!
//! Lets the authenticated user update their human-editable profile fields:
//! display_name, pronouns, bio. Avatar has its own dedicated endpoint
//! (see [`crate::avatar`]).
//!
//! ### API contract
//!
//! All three fields are sent on every request — the frontend always submits
//! the full draft state. Server semantics:
//!
//! - `display_name` — required, trimmed, 1‥=50 chars.
//! - `pronouns` — `null` | `"he"` | `"she"` | `"non-binary"`. Anything else
//!   produces a 400.
//! - `bio` — empty string clears, otherwise ≤ 190 chars.
//!
//! On success we trigger [`propagate_profile_update`] so the new
//! display_name flows to local + remote friends. (`pronouns` and `bio` are
//! not federated yet — there's no AP standard field for either, and we'd
//! need a parallel Mastodon-compatible extension if cross-instance
//! visibility is desired later.)

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;

use idp_db::repos::users;
use idp_federation::auth::require_auth;
use idp_federation::profile::propagate_profile_update;

use crate::userinfo::UserinfoResponse;
use crate::{AppState, OidcError};

const DISPLAY_NAME_MAX: usize = 50;
const BIO_MAX: usize = 190;
const ALLOWED_PRONOUNS: &[&str] = &["he", "she", "non-binary"];

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    /// `None` (or JSON null) clears; `Some(value)` must be one of
    /// `ALLOWED_PRONOUNS`.
    #[serde(default)]
    pub pronouns: Option<String>,
    /// Empty string clears.
    pub bio: Option<String>,
}

/// PATCH /api/profile
#[tracing::instrument(skip_all)]
pub async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateProfileRequest>,
) -> Result<Json<UserinfoResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    // ── display_name ────────────────────────────────────────────────────
    let display_name = body
        .display_name
        .as_deref()
        .map(str::trim)
        .ok_or_else(|| OidcError::invalid_request("display_name is required"))?;
    if display_name.is_empty() {
        return Err(OidcError::invalid_request("display_name cannot be blank"));
    }
    if display_name.chars().count() > DISPLAY_NAME_MAX {
        return Err(OidcError::invalid_request(format!(
            "display_name must be ≤ {DISPLAY_NAME_MAX} characters"
        )));
    }

    // ── pronouns ────────────────────────────────────────────────────────
    let pronouns: Option<&str> = match body.pronouns.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) => {
            if !ALLOWED_PRONOUNS.contains(&value) {
                return Err(OidcError::invalid_request(format!(
                    "pronouns must be one of: {}",
                    ALLOWED_PRONOUNS.join(", ")
                )));
            }
            Some(value)
        }
    };

    // ── bio ─────────────────────────────────────────────────────────────
    let bio: Option<&str> = match body.bio.as_deref() {
        None => None,
        Some("") => None,
        Some(value) => {
            if value.chars().count() > BIO_MAX {
                return Err(OidcError::invalid_request(format!(
                    "bio must be ≤ {BIO_MAX} characters"
                )));
            }
            Some(value)
        }
    };

    let updated = users::update_profile(&state.pool, user_id, Some(display_name), pronouns, bio)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user_id, "profile updated");

    // Fan the new display_name out to local + remote friends. Spawned so the
    // HTTP response isn't blocked on remote inbox POSTs.
    let state_clone = state.clone();
    tokio::spawn(async move {
        propagate_profile_update(&state_clone, user_id).await;
    });

    let address = updated.federated_address(&state.config.domain);
    let actor_uri = updated
        .actor_uri
        .clone()
        .unwrap_or_else(|| format!("{}/users/{}", state.config.issuer(), updated.username));
    Ok(Json(UserinfoResponse {
        sub: updated.id.to_string(),
        email: updated.email,
        email_verified: updated.email_verified_at.is_some(),
        totp_enabled: updated.totp_enabled,
        preferred_username: updated.username,
        display_name: updated.display_name,
        address,
        actor_uri,
        avatar_url: updated.avatar_url,
        pronouns: updated.pronouns,
        bio: updated.bio,
    }))
}
