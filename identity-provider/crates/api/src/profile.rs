//! `/userinfo`, the profile and the avatar — see
//! identity-provider/specs/01-identity-federation.md § 1.5.

use std::sync::Arc;

use application::profile::{ClearAvatar, EditProfile, ReadUserinfo, SetAvatar, Userinfo};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use domain::profile::{AvatarImage, ProfileEdit, ProfileError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ApiError;
use crate::auth::Authenticated;
use crate::privacy::Privacy;

#[derive(Debug, Serialize)]
pub struct UserinfoResponse {
    sub: String,
    email: String,
    email_verified: bool,
    totp_enabled: bool,
    preferred_username: String,
    display_name: Option<String>,
    address: String,
    actor_uri: String,
    avatar_url: Option<String>,
    pronouns: Option<&'static str>,
    bio: Option<String>,
    settings: Value,
    privacy: Privacy,
}

impl From<Userinfo> for UserinfoResponse {
    fn from(userinfo: Userinfo) -> Self {
        let profile = userinfo.profile;
        Self {
            sub: profile.id.to_string(),
            email: profile.email,
            email_verified: profile.email_verified,
            totp_enabled: profile.totp_enabled,
            preferred_username: profile.username,
            display_name: profile.display_name,
            address: userinfo.address,
            actor_uri: userinfo.actor_uri,
            avatar_url: profile.avatar_url,
            pronouns: profile.pronouns.map(|p| p.as_str()),
            bio: profile.bio,
            settings: userinfo.settings.as_value().clone(),
            privacy: Privacy {
                contact_policy: userinfo.contact_policy.as_str(),
            },
        }
    }
}

/// `GET /userinfo`.
pub async fn userinfo(
    State(read): State<Arc<ReadUserinfo>>,
    Authenticated(user): Authenticated,
) -> Result<Json<UserinfoResponse>, ApiError> {
    Ok(Json(read.execute(user).await?.into()))
}

/// Every field is sent on every save.
#[derive(Debug, Deserialize)]
pub struct EditRequest {
    display_name: Option<String>,
    #[serde(default)]
    pronouns: Option<String>,
    bio: Option<String>,
}

/// `PATCH /api/profile`: answers the new userinfo.
pub async fn edit(
    State(edit): State<Arc<EditProfile>>,
    Authenticated(user): Authenticated,
    Json(form): Json<EditRequest>,
) -> Result<Json<UserinfoResponse>, ApiError> {
    let change = ProfileEdit::parse(
        form.display_name.as_deref(),
        form.pronouns.as_deref(),
        form.bio.as_deref(),
    )
    .map_err(|e| ApiError::bad_request(e.reason))?;
    let userinfo = edit.execute(user, change).await?;
    tracing::info!(user_id = %user, "profile updated");
    Ok(Json(userinfo.into()))
}

#[derive(Debug, Serialize)]
pub struct AvatarResponse {
    avatar_url: String,
}

/// `PUT /api/avatar`: the raw image, typed by its `Content-Type`.
pub async fn put_avatar(
    State(set): State<Arc<SetAvatar>>,
    Authenticated(user): Authenticated,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<AvatarResponse>, ApiError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let image =
        AvatarImage::parse(content_type, body).map_err(|e| ApiError::bad_request(e.reason))?;
    let avatar_url = set.execute(user, image, OffsetDateTime::now_utc()).await?;
    tracing::info!(user_id = %user, "avatar updated");
    Ok(Json(AvatarResponse { avatar_url }))
}

/// `DELETE /api/avatar`.
pub async fn delete_avatar(
    State(clear): State<Arc<ClearAvatar>>,
    Authenticated(user): Authenticated,
) -> Result<StatusCode, ApiError> {
    clear.execute(user).await?;
    tracing::info!(user_id = %user, "avatar deleted");
    Ok(StatusCode::NO_CONTENT)
}

impl From<ProfileError> for ApiError {
    fn from(error: ProfileError) -> Self {
        match error {
            // The token outlived its account.
            ProfileError::UnknownUser => ApiError::invalid_token("User not found", true),
            ProfileError::NotItsOwn => ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "access_denied",
                error.to_string(),
            ),
            ProfileError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
