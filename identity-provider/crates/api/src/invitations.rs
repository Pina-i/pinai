//! What admins do with invitations: create, list and revoke them — see
//! identity-provider/specs/auth.md § 5.

use std::sync::Arc;

use application::auth::{CreateInvitation, ListInvitations, RevokeInvitation};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::InvitationId;
use domain::auth::{AuthError, OpenInvitation};
use domain::identity::InstanceOrigin;
use serde::Serialize;
use time::OffsetDateTime;

use crate::ApiError;
use crate::auth::{Authenticated, not_admin};
use crate::invite::invitation_path;

#[derive(Serialize)]
pub struct CreatedBody {
    id: String,
    /// The only answer the token is ever in.
    link: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct Named {
    /// `null` for an account without one.
    display_name: Option<String>,
}

#[derive(Serialize)]
pub struct OpenBody {
    id: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    created_by: Named,
}

impl From<OpenInvitation> for OpenBody {
    fn from(open: OpenInvitation) -> Self {
        Self {
            id: open.id.to_string(),
            created_at: open.created_at,
            expires_at: open.expires_at,
            created_by: Named {
                display_name: open.inviter,
            },
        }
    }
}

fn refusal(error: AuthError) -> ApiError {
    match error {
        AuthError::NotAdmin => not_admin(),
        AuthError::InvitationUnusable => ApiError::not_found("Invitation not found"),
        AuthError::RegistrationsOpen => ApiError::new(
            StatusCode::CONFLICT,
            "registrations_open",
            "This instance is open: people sign up themselves",
        ),
        other => ApiError::internal(anyhow::Error::from(other)),
    }
}

/// `POST /api/admin/invitations`
pub async fn create(
    State(create): State<Arc<CreateInvitation>>,
    State(origin): State<InstanceOrigin>,
    Authenticated(user): Authenticated,
) -> Result<(StatusCode, Json<CreatedBody>), ApiError> {
    let created = create
        .execute(user, OffsetDateTime::now_utc())
        .await
        .map_err(refusal)?;
    tracing::info!(user_id = %user, invitation = %created.id, "created an invitation");
    Ok((
        StatusCode::CREATED,
        Json(CreatedBody {
            id: created.id.to_string(),
            link: format!("{}{}", origin.base_url(), invitation_path(&created.token)),
            expires_at: created.expires_at,
        }),
    ))
}

/// `GET /api/admin/invitations` — the open ones, newest first.
pub async fn list(
    State(list): State<Arc<ListInvitations>>,
    Authenticated(user): Authenticated,
) -> Result<Json<Vec<OpenBody>>, ApiError> {
    let open = list
        .execute(user, OffsetDateTime::now_utc())
        .await
        .map_err(refusal)?;
    Ok(Json(open.into_iter().map(OpenBody::from).collect()))
}

/// `DELETE /api/admin/invitations/{id}`
pub async fn revoke(
    State(revoke): State<Arc<RevokeInvitation>>,
    Authenticated(user): Authenticated,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    // A malformed id names no invitation: the use case still asks for an admin first.
    let id = uuid::Uuid::parse_str(&id).ok().map(InvitationId::from);
    revoke
        .execute(user, id, OffsetDateTime::now_utc())
        .await
        .map_err(refusal)?;
    if let Some(id) = id {
        tracing::info!(user_id = %user, invitation = %id, "revoked an invitation");
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
