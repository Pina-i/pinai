//! What admins see of the members and do for them: the list, and a reset link for a forgotten
//! password — see identity-provider/specs/auth.md § 4 and § 7.

use std::sync::Arc;

use application::auth::{IssuePasswordReset, ListMembers, ListedMember};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::UserId;
use domain::auth::{AuthError, reset_link};
use domain::identity::InstanceOrigin;
use serde::Serialize;
use time::OffsetDateTime;

use crate::ApiError;
use crate::auth::{Authenticated, RecentlySignedIn, not_admin};

#[derive(Serialize)]
pub struct MemberBody {
    id: String,
    /// `null` for an account without one; never a handle or an address.
    display_name: Option<String>,
    admin: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    last_active_at: Option<OffsetDateTime>,
    online: bool,
}

impl From<ListedMember> for MemberBody {
    fn from(member: ListedMember) -> Self {
        Self {
            id: member.id.to_string(),
            display_name: member.display_name,
            admin: member.admin,
            last_active_at: member.last_active_at,
            online: member.online,
        }
    }
}

#[derive(Serialize)]
pub struct ResetBody {
    /// The only answer the token is ever in.
    link: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

fn refusal(error: AuthError) -> ApiError {
    match error {
        AuthError::NotAdmin => not_admin(),
        AuthError::UnknownUser => ApiError::not_found("Member not found"),
        // 409, not 403: the caller may do this, the account's state refuses it.
        AuthError::AdminNotResettable => ApiError::new(
            StatusCode::CONFLICT,
            "admin_account",
            "An admin recovers their access through ADMIN_EMAIL and ADMIN_PASSWORD, not a reset link",
        ),
        other => ApiError::internal(anyhow::Error::from(other)),
    }
}

/// `GET /api/admin/members` — the most recently active first.
pub async fn list(
    State(list): State<Arc<ListMembers>>,
    Authenticated(user): Authenticated,
) -> Result<Json<Vec<MemberBody>>, ApiError> {
    let members = list
        .execute(user, OffsetDateTime::now_utc())
        .await
        .map_err(refusal)?;
    Ok(Json(members.into_iter().map(MemberBody::from).collect()))
}

/// `POST /api/admin/members/{id}/password-reset`
pub async fn issue_reset(
    State(issue): State<Arc<IssuePasswordReset>>,
    State(origin): State<InstanceOrigin>,
    RecentlySignedIn(bearer): RecentlySignedIn,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ResetBody>), ApiError> {
    // A malformed id names no account: the use case still asks for an admin first.
    let member = uuid::Uuid::parse_str(&id).ok().map(UserId::from);
    let issued = issue
        .execute(bearer.user, member, OffsetDateTime::now_utc())
        .await
        .map_err(refusal)?;
    tracing::info!(user_id = %bearer.user, member = %issued.member, "issued a password reset link");
    Ok((
        StatusCode::CREATED,
        Json(ResetBody {
            link: reset_link(&origin, &issued.token),
            expires_at: issued.expires_at,
        }),
    ))
}

#[cfg(test)]
mod tests;
