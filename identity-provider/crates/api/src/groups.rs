//! Group management — see identity-provider/specs/03-direct-messages.md § 9.

use std::sync::Arc;

use application::messaging::{
    AddGroupMember, CreateGroup, GroupView, ListGroupMembers, MemberProfile, RemoveGroupMember,
    RenameGroup, SetMemberRole,
};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::identity::ActorUri;
use domain::messaging::{GroupName, MessagingError, Role};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::Authenticated;

#[derive(Deserialize)]
pub struct CreateGroupBody {
    #[serde(default)]
    name: Option<String>,
    /// The members besides the creator.
    member_actor_uris: Vec<String>,
}

#[derive(Deserialize)]
pub struct AddMemberBody {
    actor_uri: String,
}

#[derive(Deserialize)]
pub struct RenameBody {
    name: String,
}

#[derive(Deserialize)]
pub struct RoleBody {
    role: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMemberBody {
    actor_uri: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    role: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupBody {
    conversation_id: Uuid,
    kind: &'static str,
    name: Option<String>,
    members: Vec<GroupMemberBody>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl From<MemberProfile> for GroupMemberBody {
    fn from(profile: MemberProfile) -> Self {
        Self {
            actor_uri: profile.member.actor_uri.to_string(),
            display_name: profile.display_name,
            avatar_url: profile.avatar_url,
            role: profile.member.role.as_str(),
        }
    }
}

impl From<GroupView> for GroupBody {
    fn from(view: GroupView) -> Self {
        Self {
            conversation_id: view.group.id.as_uuid(),
            kind: view.group.kind.as_str(),
            name: view.group.name,
            members: view
                .members
                .into_iter()
                .map(GroupMemberBody::from)
                .collect(),
            created_at: view.group.created_at,
        }
    }
}

/// A path segment naming a member: one that is no actor URI names nobody in the group.
fn member_uri(raw: &str) -> Result<ActorUri, MessagingError> {
    ActorUri::parse(raw).map_err(|_| MessagingError::MemberNotFound)
}

/// `POST /api/groups`
pub async fn create(
    State(create): State<Arc<CreateGroup>>,
    Authenticated(user): Authenticated,
    Json(body): Json<CreateGroupBody>,
) -> Result<(StatusCode, Json<GroupBody>), ApiError> {
    let name = GroupName::parse_optional(body.name.as_deref())
        .map_err(|e| ApiError::bad_request(format!("Group name {}", e.reason)))?;
    let invited = body
        .member_actor_uris
        .iter()
        .map(|uri| ActorUri::parse(uri))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            ApiError::bad_request("`member_actor_uris` holds something that is not an actor URI")
        })?;
    let view = create.execute(user, name, invited).await?;
    tracing::info!(user_id = %user, group = %view.group.id, "group created");
    Ok((StatusCode::CREATED, Json(view.into())))
}

/// `GET /api/groups/{conversation_id}/members`
pub async fn members(
    State(list): State<Arc<ListGroupMembers>>,
    Authenticated(user): Authenticated,
    Path(group): Path<Uuid>,
) -> Result<Json<Vec<GroupMemberBody>>, ApiError> {
    let members = list.execute(user, group.into()).await?;
    Ok(Json(
        members.into_iter().map(GroupMemberBody::from).collect(),
    ))
}

/// `POST /api/groups/{conversation_id}/members`
pub async fn add(
    State(add): State<Arc<AddGroupMember>>,
    Authenticated(user): Authenticated,
    Path(group): Path<Uuid>,
    Json(body): Json<AddMemberBody>,
) -> Result<(StatusCode, Json<GroupMemberBody>), ApiError> {
    let actor = ActorUri::parse(&body.actor_uri)
        .map_err(|_| ApiError::bad_request("`actor_uri` is not an actor URI"))?;
    let added = add.execute(user, group.into(), actor).await?;
    Ok((StatusCode::CREATED, Json(added.into())))
}

/// `DELETE /api/groups/{conversation_id}/members/{actor_uri}` — `actor_uri` percent-encoded.
pub async fn remove(
    State(remove): State<Arc<RemoveGroupMember>>,
    Authenticated(user): Authenticated,
    Path((group, actor)): Path<(Uuid, String)>,
) -> Result<StatusCode, ApiError> {
    remove
        .execute(user, group.into(), member_uri(&actor)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PATCH /api/groups/{conversation_id}`
pub async fn rename(
    State(rename): State<Arc<RenameGroup>>,
    Authenticated(user): Authenticated,
    Path(group): Path<Uuid>,
    Json(body): Json<RenameBody>,
) -> Result<Json<GroupBody>, ApiError> {
    let name = GroupName::parse(&body.name)
        .map_err(|e| ApiError::bad_request(format!("Group name {}", e.reason)))?;
    let view = rename.execute(user, group.into(), name).await?;
    Ok(Json(view.into()))
}

/// `POST /api/groups/{conversation_id}/members/{actor_uri}/role`
pub async fn set_role(
    State(set_role): State<Arc<SetMemberRole>>,
    Authenticated(user): Authenticated,
    Path((group, actor)): Path<(Uuid, String)>,
    Json(body): Json<RoleBody>,
) -> Result<Json<GroupMemberBody>, ApiError> {
    let role: Role = body
        .role
        .parse()
        .map_err(|_| ApiError::bad_request("role must be 'admin' or 'member'"))?;
    let changed = set_role
        .execute(user, group.into(), member_uri(&actor)?, role)
        .await?;
    Ok(Json(changed.into()))
}

#[cfg(test)]
mod tests;
