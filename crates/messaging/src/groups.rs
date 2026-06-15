//! REST API handlers for group-conversation management: create, list members,
//! add / remove members, rename, and role changes (admin/member).
//!
//! Membership lives in `conversation_members`; these endpoints own the
//! authorization gates (only admins manage membership) and emit the membership
//! WS events. MLS key material (commits/welcomes) still flows through the
//! Delivery Service in `idp-e2ee` — the client bootstraps the MLS group against
//! the conversation id returned here.
//!
//! All endpoints require a valid Bearer access token.

use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use idp_db::models::ConversationMember;
use idp_db::repos::{conversations, remote_actors, users};
use idp_federation::auth::require_auth;
use idp_realtime::{
    GroupCreatedPayload, GroupRenamedPayload, MemberAddedPayload, MemberRemovedPayload,
    MemberRoleChangedPayload, WsEvent,
};
use idp_state::{AppState, OidcError};

// ─── Request / response DTOs ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    /// Optional group name. Blank/absent → client derives a title from members.
    #[serde(default)]
    pub name: Option<String>,
    /// Initial members (actor URIs), excluding the creator.
    pub member_actor_uris: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub actor_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct RenameGroupRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub actor_uri: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub conversation_id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub members: Vec<GroupMember>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────

/// Resolve the caller's actor URI from the Bearer token.
async fn require_caller_actor(state: &AppState, headers: &HeaderMap) -> Result<String, OidcError> {
    let caller_id = require_auth(state, headers).await?;
    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;
    caller
        .actor_uri
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))
}

/// Require the caller to be an active admin of the conversation.
async fn require_admin(
    state: &AppState,
    conversation_id: Uuid,
    caller_actor_uri: &str,
) -> Result<(), OidcError> {
    let member = conversations::get_member(&state.pool, conversation_id, caller_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    match member {
        Some(m) if m.role == "admin" => Ok(()),
        Some(_) => Err(OidcError::access_denied("Only group admins can do this")),
        None => Err(OidcError::not_found("Conversation not found")),
    }
}

/// Resolve a member's display name + avatar (local user or cached remote actor).
async fn resolve_member(state: &AppState, actor_uri: &str, role: String) -> GroupMember {
    if let Ok(Some(u)) = users::find_by_actor_uri(&state.pool, actor_uri).await {
        return GroupMember {
            actor_uri: actor_uri.to_string(),
            display_name: Some(u.display_name.unwrap_or(u.username)),
            avatar_url: u.avatar_url,
            role,
        };
    }
    if let Ok(Some(ra)) = remote_actors::find_by_actor_uri(&state.pool, actor_uri).await {
        return GroupMember {
            actor_uri: actor_uri.to_string(),
            display_name: ra.display_name,
            avatar_url: ra.avatar_url,
            role,
        };
    }
    GroupMember { actor_uri: actor_uri.to_string(), display_name: None, avatar_url: None, role }
}

async fn build_member_views(state: &AppState, members: &[ConversationMember]) -> Vec<GroupMember> {
    let mut out = Vec::with_capacity(members.len());
    for m in members {
        out.push(resolve_member(state, &m.actor_uri, m.role.clone()).await);
    }
    out
}

/// Push a membership event to every *local* member of the conversation. Remote
/// members learn membership via the MLS commit/welcome federation path.
async fn fanout_to_local_members(state: &AppState, members: &[ConversationMember], event: WsEvent) {
    let prefix = format!("{}/users/", state.config.issuer());
    for member in members {
        if !member.actor_uri.starts_with(&prefix) {
            continue;
        }
        if let Ok(Some(u)) = users::find_by_actor_uri(&state.pool, &member.actor_uri).await {
            state.hub.send_to_user(&u.id, event.clone());
        }
    }
}

// ─── POST /api/groups ─────────────────────────────────────────────────────────────

/// Create a group conversation. The caller becomes its first admin; every
/// `member_actor_uris` entry joins as a regular member. The client then
/// bootstraps the MLS group (commits + welcomes) against the returned id.
#[tracing::instrument(skip_all)]
pub async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<GroupView>), OidcError> {
    let caller_actor = require_caller_actor(&state, &headers).await?;

    if body.member_actor_uris.is_empty() {
        return Err(OidcError::invalid_request("A group needs at least one other member"));
    }

    let name = body.name.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let conv = conversations::create_conversation(&state.pool, "group", name)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    conversations::add_member_with_role(&state.pool, conv.id, &caller_actor, "admin")
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut seen = HashSet::new();
    seen.insert(caller_actor.clone());
    for uri in &body.member_actor_uris {
        if seen.insert(uri.clone()) {
            conversations::add_member_with_role(&state.pool, conv.id, uri, "member")
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?;
        }
    }

    let member_rows = conversations::get_members(&state.pool, conv.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    let members = build_member_views(&state, &member_rows).await;

    fanout_to_local_members(
        &state,
        &member_rows,
        WsEvent::GroupCreated(GroupCreatedPayload {
            conversation_id: conv.id,
            name: conv.name.clone(),
            creator_actor_uri: caller_actor,
            created_at: conv.created_at,
        }),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(GroupView {
            conversation_id: conv.id,
            kind: conv.kind,
            name: conv.name,
            members,
            created_at: conv.created_at,
        }),
    ))
}

// ─── GET /api/groups/:id/members ──────────────────────────────────────────────────

/// List a group's members with their roles. Membership-gated.
#[tracing::instrument(skip_all, fields(conversation_id = %conversation_id))]
pub async fn list_group_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_id): Path<Uuid>,
) -> Result<Json<Vec<GroupMember>>, OidcError> {
    let caller_actor = require_caller_actor(&state, &headers).await?;

    let member_rows = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if !member_rows.iter().any(|m| m.actor_uri == caller_actor) {
        return Err(OidcError::not_found("Conversation not found"));
    }

    Ok(Json(build_member_views(&state, &member_rows).await))
}

// ─── POST /api/groups/:id/members ──────────────────────────────────────────────────

/// Add a member to a group (admin only). Key delivery happens separately via
/// the MLS welcome the client posts for the new member.
#[tracing::instrument(skip_all, fields(conversation_id = %conversation_id))]
pub async fn add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_id): Path<Uuid>,
    Json(body): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<GroupMember>), OidcError> {
    let caller_actor = require_caller_actor(&state, &headers).await?;
    require_admin(&state, conversation_id, &caller_actor).await?;

    let member =
        conversations::add_member_with_role(&state.pool, conversation_id, &body.actor_uri, "member")
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

    let view = resolve_member(&state, &body.actor_uri, member.role.clone()).await;

    let member_rows = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    fanout_to_local_members(
        &state,
        &member_rows,
        WsEvent::MemberAdded(MemberAddedPayload {
            conversation_id,
            actor_uri: body.actor_uri,
            role: member.role,
            added_by_actor_uri: caller_actor,
        }),
    )
    .await;

    Ok((StatusCode::CREATED, Json(view)))
}

// ─── DELETE /api/groups/:id/members/:actor_uri ─────────────────────────────────────

/// Remove a member (admin only) or leave the group (caller == target). The
/// `actor_uri` path segment is percent-encoded by the client.
#[tracing::instrument(skip_all, fields(conversation_id = %conversation_id))]
pub async fn remove_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((conversation_id, actor_uri)): Path<(Uuid, String)>,
) -> Result<StatusCode, OidcError> {
    let caller_actor = require_caller_actor(&state, &headers).await?;
    let is_self = caller_actor == actor_uri;
    if !is_self {
        require_admin(&state, conversation_id, &caller_actor).await?;
    }

    // Snapshot members BEFORE removal so the removed member's own sessions also
    // receive the event.
    let member_rows = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let removed = conversations::remove_member(&state.pool, conversation_id, &actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if removed.is_none() {
        return Err(OidcError::not_found("Member not found"));
    }

    fanout_to_local_members(
        &state,
        &member_rows,
        WsEvent::MemberRemoved(MemberRemovedPayload {
            conversation_id,
            actor_uri,
            removed_by_actor_uri: if is_self { None } else { Some(caller_actor) },
        }),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ─── PATCH /api/groups/:id ──────────────────────────────────────────────────────────

/// Rename a group (admin only).
#[tracing::instrument(skip_all, fields(conversation_id = %conversation_id))]
pub async fn rename_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_id): Path<Uuid>,
    Json(body): Json<RenameGroupRequest>,
) -> Result<Json<GroupView>, OidcError> {
    let caller_actor = require_caller_actor(&state, &headers).await?;
    require_admin(&state, conversation_id, &caller_actor).await?;

    let name = body.name.trim();
    if name.is_empty() {
        return Err(OidcError::invalid_request("Group name cannot be empty"));
    }

    let conv = conversations::update_name(&state.pool, conversation_id, name)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Group not found"))?;

    let member_rows = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    let members = build_member_views(&state, &member_rows).await;

    fanout_to_local_members(
        &state,
        &member_rows,
        WsEvent::GroupRenamed(GroupRenamedPayload {
            conversation_id,
            name: conv.name.clone(),
            renamed_by_actor_uri: caller_actor,
        }),
    )
    .await;

    Ok(Json(GroupView {
        conversation_id: conv.id,
        kind: conv.kind,
        name: conv.name,
        members,
        created_at: conv.created_at,
    }))
}

// ─── POST /api/groups/:id/members/:actor_uri/role ──────────────────────────────────

/// Change a member's role (admin only). Body: `{ "role": "admin" | "member" }`.
/// The `actor_uri` path segment is percent-encoded by the client.
#[tracing::instrument(skip_all, fields(conversation_id = %conversation_id))]
pub async fn set_member_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((conversation_id, actor_uri)): Path<(Uuid, String)>,
    Json(body): Json<SetRoleRequest>,
) -> Result<Json<GroupMember>, OidcError> {
    let caller_actor = require_caller_actor(&state, &headers).await?;
    require_admin(&state, conversation_id, &caller_actor).await?;

    if body.role != "admin" && body.role != "member" {
        return Err(OidcError::invalid_request("role must be 'admin' or 'member'"));
    }

    let updated = conversations::set_role(&state.pool, conversation_id, &actor_uri, &body.role)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Member not found"))?;

    let view = resolve_member(&state, &actor_uri, updated.role.clone()).await;

    let member_rows = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    fanout_to_local_members(
        &state,
        &member_rows,
        WsEvent::MemberRoleChanged(MemberRoleChangedPayload {
            conversation_id,
            actor_uri,
            role: updated.role,
            changed_by_actor_uri: caller_actor,
        }),
    )
    .await;

    Ok(Json(view))
}
