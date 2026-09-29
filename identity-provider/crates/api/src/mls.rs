//! The MLS Delivery Service — see identity-provider/specs/05-e2ee.md § 5.

use std::sync::Arc;

use application::e2ee::{AppendCommit, CatchUpCommits, ClaimWelcomes, SendWelcome};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{Commit, CommitBlob, DeliveryError, Epoch, Welcome, WelcomeBlob};
use domain::identity::ActorUri;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::Authenticated;

#[derive(Serialize)]
pub struct CommitView {
    id: Uuid,
    conversation_id: Uuid,
    epoch: i64,
    proposer_actor_uri: String,
    /// Base64 of the TLS-encoded MLS Commit.
    commit_blob: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl From<Commit> for CommitView {
    fn from(commit: Commit) -> Self {
        Self {
            id: commit.id.as_uuid(),
            conversation_id: commit.conversation.as_uuid(),
            epoch: commit.epoch.value(),
            proposer_actor_uri: commit.proposer.to_string(),
            commit_blob: B64.encode(commit.blob.as_bytes()),
            created_at: commit.created_at,
        }
    }
}

impl From<Welcome> for WelcomeView {
    fn from(welcome: Welcome) -> Self {
        Self {
            id: welcome.id.as_uuid(),
            conversation_id: welcome.conversation.as_uuid(),
            recipient_device_id: welcome.device.as_uuid(),
            welcome_blob: B64.encode(welcome.blob.as_bytes()),
            created_at: welcome.created_at,
        }
    }
}

/// A base64 MLS message, refused when undecodable or empty.
fn blob(field: &str, raw: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = B64
        .decode(raw)
        .map_err(|_| ApiError::bad_request(format!("`{field}` is not valid base64")))?;
    if bytes.is_empty() {
        return Err(ApiError::bad_request(format!("`{field}` is empty")));
    }
    Ok(bytes)
}

fn epoch(field: &str, value: i64) -> Result<Epoch, ApiError> {
    Epoch::parse(value)
        .map_err(|_| ApiError::bad_request(format!("`{field}` must be non-negative")))
}

#[derive(Deserialize)]
pub struct CommitRequest {
    /// The epoch the proposer believes is next.
    epoch: i64,
    commit_blob: String,
}

#[derive(Deserialize)]
pub struct CatchUpQuery {
    /// Commits after this epoch; 0 on a first sync.
    #[serde(default)]
    since: i64,
}

#[derive(Serialize)]
pub struct CommitPageBody {
    commits: Vec<CommitView>,
    has_more: bool,
}

#[derive(Deserialize)]
pub struct WelcomesQuery {
    device_id: Uuid,
}

#[derive(Serialize)]
pub struct WelcomeView {
    id: Uuid,
    conversation_id: Uuid,
    recipient_device_id: Uuid,
    welcome_blob: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct WelcomesBody {
    welcomes: Vec<WelcomeView>,
}

#[derive(Deserialize)]
pub struct WelcomeRequest {
    recipient_actor_uri: String,
    recipient_device_id: Uuid,
    conversation_id: Uuid,
    welcome_blob: String,
}

#[derive(Serialize)]
pub struct SentWelcomeBody {
    /// Nil for a Welcome sent to another instance: nothing is stored here.
    id: Uuid,
}

/// `POST /api/mls/groups/{conversation_id}/commits`
pub async fn append(
    State(append): State<Arc<AppendCommit>>,
    Authenticated(user): Authenticated,
    Path(conversation): Path<Uuid>,
    Json(body): Json<CommitRequest>,
) -> Result<(StatusCode, Json<CommitView>), ApiError> {
    let blob = CommitBlob::parse(blob("commit_blob", &body.commit_blob)?)
        .map_err(|e| ApiError::internal(e.into()))?;
    let epoch = epoch("epoch", body.epoch)?;
    let commit = append
        .execute(user, conversation.into(), epoch, blob)
        .await?;
    Ok((StatusCode::CREATED, Json(commit.into())))
}

/// `GET /api/mls/groups/{conversation_id}/commits?since=`
pub async fn catch_up(
    State(catch_up): State<Arc<CatchUpCommits>>,
    Authenticated(user): Authenticated,
    Path(conversation): Path<Uuid>,
    Query(query): Query<CatchUpQuery>,
) -> Result<Json<CommitPageBody>, ApiError> {
    let since = epoch("since", query.since)?;
    let page = catch_up.execute(user, conversation.into(), since).await?;
    Ok(Json(CommitPageBody {
        commits: page.commits.into_iter().map(CommitView::from).collect(),
        has_more: page.has_more,
    }))
}

/// `GET /api/mls/welcomes?device_id=`
pub async fn welcomes(
    State(claim): State<Arc<ClaimWelcomes>>,
    Authenticated(user): Authenticated,
    Query(query): Query<WelcomesQuery>,
) -> Result<Json<WelcomesBody>, ApiError> {
    let welcomes = claim.execute(user, query.device_id.into()).await?;
    if !welcomes.is_empty() {
        tracing::info!(user_id = %user, device_id = %query.device_id, count = welcomes.len(), "delivered pending mls welcomes");
    }
    Ok(Json(WelcomesBody {
        welcomes: welcomes.into_iter().map(WelcomeView::from).collect(),
    }))
}

/// `POST /api/mls/welcomes`
pub async fn send_welcome(
    State(send): State<Arc<SendWelcome>>,
    Authenticated(user): Authenticated,
    Json(body): Json<WelcomeRequest>,
) -> Result<Json<SentWelcomeBody>, ApiError> {
    let blob = WelcomeBlob::parse(blob("welcome_blob", &body.welcome_blob)?)
        .map_err(|e| ApiError::internal(e.into()))?;
    let recipient = ActorUri::parse(&body.recipient_actor_uri)
        .map_err(|_| ApiError::bad_request("recipient_actor_uri is not a valid URL"))?;
    let stored = send
        .execute(
            user,
            &recipient,
            body.recipient_device_id.into(),
            body.conversation_id.into(),
            blob,
        )
        .await?;
    Ok(Json(SentWelcomeBody {
        id: stored.map_or(Uuid::nil(), |welcome| welcome.id.as_uuid()),
    }))
}

impl From<DeliveryError> for ApiError {
    fn from(error: DeliveryError) -> Self {
        match error {
            DeliveryError::ConversationNotFound => ApiError::not_found("conversation not found"),
            DeliveryError::NotAMember => ApiError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "not a member of this conversation",
            ),
            DeliveryError::RecipientNotAMember => ApiError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "the recipient is not a member of this conversation",
            ),
            DeliveryError::RecipientNotFound => {
                ApiError::not_found("recipient_actor_uri matches our issuer but no such user")
            }
            DeliveryError::EpochTaken(winner) => {
                let description = DeliveryError::EpochTaken(winner.clone()).to_string();
                let winning = serde_json::to_value(CommitView::from(*winner))
                    .unwrap_or(serde_json::Value::Null);
                ApiError::new(StatusCode::CONFLICT, "epoch_conflict", description)
                    .with("winning_commit", winning)
            }
            DeliveryError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
