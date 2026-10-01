//! The block list — see identity-provider/specs/01-identity-federation.md § 1.7.

use std::sync::Arc;

use application::social::{Block, ListBlocks, Unblock};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::identity::ActorUri;
use domain::social::{BlockedActor, SocialError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ApiError;
use crate::auth::Authenticated;

#[derive(Deserialize)]
pub struct BlockBody {
    actor_uri: String,
}

#[derive(Serialize)]
pub struct BlockedBody {
    actor_uri: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    blocked_at: OffsetDateTime,
}

pub async fn list(
    State(list): State<Arc<ListBlocks>>,
    Authenticated(user): Authenticated,
) -> Result<Json<Vec<BlockedBody>>, ApiError> {
    let blocked = list.execute(user).await?;
    Ok(Json(blocked.into_iter().map(BlockedBody::from).collect()))
}

pub async fn block(
    State(block): State<Arc<Block>>,
    Authenticated(user): Authenticated,
    Json(body): Json<BlockBody>,
) -> Result<StatusCode, ApiError> {
    let actor =
        ActorUri::parse(&body.actor_uri).map_err(|_| ApiError::bad_request("Invalid actor URI"))?;
    block.execute(user, actor).await?;
    tracing::info!(user_id = %user, "blocked an actor");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unblock(
    State(unblock): State<Arc<Unblock>>,
    Authenticated(user): Authenticated,
    Path(actor): Path<String>,
) -> Result<StatusCode, ApiError> {
    let actor = ActorUri::parse(&actor).map_err(|_| SocialError::NotBlocked)?;
    unblock.execute(user, actor).await?;
    tracing::info!(user_id = %user, "unblocked an actor");
    Ok(StatusCode::NO_CONTENT)
}

impl From<BlockedActor> for BlockedBody {
    fn from(blocked: BlockedActor) -> Self {
        Self {
            actor_uri: blocked.actor.as_str().to_owned(),
            display_name: blocked.display_name,
            avatar_url: blocked.avatar_url,
            blocked_at: blocked.blocked_at,
        }
    }
}

#[cfg(test)]
mod tests;
