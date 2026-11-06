//! Starting the history over from a device not approved — see identity-provider/specs/e2ee.md
//! § 3.12.

use std::sync::Arc;

use application::e2ee::{AskToStartOver, EndStartOver, LoadStartOver, PendingStartOver};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::SignedIn;

#[derive(Serialize)]
pub struct AskedBody {
    id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// When it matures as of this answer.
    #[serde(with = "time::serde::rfc3339")]
    ready_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct PendingBody {
    id: Uuid,
    /// The device asking.
    device_id: Uuid,
    display_name: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    ready_at: OffsetDateTime,
    /// How it ended, for the device that asked; `null` while open.
    ended: Option<EndedBody>,
}

#[derive(Serialize)]
pub struct EndedBody {
    reason: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    at: OffsetDateTime,
}

impl From<PendingStartOver> for PendingBody {
    fn from(
        PendingStartOver {
            request,
            display_name,
            ready_at,
        }: PendingStartOver,
    ) -> Self {
        Self {
            id: request.id.as_uuid(),
            device_id: request.device.as_uuid(),
            display_name,
            created_at: request.created_at,
            ready_at,
            ended: request.ended.map(|ended| EndedBody {
                reason: ended.how.as_str(),
                at: ended.at,
            }),
        }
    }
}

/// `POST /api/history/start-over` — `201` for a new request, `200` for the device's own open one.
pub async fn ask(
    State(ask): State<Arc<AskToStartOver>>,
    SignedIn(bearer): SignedIn,
) -> Result<(StatusCode, Json<AskedBody>), ApiError> {
    let asked = ask.execute(&bearer, OffsetDateTime::now_utc()).await?;
    let status = if asked.opened {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(AskedBody {
            id: asked.request.id.as_uuid(),
            created_at: asked.request.created_at,
            ready_at: asked.ready_at,
        }),
    ))
}

/// `GET /api/history/start-over`
pub async fn pending(
    State(load): State<Arc<LoadStartOver>>,
    SignedIn(bearer): SignedIn,
) -> Result<Json<PendingBody>, ApiError> {
    Ok(Json(load.execute(&bearer).await?.into()))
}

/// `DELETE /api/history/start-over/{id}` — no recent password: cancelling must be quick.
pub async fn end(
    State(end): State<Arc<EndStartOver>>,
    SignedIn(bearer): SignedIn,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    end.execute(&bearer, id.into(), OffsetDateTime::now_utc())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
