//! Where the instance sends a device's push notices — see identity-provider/specs/push.md.

use std::sync::Arc;

use application::e2ee::{RegisterPush, UnregisterPush};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::e2ee::{PushRegistration, PushRelay, PushToken};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::SignedIn;

#[derive(Deserialize)]
pub struct PushBody {
    relay: String,
    token: String,
}

/// `PUT /api/keys/devices/{device_id}/push` — no recent password: the device sets it at each start.
pub async fn register(
    State(register): State<Arc<RegisterPush>>,
    SignedIn(bearer): SignedIn,
    Path(device_id): Path<Uuid>,
    Json(body): Json<PushBody>,
) -> Result<StatusCode, ApiError> {
    let registration = PushRegistration {
        relay: PushRelay::parse(&body.relay)?,
        token: PushToken::parse(&body.token)?,
    };
    register
        .execute(
            &bearer,
            device_id.into(),
            &registration,
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/keys/devices/{device_id}/push`
pub async fn unregister(
    State(unregister): State<Arc<UnregisterPush>>,
    SignedIn(bearer): SignedIn,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    unregister.execute(&bearer, device_id.into()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
