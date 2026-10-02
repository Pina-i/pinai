//! `PATCH /api/privacy`: who may message the account or add it to a group — see
//! identity-provider/specs/social.md § 2.

use std::sync::Arc;

use application::social::SetContactPolicy;
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::auth::Authenticated;

#[derive(Deserialize)]
pub struct PrivacyBody {
    contact_policy: String,
}

#[derive(Debug, Serialize)]
pub struct Privacy {
    pub contact_policy: &'static str,
}

pub async fn update(
    State(set): State<Arc<SetContactPolicy>>,
    Authenticated(user): Authenticated,
    Json(body): Json<PrivacyBody>,
) -> Result<Json<Privacy>, ApiError> {
    let policy = body.contact_policy.parse().map_err(|_| {
        ApiError::bad_request("contact_policy must be everyone, friends_and_groups or friends")
    })?;
    let set = set.execute(user, policy).await?;
    tracing::info!(user_id = %user, contact_policy = set.as_str(), "contact setting changed");
    Ok(Json(Privacy {
        contact_policy: set.as_str(),
    }))
}

#[cfg(test)]
mod tests;
