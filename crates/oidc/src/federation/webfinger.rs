//! GET /.well-known/webfinger
//!
//! Allows remote servers and clients to discover a user's Actor URL
//! from their handle, e.g. `acct:alex-7G4K@pinai.example.com`.

use axum::{
    extract::{Query, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use activitypub::WebFingerResponse;
use idp_db::repos::users;

use crate::{AppState, OidcError};

#[derive(Debug, Deserialize)]
pub struct WebFingerQuery {
    /// e.g. `acct:alex-7G4K@example.com` or `acct:alex-7G4K`
    pub resource: String,
}

/// GET /.well-known/webfinger?resource=acct:{handle}@{domain}
#[tracing::instrument(skip_all, fields(resource = %query.resource))]
pub async fn get_webfinger(
    State(state): State<AppState>,
    Query(query): Query<WebFingerQuery>,
) -> Result<Response, OidcError> {
    // Strip the `acct:` prefix.
    let acct = query
        .resource
        .strip_prefix("acct:")
        .unwrap_or(&query.resource);

    // Handle can be `username-SUFFIX` or `username-SUFFIX@domain`.
    let handle = acct.split('@').next().unwrap_or(acct);

    let user = users::find_by_handle(&state.pool, handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let base = state.config.issuer();
    let actor_url = format!("{}/users/{}", base, user.handle());
    let subject = format!("acct:{}@{}", user.handle(), state.config.domain);

    let wf = WebFingerResponse::for_actor(&subject, &actor_url);

    // WebFinger responses use `application/jrd+json`.
    let mut response = Json(wf).into_response();
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/jrd+json; charset=utf-8"),
    );
    Ok(response)
}
