//! GET /users/:handle — ActivityPub Actor profile

use axum::{
    extract::{Path, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    Json,
};

use activitypub::Actor;
use idp_db::repos::users;

use crate::{AppState, OidcError};

/// GET /users/:handle
///
/// Returns an ActivityPub `Person` actor document.
/// Responds to both `text/html` and `application/activity+json` Accept headers.
#[tracing::instrument(skip_all, fields(handle = %handle))]
pub async fn get_actor(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, OidcError> {
    let user = users::find_by_handle(&state.pool, &handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let base = state.config.issuer();
    let actor = Actor::person(
        &base,
        &user.handle(),
        &user.username,
        &state.keypair.public_key_pem,
    );

    let mut response = Json(actor).into_response();
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/activity+json; charset=utf-8"),
    );
    Ok(response)
}
