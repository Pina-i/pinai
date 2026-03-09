//! GET /users/:username — ActivityPub Actor profile

use axum::{
    extract::{Path, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    Json,
};

use activitypub::Actor;
use idp_db::repos::users;

use crate::{AppState, OidcError};

/// GET /users/:username
///
/// Returns an ActivityPub `Person` actor document.
#[tracing::instrument(skip_all, fields(username = %username))]
pub async fn get_actor(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Response, OidcError> {
    let user = users::find_by_username(&state.pool, &username)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let base = state.config.issuer();
    let display_name = user.display_name.as_deref().unwrap_or(&user.username);
    let actor = Actor::person(
        &base,
        &user.username,
        display_name,
        &state.keypair.public_key_pem,
    );

    let mut response = Json(actor).into_response();
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/activity+json; charset=utf-8"),
    );
    Ok(response)
}
