//! GET /users/:username/outbox
//! GET /users/:username/followers
//! GET /users/:username/following

use axum::{
    extract::{Path, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use activitypub::OrderedCollection;
use idp_db::repos::{friendships, users};

use idp_state::{AppState, OidcError};

/// GET /users/:slug/outbox
#[tracing::instrument(skip_all, fields(slug = %slug))]
pub async fn get_outbox(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, OidcError> {
    let base = state.config.issuer();
    let actor_uri = format!("{}/users/{}", base, slug);
    let user = users::find_by_actor_uri(&state.pool, &actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let fallback = format!("{}/outbox", actor_uri);
    let outbox_url = user.outbox_url.as_deref().unwrap_or(&fallback);

    // Empty outbox for now — activities will be appended in future phases.
    let collection = OrderedCollection::new(outbox_url, 0, vec![]);
    ap_response(Json(collection))
}

/// GET /users/:slug/followers
#[tracing::instrument(skip_all, fields(slug = %slug))]
pub async fn get_followers(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, OidcError> {
    let base = state.config.issuer();
    let actor_uri = format!("{}/users/{}", base, slug);
    let user = users::find_by_actor_uri(&state.pool, &actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let followers_url = format!("{}/followers", actor_uri);

    // In the friendship model, "followers" = people who have me as a friend.
    // We can approximate this with the friends list (symmetric friendships).
    let friends = friendships::get_friends(&state.pool, user.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let items: Vec<serde_json::Value> = friends
        .iter()
        .map(|f| json!(f.friend_actor_uri))
        .collect();

    let collection = OrderedCollection::new(&followers_url, items.len() as i64, items);
    ap_response(Json(collection))
}

/// GET /users/:slug/following
#[tracing::instrument(skip_all, fields(slug = %slug))]
pub async fn get_following(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, OidcError> {
    let base = state.config.issuer();
    let actor_uri = format!("{}/users/{}", base, slug);
    let user = users::find_by_actor_uri(&state.pool, &actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let following_url = format!("{}/following", actor_uri);

    let friends = friendships::get_friends(&state.pool, user.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let items: Vec<serde_json::Value> = friends
        .iter()
        .map(|f| json!(f.friend_actor_uri))
        .collect();

    let collection = OrderedCollection::new(&following_url, items.len() as i64, items);
    ap_response(Json(collection))
}

fn ap_response(json: Json<impl serde::Serialize>) -> Result<Response, OidcError> {
    let mut response = json.into_response();
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/activity+json; charset=utf-8"),
    );
    Ok(response)
}
