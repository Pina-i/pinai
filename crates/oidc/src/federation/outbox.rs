//! GET /users/:handle/outbox
//! GET /users/:handle/followers
//! GET /users/:handle/following

use axum::{
    extract::{Path, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use activitypub::OrderedCollection;
use idp_db::repos::{follows, users};

use crate::{AppState, OidcError};

/// GET /users/:handle/outbox
#[tracing::instrument(skip_all, fields(handle = %handle))]
pub async fn get_outbox(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, OidcError> {
    let user = users::find_by_handle(&state.pool, &handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let base = state.config.issuer();
    let outbox_url = format!("{}/users/{}/outbox", base, user.handle());

    // Empty outbox for now — activities will be appended in future phases.
    let collection = OrderedCollection::new(&outbox_url, 0, vec![]);
    ap_response(Json(collection))
}

/// GET /users/:handle/followers
#[tracing::instrument(skip_all, fields(handle = %handle))]
pub async fn get_followers(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, OidcError> {
    let user = users::find_by_handle(&state.pool, &handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let base = state.config.issuer();
    let followers_url = format!("{}/users/{}/followers", base, user.handle());

    let rows = follows::get_followers(&state.pool, user.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut items: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
    for row in &rows {
        if let Some(u) = users::find_by_id(&state.pool, row.follower_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            items.push(json!(format!("{}/users/{}", base, u.handle())));
        }
    }

    let collection = OrderedCollection::new(&followers_url, items.len() as i64, items);
    ap_response(Json(collection))
}

/// GET /users/:handle/following
#[tracing::instrument(skip_all, fields(handle = %handle))]
pub async fn get_following(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, OidcError> {
    let user = users::find_by_handle(&state.pool, &handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let base = state.config.issuer();
    let following_url = format!("{}/users/{}/following", base, user.handle());

    let rows = follows::get_following(&state.pool, user.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut items: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
    for row in &rows {
        if let Some(u) = users::find_by_id(&state.pool, row.following_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            items.push(json!(format!("{}/users/{}", base, u.handle())));
        }
    }

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
