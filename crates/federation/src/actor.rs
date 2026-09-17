//! ActivityPub actor endpoints.
//!
//! - `GET /users/:username` — per-user `Person` actor profile.
//! - `GET /actor`           — instance-level `Application` actor used for
//!                            HTTP-Signature key resolution on inter-IdP calls
//!                            (presence batch poll, presence SSE stream).

use axum::{
    extract::{Path, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    Json,
};

use activitypub::Actor;
use idp_db::repos::users;

use idp_state::{AppState, OidcError};

/// GET /users/:slug
///
/// Returns an ActivityPub `Person` actor document.
#[tracing::instrument(skip_all, fields(slug = %slug))]
pub async fn get_actor(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, OidcError> {
    let base = state.config.issuer();
    let actor_uri = format!("{}/users/{}", base, slug);
    let user = users::find_by_actor_uri(&state.pool, &actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let display_name = user.display_name.as_deref().unwrap_or(&user.username);
    let actor = Actor::person(&base, &slug, display_name, &state.keypair.public_key_pem);

    let mut response = Json(actor).into_response();
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/activity+json; charset=utf-8"),
    );
    Ok(response)
}

/// GET /actor
///
/// Returns the instance's `Application` actor. Resolves the keyId
/// `<issuer>/actor#main-key` used to sign inter-IdP requests.
#[tracing::instrument(skip_all)]
pub async fn get_instance_actor(State(state): State<AppState>) -> Response {
    let base = state.config.issuer();
    let actor_url = format!("{}/actor", base);
    let body = serde_json::json!({
        "@context": ["https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"],
        "id": actor_url,
        "type": "Application",
        "preferredUsername": "instance",
        "name": base,
        "inbox": format!("{}/inbox", actor_url),
        "outbox": format!("{}/outbox", actor_url),
        "followers": format!("{}/followers", actor_url),
        "following": format!("{}/following", actor_url),
        "url": base,
        "publicKey": {
            "id": format!("{}#main-key", actor_url),
            "owner": actor_url,
            "publicKeyPem": state.keypair.public_key_pem,
        },
    });
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/activity+json; charset=utf-8"),
    );
    response
}
