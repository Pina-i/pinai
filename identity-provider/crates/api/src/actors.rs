//! What peers read of this instance's accounts: WebFinger, the actor documents and their
//! collections — see identity-provider/specs/identity.md § 3.

use std::sync::Arc;

use activitypub::{Actor, OrderedCollection, WebFingerResponse};
use application::identity::{FindAccount, WebFinger};
use application::profile::{Person, ShowPerson};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use domain::identity::{Account, InstanceOrigin};
use domain::profile::Pronouns;
use serde::Deserialize;
use serde_json::json;

use crate::ApiError;

/// The instance key's public half, which every actor document publishes.
#[derive(Clone)]
pub struct PublicKeyPem(pub Arc<str>);

const ACTIVITY_JSON: &str = "application/activity+json; charset=utf-8";

fn typed(body: impl serde::Serialize, content_type: &'static str) -> Response {
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

async fn account(find: &FindAccount, slug: &str) -> Result<Account, ApiError> {
    find.execute(slug)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))
}

#[derive(Debug, Deserialize)]
pub struct WebFingerQuery {
    /// e.g. `acct:alice_xk9mp@idp.alice.com`
    resource: String,
}

/// `GET /.well-known/webfinger`
pub async fn web_finger(
    State(web_finger): State<Arc<WebFinger>>,
    State(origin): State<InstanceOrigin>,
    Query(query): Query<WebFingerQuery>,
) -> Result<Response, ApiError> {
    let account = web_finger
        .execute(&query.resource)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let subject = format!("acct:{}@{}", account.username, origin.domain());
    Ok(typed(
        WebFingerResponse::for_actor(&subject, account.actor_uri.as_str()),
        "application/jrd+json; charset=utf-8",
    ))
}

/// `GET /actor` — the instance's `Application` actor, whose key signs inter-instance requests.
pub async fn instance_actor(
    State(origin): State<InstanceOrigin>,
    State(key): State<PublicKeyPem>,
) -> Response {
    let base = origin.base_url();
    let actor_url = format!("{base}/actor");
    let body = json!({
        "@context": ["https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"],
        "id": actor_url,
        "type": "Application",
        "preferredUsername": "instance",
        "name": base,
        "inbox": format!("{actor_url}/inbox"),
        "outbox": format!("{actor_url}/outbox"),
        "followers": format!("{actor_url}/followers"),
        "following": format!("{actor_url}/following"),
        "url": base,
        "publicKey": {
            "id": format!("{actor_url}#main-key"),
            "owner": actor_url,
            "publicKeyPem": &*key.0,
        },
    });
    typed(body, ACTIVITY_JSON)
}

/// `GET /users/{slug}` — an account's `Person`.
pub async fn person(
    State(show): State<Arc<ShowPerson>>,
    State(origin): State<InstanceOrigin>,
    State(key): State<PublicKeyPem>,
    Path(slug): Path<String>,
) -> Result<Response, ApiError> {
    let Person {
        account,
        pronouns,
        bio,
    } = show
        .execute(&slug)
        .await
        .map_err(|e| ApiError::internal(e.into()))?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let name = account.display_name.as_deref().unwrap_or(&account.username);
    let actor = Actor::person(&origin.base_url(), &slug, name, &key.0)
        .with_icon(account.avatar_url.as_deref())
        .with_profile(bio.as_deref(), pronouns.map(Pronouns::as_str));
    Ok(typed(actor, ACTIVITY_JSON))
}

/// `GET /users/{slug}/outbox` — always empty: nothing is published.
pub async fn outbox(
    State(find): State<Arc<FindAccount>>,
    Path(slug): Path<String>,
) -> Result<Response, ApiError> {
    empty(&find, &slug, "outbox").await
}

/// `GET /users/{slug}/followers` — empty: whom an account is friends with is its own business,
/// and no peer reads it.
pub async fn followers(
    State(find): State<Arc<FindAccount>>,
    Path(slug): Path<String>,
) -> Result<Response, ApiError> {
    empty(&find, &slug, "followers").await
}

/// `GET /users/{slug}/following` — empty, as the followers.
pub async fn following(
    State(find): State<Arc<FindAccount>>,
    Path(slug): Path<String>,
) -> Result<Response, ApiError> {
    empty(&find, &slug, "following").await
}

async fn empty(find: &FindAccount, slug: &str, collection: &str) -> Result<Response, ApiError> {
    let account = account(find, slug).await?;
    let id = format!("{}/{collection}", account.actor_uri);
    Ok(typed(OrderedCollection::new(&id, 0, vec![]), ACTIVITY_JSON))
}

#[cfg(test)]
mod tests;
