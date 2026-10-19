//! NodeInfo 2.1, how a fediverse instance describes itself: what a client shows of an instance
//! before signing in to it — see identity-provider/specs/identity.md § 6.

use std::sync::Arc;

use application::identity::DescribeInstance;
use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use domain::identity::InstanceOrigin;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::ApiError;

const SCHEMA: &str = "http://nodeinfo.diaspora.software/ns/schema/2.1";

/// `GET /.well-known/nodeinfo` — where the document is.
pub async fn discovery(State(origin): State<InstanceOrigin>) -> Json<Value> {
    Json(json!({
        "links": [{ "rel": SCHEMA, "href": format!("{}/nodeinfo/2.1", origin.base_url()) }],
    }))
}

/// `GET /nodeinfo/2.1` — the instance: its software, its accounts, whether anyone may sign up,
/// its name and description.
pub async fn document(State(describe): State<Arc<DescribeInstance>>) -> Result<Response, ApiError> {
    let facts = describe
        .execute(OffsetDateTime::now_utc())
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
    let mut metadata = json!({ "nodeName": facts.name });
    if let Some(description) = facts.description {
        metadata["nodeDescription"] = description.into();
    }
    let document = json!({
        "version": "2.1",
        "software": {
            "name": "pinai",
            "version": env!("CARGO_PKG_VERSION"),
            "repository": "https://github.com/Pina-i/pinai",
        },
        "protocols": ["activitypub"],
        "services": { "inbound": [], "outbound": [] },
        "openRegistrations": facts.open_registrations,
        "usage": { "users": { "total": facts.people } },
        "metadata": metadata,
    });
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "application/json; profile=\"http://nodeinfo.diaspora.software/ns/schema/2.1#\"",
            ),
            (header::CACHE_CONTROL, "public, max-age=60"),
        ],
        document.to_string(),
    )
        .into_response())
}

#[cfg(test)]
mod tests;
