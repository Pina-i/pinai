//! `GET /api/users/search` and `GET /api/users/lookup` — see
//! identity-provider/specs/identity.md § 7.

use std::sync::Arc;

use application::social::{LookUpAddress, SearchPeople};
use axum::Json;
use axum::extract::{Query, State};
use domain::identity::InstanceOrigin;
use domain::social::{FoundPerson, GroupPerson, PeopleFound, SearchQuery, Standing};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Authenticated;
use crate::{ApiError, RateLimiter};

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    q: String,
    #[serde(default = "twenty")]
    limit: i64,
}

fn twenty() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct PersonBody {
    actor_uri: String,
    address: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    relation: &'static str,
    /// The caller's side of the request, to accept it: with `request_received` only.
    friendship_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct GroupPersonBody {
    #[serde(flatten)]
    person: PersonBody,
    group: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PeopleBody {
    server: Vec<PersonBody>,
    groups: Vec<GroupPersonBody>,
}

impl From<FoundPerson> for PersonBody {
    fn from(person: FoundPerson) -> Self {
        let (relation, friendship_id) = match person.ties.standing() {
            Standing::Blocked => ("blocked", None),
            Standing::Friend => ("friend", None),
            Standing::RequestReceived(id) => ("request_received", Some(id.as_uuid())),
            Standing::RequestSent => ("request_sent", None),
            Standing::Unrelated => ("none", None),
        };
        Self {
            actor_uri: person.actor.to_string(),
            address: person.address.to_string(),
            display_name: person.display_name,
            avatar_url: person.avatar_url,
            relation,
            friendship_id,
        }
    }
}

impl From<GroupPerson> for GroupPersonBody {
    fn from(found: GroupPerson) -> Self {
        Self {
            person: found.person.into(),
            group: found.group,
        }
    }
}

impl From<PeopleFound> for PeopleBody {
    fn from(found: PeopleFound) -> Self {
        Self {
            server: found.server.into_iter().map(Into::into).collect(),
            groups: found.groups.into_iter().map(Into::into).collect(),
        }
    }
}

pub async fn search(
    State(search): State<Arc<SearchPeople>>,
    Authenticated(caller): Authenticated,
    Query(query): Query<SearchParams>,
) -> Result<Json<PeopleBody>, ApiError> {
    let found = search
        .execute(caller, &SearchQuery::parse(&query.q)?, query.limit)
        .await?;
    Ok(Json(found.into()))
}

#[derive(Debug, Deserialize)]
pub struct LookupParams {
    address: String,
}

/// Lookups per caller — each may ask another instance twice and write to its cache: 60, then one
/// a second.
#[derive(Clone)]
pub struct LookupLimiter(pub Arc<RateLimiter>);

impl LookupLimiter {
    pub fn new() -> Self {
        Self(Arc::new(RateLimiter::new(60, 1.0)))
    }
}

impl Default for LookupLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn look_up(
    State(look_up): State<Arc<LookUpAddress>>,
    State(origin): State<InstanceOrigin>,
    State(LookupLimiter(limiter)): State<LookupLimiter>,
    Authenticated(caller): Authenticated,
    Query(query): Query<LookupParams>,
) -> Result<Json<PersonBody>, ApiError> {
    if !limiter.allow(&caller.to_string()) {
        tracing::warn!(user_id = %caller, "rate-limited lookup");
        return Err(ApiError::rate_limited());
    }
    let found = match origin.sought(query.address.trim())? {
        Some(address) => look_up.execute(caller, &address).await?,
        None => None,
    };
    let found = found.ok_or_else(|| ApiError::not_found("No account at this address"))?;
    Ok(Json(found.into()))
}

#[cfg(test)]
mod tests;
