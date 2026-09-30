//! `GET /api/users/search`.

use std::sync::Arc;

use application::identity::SearchAccounts;
use axum::Json;
use axum::extract::{Query, State};
use domain::identity::{AccountsError, SearchQuery};
use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::auth::Authenticated;

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
pub struct AccountSummary {
    actor_uri: String,
    username: String,
    display_name: Option<String>,
}

pub async fn search(
    State(search): State<Arc<SearchAccounts>>,
    Authenticated(_): Authenticated,
    Query(query): Query<SearchParams>,
) -> Result<Json<Vec<AccountSummary>>, ApiError> {
    let found = search
        .execute(&SearchQuery::parse(&query.q)?, query.limit)
        .await?;
    Ok(Json(
        found
            .into_iter()
            .map(|account| AccountSummary {
                actor_uri: account.actor_uri.to_string(),
                username: account.username,
                display_name: account.display_name,
            })
            .collect(),
    ))
}

impl From<AccountsError> for ApiError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
