use sqlx::PgPool;

use crate::models::OAuthClient;

pub async fn find_client_by_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<OAuthClient>, sqlx::Error> {
    sqlx::query_as::<_, OAuthClient>("SELECT * FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_optional(pool)
        .await
}

/// Returns true if `redirect_uri` is registered for this client.
/// Performs case-sensitive exact match (required by RFC 6749 §3.1.2).
pub async fn validate_redirect_uri(
    pool: &PgPool,
    client_id: &str,
    redirect_uri: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT $2 = ANY(redirect_uris) FROM oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .bind(redirect_uri)
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(v,)| v).unwrap_or(false))
}
