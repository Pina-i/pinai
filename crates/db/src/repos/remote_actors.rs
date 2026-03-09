use sqlx::PgPool;

use crate::models::RemoteActor;

/// Insert or update a remote actor in the cache.
pub async fn upsert(
    pool: &PgPool,
    actor_uri: &str,
    username: &str,
    instance: &str,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<RemoteActor, sqlx::Error> {
    sqlx::query_as::<_, RemoteActor>(
        r#"
        INSERT INTO remote_actors (actor_uri, username, instance, display_name, avatar_url)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (actor_uri) DO UPDATE SET
            username = EXCLUDED.username,
            display_name = EXCLUDED.display_name,
            avatar_url = EXCLUDED.avatar_url,
            fetched_at = now(),
            updated_at = now()
        RETURNING *
        "#,
    )
    .bind(actor_uri)
    .bind(username)
    .bind(instance)
    .bind(display_name)
    .bind(avatar_url)
    .fetch_one(pool)
    .await
}

pub async fn find_by_actor_uri(
    pool: &PgPool,
    actor_uri: &str,
) -> Result<Option<RemoteActor>, sqlx::Error> {
    sqlx::query_as::<_, RemoteActor>("SELECT * FROM remote_actors WHERE actor_uri = $1")
        .bind(actor_uri)
        .fetch_optional(pool)
        .await
}

/// Update a remote actor's profile (triggered by AP Update activity).
pub async fn update_profile(
    pool: &PgPool,
    actor_uri: &str,
    username: Option<&str>,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<Option<RemoteActor>, sqlx::Error> {
    sqlx::query_as::<_, RemoteActor>(
        r#"
        UPDATE remote_actors
        SET username     = COALESCE($2, username),
            display_name = $3,
            avatar_url   = $4,
            updated_at   = now()
        WHERE actor_uri = $1
        RETURNING *
        "#,
    )
    .bind(actor_uri)
    .bind(username)
    .bind(display_name)
    .bind(avatar_url)
    .fetch_optional(pool)
    .await
}
