# Errors

Errors serve two purposes: **control flow** (the caller reacts — read by code, so it needs types and
variants) and **reporting** (a human diagnoses — read from logs, so it needs the full cause chain).
At the HTTP edge, control flow becomes the status code and reporting becomes the response body.

## Contents
1. Domain and application enums
2. Port errors and adapters
3. `ApiError` at the edge
4. Logging
5. OAuth and bearer endpoints

## 1. Domain and application enums

```rust
// domain/src/social/error.rs
#[derive(Debug, thiserror::Error)]
pub enum SocialError {
    #[error("the two users are not friends")]
    NotFriends,
    #[error("a user cannot befriend themselves")]
    SelfRequest,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}
```

- One enum per bounded context. Add a per-use-case enum only when its caller reacts differently —
  e.g. a commit race carrying the winning commit: `PostCommitError::EpochConflict { winning }`.
- Variants name what the **caller** reacts to, never the step that failed. "Ball of mud" enums
  (one variant per fallible call) leak implementation and nobody matches on them.
- `Unexpected` carries an opaque `anyhow::Error`: the caller only reports it. `anyhow` is used
  nowhere else in the domain — no use case returns `anyhow::Result`.
- `Display` is a short message; `Debug` is for operators. `anyhow`'s `{:?}` already prints the whole
  `Caused by:` chain, so no hand-written chain formatter is needed.

## 2. Port errors and adapters

```rust
// domain/src/social/ports.rs
#[derive(Debug, thiserror::Error)]
pub enum SocialStoreError {
    #[error("the friendship changed concurrently")]
    Conflict,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}
```

```rust
// infrastructure/src/postgres/social.rs
use anyhow::Context;

async fn insert_friendship(c: &mut PgConnection, row: &NewFriendship) -> Result<(), SocialStoreError> {
    sqlx::query("INSERT INTO friendships (id, owner_user_id, friend_actor_uri) VALUES ($1, $2, $3)")
        .bind(row.id.as_uuid())
        .bind(row.owner.as_uuid())
        .bind(row.friend.as_str())
        .execute(c)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                SocialStoreError::Conflict
            } else {
                anyhow::Error::new(e).context("insert friendship").into()
            }
        })?;
    Ok(())
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

async fn friend_uris(c: &mut PgConnection, owner: UserId) -> Result<Vec<String>, SocialStoreError> {
    let uris = sqlx::query_scalar("SELECT friend_actor_uri FROM friendships WHERE owner_user_id = $1")
        .bind(owner.as_uuid())
        .fetch_all(c)
        .await
        .context("list friend actor URIs")?;
    Ok(uris)
}
```

- Absence is `Option`, not an error variant.
- The adapter owns the SQLSTATE codes (`23505` unique violation, `23514` check violation…). A
  handler or use case matching on a database code is a layering bug.
- `.context("…")` states what the code was doing; the source stays attached for the logs.
- Use cases convert port errors into their context error with `From` or a `map_err` at the call
  site when the same port error means different things in different flows.

## 3. `ApiError` at the edge

The orphan rule forbids `impl IntoResponse for application::SocialError` in `api`, and HTTP does not
belong in `application` anyway, so `api` owns one type:

```rust
// api/src/error.rs — as scaffolded by rust-bootstrap-backend-project
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    description: String,
    source: Option<anyhow::Error>,
    extra: serde_json::Map<String, serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self { status, code, description: description.into(), source: None, extra: Default::default() }
    }
    pub fn bad_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }
    pub fn not_found(description: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", description)
    }
    pub fn internal(source: anyhow::Error) -> Self {
        Self { source: Some(source), ..Self::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal error") }
    }
    /// Extra top-level fields, e.g. `winning_commit` on a 409.
    pub fn with(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.extra.insert(key.to_owned(), value.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match &self.source {
            Some(source) if self.status.is_server_error() => tracing::error!(error = ?source, "request failed"),
            _ => tracing::debug!(status = %self.status, code = self.code, "request refused"),
        }
        let mut body = self.extra;
        body.insert("error".into(), self.code.into());
        body.insert("error_description".into(), self.description.into());
        (self.status, Json(body)).into_response()
    }
}

impl From<SocialError> for ApiError {
    fn from(e: SocialError) -> Self {
        match e {
            SocialError::NotFriends => ApiError::not_found("Friendship not found"),
            SocialError::SelfRequest => ApiError::bad_request("Cannot befriend yourself"),
            SocialError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

impl From<ValidationError> for ApiError {
    fn from(e: ValidationError) -> Self {
        ApiError::bad_request(e.to_string())
    }
}
```

- The `match` in each `From` impl **is** the status-code policy — one place per context.
- A 4xx description helps the caller fix the request. A 500 description is fixed: database, Redis
  or peer error text never reaches a client.
- Hiding existence: "not a member" is usually a 404, not a 403.
- Handlers return `Result<impl IntoResponse, ApiError>` and use `?` freely.

## 4. Logging

"Errors should be logged when they are handled."

- **HTTP**: once, at the edge — `IntoResponse` above logs 5xx at `error` with the full chain and 4xx
  at `debug`, inside the request span of the trace layer. A later refinement: put the error in
  response extensions and log it from the trace layer's `on_failure`.
- **Background tasks** (spawned deliveries, sweeps, workers) are their own edge: log once where the
  error is finally handled, then drop it.
- Never log in an error constructor, and never log-and-return: the caller would log it again.
- Use `tracing`, never `println!` or `log`. Record fields (`error = ?e`, `conversation_id = %id`)
  rather than formatting them into the message.

## 5. OAuth and bearer endpoints

- OAuth 2 token endpoints answer with the RFC 6749 §5.2 codes only: `invalid_request`,
  `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`,
  `invalid_scope`. Model them as a restricted enum in `api` rather than free strings.
- A missing or invalid bearer token is `401` with code `invalid_token` (RFC 6750) and a
  `WWW-Authenticate: Bearer` header — not `invalid_client`.
