//! `/api/history/*` — encrypted plaintext archive. Server stores opaque
//! ciphertexts; clients derive the History Archive Key via
//! Argon2id(passphrase, salt) and encrypt every decrypted plaintext
//! before upload.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tracing::instrument;
use uuid::Uuid;

use idp_db::repos::{history_messages, history_salt, users};
use idp_federation::auth::require_auth;
use idp_state::{AppState, OidcError};

const BATCH_CAP: usize = 50;
const DEFAULT_PAGE_LIMIT: i64 = 100;
const MAX_PAGE_LIMIT: i64 = 500;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;

// ─── POST /api/history/messages ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PostBatchRequest {
    pub entries: Vec<PostBatchEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PostBatchEntry {
    pub id: Uuid,
    pub conversation_id: Uuid,
    /// Standard-base64-encoded AES-256-GCM ciphertext.
    pub ciphertext: String,
    /// Standard-base64-encoded 12-byte nonce.
    pub nonce: String,
    #[serde(default)]
    pub client_message_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PostBatchResponse {
    pub inserted: usize,
}

#[instrument(skip_all, fields(entries = body.entries.len()))]
pub async fn post_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PostBatchRequest>,
) -> Result<Json<PostBatchResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    if body.entries.is_empty() || body.entries.len() > BATCH_CAP {
        return Err(OidcError::invalid_request(format!(
            "batch size must be 1..={BATCH_CAP}"
        )));
    }

    // Membership is keyed by actor_uri in conversation_members.
    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("authenticated user vanished"))?;
    let actor_uri = user
        .actor_uri
        .ok_or_else(|| OidcError::server_error("user has no actor_uri"))?;
    let convo_ids: Vec<Uuid> = body.entries.iter().map(|e| e.conversation_id).collect();
    let allowed = member_of_conversations(&state.pool, &actor_uri, &convo_ids).await?;
    if allowed.len() != dedup_count(&convo_ids) {
        return Err(OidcError::access_denied(
            "not a member of one or more conversations",
        ));
    }

    // Validate every entry before any DB write — partial batches are worse than rejection.
    let mut decoded: Vec<(Uuid, Uuid, Vec<u8>, Vec<u8>, Option<String>)> =
        Vec::with_capacity(body.entries.len());
    for e in body.entries {
        let ct = Base64::decode_vec(&e.ciphertext)
            .map_err(|_| OidcError::invalid_request("ciphertext must be base64"))?;
        let nc = Base64::decode_vec(&e.nonce)
            .map_err(|_| OidcError::invalid_request("nonce must be base64"))?;
        if nc.len() != NONCE_BYTES {
            return Err(OidcError::invalid_request("nonce must be 12 bytes (AES-GCM)"));
        }
        decoded.push((e.id, e.conversation_id, ct, nc, e.client_message_id));
    }

    let entries: Vec<_> = decoded
        .iter()
        .map(|(id, convo, ct, nc, cmid)| history_messages::InsertEntry {
            id: *id,
            conversation_id: *convo,
            ciphertext: ct.as_slice(),
            nonce: nc.as_slice(),
            client_message_id: cmid.as_deref(),
        })
        .collect();
    let inserted = history_messages::insert_batch(&state.pool, user_id, &entries)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    Ok(Json(PostBatchResponse { inserted }))
}

// ─── GET /api/history/messages ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub after_id: Option<Uuid>,
    /// RFC3339 timestamp; required when `after_id` is set.
    pub after_created_at: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    DEFAULT_PAGE_LIMIT
}

#[derive(Debug, Serialize)]
pub struct PageResponse {
    pub entries: Vec<PageEntry>,
    pub next_cursor: Option<NextCursor>,
}

#[derive(Debug, Serialize)]
pub struct PageEntry {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub ciphertext: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_message_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct NextCursor {
    pub after_id: Uuid,
    pub after_created_at: String,
}

#[instrument(skip_all)]
pub async fn get_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Result<Json<PageResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    let limit = q.limit.clamp(1, MAX_PAGE_LIMIT);

    let after = match (q.after_id, q.after_created_at.as_deref()) {
        (Some(id), Some(ts)) => {
            let t = OffsetDateTime::parse(ts, &Rfc3339)
                .map_err(|_| OidcError::invalid_request("after_created_at not RFC3339"))?;
            Some((t, id))
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(OidcError::invalid_request(
                "after_id and after_created_at must be set together",
            ));
        }
        (None, None) => None,
    };

    let rows = history_messages::page(&state.pool, user_id, after, limit)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let next_cursor = rows.last().map(|r| NextCursor {
        after_id: r.id,
        after_created_at: r
            .created_at
            .format(&Rfc3339)
            .expect("RFC3339 format never fails"),
    });
    let entries = rows
        .into_iter()
        .map(|r| PageEntry {
            id: r.id,
            conversation_id: r.conversation_id,
            ciphertext: Base64::encode_string(&r.ciphertext),
            nonce: Base64::encode_string(&r.nonce),
            client_message_id: r.client_message_id,
            created_at: r
                .created_at
                .format(&Rfc3339)
                .expect("RFC3339 format never fails"),
        })
        .collect();
    Ok(Json(PageResponse {
        entries,
        next_cursor,
    }))
}

// ─── DELETE /api/history/messages ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub deleted: u64,
}

#[instrument(skip_all)]
pub async fn delete_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<DeleteResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    let n = history_messages::delete_all(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    Ok(Json(DeleteResponse { deleted: n }))
}

// ─── GET/POST /api/history/salt ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SaltResponse {
    pub salt_base64: String,
}

#[instrument(skip_all)]
pub async fn get_salt(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<SaltResponse>), OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    match history_salt::get(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    {
        Some(s) => Ok((
            StatusCode::OK,
            Json(SaltResponse {
                salt_base64: Base64::encode_string(&s),
            }),
        )),
        None => Err(OidcError::not_found("no salt set")),
    }
}

#[derive(Debug, Deserialize)]
pub struct PostSaltRequest {
    pub salt_base64: String,
}

#[instrument(skip_all)]
pub async fn post_salt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PostSaltRequest>,
) -> Result<Json<SaltResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    let salt = Base64::decode_vec(&body.salt_base64)
        .map_err(|_| OidcError::invalid_request("salt must be base64"))?;
    if salt.len() != SALT_BYTES {
        return Err(OidcError::invalid_request("salt must be exactly 16 bytes"));
    }
    let stored = history_salt::set_if_unset(&state.pool, user_id, &salt)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    Ok(Json(SaltResponse {
        salt_base64: Base64::encode_string(&stored),
    }))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Subset of `conversation_ids` the actor is or was a member of.
async fn member_of_conversations(
    pool: &PgPool,
    actor_uri: &str,
    conversation_ids: &[Uuid],
) -> Result<Vec<Uuid>, OidcError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT conversation_id
        FROM conversation_members
        WHERE actor_uri = $1
          AND conversation_id = ANY($2)
        "#,
    )
    .bind(actor_uri)
    .bind(conversation_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

fn dedup_count(ids: &[Uuid]) -> usize {
    let mut copy: Vec<_> = ids.iter().copied().collect();
    copy.sort();
    copy.dedup();
    copy.len()
}
