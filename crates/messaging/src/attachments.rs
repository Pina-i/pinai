//! `POST /api/attachments` — upload one or more files as orphan attachments.
//!
//! Orphans are owned by the uploader and reaped by the orphan-sweep task if
//! not linked to a message within `attachment_orphan_ttl`. The follow-up call
//! `POST /api/dm` accepts an `attachment_ids` array to link them.

use axum::{
    extract::{Multipart, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use idp_db::models::Attachment;
use idp_db::repos::{attachments, conversations, messages, users};
use idp_federation::auth::require_auth;
use idp_state::{AppState, OidcError};

use crate::blob::{build_blob_url, mint_blob_token};

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentMetadata {
    pub id: Uuid,
    pub mime_type: String,
    pub byte_size: i64,
    pub original_filename: String,
}

impl From<&Attachment> for AttachmentMetadata {
    fn from(a: &Attachment) -> Self {
        Self {
            id: a.id,
            mime_type: a.mime_type.clone(),
            byte_size: a.byte_size,
            original_filename: a.original_filename.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UploadAttachmentsResponse {
    pub attachments: Vec<AttachmentMetadata>,
}

/// Accept up to `attachment_max_files_per_message` parts of `multipart/form-data`.
/// Each part must have a filename; the part name is ignored. The returned IDs
/// are the orphan attachment rows the caller can reference in `POST /api/dm`.
#[tracing::instrument(skip_all)]
pub async fn upload_attachments(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadAttachmentsResponse>), OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let storage = state
        .storage
        .as_ref()
        .ok_or_else(|| OidcError::server_error("Object storage not configured"))?;

    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Authenticated user not found"))?;

    let actor_uri = user
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Authenticated user has no actor_uri"))?;

    let max_files = state.config.attachment_max_files_per_message;
    let max_bytes = state.config.attachment_max_byte_size;

    // ── Collect & validate parts ─────────────────────────────────────────────
    // We hold all parts in memory before any side effect so that a validation
    // failure on file N doesn't leave files 1..N-1 uploaded as orphans.

    struct ParsedPart {
        id: Uuid,
        bytes: Vec<u8>,
        mime: String,
        filename: String,
    }

    let mut parsed: Vec<ParsedPart> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| OidcError::invalid_request(format!("multipart error: {e}")))?
    {
        if parsed.len() >= max_files {
            return Err(OidcError::invalid_request(format!(
                "too many files (max {max_files} per request)"
            )));
        }

        let filename = field
            .file_name()
            .ok_or_else(|| OidcError::invalid_request("file part missing filename"))?
            .to_string();

        let mime = field
            .content_type()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        // Extension blocklist BEFORE reading bytes.
        if let Some(ext) = file_extension(&filename) {
            if state
                .config
                .attachment_blocked_extensions
                .iter()
                .any(|b| b == &ext)
            {
                return Err(OidcError::invalid_request(format!(
                    "file extension '.{ext}' is not allowed"
                )));
            }
        }

        let mime_lower = mime.to_lowercase();
        if state
            .config
            .attachment_blocked_mimes
            .iter()
            .any(|b| b == &mime_lower)
        {
            return Err(OidcError::invalid_request(format!(
                "MIME type '{mime}' is not allowed"
            )));
        }

        let bytes = field
            .bytes()
            .await
            .map_err(|e| OidcError::invalid_request(format!("multipart read error: {e}")))?
            .to_vec();

        if bytes.is_empty() {
            return Err(OidcError::invalid_request(format!(
                "file '{filename}' is empty"
            )));
        }
        if bytes.len() as u64 > max_bytes {
            return Err(OidcError::invalid_request(format!(
                "file '{filename}' exceeds max size of {max_bytes} bytes"
            )));
        }

        parsed.push(ParsedPart {
            id: Uuid::new_v4(),
            bytes,
            mime,
            filename,
        });
    }

    if parsed.is_empty() {
        return Err(OidcError::invalid_request("no files in upload"));
    }

    // ── Upload + insert ──────────────────────────────────────────────────────
    // Track success so we can roll back partial work on the first failure.

    let mut uploaded_keys: Vec<String> = Vec::new();
    let mut inserted: Vec<Attachment> = Vec::new();

    for part in parsed {
        let storage_key = part.id.to_string();
        let byte_size = part.bytes.len() as i64;

        if let Err(e) = storage
            .upload_attachment(&storage_key, part.bytes, &part.mime)
            .await
        {
            rollback(storage, &state.pool, &uploaded_keys, &inserted).await;
            return Err(OidcError::server_error(format!("upload failed: {e}")));
        }
        uploaded_keys.push(storage_key.clone());

        match attachments::insert_orphan(
            &state.pool,
            part.id,
            actor_uri,
            &storage_key,
            &part.mime,
            byte_size,
            &part.filename,
        )
        .await
        {
            Ok(row) => inserted.push(row),
            Err(e) => {
                rollback(storage, &state.pool, &uploaded_keys, &inserted).await;
                return Err(OidcError::server_error(format!("DB insert failed: {e}")));
            }
        }
    }

    tracing::info!(
        user = %user.username,
        count = inserted.len(),
        "attachments uploaded as orphans"
    );

    let response = UploadAttachmentsResponse {
        attachments: inserted.iter().map(AttachmentMetadata::from).collect(),
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Best-effort cleanup of partially-uploaded attachments after a failure.
async fn rollback(
    storage: &idp_storage::StorageClient,
    pool: &idp_db::PgPool,
    uploaded_keys: &[String],
    inserted: &[Attachment],
) {
    for key in uploaded_keys {
        if let Err(e) = storage.delete_attachment(key).await {
            tracing::warn!(key = %key, "rollback: failed to delete uploaded object: {e}");
        }
    }
    for row in inserted {
        if let Err(e) = attachments::delete_by_id(pool, row.id).await {
            tracing::warn!(id = %row.id, "rollback: failed to delete attachment row: {e}");
        }
    }
}

/// Extract a lowercased extension (no leading dot) from a filename.
/// Returns None if there's no dot or the dot is the leading character.
fn file_extension(filename: &str) -> Option<String> {
    let (stem, ext) = filename.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext.to_lowercase())
}

// ── Read: GET /api/attachments/{id} ──────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AttachmentUrlResponse {
    /// Token-protected URL on this IdP. Resolves to a `302` redirect (local
    /// attachments) or a streamed response (remote attachments, Phase 10).
    pub url: String,
    /// RFC 3339. The token expires after this; clients should re-fetch this
    /// envelope to mint a new one.
    pub expires_at: String,
    pub mime_type: String,
    pub byte_size: i64,
    pub original_filename: String,
}

/// `GET /api/attachments/{id}` — Bearer auth.
///
/// Access check:
/// - Caller is the uploader of the row, OR
/// - Caller is a member of the conversation containing the linked message.
///
/// Returns a JSON envelope whose `url` points at this IdP's `/blob` endpoint
/// with a fresh HMAC token.
#[tracing::instrument(skip_all, fields(id = %id))]
pub async fn get_attachment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Authenticated user not found"))?;
    let caller_actor_uri = user
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Authenticated user has no actor_uri"))?;

    let attachment = attachments::find_by_id(&state.pool, id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Attachment not found"))?;

    let allowed = if attachment.uploaded_by_actor_uri == caller_actor_uri {
        true
    } else if let Some(message_id) = attachment.message_id {
        // Linked: caller must be a conversation member.
        let msg = messages::find_by_id(&state.pool, message_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .ok_or_else(|| OidcError::not_found("Attachment's message not found"))?;
        if msg.deleted_at.is_some() {
            return Err(OidcError::not_found("Attachment's message is deleted"));
        }
        let members = conversations::get_members(&state.pool, msg.conversation_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        members.iter().any(|m| m.actor_uri == caller_actor_uri)
    } else {
        // Orphan owned by someone else.
        false
    };

    if !allowed {
        return Err(OidcError::access_denied("Not authorised to access attachment"));
    }

    let (token, expires_at_system) = mint_blob_token(
        state.config.session_secret.as_bytes(),
        user_id,
        id,
        state.config.attachment_url_ttl,
    );

    let expires_at = format_rfc3339(expires_at_system);
    let url = build_blob_url(&state.config.issuer(), id, &token);

    let body = AttachmentUrlResponse {
        url,
        expires_at,
        mime_type: attachment.mime_type,
        byte_size: attachment.byte_size,
        original_filename: attachment.original_filename,
    };

    let mut response = (StatusCode::OK, Json(body)).into_response();
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

/// Format a `SystemTime` as an RFC 3339 string with second precision.
fn format_rfc3339(t: SystemTime) -> String {
    use time::format_description::well_known::Rfc3339;
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_default()
}

// ── Cleanup helpers ──────────────────────────────────────────────────────────
//
// Reused by:
//   - The orphan-sweep background task (Phase 6).
//   - A future message-delete handler (when one lands; the schema's
//     `deleted_at` column is currently unused).
//   - A future AP `Delete{Note}` inbox path.
//
// All errors are logged, not propagated — these are best-effort cleanup
// helpers and the orphan sweep is the safety net for any RustFS object that
// fails to delete.

/// Delete a single attachment: remove the bytes from RustFS (for local rows)
/// and then the DB row. Idempotent.
pub async fn delete_attachment_with_object(
    pool: &idp_db::PgPool,
    storage: Option<&idp_storage::StorageClient>,
    attachment: &Attachment,
) {
    if attachment.remote_origin_url.is_none() {
        if let Some(s) = storage {
            if let Err(e) = s.delete_attachment(&attachment.storage_key).await {
                tracing::warn!(
                    attachment_id = %attachment.id,
                    "storage delete failed: {e}"
                );
            }
        }
    }
    if let Err(e) = attachments::delete_by_id(pool, attachment.id).await {
        tracing::warn!(
            attachment_id = %attachment.id,
            "row delete failed: {e}"
        );
    }
}

/// Hard-delete every attachment linked to `message_id`. Call this **before**
/// setting `deleted_at` on a message so a failure here doesn't leave RustFS
/// objects orphaned. Errors loading the rows are propagated; per-attachment
/// errors are logged.
pub async fn delete_attachments_for_message(
    pool: &idp_db::PgPool,
    storage: Option<&idp_storage::StorageClient>,
    message_id: Uuid,
) -> Result<(), sqlx::Error> {
    let rows = attachments::find_for_message(pool, message_id).await?;
    for row in &rows {
        delete_attachment_with_object(pool, storage, row).await;
    }
    Ok(())
}

// ── ActivityPub outbound ─────────────────────────────────────────────────────

/// Append `Document` entries to a `Create{Note}` activity's `object.attachment`
/// array. Each entry's `url` points at this IdP's HTTP-Signature-protected
/// `/api/attachments/{id}/content` endpoint — peer IdPs fetch from there.
///
/// No-op when `attachments` is empty.
pub fn inject_attachments_into_ap_activity(
    activity: &mut serde_json::Value,
    issuer: &str,
    attachments: &[AttachmentMetadata],
) {
    if attachments.is_empty() {
        return;
    }

    let docs: Vec<serde_json::Value> = attachments
        .iter()
        .map(|a| {
            serde_json::json!({
                "type": "Document",
                "mediaType": a.mime_type,
                "url": format!("{}/api/attachments/{}/content", issuer, a.id),
                "name": a.original_filename,
                "size": a.byte_size,
            })
        })
        .collect();

    if let Some(obj) = activity.get_mut("object").and_then(|o| o.as_object_mut()) {
        obj.insert("attachment".to_string(), serde_json::Value::Array(docs));
    }
}
