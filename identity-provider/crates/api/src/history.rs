//! The history archive — see identity-provider/specs/05-e2ee.md § 5.

use std::sync::Arc;

use application::e2ee::{
    ArchiveMessages, ClearArchive, LoadArchiveSalt, ReadArchive, SetArchiveSalt,
};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{
    ArchiveCursor, ArchiveEntry, ArchiveError, ArchiveNonce, ArchiveSalt, NewArchiveEntry,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::Authenticated;

#[derive(Deserialize)]
pub struct UploadRequest {
    entries: Vec<UploadEntry>,
}

#[derive(Deserialize)]
pub struct UploadEntry {
    /// The message's id.
    id: Uuid,
    conversation_id: Uuid,
    /// Standard base64 of the AES-256-GCM ciphertext.
    ciphertext: String,
    /// Standard base64 of the 12-byte nonce.
    nonce: String,
    #[serde(default)]
    client_message_id: Option<String>,
}

#[derive(Serialize)]
pub struct UploadedBody {
    inserted: usize,
}

#[derive(Deserialize)]
pub struct PageQuery {
    after_id: Option<Uuid>,
    /// RFC 3339; set together with `after_id`.
    after_created_at: Option<String>,
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct EntryBody {
    id: Uuid,
    conversation_id: Uuid,
    ciphertext: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_message_id: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
pub struct CursorBody {
    after_id: Uuid,
    after_created_at: String,
}

#[derive(Serialize)]
pub struct PageBody {
    entries: Vec<EntryBody>,
    next_cursor: Option<CursorBody>,
}

#[derive(Serialize)]
pub struct ClearedBody {
    deleted: usize,
}

#[derive(Deserialize, Serialize)]
pub struct SaltBody {
    salt_base64: String,
}

fn rfc3339(at: OffsetDateTime) -> Result<String, ApiError> {
    at.format(&Rfc3339)
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))
}

impl TryFrom<UploadEntry> for NewArchiveEntry {
    type Error = ApiError;

    fn try_from(entry: UploadEntry) -> Result<Self, Self::Error> {
        let ciphertext = B64
            .decode(&entry.ciphertext)
            .map_err(|_| ApiError::bad_request("ciphertext must be base64"))?;
        let nonce = B64
            .decode(&entry.nonce)
            .map_err(|_| ApiError::bad_request("nonce must be base64"))?;
        Ok(NewArchiveEntry {
            id: entry.id.into(),
            conversation: entry.conversation_id.into(),
            ciphertext,
            nonce: ArchiveNonce::parse(&nonce)
                .map_err(|_| ApiError::bad_request("nonce must be 12 bytes (AES-GCM)"))?,
            client_message_id: entry.client_message_id,
        })
    }
}

impl TryFrom<ArchiveEntry> for EntryBody {
    type Error = ApiError;

    fn try_from(entry: ArchiveEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            id: entry.id.as_uuid(),
            conversation_id: entry.conversation.as_uuid(),
            ciphertext: B64.encode(&entry.ciphertext),
            nonce: B64.encode(entry.nonce.as_bytes()),
            client_message_id: entry.client_message_id,
            created_at: rfc3339(entry.created_at)?,
        })
    }
}

/// `POST /api/history/messages`
pub async fn upload(
    State(archive): State<Arc<ArchiveMessages>>,
    Authenticated(user): Authenticated,
    Json(body): Json<UploadRequest>,
) -> Result<Json<UploadedBody>, ApiError> {
    let entries = body
        .entries
        .into_iter()
        .map(NewArchiveEntry::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let inserted = archive.execute(user, entries).await?;
    Ok(Json(UploadedBody { inserted }))
}

/// `GET /api/history/messages?after_id=&after_created_at=&limit=`
pub async fn page(
    State(read): State<Arc<ReadArchive>>,
    Authenticated(user): Authenticated,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageBody>, ApiError> {
    let after = match (query.after_id, query.after_created_at.as_deref()) {
        (Some(id), Some(at)) => Some(ArchiveCursor {
            created_at: OffsetDateTime::parse(at, &Rfc3339)
                .map_err(|_| ApiError::bad_request("after_created_at not RFC3339"))?,
            id: id.into(),
        }),
        (None, None) => None,
        _ => {
            return Err(ApiError::bad_request(
                "after_id and after_created_at must be set together",
            ));
        }
    };
    let page = read.execute(user, after, query.limit).await?;
    Ok(Json(PageBody {
        next_cursor: page
            .next
            .map(|next| {
                Ok::<_, ApiError>(CursorBody {
                    after_id: next.id.as_uuid(),
                    after_created_at: rfc3339(next.created_at)?,
                })
            })
            .transpose()?,
        entries: page
            .entries
            .into_iter()
            .map(EntryBody::try_from)
            .collect::<Result<_, _>>()?,
    }))
}

/// `DELETE /api/history/messages`
pub async fn clear(
    State(clear): State<Arc<ClearArchive>>,
    Authenticated(user): Authenticated,
) -> Result<Json<ClearedBody>, ApiError> {
    let deleted = clear.execute(user).await?;
    Ok(Json(ClearedBody { deleted }))
}

/// `GET /api/history/salt`
pub async fn salt(
    State(load): State<Arc<LoadArchiveSalt>>,
    Authenticated(user): Authenticated,
) -> Result<Json<SaltBody>, ApiError> {
    let salt = load.execute(user).await?;
    Ok(Json(SaltBody {
        salt_base64: B64.encode(salt.as_bytes()),
    }))
}

/// `POST /api/history/salt`
pub async fn set_salt(
    State(set): State<Arc<SetArchiveSalt>>,
    Authenticated(user): Authenticated,
    Json(body): Json<SaltBody>,
) -> Result<Json<SaltBody>, ApiError> {
    let salt = B64
        .decode(&body.salt_base64)
        .map_err(|_| ApiError::bad_request("salt must be base64"))?;
    let salt = ArchiveSalt::parse(&salt)
        .map_err(|_| ApiError::bad_request("salt must be exactly 16 bytes"))?;
    let held = set.execute(user, salt).await?;
    Ok(Json(SaltBody {
        salt_base64: B64.encode(held.as_bytes()),
    }))
}

impl From<ArchiveError> for ApiError {
    fn from(error: ArchiveError) -> Self {
        match error {
            ArchiveError::Refused(refusal) => ApiError::bad_request(refusal.to_string()),
            ArchiveError::NotAMember => ApiError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "not a member of one or more conversations",
            ),
            ArchiveError::NoSalt => ApiError::not_found("no salt set"),
            ArchiveError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
