//! The history archive and its key — see identity-provider/specs/e2ee.md § 5.

use std::sync::Arc;

use application::e2ee::{
    ArchiveMessages, ClearArchive, LoadHistoryKey, ReadArchive, SetHistoryKey,
};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{
    ApprovalPublicKey, ArchiveCursor, ArchiveEntry, ArchiveError, ArchiveNonce, HeldHistoryKey,
    HistoryCheckValue, HistoryGeneration, HistoryKey, HistorySalt, NewArchiveEntry,
};
use domain::identity::RECENT_SIGN_IN;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::{Authenticated, RecentlySignedIn, SignedIn};
use crate::e2ee::{
    approval_required, base64_field, device_required, stale_history_key, start_over_refused,
};

#[derive(Deserialize)]
pub struct UploadRequest {
    /// The history key's generation the entries are sealed under: the current one only.
    generation: i64,
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

/// The account's history key, bytes in standard base64, as `PUT` takes it.
#[derive(Deserialize, Serialize)]
pub struct KeyBody {
    generation: i64,
    salt: String,
    check_value: String,
    approval_public_key: String,
}

impl TryFrom<KeyBody> for HistoryKey {
    type Error = ApiError;

    fn try_from(body: KeyBody) -> Result<Self, Self::Error> {
        Ok(HistoryKey {
            generation: HistoryGeneration::parse(body.generation)?,
            salt: base64_field("salt", &body.salt, HistorySalt::parse)?,
            check_value: base64_field("check_value", &body.check_value, HistoryCheckValue::parse)?,
            approval_public_key: base64_field(
                "approval_public_key",
                &body.approval_public_key,
                ApprovalPublicKey::parse,
            )?,
        })
    }
}

/// The same, as `GET` answers it.
#[derive(Serialize)]
pub struct HeldKeyBody {
    #[serde(flatten)]
    key: KeyBody,
    /// The device whose session set it.
    set_by_device: Option<Uuid>,
}

impl From<HeldHistoryKey> for HeldKeyBody {
    fn from(HeldHistoryKey { key, set_by }: HeldHistoryKey) -> Self {
        Self {
            key: KeyBody {
                generation: key.generation.value().into(),
                salt: B64.encode(key.salt.as_bytes()),
                check_value: B64.encode(key.check_value.as_bytes()),
                approval_public_key: B64.encode(key.approval_public_key.as_bytes()),
            },
            set_by_device: set_by.map(|device| device.as_uuid()),
        }
    }
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
    let generation = HistoryGeneration::parse(body.generation)?;
    let entries = body
        .entries
        .into_iter()
        .map(NewArchiveEntry::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let inserted = archive.execute(user, generation, entries).await?;
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
    RecentlySignedIn(bearer): RecentlySignedIn,
) -> Result<Json<ClearedBody>, ApiError> {
    let deleted = clear.execute(&bearer).await?;
    Ok(Json(ClearedBody { deleted }))
}

/// `GET /api/history/key`
pub async fn key(
    State(load): State<Arc<LoadHistoryKey>>,
    Authenticated(user): Authenticated,
) -> Result<Json<HeldKeyBody>, ApiError> {
    Ok(Json(load.execute(user).await?.into()))
}

/// `PUT /api/history/key` — the recent password a later generation takes is the use case's to
/// ask, by the generation.
pub async fn set_key(
    State(set): State<Arc<SetHistoryKey>>,
    SignedIn(bearer): SignedIn,
    Json(body): Json<KeyBody>,
) -> Result<StatusCode, ApiError> {
    set.execute(&bearer, body.try_into()?, OffsetDateTime::now_utc())
        .await?;
    Ok(StatusCode::NO_CONTENT)
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
            ArchiveError::NoKey => ApiError::not_found("No history key set"),
            ArchiveError::Stale(_) => stale_history_key(),
            ArchiveError::KeyConflict { current } => ApiError::new(
                StatusCode::CONFLICT,
                "history_key_conflict",
                "The history key is at another generation",
            )
            .with(
                "current_generation",
                current.map_or(0, HistoryGeneration::value),
            ),
            ArchiveError::RecentSignInRequired => {
                ApiError::insufficient_user_authentication(RECENT_SIGN_IN)
            }
            ArchiveError::StartOver(refusal) => start_over_refused(refusal),
            ArchiveError::DeviceRequired(_) => device_required(),
            ArchiveError::ApprovalRequired(_) => approval_required(),
            ArchiveError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
