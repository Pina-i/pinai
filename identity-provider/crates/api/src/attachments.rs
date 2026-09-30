//! Attachments — see identity-provider/specs/03-direct-messages.md § 9.

use std::sync::Arc;

use application::messaging::{Blob, OpenAttachment, ReadBlob, ServePeerContent, UploadAttachments};
use axum::Json;
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use domain::AttachmentId;
use domain::identity::InstanceOrigin;
use domain::messaging::{AttachmentError, AttachmentLimits, AttachmentView, UploadFile};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::{Authenticated, SignedPeer};

#[derive(Serialize)]
pub struct AttachmentBody {
    id: Uuid,
    mime_type: String,
    byte_size: i64,
    original_filename: String,
}

#[derive(Serialize)]
pub struct UploadedBody {
    attachments: Vec<AttachmentBody>,
}

#[derive(Serialize)]
pub struct OpenedBody {
    /// A token-protected URL on this instance.
    url: String,
    /// RFC 3339; the client opens the attachment again for a fresh token.
    expires_at: String,
    mime_type: String,
    byte_size: i64,
    original_filename: String,
}

#[derive(Deserialize)]
pub struct BlobQuery {
    token: String,
}

impl From<AttachmentView> for AttachmentBody {
    fn from(view: AttachmentView) -> Self {
        Self {
            id: view.id.as_uuid(),
            mime_type: view.mime_type,
            byte_size: view.byte_size,
            original_filename: view.original_filename,
        }
    }
}

fn multipart_error(e: impl std::fmt::Display, what: &str) -> ApiError {
    ApiError::bad_request(format!("{what}: {e}"))
}

/// `POST /api/attachments` — `multipart/form-data`: file parts, and optionally one
/// `attachment_id` the client chose for a single file.
pub async fn upload(
    State(upload): State<Arc<UploadAttachments>>,
    State(limits): State<AttachmentLimits>,
    Authenticated(user): Authenticated,
    mut multipart: Multipart,
) -> Result<Json<UploadedBody>, ApiError> {
    let mut files = Vec::new();
    let mut chosen: Option<AttachmentId> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_error(e, "multipart error"))?
    {
        if field.name() == Some("attachment_id") {
            if chosen.is_some() {
                return Err(ApiError::bad_request(
                    "duplicate `attachment_id` form field",
                ));
            }
            let raw = field
                .text()
                .await
                .map_err(|e| multipart_error(e, "multipart read error"))?;
            let id: Uuid = raw
                .parse()
                .map_err(|_| ApiError::bad_request("`attachment_id` is not a UUID"))?;
            chosen = Some(id.into());
            continue;
        }
        limits.check_count(files.len() + 1).map_err(refused)?;
        let filename = field
            .file_name()
            .ok_or_else(|| ApiError::bad_request("file part missing filename"))?
            .to_owned();
        let mime_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_owned();
        // Refused before the bytes are read.
        limits.check_file(&filename, &mime_type).map_err(refused)?;
        let bytes = field
            .bytes()
            .await
            .map_err(|e| multipart_error(e, "multipart read error"))?;
        files.push(UploadFile::new(&limits, filename, mime_type, bytes.to_vec()).map_err(refused)?);
    }
    let views = upload.execute(user, files, chosen).await?;
    tracing::info!(user_id = %user, count = views.len(), "attachments uploaded as orphans");
    Ok(Json(UploadedBody {
        attachments: views.into_iter().map(AttachmentBody::from).collect(),
    }))
}

fn refused(refusal: domain::messaging::UploadRefusal) -> ApiError {
    ApiError::bad_request(refusal.to_string())
}

/// `GET /api/attachments/{id}`
pub async fn open(
    State(open): State<Arc<OpenAttachment>>,
    State(origin): State<InstanceOrigin>,
    Authenticated(user): Authenticated,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let opened = open.execute(user, id.into()).await?;
    let a = opened.attachment;
    let body = OpenedBody {
        url: format!(
            "{}/api/attachments/{id}/blob?token={}",
            origin.base_url(),
            opened.token
        ),
        expires_at: opened
            .expires_at
            .replace_nanosecond(0)
            .ok()
            .and_then(|at| at.format(&Rfc3339).ok())
            .unwrap_or_default(),
        mime_type: a.mime_type,
        byte_size: a.byte_size,
        original_filename: a.original_filename,
    };
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

/// `GET /api/attachments/{id}/blob?token=` — the token is the authorisation: a browser cannot
/// send a bearer token with an `<img>`.
pub async fn blob(
    State(read): State<Arc<ReadBlob>>,
    Path(id): Path<Uuid>,
    Query(query): Query<BlobQuery>,
) -> Result<Response, ApiError> {
    let blob = read.execute(id.into(), &query.token).await?;
    blob_response(blob)
}

/// `GET /api/attachments/{id}/content` — the source of an attachment uploaded here, for a peer
/// with a member in its conversation.
pub async fn content(
    State(serve): State<Arc<ServePeerContent>>,
    SignedPeer(peer): SignedPeer,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let blob = serve
        .execute(&peer, id.into())
        .await
        .map_err(peer_refused)?;
    blob_response(blob)
}

/// The peer-facing answers, which differ from the client's in places.
fn peer_refused(error: AttachmentError) -> ApiError {
    let denied = |description| ApiError::new(StatusCode::FORBIDDEN, "access_denied", description);
    match error {
        AttachmentError::NotFound => ApiError::not_found("Attachment not found"),
        AttachmentError::NotHostedHere => ApiError::not_found("Attachment is not hosted here"),
        AttachmentError::Unlinked => denied("Attachment is unlinked"),
        AttachmentError::MessageMissing => ApiError::not_found("Linked message missing"),
        AttachmentError::PeerNotInConversation => {
            denied("Requesting peer has no actor in this conversation")
        }
        AttachmentError::Unexpected(e) => ApiError::internal(e),
        other => ApiError::bad_request(other.to_string()),
    }
}

/// The bytes as a download: `nosniff` and `attachment` keep a browser from rendering them.
pub fn blob_response(blob: Blob) -> Result<Response, ApiError> {
    let disposition = format!(
        r#"attachment; filename="{}""#,
        blob.original_filename.replace('"', "")
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &blob.mime_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header("x-content-type-options", "nosniff");
    if let Some(length) = blob.bytes.length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    builder
        .body(Body::from_stream(blob.bytes.chunks))
        .map_err(|e| ApiError::internal(e.into()))
}

impl From<AttachmentError> for ApiError {
    fn from(error: AttachmentError) -> Self {
        let denied =
            |description| ApiError::new(StatusCode::FORBIDDEN, "access_denied", description);
        match error {
            AttachmentError::Refused(refusal) => refused(refusal),
            AttachmentError::NotFound => ApiError::not_found("Attachment not found"),
            AttachmentError::MessageMissing => {
                ApiError::not_found("Attachment's message not found")
            }
            AttachmentError::Forbidden => denied("Not authorised to access attachment"),
            AttachmentError::TokenExpired => denied("Token expired"),
            AttachmentError::TokenInvalid => denied("Invalid token"),
            AttachmentError::TokenMismatch => denied("Token does not match attachment"),
            AttachmentError::NotHostedHere => ApiError::not_found("Attachment is not hosted here"),
            AttachmentError::Unlinked => denied("Attachment is unlinked"),
            AttachmentError::PeerNotInConversation => {
                denied("Requesting peer has no actor in this conversation")
            }
            AttachmentError::IdTaken => ApiError::new(
                StatusCode::CONFLICT,
                "conflict",
                "Attachment id already taken",
            ),
            AttachmentError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
