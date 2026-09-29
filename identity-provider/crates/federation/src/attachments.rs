//! `GET /api/attachments/{id}/content` — the peer-facing source of an attachment uploaded here.
//! The peer authenticates with an HTTP Signature; `application::messaging::ServePeerContent`
//! decides whether it may have the bytes.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use domain::identity::ActorUri;
use domain::messaging::AttachmentError;
use uuid::Uuid;

use idp_state::{AppState, OidcError};

use crate::http_signature::verify_http_signature;

#[tracing::instrument(skip_all, fields(id = %id))]
pub async fn get_attachment_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, OidcError> {
    let path = format!("/api/attachments/{id}/content");
    let key_id = verify_http_signature(&state.key_cache, &headers, "get", &path).await?;
    // The signing key's actor, e.g. `https://idp.bob.com/actor#main-key`.
    let peer = key_id
        .split('#')
        .next()
        .and_then(|actor| ActorUri::parse(actor).ok())
        .ok_or_else(|| OidcError::invalid_request("invalid keyId in signature"))?;

    let blob = state
        .serve_peer_content
        .execute(&peer, id.into())
        .await
        .map_err(refused)?;

    let disposition = format!(
        r#"attachment; filename="{}""#,
        blob.original_filename.replace('"', "")
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &blob.mime_type)
        .header(header::CONTENT_DISPOSITION, &disposition)
        .header("x-content-type-options", "nosniff");
    if let Some(length) = blob.bytes.length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    builder
        .body(Body::from_stream(blob.bytes.chunks))
        .map_err(|e| OidcError::server_error(e.to_string()))
}

fn refused(error: AttachmentError) -> OidcError {
    match error {
        AttachmentError::NotFound => OidcError::not_found("Attachment not found"),
        AttachmentError::NotHostedHere => OidcError::not_found("Attachment is not hosted here"),
        AttachmentError::Unlinked => OidcError::access_denied("Attachment is unlinked"),
        AttachmentError::MessageMissing => OidcError::not_found("Linked message missing"),
        AttachmentError::PeerNotInConversation => {
            OidcError::access_denied("Requesting peer has no actor in this conversation")
        }
        AttachmentError::Unexpected(e) => {
            tracing::error!(error = ?e, "peer attachment fetch failed");
            OidcError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: "server_error",
                error_description: "internal error".to_owned(),
            }
        }
        other => OidcError::invalid_request(other.to_string()),
    }
}
