//! `GET /api/attachments/{id}/content` — peer-IdP-facing endpoint that serves
//! attachment bytes after HTTP-Signature authentication.
//!
//! Flow:
//! 1. Verify the incoming HTTP Signature.
//! 2. Resolve the requesting peer's host (from `keyId`).
//! 3. Look up the attachment row. If `remote_origin_url` is set, this IdP is
//!    not authoritative — `404`. (Peers should fetch directly from origin.)
//! 4. Verify that one or more of the requesting peer's actors are members of
//!    the conversation containing the linked message — `403` if not.
//! 5. Stream the bytes back from our local object store. The store stays on
//!    the private network, the peer only ever talks to this endpoint.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

use idp_db::repos::{attachments, conversations};
use idp_state::{AppState, OidcError};

use crate::http_signature::verify_http_signature;

#[tracing::instrument(skip_all, fields(id = %id))]
pub async fn get_attachment_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, OidcError> {
    let path = format!("/api/attachments/{id}/content");
    let key_id = verify_http_signature(&headers, "get", &path).await?;

    // Extract the peer's host from `keyId` (e.g. https://idp.bob.com/actor#main-key).
    let peer_host = key_id
        .split('#')
        .next()
        .and_then(|u| reqwest::Url::parse(u).ok())
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        })
        .ok_or_else(|| OidcError::invalid_request("invalid keyId in signature"))?;

    let attachment = attachments::find_by_id(&state.pool, id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Attachment not found"))?;

    // We're authoritative only for local attachments.
    if attachment.remote_origin_url.is_some() {
        return Err(OidcError::not_found("Attachment is not hosted here"));
    }

    let message_id = attachment
        .message_id
        .ok_or_else(|| OidcError::access_denied("Attachment is unlinked"))?;

    // Membership check: at least one conversation member must belong to the
    // requesting peer's host.
    let members = conversations::get_members(
        &state.pool,
        idp_db::repos::messages::find_by_id(&state.pool, message_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .ok_or_else(|| OidcError::not_found("Linked message missing"))?
            .conversation_id,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let peer_is_member = members.iter().any(|m| {
        reqwest::Url::parse(&m.actor_uri)
            .ok()
            .and_then(|u| {
                u.host_str().map(|h| match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                })
            })
            .is_some_and(|h| h == peer_host)
    });

    if !peer_is_member {
        return Err(OidcError::access_denied(
            "Requesting peer has no actor in this conversation",
        ));
    }

    let storage = state
        .storage
        .as_ref()
        .ok_or_else(|| OidcError::server_error("Object storage not configured"))?;

    let (stream, content_length) = storage
        .fetch_attachment_stream(&attachment.storage_key)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let disposition = format!(
        r#"attachment; filename="{}""#,
        attachment.original_filename.replace('"', "")
    );

    let body = Body::from_stream(stream);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &attachment.mime_type)
        .header(header::CONTENT_DISPOSITION, &disposition)
        .header("x-content-type-options", "nosniff");
    if let Some(len) = content_length.filter(|n| *n >= 0) {
        builder = builder.header(header::CONTENT_LENGTH, len.to_string());
    }
    builder
        .body(body)
        .map_err(|e| OidcError::server_error(e.to_string()))
}
