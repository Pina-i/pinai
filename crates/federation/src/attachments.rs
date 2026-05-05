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
//! 5. `302` redirect to a fresh RustFS presigned URL with response-header
//!    overrides for MIME and `Content-Disposition: attachment`.

use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Redirect, Response},
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
            .map_or(false, |h| h == peer_host)
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

    let presigned = storage
        .presign_attachment_get(
            &attachment.storage_key,
            &attachment.mime_type,
            &attachment.original_filename,
            Duration::from_secs(300),
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut response = Redirect::temporary(&presigned).into_response();
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}
