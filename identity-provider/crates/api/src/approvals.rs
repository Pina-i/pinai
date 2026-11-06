//! Approvals of the account's devices, and the requests relaying their code handshake — see
//! identity-provider/specs/e2ee.md § 5.

use std::sync::Arc;

use application::e2ee::{
    ApproveDevice, CloseApprovalRequest, ListApprovalRequests, ListedRequest, OpenApprovalRequest,
    PostApprovalMessage, ReadApprovalMessages,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{
    ApprovalBy, ApprovalMessage, ApprovalMessageBody, Ed25519Signature, HistoryGeneration,
    MessageSeq,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::SignedIn;
use crate::e2ee::base64_field;

#[derive(Deserialize)]
pub struct ApproveBody {
    by: String,
    /// Standard base64 of the 64-byte Ed25519 signature over the approval's canonical bytes.
    signature: String,
    /// The generation whose approval key signed, with `by: "passphrase"` only.
    generation: Option<i64>,
}

#[derive(Serialize)]
pub struct OpenedBody {
    id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct RequestEntry {
    id: Uuid,
    /// The device asking to be approved.
    device_id: Uuid,
    display_name: String,
    /// The device answering it; `None` until one posts.
    approver_device_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct RequestsBody {
    requests: Vec<RequestEntry>,
}

#[derive(Deserialize)]
pub struct MessageBody {
    /// Standard base64, 1 to 4096 bytes once decoded.
    body: String,
}

#[derive(Serialize)]
pub struct PostedBody {
    seq: i32,
}

#[derive(Deserialize)]
pub struct AfterQuery {
    after: Option<i64>,
}

#[derive(Serialize)]
pub struct MessageEntry {
    seq: i32,
    /// The device that posted it.
    device_id: Uuid,
    body: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct MessagesBody {
    messages: Vec<MessageEntry>,
}

impl From<ListedRequest> for RequestEntry {
    fn from(
        ListedRequest {
            request,
            display_name,
        }: ListedRequest,
    ) -> Self {
        Self {
            id: request.id.as_uuid(),
            device_id: request.device.as_uuid(),
            display_name,
            approver_device_id: request.approver.map(|device| device.as_uuid()),
            created_at: request.created_at,
            expires_at: request.expires_at,
        }
    }
}

impl From<ApprovalMessage> for MessageEntry {
    fn from(message: ApprovalMessage) -> Self {
        Self {
            seq: message.seq.value(),
            device_id: message.from.as_uuid(),
            body: B64.encode(message.body.as_bytes()),
            created_at: message.created_at,
        }
    }
}

fn approval_by(body: &ApproveBody) -> Result<ApprovalBy, ApiError> {
    match (body.by.as_str(), body.generation) {
        ("device", None) => Ok(ApprovalBy::Device),
        ("passphrase", Some(generation)) => Ok(ApprovalBy::Passphrase(HistoryGeneration::parse(
            generation,
        )?)),
        ("device", Some(_)) => Err(ApiError::bad_request(
            "generation comes with by: passphrase only",
        )),
        ("passphrase", None) => Err(ApiError::bad_request(
            "generation is required with by: passphrase",
        )),
        _ => Err(ApiError::bad_request("by must be 'device' or 'passphrase'")),
    }
}

/// `POST /api/keys/devices/{device_id}/approvals`
pub async fn approve(
    State(approve): State<Arc<ApproveDevice>>,
    SignedIn(bearer): SignedIn,
    Path(device_id): Path<Uuid>,
    Json(body): Json<ApproveBody>,
) -> Result<StatusCode, ApiError> {
    let by = approval_by(&body)?;
    let signature = base64_field("signature", &body.signature, |bytes| {
        Ed25519Signature::parse("signature", bytes)
    })?;
    approve
        .execute(&bearer, device_id.into(), by, signature)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/keys/devices/approval-requests`
pub async fn open(
    State(open): State<Arc<OpenApprovalRequest>>,
    SignedIn(bearer): SignedIn,
) -> Result<(StatusCode, Json<OpenedBody>), ApiError> {
    let request = open.execute(&bearer, OffsetDateTime::now_utc()).await?;
    Ok((
        StatusCode::CREATED,
        Json(OpenedBody {
            id: request.id.as_uuid(),
            expires_at: request.expires_at,
        }),
    ))
}

/// `GET /api/keys/devices/approval-requests`
pub async fn requests(
    State(list): State<Arc<ListApprovalRequests>>,
    SignedIn(bearer): SignedIn,
) -> Result<Json<RequestsBody>, ApiError> {
    let open = list.execute(&bearer, OffsetDateTime::now_utc()).await?;
    Ok(Json(RequestsBody {
        requests: open.into_iter().map(RequestEntry::from).collect(),
    }))
}

/// `POST /api/keys/devices/approval-requests/{request_id}/messages`
pub async fn post_message(
    State(post): State<Arc<PostApprovalMessage>>,
    SignedIn(bearer): SignedIn,
    Path(request_id): Path<Uuid>,
    Json(body): Json<MessageBody>,
) -> Result<(StatusCode, Json<PostedBody>), ApiError> {
    let body = base64_field("body", &body.body, |bytes| {
        ApprovalMessageBody::parse(bytes.to_vec())
    })?;
    let seq = post
        .execute(&bearer, request_id.into(), body, OffsetDateTime::now_utc())
        .await?;
    Ok((StatusCode::CREATED, Json(PostedBody { seq: seq.value() })))
}

/// `GET /api/keys/devices/approval-requests/{request_id}/messages?after=`
pub async fn messages(
    State(read): State<Arc<ReadApprovalMessages>>,
    SignedIn(bearer): SignedIn,
    Path(request_id): Path<Uuid>,
    Query(query): Query<AfterQuery>,
) -> Result<Json<MessagesBody>, ApiError> {
    let after = query
        .after
        .map(MessageSeq::parse)
        .transpose()?
        .unwrap_or(MessageSeq::START);
    let messages = read
        .execute(&bearer, request_id.into(), after, OffsetDateTime::now_utc())
        .await?;
    Ok(Json(MessagesBody {
        messages: messages.into_iter().map(MessageEntry::from).collect(),
    }))
}

/// `DELETE /api/keys/devices/approval-requests/{request_id}`
pub async fn close(
    State(close): State<Arc<CloseApprovalRequest>>,
    SignedIn(bearer): SignedIn,
    Path(request_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    close
        .execute(&bearer, request_id.into(), OffsetDateTime::now_utc())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
