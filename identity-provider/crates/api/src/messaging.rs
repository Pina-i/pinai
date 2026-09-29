//! Direct and group messages — see identity-provider/specs/03-direct-messages.md.

use std::sync::Arc;

use application::messaging::{
    DeliverDirectMessage, DirectMessageCommand, EditMessage, GroupMessageCommand, HistoryEntry,
    ListConversations, LoadHistory, MarkRead, SendDirectMessage, SendGroupMessage,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use domain::identity::InstanceOrigin;
use domain::messaging::{
    ConversationSummary, HistoryCursor, Message, MessagingError, MlsCiphertext,
};
use domain::{AttachmentId, ConversationId, MessageId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::Authenticated;

#[derive(Deserialize)]
pub struct SendMessageBody {
    /// A bare name for a local account, or `user@domain`.
    recipient_address: String,
    mls_ciphertext: String,
    reply_to_id: Option<Uuid>,
    #[serde(default)]
    attachment_ids: Vec<Uuid>,
    conversation_id: Option<Uuid>,
    #[serde(default)]
    client_id: Option<String>,
}

#[derive(Deserialize)]
pub struct SendGroupMessageBody {
    mls_ciphertext: String,
    #[serde(default)]
    reply_to_id: Option<Uuid>,
    #[serde(default)]
    attachment_ids: Vec<Uuid>,
}

#[derive(Deserialize)]
pub struct EditBody {
    mls_ciphertext: String,
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// RFC 3339, as each message's `created_at` is returned.
    #[serde(default, with = "time::serde::rfc3339::option")]
    cursor_created_at: Option<OffsetDateTime>,
    cursor_id: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct AttachmentBody {
    id: Uuid,
    mime_type: String,
    byte_size: i64,
    original_filename: String,
}

#[derive(Serialize)]
pub struct MessageBody {
    id: Uuid,
    conversation_id: Uuid,
    sender_actor_uri: String,
    sender_display_name: Option<String>,
    mls_ciphertext: String,
    activity_uri: String,
    federation_status: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    edited_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to_id: Option<Uuid>,
    attachments: Vec<AttachmentBody>,
}

#[derive(Serialize)]
pub struct MemberBody {
    #[serde(rename = "actorUri")]
    actor_uri: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "avatarUrl")]
    avatar_url: Option<String>,
}

#[derive(Serialize)]
pub struct ConversationBody {
    conversation_id: Uuid,
    kind: &'static str,
    name: Option<String>,
    members: Vec<MemberBody>,
    last_message_sender: Option<String>,
    unread_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    last_message_at: Option<OffsetDateTime>,
}

fn ciphertext(b64: &str) -> Result<MlsCiphertext, ApiError> {
    let bytes = B64
        .decode(b64)
        .map_err(|_| ApiError::bad_request("`mls_ciphertext` is not valid base64"))?;
    MlsCiphertext::parse(bytes)
        .map_err(|e| ApiError::bad_request(format!("`mls_ciphertext` {}", e.reason)))
}

fn attachment_ids(ids: Vec<Uuid>) -> Vec<AttachmentId> {
    ids.into_iter().map(AttachmentId::from).collect()
}

impl MessageBody {
    fn new(message: Message, sender_display_name: Option<String>) -> Self {
        Self {
            id: message.id.as_uuid(),
            conversation_id: message.conversation.as_uuid(),
            sender_actor_uri: message.sender.to_string(),
            sender_display_name,
            mls_ciphertext: B64.encode(message.ciphertext.as_bytes()),
            activity_uri: message.activity_uri,
            federation_status: message.delivery.as_str(),
            created_at: message.created_at,
            edited_at: message.edited_at,
            reply_to_id: message.reply_to.map(|id| id.as_uuid()),
            attachments: message
                .attachments
                .into_iter()
                .map(|a| AttachmentBody {
                    id: a.id.as_uuid(),
                    mime_type: a.mime_type,
                    byte_size: a.byte_size,
                    original_filename: a.original_filename,
                })
                .collect(),
        }
    }
}

impl From<ConversationSummary> for ConversationBody {
    fn from(summary: ConversationSummary) -> Self {
        Self {
            conversation_id: summary.id.as_uuid(),
            kind: summary.kind.as_str(),
            name: summary.name,
            members: summary
                .members
                .into_iter()
                .map(|m| MemberBody {
                    actor_uri: m.actor_uri.to_string(),
                    display_name: m.display_name,
                    avatar_url: m.avatar_url,
                })
                .collect(),
            last_message_sender: summary.last_message_sender.map(|s| s.to_string()),
            unread_count: summary.unread_count,
            last_message_at: summary.last_message_at,
        }
    }
}

/// `POST /api/dm`
pub async fn send_message(
    State(send): State<Arc<SendDirectMessage>>,
    State(deliver): State<Arc<DeliverDirectMessage>>,
    State(origin): State<InstanceOrigin>,
    Authenticated(user): Authenticated,
    Json(body): Json<SendMessageBody>,
) -> Result<(StatusCode, Json<MessageBody>), ApiError> {
    let ciphertext = ciphertext(&body.mls_ciphertext)?;
    let recipient = origin
        .resolve(&body.recipient_address)
        .map_err(|_| MessagingError::RecipientNotFound)?;
    let sent = send
        .execute(
            user,
            DirectMessageCommand {
                recipient,
                ciphertext,
                reply_to: body.reply_to_id.map(MessageId::from),
                attachments: attachment_ids(body.attachment_ids),
                pinned: body.conversation_id.map(ConversationId::from),
                client_id: body.client_id,
            },
        )
        .await?;
    tracing::info!(user_id = %user, message_id = %sent.message.id, "direct message sent");
    // Answered first: the sender's client learns the message id before any delivery outcome.
    if let Some(delivery) = sent.delivery {
        tokio::spawn(async move {
            deliver.execute(delivery).await;
        });
    }
    Ok((
        StatusCode::CREATED,
        Json(MessageBody::new(
            sent.message,
            Some(sent.sender_display_name),
        )),
    ))
}

/// `POST /api/groups/{conversation_id}/messages`
pub async fn send_group_message(
    State(send): State<Arc<SendGroupMessage>>,
    Authenticated(user): Authenticated,
    Path(conversation): Path<Uuid>,
    Json(body): Json<SendGroupMessageBody>,
) -> Result<(StatusCode, Json<MessageBody>), ApiError> {
    let ciphertext = ciphertext(&body.mls_ciphertext)?;
    let posted = send
        .execute(
            user,
            GroupMessageCommand {
                conversation: conversation.into(),
                ciphertext,
                reply_to: body.reply_to_id.map(MessageId::from),
                attachments: attachment_ids(body.attachment_ids),
            },
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(MessageBody::new(
            posted.message,
            Some(posted.sender_display_name),
        )),
    ))
}

/// `PATCH /api/dm/{message_id}/edit`
pub async fn edit(
    State(edit): State<Arc<EditMessage>>,
    Authenticated(user): Authenticated,
    Path(message): Path<Uuid>,
    Json(body): Json<EditBody>,
) -> Result<Json<MessageBody>, ApiError> {
    let ciphertext = ciphertext(&body.mls_ciphertext)?;
    let edited = edit.execute(user, message.into(), ciphertext).await?;
    tracing::info!(message_id = %message, "message edited");
    Ok(Json(MessageBody::new(
        edited.message,
        Some(edited.sender_display_name),
    )))
}

/// `GET /api/dm/{conversation_id}`
pub async fn history(
    State(load): State<Arc<LoadHistory>>,
    Authenticated(user): Authenticated,
    Path(conversation): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<MessageBody>>, ApiError> {
    // A cursor needs both halves; either alone reads the first page.
    let before = match (query.cursor_created_at, query.cursor_id) {
        (Some(created_at), Some(id)) => Some(HistoryCursor {
            created_at,
            id: id.into(),
        }),
        _ => None,
    };
    let page = load
        .execute(user, conversation.into(), before, query.limit)
        .await?;
    Ok(Json(
        page.into_iter()
            .map(
                |HistoryEntry {
                     message,
                     sender_display_name,
                 }| { MessageBody::new(message, sender_display_name) },
            )
            .collect(),
    ))
}

/// `POST /api/dm/{conversation_id}/read`
pub async fn mark_read(
    State(mark): State<Arc<MarkRead>>,
    Authenticated(user): Authenticated,
    Path(conversation): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    mark.execute(user, conversation.into()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/dm`
pub async fn conversations(
    State(list): State<Arc<ListConversations>>,
    Authenticated(user): Authenticated,
) -> Result<Json<Vec<ConversationBody>>, ApiError> {
    let listed = list.execute(user).await?;
    Ok(Json(
        listed.into_iter().map(ConversationBody::from).collect(),
    ))
}

impl From<MessagingError> for ApiError {
    fn from(error: MessagingError) -> Self {
        match error {
            MessagingError::RecipientNotFound => ApiError::not_found("Recipient not found"),
            MessagingError::SelfMessage => ApiError::bad_request("Cannot send a DM to yourself"),
            MessagingError::ConversationNotFound => ApiError::not_found("Conversation not found"),
            MessagingError::ParentNotFound => ApiError::not_found("Parent message not found"),
            MessagingError::MessageNotFound => {
                ApiError::not_found("Message not found or you are not the sender")
            }
            MessagingError::TooManyAttachments(max) => {
                ApiError::bad_request(format!("too many attachments (max {max} per message)"))
            }
            MessagingError::AttachmentsUnavailable => ApiError::bad_request(
                "one or more attachment IDs are missing, linked to a delivered message, or not owned by sender",
            ),
            MessagingError::PeerNotAllowed(reason) => {
                ApiError::new(StatusCode::FORBIDDEN, "access_denied", reason)
            }
            MessagingError::NotAnAdmin => ApiError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Only group admins can do this",
            ),
            MessagingError::MemberNotFound => ApiError::not_found("Member not found"),
            MessagingError::GroupNotFound => ApiError::not_found("Group not found"),
            MessagingError::GroupNeedsMembers => {
                ApiError::bad_request("A group needs at least one other member")
            }
            MessagingError::AlreadyAMember => {
                ApiError::new(StatusCode::CONFLICT, "conflict", "Already a member")
            }
            MessagingError::LastAdmin => ApiError::new(
                StatusCode::CONFLICT,
                "conflict",
                "The last admin cannot step down while others remain: promote another member first",
            ),
            MessagingError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
