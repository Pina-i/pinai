//! MLS Notes: a `Create{Note}` with `mediaType: application/mls`, whose `mlsKind` names the use
//! case — commit, Welcome or application message — and an `Update{Note}`, an edit. Any other
//! Note is dropped: a peer on a pre-MLS build cannot interoperate. Outbound Notes are
//! `infrastructure::federation::{ApMessageFederation, ApMlsFederation}`; see
//! `identity-provider/specs/05-e2ee.md § 5`.

use application::e2ee::{IncomingCommit, IncomingWelcome};
use application::messaging::{IncomingEdit, IncomingMessage};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{CommitBlob, DeliveryError, Epoch, WelcomeBlob};
use domain::identity::{Account, ActorUri};
use domain::messaging::{
    GroupSnapshot, Member, MessagingError, MlsCiphertext, OfferedAttachment, Role,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{ApiError, AppState};

const MLS: &str = "application/mls";

fn media_type(note: &Value) -> &str {
    note.get("mediaType").and_then(Value::as_str).unwrap_or("")
}

/// `activity` is the `Create`, `note` its object; `recipient` owns the inbox it arrived at.
pub(super) async fn create(
    state: &AppState,
    activity: &Value,
    note: &Value,
    recipient: &Account,
    sender: ActorUri,
) -> Result<(), ApiError> {
    if media_type(note) != MLS {
        tracing::warn!(
            recipient = %recipient.username,
            media_type = %media_type(note),
            "rejecting Create{{Note}} without `mediaType: application/mls` — peer must run an MLS-capable build"
        );
        return Ok(());
    }
    let conversation: Uuid = note
        .get("context")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("MLS Note missing `context` (conversation_id)"))?
        .parse()
        .map_err(|_| ApiError::bad_request("MLS Note `context` is not a UUID"))?;
    let content = note
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("MLS Note missing base64 `content`"))?;
    let blob = B64
        .decode(content)
        .map_err(|_| ApiError::bad_request("MLS Note `content` is not valid base64"))?;
    if blob.is_empty() {
        return Err(ApiError::bad_request("MLS Note `content` is empty"));
    }

    match note.get("mlsKind").and_then(Value::as_str).unwrap_or("") {
        "commit" => {
            let epoch = note
                .get("mlsEpoch")
                .and_then(Value::as_i64)
                .ok_or_else(|| ApiError::bad_request("MLS commit Note missing `mlsEpoch`"))?;
            let incoming = IncomingCommit {
                proposer: sender,
                conversation: conversation.into(),
                epoch: Epoch::parse(epoch)
                    .map_err(|_| ApiError::bad_request("MLS commit `mlsEpoch` is negative"))?,
                blob: CommitBlob::parse(blob)
                    .map_err(|_| ApiError::bad_request("MLS Note `content` is empty"))?,
            };
            state
                .receive_commit
                .execute(incoming)
                .await
                .map_err(delivery_refused)
        }
        "welcome" => {
            let device: Uuid = note
                .get("mlsRecipientDeviceId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ApiError::bad_request("MLS welcome Note missing `mlsRecipientDeviceId`")
                })?
                .parse()
                .map_err(|_| {
                    ApiError::bad_request("MLS welcome `mlsRecipientDeviceId` is not a UUID")
                })?;
            let incoming = IncomingWelcome {
                recipient: recipient.id,
                sender,
                conversation: conversation.into(),
                device: device.into(),
                blob: WelcomeBlob::parse(blob)
                    .map_err(|_| ApiError::bad_request("MLS Note `content` is empty"))?,
                roster: group_snapshot(note),
            };
            state
                .receive_welcome
                .execute(incoming)
                .await
                .map_err(delivery_refused)?;
            tracing::info!(
                recipient = %recipient.username,
                device_id = %device,
                conversation_id = %conversation,
                "stored inbound mls welcome"
            );
            Ok(())
        }
        "application" => {
            // The activity id, else the Note's: some senders set it only there.
            let activity_uri = activity
                .get("id")
                .and_then(Value::as_str)
                .or_else(|| note.get("id").and_then(Value::as_str))
                .ok_or_else(|| ApiError::bad_request("Create activity missing id"))?;
            let bytes = blob.len();
            let incoming = IncomingMessage {
                recipient: recipient.id,
                sender: sender.clone(),
                conversation: conversation.into(),
                activity_uri: activity_uri.to_owned(),
                ciphertext: MlsCiphertext::parse(blob).map_err(|e| {
                    ApiError::bad_request(format!("MLS Note `content` {}", e.reason))
                })?,
                in_reply_to: note
                    .get("inReplyTo")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                group: group_snapshot(note),
                attachments: offered_attachments(note.get("attachment")),
            };
            state
                .receive_message
                .execute(incoming)
                .await
                .map_err(messaging_refused)?;
            tracing::info!(
                %sender,
                recipient = %recipient.username,
                bytes,
                "MLS application message persisted via AP inbox"
            );
            Ok(())
        }
        other => {
            tracing::warn!(mls_kind = %other, "unknown mlsKind — dropping");
            Ok(())
        }
    }
}

/// An `Update{Note}`: an edit, which replaces the message's ciphertext.
pub(super) async fn update(
    state: &AppState,
    note: &Value,
    recipient: &Account,
    sender: ActorUri,
) -> Result<(), ApiError> {
    if media_type(note) != MLS {
        tracing::warn!(media_type = %media_type(note), "rejecting Update{{Note}} without `mediaType: application/mls`");
        return Ok(());
    }
    let activity_uri = note.get("id").and_then(Value::as_str).unwrap_or("");
    let content = note.get("content").and_then(Value::as_str).unwrap_or("");
    if activity_uri.is_empty() || content.is_empty() {
        return Ok(());
    }
    let ciphertext = match B64.decode(content) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => {
            tracing::warn!(%activity_uri, "Update{{Note}} content is not valid non-empty base64");
            return Ok(());
        }
    };
    let ciphertext = MlsCiphertext::parse(ciphertext)
        .map_err(|e| ApiError::bad_request(format!("Update{{Note}} `content` {}", e.reason)))?;
    state
        .receive_edit
        .execute(IncomingEdit {
            recipient: recipient.id,
            sender,
            activity_uri: activity_uri.to_owned(),
            ciphertext,
        })
        .await
        .map_err(messaging_refused)
}

/// The `mlsGroup` roster a group Note carries; entries that name no actor or role are skipped.
fn group_snapshot(note: &Value) -> Option<GroupSnapshot> {
    let snapshot = note.get("mlsGroup")?;
    let members = snapshot
        .get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(|m| {
                    Some(Member {
                        actor_uri: ActorUri::parse(m.get("actorUri")?.as_str()?).ok()?,
                        role: m.get("role")?.as_str()?.parse::<Role>().ok()?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(GroupSnapshot {
        name: snapshot
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        members,
    })
}

/// A Note's `attachment` array, as offered: the limits decide what is recorded.
fn offered_attachments(value: Option<&Value>) -> Vec<OfferedAttachment> {
    let Some(entries) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let text = |entry: &Value, key: &str| entry.get(key).and_then(Value::as_str).map(str::to_owned);
    entries
        .iter()
        .map(|entry| OfferedAttachment {
            is_document: entry.get("type").and_then(Value::as_str) == Some("Document"),
            url: text(entry, "url"),
            media_type: text(entry, "mediaType"),
            name: text(entry, "name"),
            size: entry.get("size").and_then(Value::as_i64),
        })
        .collect()
}

fn messaging_refused(error: MessagingError) -> ApiError {
    match error {
        // The answer a local sender gets, so that nothing tells a peer more.
        undeliverable @ MessagingError::Undeliverable => undeliverable.into(),
        MessagingError::Unexpected(e) => ApiError::internal(e),
        other => ApiError::bad_request(other.to_string()),
    }
}

fn delivery_refused(error: DeliveryError) -> ApiError {
    match error {
        unreachable @ DeliveryError::Unreachable => unreachable.into(),
        DeliveryError::Unexpected(e) => ApiError::internal(e),
        other => ApiError::bad_request(other.to_string()),
    }
}
