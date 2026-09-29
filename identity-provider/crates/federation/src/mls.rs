//! Inbound MLS Notes: `crates/federation/src/inbox.rs` hands every `Create{Note}` with
//! `mediaType: application/mls` here, and the `mlsKind` discriminator names the use case —
//! commit, Welcome, or application message. Outbound Notes are
//! `infrastructure::federation::{ApMessageFederation, ApMlsFederation}`; see
//! `identity-provider/specs/05-e2ee.md § 5`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::Value;
use uuid::Uuid;

use application::e2ee::{IncomingCommit, IncomingWelcome};
use application::messaging::IncomingMessage;
use domain::e2ee::{CommitBlob, DeliveryError, Epoch, WelcomeBlob};
use domain::identity::ActorUri;
use domain::messaging::{
    GroupSnapshot as Roster, Member, MessagingError, MlsCiphertext, OfferedAttachment, Role,
};
use idp_state::{AppState, OidcError};

// ─── Inbound dispatcher ──────────────────────────────────────────────────────
//
// `crates/federation/src/inbox.rs` calls `handle_inbound_mls_note` when an
// incoming `Create{Note}` carries `mediaType: application/mls`. Lives here
// rather than in the e2ee crate so the inbox dispatcher (federation) stays
// the single owner of incoming AP envelopes — no `e2ee → federation →
// e2ee` cycle.

/// Entry point invoked by `federation::inbox::handle_create` when the Note's
/// `mediaType` is `application/mls`.
///
/// `body` is the outer Activity, `note` is the inner Note. `recipient` is
/// the local user whose `/inbox` the activity arrived at.
#[tracing::instrument(skip_all, fields(recipient = %recipient.username))]
pub async fn handle_inbound_mls_note(
    state: &AppState,
    body: &Value,
    note: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let mls_kind = note.get("mlsKind").and_then(|v| v.as_str()).unwrap_or("");

    let conversation_id_str = note
        .get("context")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OidcError::invalid_request("MLS Note missing `context` (conversation_id)")
        })?;
    let conversation_id: Uuid = conversation_id_str
        .parse()
        .map_err(|_| OidcError::invalid_request("MLS Note `context` is not a UUID"))?;

    let content_b64 = note
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::invalid_request("MLS Note missing base64 `content`"))?;
    let blob = B64
        .decode(content_b64)
        .map_err(|_| OidcError::invalid_request("MLS Note `content` is not valid base64"))?;
    if blob.is_empty() {
        return Err(OidcError::invalid_request("MLS Note `content` is empty"));
    }

    let proposer_actor_uri = body
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::invalid_request("MLS activity missing `actor`"))?;

    match mls_kind {
        "commit" => {
            let epoch = note
                .get("mlsEpoch")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| OidcError::invalid_request("MLS commit Note missing `mlsEpoch`"))?;
            ingest_commit(state, conversation_id, epoch, &blob, proposer_actor_uri).await
        }
        "welcome" => {
            let device_id_str = note
                .get("mlsRecipientDeviceId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OidcError::invalid_request("MLS welcome Note missing `mlsRecipientDeviceId`")
                })?;
            let device_id: Uuid = device_id_str.parse().map_err(|_| {
                OidcError::invalid_request("MLS welcome `mlsRecipientDeviceId` is not a UUID")
            })?;
            ingest_welcome(
                state,
                note,
                recipient,
                device_id,
                conversation_id,
                &blob,
                proposer_actor_uri,
            )
            .await
        }
        "application" => {
            ingest_application_message(
                state,
                body,
                note,
                recipient,
                conversation_id,
                &blob,
                proposer_actor_uri,
            )
            .await
        }
        other => {
            tracing::warn!(mls_kind = %other, "unknown mlsKind — dropping");
            Ok(())
        }
    }
}

async fn ingest_commit(
    state: &AppState,
    conversation_id: Uuid,
    epoch: i64,
    blob: &[u8],
    proposer_actor_uri: &str,
) -> Result<(), OidcError> {
    let incoming = IncomingCommit {
        proposer: sender(proposer_actor_uri)?,
        conversation: conversation_id.into(),
        epoch: Epoch::parse(epoch)
            .map_err(|_| OidcError::invalid_request("MLS commit `mlsEpoch` is negative"))?,
        blob: CommitBlob::parse(blob.to_vec())
            .map_err(|_| OidcError::invalid_request("MLS Note `content` is empty"))?,
    };
    state
        .receive_commit
        .execute(incoming)
        .await
        .map_err(delivery_refused)
}

async fn ingest_application_message(
    state: &AppState,
    body: &Value,
    note: &Value,
    recipient: &idp_db::models::User,
    conversation_id: Uuid,
    mls_ciphertext: &[u8],
    sender_actor_uri: &str,
) -> Result<(), OidcError> {
    // The activity id, else the Note's (some senders set it only there).
    let activity_uri = body
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| note.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| OidcError::invalid_request("Create activity missing id"))?;
    let incoming = IncomingMessage {
        recipient: recipient.id.into(),
        sender: sender(sender_actor_uri)?,
        conversation: conversation_id.into(),
        activity_uri: activity_uri.to_owned(),
        ciphertext: MlsCiphertext::parse(mls_ciphertext.to_vec())
            .map_err(|e| OidcError::invalid_request(format!("MLS Note `content` {}", e.reason)))?,
        in_reply_to: note
            .get("inReplyTo")
            .and_then(|v| v.as_str())
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
        sender = %sender_actor_uri,
        recipient = %recipient.username,
        bytes = mls_ciphertext.len(),
        "MLS application message persisted via AP inbox"
    );
    Ok(())
}

/// The activity's actor, already bound to the signing key by the inbox.
fn sender(actor_uri: &str) -> Result<ActorUri, OidcError> {
    ActorUri::parse(actor_uri)
        .map_err(|_| OidcError::invalid_request("MLS activity `actor` is not an actor URI"))
}

/// The `mlsGroup` roster a group Note carries; entries that name no actor or role are skipped.
fn group_snapshot(note: &Value) -> Option<Roster> {
    let snapshot = note.get("mlsGroup")?;
    let members = snapshot
        .get("members")
        .and_then(|v| v.as_array())
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
    Some(Roster {
        name: snapshot
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        members,
    })
}

/// A Note's `attachment` array, as offered: the limits decide what is recorded.
fn offered_attachments(value: Option<&Value>) -> Vec<OfferedAttachment> {
    let Some(entries) = value.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    entries
        .iter()
        .map(|entry| OfferedAttachment {
            is_document: entry.get("type").and_then(|v| v.as_str()) == Some("Document"),
            url: entry.get("url").and_then(|v| v.as_str()).map(str::to_owned),
            media_type: entry
                .get("mediaType")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            name: entry
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            size: entry.get("size").and_then(|v| v.as_i64()),
        })
        .collect()
}

pub(crate) fn messaging_refused(error: MessagingError) -> OidcError {
    match error {
        MessagingError::Unexpected(e) => {
            tracing::error!(error = ?e, "inbound MLS message failed");
            OidcError {
                status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                error: "server_error",
                error_description: "internal error".to_owned(),
            }
        }
        other => OidcError::invalid_request(other.to_string()),
    }
}

pub(crate) fn delivery_refused(error: DeliveryError) -> OidcError {
    match error {
        DeliveryError::Unexpected(e) => {
            tracing::error!(error = ?e, "inbound MLS commit or Welcome failed");
            OidcError {
                status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                error: "server_error",
                error_description: "internal error".to_owned(),
            }
        }
        other => OidcError::invalid_request(other.to_string()),
    }
}

async fn ingest_welcome(
    state: &AppState,
    note: &Value,
    recipient: &idp_db::models::User,
    device_id: Uuid,
    conversation_id: Uuid,
    blob: &[u8],
    sender_actor_uri: &str,
) -> Result<(), OidcError> {
    let incoming = IncomingWelcome {
        recipient: recipient.id.into(),
        sender: sender(sender_actor_uri)?,
        conversation: conversation_id.into(),
        device: device_id.into(),
        blob: WelcomeBlob::parse(blob.to_vec())
            .map_err(|_| OidcError::invalid_request("MLS Note `content` is empty"))?,
        roster: group_snapshot(note),
    };
    state
        .receive_welcome
        .execute(incoming)
        .await
        .map_err(delivery_refused)?;
    tracing::info!(
        recipient = %recipient.username,
        device_id = %device_id,
        conversation_id = %conversation_id,
        "stored inbound mls welcome"
    );
    Ok(())
}
