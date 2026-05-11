//! Outbound ActivityPub delivery for MLS payloads.
//!
//! Mirrors `federation::profile`: best-effort, inline `tokio::spawn` per
//! remote inbox, no durable outbox. Recovery story is built into MLS
//! itself — clients pull missed commits via `GET /api/mls/groups/.../commits`
//! on reconnect (the `wire_format` discriminator inside the MLSMessage
//! re-establishes group state without server replay).
//!
//! ## AP envelope
//!
//! Every MLS payload rides inside a `Create{Note}` activity with
//! `mediaType: application/mls`. A custom `mlsKind` field discriminates
//! commit / welcome / application without forcing the server to parse the
//! opaque MLSMessage body. See `specs/05-e2ee.md § 5`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use uuid::Uuid;

use idp_db::models::ConversationMember;
use idp_db::repos::{
    attachments as attachments_repo, conversations, messages, mls_commits, mls_welcomes,
    remote_actors, users,
};
use idp_realtime::{DmPayload, MlsCommitPayload, MlsWelcomeReadyPayload, WsAttachment, WsEvent};
use idp_state::{AppState, OidcError};

use crate::delivery;

/// Build a `Create{Note}` activity for an MLS application message (regular
/// DM, reply, edit, reaction — all opaque to the server). The caller controls
/// `activity_id` and `note_id` so the local `direct_messages.activity_uri`
/// matches what's on the wire.
///
/// `reply_to_activity_uri` becomes the AP `inReplyTo` field when present.
/// Attachments are not injected here — call
/// `messaging::attachments::inject_attachments_into_ap_activity` on the
/// returned Value when needed.
pub fn build_application_create_activity(
    activity_id: &str,
    note_id: &str,
    sender_actor_uri: &str,
    recipient_actor_uri: &str,
    conversation_id: Uuid,
    mls_ciphertext: &[u8],
    reply_to_activity_uri: Option<&str>,
) -> Value {
    let mut extra = serde_json::Map::new();
    if let Some(parent_uri) = reply_to_activity_uri {
        extra.insert(
            "inReplyTo".to_string(),
            Value::String(parent_uri.to_string()),
        );
    }
    let note = build_mls_note(
        note_id,
        sender_actor_uri,
        recipient_actor_uri,
        conversation_id,
        "application",
        &B64.encode(mls_ciphertext),
        Value::Object(extra),
    );
    build_create_envelope(activity_id, sender_actor_uri, recipient_actor_uri, note)
}

/// Build an `Update{Note}` activity carrying a fresh MLS ciphertext for an
/// edit. Recipient's inbox replaces the existing row's `mls_ciphertext` and
/// stamps `edited_at`. The `note_id` is the message's existing `activity_uri`
/// so the receiving side can find the row.
pub fn build_application_update_activity(
    update_activity_id: &str,
    note_id_for_target: &str,
    sender_actor_uri: &str,
    recipient_actor_uri: &str,
    conversation_id: Uuid,
    new_mls_ciphertext: &[u8],
) -> Value {
    let note = build_mls_note(
        note_id_for_target,
        sender_actor_uri,
        recipient_actor_uri,
        conversation_id,
        "edit",
        &B64.encode(new_mls_ciphertext),
        Value::Object(serde_json::Map::new()),
    );
    serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": update_activity_id,
        "type": "Update",
        "actor": sender_actor_uri,
        "to": [recipient_actor_uri],
        "object": note,
    })
}

/// Build the `Note` object for an MLS payload. Shared by commit, welcome,
/// and application messages.
fn build_mls_note(
    note_id: &str,
    sender_actor_uri: &str,
    recipient_actor_uri: &str,
    conversation_id: Uuid,
    mls_kind: &str,
    content_b64: &str,
    extra: Value,
) -> Value {
    let mut note = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": note_id,
        "type": "Note",
        "attributedTo": sender_actor_uri,
        "to": [recipient_actor_uri],
        "directMessage": true,
        "mediaType": "application/mls",
        "context": conversation_id.to_string(),
        "content": content_b64,
        "mlsKind": mls_kind,
    });
    if let (Some(map), Value::Object(extra_map)) = (note.as_object_mut(), extra) {
        for (k, v) in extra_map {
            map.insert(k, v);
        }
    }
    note
}

/// Wrap an MLS Note inside a `Create` activity so it routes through the same
/// `/users/:slug/inbox` endpoint as everything else.
fn build_create_envelope(
    activity_id: &str,
    sender_actor_uri: &str,
    recipient_actor_uri: &str,
    note: Value,
) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": activity_id,
        "type": "Create",
        "actor": sender_actor_uri,
        "to": [recipient_actor_uri],
        "object": note,
    })
}

/// Resolve every remote member of a conversation to a `(actor_uri, inbox_url)`
/// pair, dropping anyone whose inbox we don't have cached. Cache misses
/// self-heal on a future profile fetch — we don't WebFinger here because
/// commits are time-sensitive and a slow remote IdP would block delivery to
/// every other peer.
async fn resolve_remote_inboxes(
    state: &AppState,
    members: &[ConversationMember],
) -> Vec<(String, String)> {
    let prefix = format!("{}/users/", state.config.issuer());
    let mut out = Vec::new();
    for member in members {
        if member.actor_uri.starts_with(&prefix) {
            continue;
        }
        match remote_actors::find_by_actor_uri(&state.pool, &member.actor_uri).await {
            Ok(Some(ra)) => {
                if let Some(inbox) = ra.inbox_url {
                    out.push((ra.actor_uri, inbox));
                } else {
                    tracing::debug!(
                        actor_uri = %member.actor_uri,
                        "skipping remote member with no cached inbox_url"
                    );
                }
            }
            Ok(None) => {
                tracing::debug!(
                    actor_uri = %member.actor_uri,
                    "skipping remote member missing from remote_actors cache"
                );
            }
            Err(e) => {
                tracing::warn!(
                    actor_uri = %member.actor_uri,
                    error = %e,
                    "remote_actors lookup failed during MLS fanout"
                );
            }
        }
    }
    out
}

/// Fan a freshly-stored Commit out to every remote member's IdP. Commits are
/// idempotent on the receiving DS (the unique index drops duplicates) so a
/// client that retries via the catch-up endpoint never produces a double
/// insert.
pub fn deliver_commit_to_remote_members(
    state: &AppState,
    members: &[ConversationMember],
    sender_username: &str,
    sender_actor_uri: &str,
    commit_blob: &[u8],
    conversation_id: Uuid,
    epoch: i64,
) {
    let state = state.clone();
    let members = members.to_vec();
    let sender_username = sender_username.to_string();
    let sender_actor_uri = sender_actor_uri.to_string();
    let content_b64 = B64.encode(commit_blob);

    tokio::spawn(async move {
        let inboxes = resolve_remote_inboxes(&state, &members).await;
        if inboxes.is_empty() {
            return;
        }

        for (recipient_actor_uri, inbox_url) in inboxes {
            let activity_id = format!(
                "{}/users/{}/activities/{}",
                state.config.issuer(),
                sender_username,
                Uuid::new_v4(),
            );
            let note_id = format!(
                "{}/users/{}/objects/{}",
                state.config.issuer(),
                sender_username,
                Uuid::new_v4(),
            );
            let note = build_mls_note(
                &note_id,
                &sender_actor_uri,
                &recipient_actor_uri,
                conversation_id,
                "commit",
                &content_b64,
                json!({ "mlsEpoch": epoch }),
            );
            let activity = build_create_envelope(
                &activity_id,
                &sender_actor_uri,
                &recipient_actor_uri,
                note,
            );

            let state_for_task = state.clone();
            let inbox_url_clone = inbox_url.clone();
            let sender_username_clone = sender_username.clone();
            tokio::spawn(async move {
                if let Err(e) = delivery::deliver_activity(
                    &state_for_task,
                    &inbox_url_clone,
                    &activity,
                    &sender_username_clone,
                )
                .await
                {
                    tracing::warn!(
                        %inbox_url_clone,
                        error = ?e,
                        "MLS commit delivery failed (will self-heal via client catch-up)"
                    );
                }
            });
        }
    });
}

/// Fan a Welcome out to a single targeted device. Local recipients have
/// already been written into `mls_welcomes` by the caller — this only
/// handles the cross-IdP path.
///
/// `recipient_actor_uri` and `recipient_inbox_url` come from a fresh AP
/// resolution by the caller, so we don't repeat the WebFinger trip.
pub fn deliver_welcome_to_remote(
    state: &AppState,
    sender_username: &str,
    sender_actor_uri: &str,
    recipient_actor_uri: &str,
    recipient_inbox_url: &str,
    recipient_device_id: Uuid,
    conversation_id: Uuid,
    welcome_blob: &[u8],
) {
    let state = state.clone();
    let sender_username = sender_username.to_string();
    let sender_actor_uri = sender_actor_uri.to_string();
    let recipient_actor_uri = recipient_actor_uri.to_string();
    let recipient_inbox_url = recipient_inbox_url.to_string();
    let content_b64 = B64.encode(welcome_blob);

    tokio::spawn(async move {
        let activity_id = format!(
            "{}/users/{}/activities/{}",
            state.config.issuer(),
            sender_username,
            Uuid::new_v4(),
        );
        let note_id = format!(
            "{}/users/{}/objects/{}",
            state.config.issuer(),
            sender_username,
            Uuid::new_v4(),
        );
        let note = build_mls_note(
            &note_id,
            &sender_actor_uri,
            &recipient_actor_uri,
            conversation_id,
            "welcome",
            &content_b64,
            json!({ "mlsRecipientDeviceId": recipient_device_id.to_string() }),
        );
        let activity = build_create_envelope(
            &activity_id,
            &sender_actor_uri,
            &recipient_actor_uri,
            note,
        );

        if let Err(e) = delivery::deliver_activity(
            &state,
            &recipient_inbox_url,
            &activity,
            &sender_username,
        )
        .await
        {
            tracing::warn!(
                %recipient_inbox_url,
                error = ?e,
                "MLS welcome delivery failed (recipient must retry pairing)"
            );
        }
    });
}

/// Look up a local `users` row for a recipient_actor_uri, when it lives on
/// this IdP. Used by the inbox handler to resolve which `recipient_user_id`
/// to insert a Welcome under.
pub async fn lookup_local_user_for_actor(
    state: &AppState,
    actor_uri: &str,
) -> Option<idp_db::models::User> {
    let prefix = format!("{}/users/", state.config.issuer());
    if !actor_uri.starts_with(&prefix) {
        return None;
    }
    users::find_by_actor_uri(&state.pool, actor_uri)
        .await
        .ok()
        .flatten()
}

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
    let mls_kind = note
        .get("mlsKind")
        .and_then(|v| v.as_str())
        .unwrap_or("");

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
                .ok_or_else(|| {
                    OidcError::invalid_request("MLS commit Note missing `mlsEpoch`")
                })?;
            ingest_commit(state, conversation_id, epoch, &blob, proposer_actor_uri).await
        }
        "welcome" => {
            let device_id_str = note
                .get("mlsRecipientDeviceId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OidcError::invalid_request(
                        "MLS welcome Note missing `mlsRecipientDeviceId`",
                    )
                })?;
            let device_id: Uuid = device_id_str.parse().map_err(|_| {
                OidcError::invalid_request("MLS welcome `mlsRecipientDeviceId` is not a UUID")
            })?;
            ingest_welcome(state, recipient, device_id, conversation_id, &blob).await
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
    let outcome = mls_commits::insert_commit(
        &state.pool,
        conversation_id,
        epoch,
        blob,
        proposer_actor_uri,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let inserted = match outcome {
        mls_commits::InsertOutcome::Inserted(row) => row,
        mls_commits::InsertOutcome::Conflict(_) => {
            // Two peers replaying the same commit, or a sender retry after
            // a previous successful delivery. Both benign — the row is
            // already there and clients have already consumed it.
            tracing::debug!(
                conversation_id = %conversation_id,
                epoch,
                "inbound commit duplicate at this epoch — already stored"
            );
            return Ok(());
        }
    };

    let members = match conversations::get_members(&state.pool, conversation_id).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                conversation_id = %conversation_id,
                error = %e,
                "could not load members for commit fanout"
            );
            return Ok(());
        }
    };

    let prefix = format!("{}/users/", state.config.issuer());
    let payload = MlsCommitPayload {
        conversation_id: inserted.conversation_id,
        epoch: inserted.epoch,
        proposer_actor_uri: inserted.proposer_actor_uri.clone(),
        commit_blob: B64.encode(&inserted.commit_blob),
        created_at: inserted.created_at,
    };
    let event = WsEvent::MlsCommit(payload);

    for member in members {
        if !member.actor_uri.starts_with(&prefix) {
            continue;
        }
        if let Ok(Some(u)) = users::find_by_actor_uri(&state.pool, &member.actor_uri).await {
            state.hub.send_to_user(&u.id, event.clone());
        }
    }

    Ok(())
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
    let recipient_actor_uri = recipient
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("recipient has no actor_uri"))?;

    // The activity_uri is the AP activity ID; falls back to the inner Note's
    // id (some senders set it only there).
    let activity_uri = body
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| note.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| OidcError::invalid_request("Create activity missing id"))?;

    // Resolve `inReplyTo` to a local row's id. The preview text/sender lives
    // inside the encrypted body — server only needs the parent's UUID for
    // routing and soft-delete cascade.
    let in_reply_to_uri = note.get("inReplyTo").and_then(|v| v.as_str());
    let mut reply_to_id: Option<Uuid> = None;
    if let Some(parent_uri) = in_reply_to_uri {
        if let Ok(Some(parent)) = messages::find_by_activity_uri(&state.pool, parent_uri).await {
            reply_to_id = Some(parent.id);
        }
    }

    // Persist the conversation under the sender-supplied UUID when present
    // (so both IdPs agree on the conversation_id from the very first DM).
    let (resolved_conversation_id, _created) = conversations::get_or_create_dm_with_id(
        &state.pool,
        conversation_id,
        sender_actor_uri,
        recipient_actor_uri,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let msg = messages::create_message(
        &state.pool,
        resolved_conversation_id,
        sender_actor_uri,
        mls_ciphertext,
        activity_uri,
        reply_to_id,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Inbound attachments: same shape as before (Note.attachment array of
    // Document objects). Their plaintext metadata is, after Phase 5,
    // intentionally obscured by the sender — server still records what
    // came in for orphan-sweep audit and size accounting.
    crate::inbox::persist_inbound_attachments(state, msg.id, sender_actor_uri, note.get("attachment"))
        .await;

    // Re-read attachments so the WS event carries them inline and the
    // recipient's UI can render without a refetch.
    let inbound_attachments: Vec<WsAttachment> =
        attachments_repo::find_for_message(&state.pool, msg.id)
            .await
            .map(|rows| {
                rows.iter()
                    .map(|a| WsAttachment {
                        id: a.id,
                        mime_type: a.mime_type.clone(),
                        byte_size: a.byte_size,
                        original_filename: a.original_filename.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

    let sender_display_name = match remote_actors::find_by_actor_uri(&state.pool, sender_actor_uri)
        .await
    {
        Ok(Some(ra)) => ra.display_name,
        _ => None,
    };

    let event = WsEvent::NewDm(DmPayload {
        message_id: msg.id,
        conversation_id: msg.conversation_id,
        kind: "dm".to_string(),
        sender_address: sender_actor_uri.to_string(),
        sender_display_name,
        mls_ciphertext: B64.encode(&msg.mls_ciphertext),
        created_at: msg.created_at,
        reply_to_id,
        attachments: inbound_attachments,
        client_id: None,
    });

    if let Ok(json) = serde_json::to_string(&event) {
        let broker = state.broker.clone();
        let rid = recipient.id;
        let json_clone = json.clone();
        tokio::spawn(async move {
            if let Err(e) = broker.publish(rid, &json_clone).await {
                tracing::warn!(%rid, "broker publish failed: {e}");
            }
        });
    }

    state.hub.send_to_user(&recipient.id, event);

    tracing::info!(
        sender = %sender_actor_uri,
        recipient = %recipient.username,
        bytes = mls_ciphertext.len(),
        "MLS application message persisted via AP inbox"
    );
    Ok(())
}

async fn ingest_welcome(
    state: &AppState,
    recipient: &idp_db::models::User,
    device_id: Uuid,
    conversation_id: Uuid,
    blob: &[u8],
) -> Result<(), OidcError> {
    let row = mls_welcomes::insert_welcome(
        &state.pool,
        recipient.id,
        device_id,
        conversation_id,
        blob,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    state.hub.send_to_user(
        &recipient.id,
        WsEvent::MlsWelcomeReady(MlsWelcomeReadyPayload {
            conversation_id: row.conversation_id,
            recipient_device_id: row.recipient_device_id,
        }),
    );

    tracing::info!(
        recipient = %recipient.username,
        device_id = %device_id,
        conversation_id = %conversation_id,
        "stored inbound mls welcome"
    );
    Ok(())
}
