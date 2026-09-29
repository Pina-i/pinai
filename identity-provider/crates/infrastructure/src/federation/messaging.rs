//! Messages to other instances: MLS application messages inside `Create{Note}` /
//! `Update{Note}` — see identity-provider/specs/05-e2ee.md § 5.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use domain::ConversationId;
use domain::identity::{Account, ActorUri, RemoteActor};
use domain::messaging::{
    DeliveryFailed, DirectDelivery, GroupSnapshot, Message, MessageFederation,
};
use federation_transport::UrlPolicy;
use jwt_utils::EdKeyPair;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::delivery::SignedDelivery;

pub struct ApMessageFederation {
    delivery: SignedDelivery,
    /// This instance's issuer: attachments are fetched from it by peers.
    issuer: String,
}

impl ApMessageFederation {
    pub fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy, issuer: String) -> Self {
        Self {
            delivery: SignedDelivery::new(keypair, policy),
            issuer,
        }
    }
}

#[async_trait::async_trait]
impl MessageFederation for ApMessageFederation {
    async fn deliver_direct(&self, delivery: &DirectDelivery) -> Result<(), DeliveryFailed> {
        let activity = create(
            &self.issuer,
            &delivery.message,
            &delivery.to.actor_uri,
            delivery.reply_to.as_deref(),
            None,
        );
        self.delivery
            .post(&delivery.from.actor_uri, &delivery.to.inbox, &activity)
            .await
            .map_err(|e| DeliveryFailed(e.to_string()))
    }

    fn send_to_group(
        &self,
        from: &Account,
        to: &[RemoteActor],
        message: &Message,
        reply_to: Option<&str>,
        group: &GroupSnapshot,
    ) {
        for member in to {
            let activity = create(
                &self.issuer,
                message,
                &member.actor_uri,
                reply_to,
                Some(group),
            );
            self.delivery
                .post_in_background(&from.actor_uri, &member.inbox, activity);
        }
    }

    fn send_edit(&self, from: &Account, to: &RemoteActor, message: &Message) {
        self.delivery.post_in_background(
            &from.actor_uri,
            &to.inbox,
            update(message, &to.actor_uri),
        );
    }
}

/// The `Note` every MLS payload rides in — application messages, edits, commits, Welcomes;
/// `mlsKind` tells the receiver what the opaque body is.
pub(super) fn mls_note(
    id: &str,
    from: &ActorUri,
    to: &ActorUri,
    conversation: ConversationId,
    body: &[u8],
    mls_kind: &str,
    extra: Map<String, Value>,
) -> Value {
    let mut note = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": id,
        "type": "Note",
        "attributedTo": from.as_str(),
        "to": [to.as_str()],
        "directMessage": true,
        "mediaType": "application/mls",
        "context": conversation.to_string(),
        "content": B64.encode(body),
        "mlsKind": mls_kind,
    });
    let fields = note.as_object_mut().expect("a JSON object");
    fields.extend(extra);
    note
}

/// The `mlsGroup` a group Note carries: how the recipient's instance holds the group.
pub(super) fn roster(group: &GroupSnapshot) -> Value {
    json!({
        "name": group.name,
        "members": group
            .members
            .iter()
            .map(|m| json!({ "actorUri": m.actor_uri.as_str(), "role": m.role.as_str() }))
            .collect::<Vec<_>>(),
    })
}

fn note(
    id: &str,
    message: &Message,
    to: &ActorUri,
    mls_kind: &str,
    extra: Map<String, Value>,
) -> Value {
    mls_note(
        id,
        &message.sender,
        to,
        message.conversation,
        message.ciphertext.as_bytes(),
        mls_kind,
        extra,
    )
}

/// A new message: the activity and its Note are both identified by the message's activity URI,
/// which is what lets the receiver derive the same message id.
fn create(
    issuer: &str,
    message: &Message,
    to: &ActorUri,
    reply_to: Option<&str>,
    group: Option<&GroupSnapshot>,
) -> Value {
    let mut extra = Map::new();
    if let Some(parent) = reply_to {
        extra.insert("inReplyTo".to_owned(), json!(parent));
    }
    if let Some(group) = group {
        extra.insert("mlsGroup".to_owned(), roster(group));
    }
    if !message.attachments.is_empty() {
        extra.insert(
            "attachment".to_owned(),
            message
                .attachments
                .iter()
                .map(|a| {
                    json!({
                        "type": "Document",
                        "mediaType": a.mime_type,
                        "url": format!("{issuer}/api/attachments/{}/content", a.id),
                        "name": a.original_filename,
                        "size": a.byte_size,
                    })
                })
                .collect(),
        );
    }
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": message.activity_uri,
        "type": "Create",
        "actor": message.sender.as_str(),
        "to": [to.as_str()],
        "object": note(&message.activity_uri, message, to, "application", extra),
    })
}

/// A message's new ciphertext, under a fresh activity whose Note names the message edited.
fn update(message: &Message, to: &ActorUri) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}/activities/{}", message.sender, Uuid::new_v4()),
        "type": "Update",
        "actor": message.sender.as_str(),
        "to": [to.as_str()],
        "object": note(&message.activity_uri, message, to, "edit", Map::new()),
    })
}

#[cfg(test)]
mod tests;
