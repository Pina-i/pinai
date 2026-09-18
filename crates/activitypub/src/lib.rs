//! ActivityPub / ActivityStreams 2.0 types for Pīna'i federation.
//!
//! Covers the subset needed for social graph (Follow/Accept/Reject) and
//! direct messaging (Create/Note).  All structs derive Serialize/Deserialize
//! so they can be sent/received as JSON-LD payloads.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─── JSON-LD context constants ────────────────────────────────────────────────

pub const AS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";
pub const SECURITY_CONTEXT: &str = "https://w3id.org/security/v1";

/// Standard two-element `@context` used by Actor documents.
pub fn actor_context() -> Value {
    serde_json::json!([AS_CONTEXT, SECURITY_CONTEXT])
}

/// Single-element `@context` for most activities and objects.
pub fn as_context() -> Value {
    Value::String(AS_CONTEXT.to_string())
}

// ─── WebFinger ────────────────────────────────────────────────────────────────

/// RFC 7033 WebFinger response (`application/jrd+json`).
#[derive(Debug, Serialize, Deserialize)]
pub struct WebFingerResponse {
    pub subject: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    pub links: Vec<WebFingerLink>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebFingerLink {
    pub rel: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

impl WebFingerResponse {
    /// Build a minimal WebFinger response pointing to the actor URL.
    pub fn for_actor(subject: &str, actor_url: &str) -> Self {
        Self {
            subject: subject.to_string(),
            aliases: vec![actor_url.to_string()],
            links: vec![
                WebFingerLink {
                    rel: "self".to_string(),
                    mime_type: Some("application/activity+json".to_string()),
                    href: Some(actor_url.to_string()),
                },
                WebFingerLink {
                    rel: "http://webfinger.net/rel/profile-page".to_string(),
                    mime_type: Some("text/html".to_string()),
                    href: Some(actor_url.to_string()),
                },
            ],
        }
    }
}

// ─── Public Key ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
}

// ─── Actor (Person) ───────────────────────────────────────────────────────────

/// ActivityPub `Person` actor.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Actor {
    #[serde(rename = "@context")]
    pub context: Value,
    pub id: String,
    #[serde(rename = "type")]
    pub actor_type: String,
    pub preferred_username: String,
    pub name: String,
    pub inbox: String,
    pub outbox: String,
    pub followers: String,
    pub following: String,
    pub public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl Actor {
    /// Construct a `Person` actor for a local user.
    ///
    /// * `base_url`        — e.g. `https://idp.example.com`
    /// * `handle`          — full handle, e.g. `alex-7G4K`
    /// * `display_name`    — human-readable name
    /// * `public_key_pem`  — PEM-encoded Ed25519 **public** key
    pub fn person(
        base_url: &str,
        handle: &str,
        display_name: &str,
        public_key_pem: &str,
    ) -> Self {
        let actor_url = format!("{}/users/{}", base_url, handle);
        Self {
            context: actor_context(),
            id: actor_url.clone(),
            actor_type: "Person".to_string(),
            preferred_username: handle.to_string(),
            name: display_name.to_string(),
            inbox: format!("{}/inbox", actor_url),
            outbox: format!("{}/outbox", actor_url),
            followers: format!("{}/followers", actor_url),
            following: format!("{}/following", actor_url),
            public_key: PublicKey {
                id: format!("{}#main-key", actor_url),
                owner: actor_url.clone(),
                public_key_pem: public_key_pem.to_string(),
            },
            summary: None,
            url: Some(actor_url),
        }
    }
}

// ─── OrderedCollection ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderedCollection {
    #[serde(rename = "@context")]
    pub context: Value,
    pub id: String,
    #[serde(rename = "type")]
    pub collection_type: String,
    pub total_items: i64,
    pub ordered_items: Vec<Value>,
}

impl OrderedCollection {
    pub fn new(id: &str, total_items: i64, ordered_items: Vec<Value>) -> Self {
        Self {
            context: as_context(),
            id: id.to_string(),
            collection_type: "OrderedCollection".to_string(),
            total_items,
            ordered_items,
        }
    }
}

// ─── Activity ─────────────────────────────────────────────────────────────────

/// Generic ActivityPub activity (Follow, Accept, Reject, Undo, Create, …).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    #[serde(rename = "@context")]
    pub context: Value,
    pub id: String,
    #[serde(rename = "type")]
    pub activity_type: String,
    pub actor: String,
    pub object: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    /// Used by `Like` activities to carry the emoji.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl Activity {
    /// Build a Follow activity.
    pub fn follow(activity_id: &str, actor_url: &str, target_actor_url: &str) -> Self {
        Self {
            context: as_context(),
            id: activity_id.to_string(),
            activity_type: "Follow".to_string(),
            actor: actor_url.to_string(),
            object: Value::String(target_actor_url.to_string()),
            to: Some(vec![target_actor_url.to_string()]),
            cc: None,
            published: Some(utc_now_rfc3339()),
            content: None,
        }
    }

    /// Build an Accept{Follow} activity.
    pub fn accept(activity_id: &str, actor_url: &str, follow_activity: Value) -> Self {
        Self {
            context: as_context(),
            id: activity_id.to_string(),
            activity_type: "Accept".to_string(),
            actor: actor_url.to_string(),
            object: follow_activity,
            to: None,
            cc: None,
            published: Some(utc_now_rfc3339()),
            content: None,
        }
    }

    /// Build a Reject{Follow} activity.
    pub fn reject(activity_id: &str, actor_url: &str, follow_activity: Value) -> Self {
        Self {
            context: as_context(),
            id: activity_id.to_string(),
            activity_type: "Reject".to_string(),
            actor: actor_url.to_string(),
            object: follow_activity,
            to: None,
            cc: None,
            published: Some(utc_now_rfc3339()),
            content: None,
        }
    }

    /// Build an Undo{Follow} activity (unfollow).
    pub fn undo_follow(activity_id: &str, actor_url: &str, follow_activity: Value) -> Self {
        Self {
            context: as_context(),
            id: activity_id.to_string(),
            activity_type: "Undo".to_string(),
            actor: actor_url.to_string(),
            object: follow_activity,
            to: None,
            cc: None,
            published: Some(utc_now_rfc3339()),
            content: None,
        }
    }

    /// Build an Update{Person} activity for profile propagation.
    pub fn update_person(
        actor_url: &str,
        username: &str,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
    ) -> Self {
        let mut person = serde_json::json!({
            "type": "Person",
            "id": actor_url,
            "preferredUsername": username,
        });
        if let Some(name) = display_name {
            person["name"] = Value::String(name.to_string());
        }
        if let Some(url) = avatar_url {
            person["icon"] = serde_json::json!({
                "type": "Image",
                "url": url,
            });
        }

        let activity_id = format!("{}/updates/{}", actor_url, uuid::Uuid::new_v4());
        Self {
            context: as_context(),
            id: activity_id,
            activity_type: "Update".to_string(),
            actor: actor_url.to_string(),
            object: person,
            to: Some(vec!["https://www.w3.org/ns/activitystreams#Public".to_string()]),
            cc: None,
            published: Some(utc_now_rfc3339()),
            content: None,
        }
    }

    /// Build a `Like` activity (reaction). The emoji is carried in `content`.
    pub fn like(activity_id: &str, actor_url: &str, object_uri: &str, emoji: &str) -> Self {
        Self {
            context: as_context(),
            id: activity_id.to_string(),
            activity_type: "Like".to_string(),
            actor: actor_url.to_string(),
            object: Value::String(object_uri.to_string()),
            to: None,
            cc: None,
            published: Some(utc_now_rfc3339()),
            content: Some(emoji.to_string()),
        }
    }

    /// Build an `Undo{Like}` activity (remove reaction).
    pub fn undo_like(activity_id: &str, actor_url: &str, like_activity: Value) -> Self {
        Self {
            context: as_context(),
            id: activity_id.to_string(),
            activity_type: "Undo".to_string(),
            actor: actor_url.to_string(),
            object: like_activity,
            to: None,
            cc: None,
            published: Some(utc_now_rfc3339()),
            content: None,
        }
    }
}

// ─── Note (Direct Message) ────────────────────────────────────────────────────

/// An ActivityPub `Note` used for direct messages.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    #[serde(rename = "@context")]
    pub context: Value,
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributed_to: String,
    pub content: String,
    pub published: String,
    pub to: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cc: Vec<String>,
    /// Set to `true` to mark as a direct message (Mastodon-compatible extension).
    #[serde(default)]
    pub direct_message: bool,
    /// ActivityPub `inReplyTo` — points to the parent message's activity URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
}

impl Note {
    pub fn direct(
        note_id: &str,
        sender_actor_url: &str,
        recipient_actor_url: &str,
        content: &str,
    ) -> Self {
        Self {
            context: as_context(),
            id: note_id.to_string(),
            object_type: "Note".to_string(),
            attributed_to: sender_actor_url.to_string(),
            content: content.to_string(),
            published: utc_now_rfc3339(),
            to: vec![recipient_actor_url.to_string()],
            cc: vec![],
            direct_message: true,
            in_reply_to: None,
        }
    }

    /// Build a direct message Note that is a reply to another message.
    pub fn direct_reply(
        note_id: &str,
        sender_actor_url: &str,
        recipient_actor_url: &str,
        content: &str,
        in_reply_to: &str,
    ) -> Self {
        let mut note = Self::direct(note_id, sender_actor_url, recipient_actor_url, content);
        note.in_reply_to = Some(in_reply_to.to_string());
        note
    }
}

/// Build a `Create{Note}` activity wrapping a Note.
pub fn create_note_activity(
    activity_id: &str,
    sender_actor_url: &str,
    recipient_actor_url: &str,
    note: Note,
) -> Activity {
    Activity {
        context: as_context(),
        id: activity_id.to_string(),
        activity_type: "Create".to_string(),
        actor: sender_actor_url.to_string(),
        object: serde_json::to_value(note).unwrap_or(Value::Null),
        to: Some(vec![recipient_actor_url.to_string()]),
        cc: None,
        published: Some(utc_now_rfc3339()),
        content: None,
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn utc_now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
