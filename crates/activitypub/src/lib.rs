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
    /// An `Image`, or a list of them: kept as sent, so an unusual shape never fails the document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<Value>,
    /// A Pina'i extension: the account's pronouns, as a word its instance chose (`"she"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
}

impl Actor {
    /// Construct a `Person` actor for a local user.
    ///
    /// * `base_url`        — e.g. `https://idp.example.com`
    /// * `handle`          — full handle, e.g. `alex-7G4K`
    /// * `display_name`    — human-readable name
    /// * `public_key_pem`  — PEM-encoded Ed25519 **public** key
    pub fn person(base_url: &str, handle: &str, display_name: &str, public_key_pem: &str) -> Self {
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
            icon: None,
            pronouns: None,
        }
    }

    /// The actor with `bio` as its summary, escaped, and its pronouns, or neither.
    pub fn with_profile(mut self, bio: Option<&str>, pronouns: Option<&str>) -> Self {
        self.summary = bio.map(summary_html);
        self.pronouns = pronouns.map(str::to_owned);
        self
    }

    /// The summary as plain text, or none when it says nothing.
    pub fn bio(&self) -> Option<String> {
        self.summary
            .as_deref()
            .map(summary_text)
            .filter(|bio| !bio.is_empty())
    }

    /// The actor with `url` as its avatar, or none.
    pub fn with_icon(mut self, url: Option<&str>) -> Self {
        self.icon = url.map(|url| serde_json::json!({ "type": "Image", "url": url }));
        self
    }

    /// The avatar's URL: the icon's, or the first of a list of them.
    pub fn icon_url(&self) -> Option<&str> {
        let icon = match self.icon.as_ref()? {
            Value::Array(icons) => icons.first()?,
            icon => icon,
        };
        icon.get("url")?.as_str()
    }
}

// ─── Summary ─────────────────────────────────────────────────────────────────

/// A plain-text bio as a `summary`, which ActivityPub reads as HTML: escaped, line breaks kept.
pub fn summary_html(text: &str) -> String {
    let mut html = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '"' => html.push_str("&quot;"),
            '\'' => html.push_str("&#39;"),
            '\n' => html.push_str("<br>"),
            c => html.push(c),
        }
    }
    html
}

/// A peer's HTML `summary` as plain text: tags dropped — a line break or the end of a paragraph
/// kept as a new line — and character references decoded.
pub fn summary_text(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open) = rest.find('<') {
        text.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('>') else {
            break;
        };
        let tag = rest[open + 1..open + close].trim().to_ascii_lowercase();
        let name = tag
            .trim_start_matches('/')
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or_default();
        if name == "br" || (tag.starts_with('/') && name == "p") {
            text.push('\n');
        }
        rest = &rest[open + close + 1..];
    }
    // An unterminated `<` reads as itself.
    text.push_str(rest);
    let decoded = decode_references(&text);
    let lines: Vec<&str> = decoded.lines().map(str::trim_end).collect();
    lines.join("\n").trim().to_owned()
}

fn decode_references(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest[1..]
            .find(';')
            .filter(|&semi| semi <= 10)
            .and_then(|semi| Some((reference(&rest[1..1 + semi])?, semi + 2)));
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn reference(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let code = match name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => name.strip_prefix('#')?.parse().ok()?,
            };
            char::from_u32(code)
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

    /// Build an Update{Person} activity for profile propagation: the whole shown profile, a
    /// field left out meaning there is none.
    pub fn update_person(
        actor_url: &str,
        username: &str,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
        bio: Option<&str>,
        pronouns: Option<&str>,
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
        if let Some(bio) = bio {
            person["summary"] = Value::String(summary_html(bio));
        }
        if let Some(pronouns) = pronouns {
            person["pronouns"] = Value::String(pronouns.to_owned());
        }

        let activity_id = format!("{}/updates/{}", actor_url, uuid::Uuid::new_v4());
        Self {
            context: as_context(),
            id: activity_id,
            activity_type: "Update".to_string(),
            actor: actor_url.to_string(),
            object: person,
            to: Some(vec![
                "https://www.w3.org/ns/activitystreams#Public".to_string()
            ]),
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

#[cfg(test)]
mod tests;
