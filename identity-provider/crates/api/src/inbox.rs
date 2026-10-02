//! `POST /users/{slug}/inbox` — the activities other instances deliver. Each is keyed on the
//! inbox it arrived at, never on a field of the activity, so a peer cannot act for other local
//! accounts; a redelivery is a no-op. The three inbound checks come first:
//! specs/06-federation-authentication.md § Inbound.

mod groups;
mod notes;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::ConversationId;
use domain::identity::ActorUri;
use domain::profile::{ProfileError, PublicProfile};
use domain::social::SocialError;
use serde_json::Value;

use crate::auth::SignedBody;
use crate::{ApiError, AppState};

pub async fn receive(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    SignedBody(signer, body): SignedBody,
) -> Result<StatusCode, ApiError> {
    let activity: Value = serde_json::from_slice(&body)
        .map_err(|e| ApiError::bad_request(format!("malformed activity JSON: {e}")))?;
    bind(&signer, &activity)?;
    let recipient = state
        .find_account
        .execute(&slug)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let kind = activity.get("type").and_then(Value::as_str).unwrap_or("");
    tracing::debug!(recipient = %recipient.username, activity_type = %kind, "inbox activity received");
    let object = activity.get("object");
    let object_type = object.and_then(|o| o.get("type")).and_then(Value::as_str);
    match (kind, object, object_type) {
        ("Follow", ..) => state
            .receive_follow
            .execute(recipient.id, signer)
            .await
            .map_err(friendship_refused)?,
        ("Accept", ..) => {
            // The Pina'i `conversationId` extension: the DM id the accepter's instance minted.
            let advertised = activity
                .get("conversationId")
                .and_then(Value::as_str)
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                .map(ConversationId::from);
            state
                .receive_accept
                .execute(recipient.id, signer, advertised)
                .await
                .map_err(friendship_refused)?
        }
        ("Reject", ..) => state
            .receive_reject
            .execute(recipient.id, signer)
            .await
            .map_err(friendship_refused)?,
        ("Undo", _, Some("Follow")) => state
            .receive_undo_follow
            .execute(recipient.id, signer)
            .await
            .map_err(friendship_refused)?,
        ("Create", Some(note), Some("Note")) => {
            notes::create(&state, &activity, note, &recipient, signer).await?
        }
        ("Update", Some(note), Some("Note")) => {
            notes::update(&state, note, &recipient, signer).await?
        }
        ("Update", Some(person), Some("Person")) => profile_update(&state, person, signer).await?,
        ("Add" | "Remove" | "Leave", ..) | ("Update", Some(_), Some("Group" | "Membership")) => {
            groups::change(&state, &activity, &recipient, signer).await?
        }
        ("Undo" | "Create" | "Update", ..) => {}
        (other, ..) => tracing::warn!(activity_type = %other, "unhandled activity type in inbox"),
    }
    Ok(StatusCode::ACCEPTED)
}

/// The activity's `actor` — a URI, or an embedded object — must be the signer: a signature
/// proves who sent the request, not whom the activity speaks for.
fn bind(signer: &ActorUri, activity: &Value) -> Result<(), ApiError> {
    let claimed = match activity.get("actor") {
        Some(Value::String(actor)) => Some(actor.as_str()),
        Some(Value::Object(actor)) => actor.get("id").and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(|| ApiError::bad_request("activity missing actor field"))?;
    if ActorUri::parse(claimed).ok().as_ref() != Some(signer) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "activity actor does not match the signing key",
        ));
    }
    Ok(())
}

fn friendship_refused(error: SocialError) -> ApiError {
    match error {
        // The follower's URI names no account this instance can address.
        SocialError::UserNotFound => ApiError::bad_request("Cannot parse remote actor URL"),
        SocialError::PeerNotAllowed(reason) => {
            ApiError::new(StatusCode::FORBIDDEN, "access_denied", reason)
        }
        SocialError::Unexpected(e) => ApiError::internal(e),
        other => ApiError::bad_request(other.to_string()),
    }
}

async fn profile_update(
    state: &AppState,
    person: &Value,
    signer: ActorUri,
) -> Result<(), ApiError> {
    let Some(actor) = person
        .get("id")
        .and_then(Value::as_str)
        .and_then(|id| ActorUri::parse(id).ok())
    else {
        return Ok(());
    };
    let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned);
    let profile = PublicProfile {
        display_name: text(person.get("name")),
        avatar_url: text(person.get("icon").and_then(|icon| icon.get("url"))),
        actor,
    };
    let actor = profile.actor.clone();
    state
        .receive_profile_update
        .execute(&signer, profile)
        .await
        .map_err(|e| match e {
            ProfileError::NotItsOwn => {
                ApiError::new(StatusCode::FORBIDDEN, "access_denied", e.to_string())
            }
            ProfileError::Unexpected(e) => ApiError::internal(e),
            other => ApiError::bad_request(other.to_string()),
        })?;
    tracing::info!(actor_uri = %actor, "profile update received");
    Ok(())
}

#[cfg(test)]
mod tests;
