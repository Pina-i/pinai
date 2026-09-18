use activitypub::{Actor, WebFingerResponse};
use tracing::debug;

use crate::error::TransportError;
use crate::http::{get_json_screened, UrlPolicy};

/// A resolved remote actor with what is needed to deliver to it and cache it.
pub struct RemoteActor {
    pub actor_url: String,
    pub inbox: String,
    pub preferred_username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Resolve a federated handle (`username@domain`) to a remote actor via WebFinger.
///
/// 1. GET `{scheme}://{domain}/.well-known/webfinger?resource=acct:{username}@{domain}`
/// 2. Extract the actor URL from the `self` link
/// 3. GET the actor URL → parse inbox + profile info
pub async fn resolve_remote_actor(
    username: &str,
    domain: &str,
    scheme: &str,
    policy: UrlPolicy,
) -> Result<RemoteActor, TransportError> {
    let resource = format!("acct:{}@{}", username, domain);
    let webfinger_url = format!(
        "{}://{}/.well-known/webfinger?resource={}",
        scheme, domain, resource
    );

    debug!(%webfinger_url, "resolving remote actor via WebFinger");

    let wf_doc = get_json_screened(&webfinger_url, "application/jrd+json", policy)
        .await
        .map_err(|e| match e {
            TransportError::Upstream(_) => {
                TransportError::NotFound("Remote user not found (WebFinger failed)".into())
            }
            other => other,
        })?;
    let wf: WebFingerResponse = serde_json::from_value(wf_doc)
        .map_err(|e| TransportError::Upstream(format!("WebFinger parse failed: {e}")))?;

    let actor_url = wf
        .links
        .iter()
        .find(|l| l.rel == "self" && l.mime_type.as_deref() == Some("application/activity+json"))
        .and_then(|l| l.href.clone())
        .ok_or_else(|| TransportError::Upstream("WebFinger response missing actor link".into()))?;

    debug!(%actor_url, "fetching remote actor");

    let actor_doc = get_json_screened(&actor_url, "application/activity+json", policy).await?;
    let actor: Actor = serde_json::from_value(actor_doc)
        .map_err(|e| TransportError::Upstream(format!("Actor parse failed: {e}")))?;

    Ok(RemoteActor {
        actor_url: actor.id,
        inbox: actor.inbox,
        preferred_username: Some(actor.preferred_username),
        display_name: if actor.name.is_empty() {
            None
        } else {
            Some(actor.name)
        },
        avatar_url: None, // Actor struct doesn't have icon field yet
    })
}
