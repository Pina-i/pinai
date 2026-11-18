use activitypub::{Actor, WebFingerResponse};
use tracing::debug;
use url::Url;

use crate::error::TransportError;
use crate::http::{get_json_screened, UrlPolicy};

/// A remote actor as its own instance describes it, with what is needed to deliver to it and
/// cache it.
#[derive(Debug)]
pub struct RemoteActor {
    /// The URL its document was fetched from, which the document names as its `id`.
    pub actor_url: Url,
    /// On the same origin as `actor_url`.
    pub inbox: Url,
    pub preferred_username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// The summary, as text.
    pub bio: Option<String>,
    /// The Pina'i `pronouns` extension, as the peer wrote it.
    pub pronouns: Option<String>,
}

/// Resolve a federated handle (`username@domain`) to an actor of the instance it names.
///
/// 1. GET `{scheme}://{domain}/.well-known/webfinger?resource=acct:{username}@{domain}`
/// 2. Take the `self` link, which must be on `{scheme}://{domain}`
/// 3. Fetch it as [`fetch_remote_actor`] does
///
/// An answer breaking any of these is [`TransportError::Upstream`]: no instance would send it.
pub async fn resolve_remote_actor(
    username: &str,
    domain: &str,
    scheme: &str,
    policy: UrlPolicy,
) -> Result<RemoteActor, TransportError> {
    let origin = origin_of(scheme, domain)?;
    let mut webfinger_url = origin.clone();
    webfinger_url.set_path("/.well-known/webfinger");
    webfinger_url
        .query_pairs_mut()
        .append_pair("resource", &format!("acct:{username}@{domain}"));

    debug!(%webfinger_url, "resolving remote actor via WebFinger");

    let wf_doc = get_json_screened(webfinger_url.as_str(), "application/jrd+json", policy).await?;
    let wf: WebFingerResponse = serde_json::from_value(wf_doc)
        .map_err(|e| TransportError::Upstream(format!("WebFinger parse failed: {e}")))?;

    let href = wf
        .links
        .iter()
        .find(|l| l.rel == "self" && l.mime_type.as_deref() == Some("application/activity+json"))
        .and_then(|l| l.href.as_deref())
        .ok_or_else(|| TransportError::Upstream("WebFinger response missing actor link".into()))?;
    let actor_url = Url::parse(href)
        .map_err(|e| TransportError::Upstream(format!("WebFinger actor link is no URL: {e}")))?;
    if actor_url.origin() != origin.origin() {
        return Err(TransportError::Upstream(format!(
            "WebFinger for {domain} names an actor elsewhere: {actor_url}"
        )));
    }

    fetch_remote_actor(actor_url.as_str(), policy).await
}

/// Fetch the actor document at `actor_url`, taken only when it names itself — its `id` is
/// `actor_url` — and its inbox is on its origin; anything else is [`TransportError::Upstream`].
pub async fn fetch_remote_actor(
    actor_url: &str,
    policy: UrlPolicy,
) -> Result<RemoteActor, TransportError> {
    let asked = Url::parse(actor_url)
        .map_err(|e| TransportError::BadRequest(format!("invalid actor URL: {e}")))?;

    debug!(%asked, "fetching remote actor");

    let actor_doc = get_json_screened(asked.as_str(), "application/activity+json", policy).await?;
    let actor: Actor = serde_json::from_value(actor_doc)
        .map_err(|e| TransportError::Upstream(format!("Actor parse failed: {e}")))?;

    if Url::parse(&actor.id).ok().as_ref() != Some(&asked) {
        return Err(TransportError::Upstream(format!(
            "the actor document at {asked} names another actor"
        )));
    }
    let inbox = Url::parse(&actor.inbox)
        .ok()
        .filter(|inbox| inbox.origin() == asked.origin())
        .ok_or_else(|| {
            TransportError::Upstream(format!(
                "the actor document at {asked} names an inbox elsewhere"
            ))
        })?;

    let avatar_url = actor.icon_url().map(str::to_owned);
    let bio = actor.bio();
    Ok(RemoteActor {
        actor_url: asked,
        inbox,
        preferred_username: Some(actor.preferred_username),
        display_name: if actor.name.is_empty() {
            None
        } else {
            Some(actor.name)
        },
        avatar_url,
        bio,
        pronouns: actor.pronouns,
    })
}

/// `{scheme}://{domain}`, refusing a `domain` that is anything but `host[:port]`.
fn origin_of(scheme: &str, domain: &str) -> Result<Url, TransportError> {
    let refuse = || TransportError::BadRequest(format!("not an http(s) domain: {domain:?}"));
    if !matches!(scheme, "http" | "https") {
        return Err(refuse());
    }
    let origin = Url::parse(&format!("{scheme}://{domain}")).map_err(|_| refuse())?;
    let bare = origin.username().is_empty()
        && origin.password().is_none()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none();
    if bare {
        Ok(origin)
    } else {
        Err(refuse())
    }
}

#[cfg(test)]
mod tests;
