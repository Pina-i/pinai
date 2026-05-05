//! Outbound ActivityPub delivery: resolve remote actors and deliver signed activities.

use activitypub::{Actor, WebFingerResponse};
use http_signatures::{http_date_now, sha256_digest, sign_request, SignParams};
use tracing::{debug, warn};

use idp_state::{AppState, OidcError};

/// Resolved remote actor with the info needed to deliver activities and cache profiles.
#[allow(dead_code)]
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
    local_issuer: &str,
) -> Result<RemoteActor, OidcError> {
    let scheme = if local_issuer.starts_with("https") {
        "https"
    } else {
        "http"
    };

    // Step 1: WebFinger
    let resource = format!("acct:{}@{}", username, domain);
    let webfinger_url = format!(
        "{}://{}/.well-known/webfinger?resource={}",
        scheme, domain, resource
    );

    debug!(%webfinger_url, "resolving remote actor via WebFinger");

    let client = reqwest::Client::new();
    let wf_resp = client
        .get(&webfinger_url)
        .header("Accept", "application/jrd+json")
        .send()
        .await
        .map_err(|e| OidcError::server_error(format!("WebFinger request failed: {e}")))?;

    if !wf_resp.status().is_success() {
        return Err(OidcError::not_found(
            "Remote user not found (WebFinger failed)",
        ));
    }

    let wf: WebFingerResponse = wf_resp
        .json()
        .await
        .map_err(|e| OidcError::server_error(format!("WebFinger parse failed: {e}")))?;

    // Step 2: Extract actor URL from the `self` link.
    let actor_url = wf
        .links
        .iter()
        .find(|l| l.rel == "self" && l.mime_type.as_deref() == Some("application/activity+json"))
        .and_then(|l| l.href.clone())
        .ok_or_else(|| OidcError::server_error("WebFinger response missing actor link"))?;

    debug!(%actor_url, "fetching remote actor");

    // Step 3: Fetch the actor document to get the inbox URL and profile info.
    let actor_resp = client
        .get(&actor_url)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| OidcError::server_error(format!("Actor fetch failed: {e}")))?;

    if !actor_resp.status().is_success() {
        return Err(OidcError::server_error("Failed to fetch remote actor"));
    }

    let actor: Actor = actor_resp
        .json()
        .await
        .map_err(|e| OidcError::server_error(format!("Actor parse failed: {e}")))?;

    Ok(RemoteActor {
        actor_url: actor.id,
        inbox: actor.inbox,
        preferred_username: Some(actor.preferred_username),
        display_name: if actor.name.is_empty() { None } else { Some(actor.name) },
        avatar_url: None, // Actor struct doesn't have icon field yet
    })
}

/// Deliver a JSON-LD activity to a remote inbox, signed with HTTP Signatures.
pub async fn deliver_activity(
    state: &AppState,
    inbox_url: &str,
    activity: &serde_json::Value,
    sender_username: &str,
) -> Result<(), OidcError> {
    let body = serde_json::to_vec(activity)
        .map_err(|e| OidcError::server_error(format!("Activity serialization failed: {e}")))?;

    // Parse the inbox URL to extract host and path.
    let url: url::Url = inbox_url
        .parse()
        .map_err(|e| OidcError::server_error(format!("Invalid inbox URL: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| OidcError::server_error("Inbox URL missing host"))?;
    let host_with_port = match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    };
    let path = url.path();

    // Build the key ID and signature.
    let date = http_date_now();
    let digest = sha256_digest(&body);
    let key_id = format!(
        "{}/users/{}#main-key",
        state.config.issuer(),
        sender_username
    );

    let signature = sign_request(SignParams {
        method: "post",
        path,
        host: &host_with_port,
        date: &date,
        digest: Some(&digest),
        key_id: &key_id,
        signing_key: &state.keypair.signing_key,
    })
    .map_err(|e| OidcError::server_error(format!("HTTP Signature failed: {e}")))?;

    debug!(%inbox_url, "delivering activity");

    let client = reqwest::Client::new();
    let resp = client
        .post(inbox_url)
        .header("Content-Type", "application/activity+json")
        .header("Date", &date)
        .header("Digest", &digest)
        .header("Host", &host_with_port)
        .header("Signature", &signature)
        .body(body)
        .send()
        .await
        .map_err(|e| OidcError::server_error(format!("Activity delivery failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        warn!(%inbox_url, %status, %text, "remote inbox rejected activity");
        return Err(OidcError::server_error(format!(
            "Remote inbox returned {status}"
        )));
    }

    debug!(%inbox_url, "activity delivered successfully");
    Ok(())
}
