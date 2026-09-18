//! Outbound ActivityPub delivery.
//!
//! The transport — WebFinger resolution and signed POSTs — lives in
//! `federation-transport`; this module only binds it to `AppState`.

use federation_transport::{signed_post, Signer, UrlPolicy};
use serde::de::DeserializeOwned;

use idp_state::{AppState, OidcError};

pub use federation_transport::RemoteActor;

/// Resolve a federated handle (`username@domain`) to a remote actor.
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
    Ok(federation_transport::resolve_remote_actor(
        username,
        domain,
        scheme,
        UrlPolicy::from_issuer(local_issuer),
    )
    .await?)
}

/// The signing identity for a local user's outbound requests.
///
/// The peer's verifier resolves this actor doc to find the public key, so the
/// request authenticates as that user.
fn user_key_id(state: &AppState, sender_username: &str) -> String {
    format!(
        "{}/users/{}#main-key",
        state.config.issuer(),
        sender_username
    )
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
    let key_id = user_key_id(state, sender_username);
    let signer = Signer {
        key_id: &key_id,
        signing_key: &state.keypair.signing_key,
    };

    signed_post(
        &signer,
        inbox_url,
        &body,
        "application/activity+json",
        state.url_policy,
    )
    .await?;
    Ok(())
}

/// Signed JSON POST to a peer IdP, for federated key-directory lookups
/// (`POST /api/keys/packages/claim`). Same signing path as
/// [`deliver_activity`], with a JSON content type and a typed response.
pub async fn signed_post_json<R>(
    state: &AppState,
    target_url: &str,
    body: &serde_json::Value,
    sender_username: &str,
) -> Result<R, OidcError>
where
    R: DeserializeOwned,
{
    let body_bytes = serde_json::to_vec(body)
        .map_err(|e| OidcError::server_error(format!("body serialize failed: {e}")))?;
    let key_id = user_key_id(state, sender_username);
    let signer = Signer {
        key_id: &key_id,
        signing_key: &state.keypair.signing_key,
    };

    signed_post(
        &signer,
        target_url,
        &body_bytes,
        "application/json",
        state.url_policy,
    )
    .await?
    .json::<R>()
    .await
    .map_err(|e| OidcError::server_error(format!("response decode failed: {e}")))
}
