//! WebSocket upgrade endpoint and per-connection message loop.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use idp_db::repos::{messages, remote_actors, users};
use jwt_utils::validate_access_token;

use crate::federation::delivery;
use crate::ws::events::{DmPayload, WsClientMessage, WsEvent};
use crate::ws::hub::ConnectionHandle;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    token: String,
    /// Optional: last event ID received by the client.
    /// When provided, the server replays all events after this ID from the
    /// broker stream before switching to live delivery.
    last_event_id: Option<String>,
}

/// GET /ws?token=<jwt>&last_event_id=<id> — validate the token, then upgrade to WebSocket.
pub async fn ws_upgrade(
    State(state): State<AppState>,
    Query(params): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Validate JWT before upgrading the connection.
    let issuer = state.config.issuer();
    let claims = match validate_access_token(&params.token, &state.keypair, &issuer, "web-client") {
        Ok(c) => c,
        Err(_) => {
            return (axum::http::StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response();
        }
    };

    let user_id = match claims.sub.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return (axum::http::StatusCode::UNAUTHORIZED, "Invalid subject claim").into_response();
        }
    };

    let last_event_id = params.last_event_id;
    ws.on_upgrade(move |socket| handle_socket(socket, user_id, last_event_id, state))
}

/// Runs after the WebSocket handshake completes.
async fn handle_socket(
    socket: WebSocket,
    user_id: Uuid,
    last_event_id: Option<String>,
    state: AppState,
) {
    let (rx, _handle) = state.hub.subscribe(user_id);
    let (mut ws_sink, ws_stream) = socket.split();

    info!(%user_id, "websocket connected");

    // Replay missed events from broker if the client provided a last_event_id
    if let Some(ref last_id) = last_event_id {
        match state.broker.read_after(user_id, last_id).await {
            Ok(entries) => {
                let count = entries.len();
                for entry in entries {
                    // Wrap payload with the stream entry ID so the client can track position
                    let envelope = format!(r#"{{"id":"{}","event":{}}}"#, entry.id, entry.payload);
                    if ws_sink.send(Message::Text(envelope.into())).await.is_err() {
                        info!(%user_id, "websocket closed during catch-up replay");
                        return;
                    }
                }
                if count > 0 {
                    info!(%user_id, count, "replayed missed events from broker");
                }
            }
            Err(e) => {
                warn!(%user_id, "broker catch-up failed: {e}");
            }
        }
    }

    // Task: hub events → WebSocket out (live delivery)
    let send_task = tokio::spawn(forward_events(rx, ws_sink));

    // Task: WebSocket in → handle client messages
    let recv_task = tokio::spawn(receive_messages(ws_stream, user_id, state, _handle));

    // When either task finishes, abort the other.
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    info!(%user_id, "websocket disconnected");
}

/// Drain events from the hub receiver and send them as JSON over WebSocket.
async fn forward_events(
    mut rx: mpsc::UnboundedReceiver<WsEvent>,
    mut sink: futures_util::stream::SplitSink<WebSocket, Message>,
) {
    while let Some(event) = rx.recv().await {
        let json = match serde_json::to_string(&event) {
            Ok(j) => j,
            Err(e) => {
                warn!("failed to serialize ws event: {e}");
                continue;
            }
        };
        if sink.send(Message::Text(json.into())).await.is_err() {
            break;
        }
    }
}

/// Read client WebSocket frames and dispatch them.
async fn receive_messages(
    mut stream: futures_util::stream::SplitStream<WebSocket>,
    user_id: Uuid,
    state: AppState,
    _handle: ConnectionHandle, // kept alive for RAII unregister on drop
) {
    while let Some(Ok(frame)) = stream.next().await {
        let text = match frame {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };

        let msg: WsClientMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                warn!(%user_id, "invalid ws message: {e}");
                continue;
            }
        };

        handle_client_message(&state, user_id, msg).await;
    }
}

/// Process a typed client-to-server message.
async fn handle_client_message(state: &AppState, sender_id: Uuid, msg: WsClientMessage) {
    match msg {
        WsClientMessage::SendDm(payload) => {
            if payload.content.is_empty() || payload.content.len() > 4096 {
                warn!(%sender_id, "invalid dm content length");
                return;
            }

            let sender = match users::find_by_id(&state.pool, sender_id).await {
                Ok(Some(u)) => u,
                _ => {
                    warn!(%sender_id, "sender not found");
                    return;
                }
            };

            let sender_actor_uri = match sender.actor_uri.as_deref() {
                Some(uri) => uri,
                None => {
                    warn!(%sender_id, "sender has no actor_uri");
                    return;
                }
            };

            // Parse recipient address: "@username@domain" or "username@domain" or bare "username"
            let address = payload.recipient_address.strip_prefix('@').unwrap_or(&payload.recipient_address);
            let mut parts = address.splitn(2, '@');
            let username = parts.next().unwrap_or(address);
            let domain_opt = parts.next();

            let is_remote = domain_opt.map_or(false, |d| d != state.config.domain);

            if is_remote {
                let domain = domain_opt.unwrap();
                handle_remote_dm(state, sender_id, &sender, sender_actor_uri, username, domain, &payload.content).await;
            } else {
                // ── Local delivery ──────────────────────────────────────────
                let recipient = match users::find_by_username(&state.pool, username).await {
                    Ok(Some(u)) => u,
                    _ => {
                        warn!(address = %payload.recipient_address, "recipient not found");
                        return;
                    }
                };

                if recipient.id == sender_id {
                    return;
                }

                let recipient_actor_uri = match recipient.actor_uri.as_deref() {
                    Some(uri) => uri,
                    None => {
                        warn!(address = %payload.recipient_address, "recipient has no actor_uri");
                        return;
                    }
                };

                let activity_uri = format!(
                    "{}/users/{}/activities/{}",
                    state.config.issuer(),
                    sender.username,
                    Uuid::new_v4(),
                );

                let msg = match messages::create_message(
                    &state.pool,
                    sender_actor_uri,
                    recipient_actor_uri,
                    &payload.content,
                    &activity_uri,
                )
                .await
                {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(%sender_id, "failed to create dm: {e}");
                        return;
                    }
                };

                let local_domain = &state.config.domain;
                let sender_display_name =
                    Some(sender.display_name.clone().unwrap_or_else(|| sender.username.clone()));
                let event = WsEvent::NewDm(DmPayload {
                    message_id: msg.id,
                    sender_address: sender.federated_address(local_domain),
                    sender_display_name,
                    content: msg.content,
                    created_at: msg.created_at,
                });

                let event_json = match serde_json::to_string(&event) {
                    Ok(j) => j,
                    Err(e) => {
                        warn!(%sender_id, "failed to serialize dm event: {e}");
                        return;
                    }
                };
                let broker = state.broker.clone();
                let recipient_id = recipient.id;
                let json_clone = event_json.clone();
                tokio::spawn(async move {
                    if let Err(e) = broker.publish(recipient_id, &json_clone).await {
                        warn!(%recipient_id, "broker publish failed: {e}");
                    }
                    if let Err(e) = broker.publish(sender_id, &event_json).await {
                        warn!(%sender_id, "broker publish failed: {e}");
                    }
                });

                state.hub.send_to_user(&recipient.id, event.clone());
                state.hub.send_to_user(&sender_id, event);

                info!(
                    sender = %sender.federated_address(local_domain),
                    recipient = %recipient.federated_address(local_domain),
                    "dm sent via websocket"
                );
            }
        }
    }
}

/// Deliver a DM to a remote recipient via ActivityPub.
///
/// Lookup order:
/// 1. Derive actor URI from address and check `remote_actors` cache for a cached `inbox_url`.
/// 2. If not cached, resolve via WebFinger and upsert into the cache.
async fn handle_remote_dm(
    state: &AppState,
    sender_id: Uuid,
    sender: &idp_db::models::User,
    sender_actor_uri: &str,
    username: &str,
    domain: &str,
    content: &str,
) {
    let issuer = state.config.issuer();
    let scheme = if issuer.starts_with("https") { "https" } else { "http" };
    let guessed_actor_uri = format!("{}://{}/users/{}", scheme, domain, username);

    // Try cache first
    let (recipient_actor_uri, inbox_url) =
        match remote_actors::find_by_actor_uri(&state.pool, &guessed_actor_uri).await {
            Ok(Some(ra)) if ra.inbox_url.is_some() => {
                (ra.actor_uri, ra.inbox_url.unwrap())
            }
            _ => {
                // Cache miss — resolve via WebFinger
                match delivery::resolve_remote_actor(username, domain, &issuer).await {
                    Ok(ra) => {
                        let inbox = ra.inbox.clone();
                        let actor_url = ra.actor_url.clone();
                        let pool = state.pool.clone();
                        let domain_owned = domain.to_string();
                        let display = ra.display_name.clone();
                        let avatar = ra.avatar_url.clone();
                        let inbox_clone = inbox.clone();
                        tokio::spawn(async move {
                            if let Err(e) = remote_actors::upsert(
                                &pool,
                                &actor_url,
                                Some(&inbox_clone),
                                &domain_owned,
                                display.as_deref(),
                                avatar.as_deref(),
                            )
                            .await
                            {
                                warn!("failed to cache remote actor: {e}");
                            }
                        });
                        (ra.actor_url, inbox)
                    }
                    Err(e) => {
                        warn!(address = %format!("{}@{}", username, domain), "failed to resolve remote actor: {e:?}");
                        return;
                    }
                }
            }
        };

    let activity_uri = format!(
        "{}/users/{}/activities/{}",
        issuer,
        sender.username,
        Uuid::new_v4()
    );

    let msg = match messages::create_message(
        &state.pool,
        sender_actor_uri,
        &recipient_actor_uri,
        content,
        &activity_uri,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            warn!(%sender_id, "failed to create remote dm: {e}");
            return;
        }
    };

    // Build Create{Note} activity
    let note = activitypub::Note::direct(
        &activity_uri,
        sender_actor_uri,
        &recipient_actor_uri,
        content,
    );
    let activity = activitypub::create_note_activity(
        &activity_uri,
        sender_actor_uri,
        &recipient_actor_uri,
        note,
    );
    let activity_value = match serde_json::to_value(&activity) {
        Ok(v) => v,
        Err(e) => {
            warn!("failed to serialize ap activity: {e}");
            return;
        }
    };

    // Deliver to remote inbox in a background task
    let state_clone = state.clone();
    let inbox = inbox_url.clone();
    let sender_username = sender.username.clone();
    tokio::spawn(async move {
        if let Err(e) =
            delivery::deliver_activity(&state_clone, &inbox, &activity_value, &sender_username)
                .await
        {
            warn!(%inbox, "failed to deliver remote dm: {e:?}");
        }
    });

    // Echo event to sender only (recipient is on a remote server)
    let local_domain = &state.config.domain;
    let sender_display_name =
        Some(sender.display_name.clone().unwrap_or_else(|| sender.username.clone()));
    let event = WsEvent::NewDm(DmPayload {
        message_id: msg.id,
        sender_address: sender.federated_address(local_domain),
        sender_display_name,
        content: msg.content,
        created_at: msg.created_at,
    });
    state.hub.send_to_user(&sender_id, event);

    info!(
        sender = %sender.federated_address(local_domain),
        recipient = %format!("{}@{}", username, domain),
        "dm dispatched to remote actor via ActivityPub"
    );
}
