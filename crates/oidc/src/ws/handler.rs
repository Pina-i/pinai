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

use idp_db::repos::{messages, users};
use jwt_utils::validate_access_token;

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
            let username = address.split('@').next().unwrap_or(address);

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

            let domain = &state.config.domain;
            let event = WsEvent::NewDm(DmPayload {
                message_id: msg.id,
                sender_address: sender.federated_address(domain),
                content: msg.content,
                created_at: msg.created_at,
            });

            // Publish to broker for durability (catch-up on reconnect)
            let event_json = match serde_json::to_string(&event) {
                Ok(j) => j,
                Err(e) => {
                    warn!(%sender_id, "failed to serialize dm event: {e}");
                    return;
                }
            };
            // Publish to both users' streams (fire-and-forget, don't block delivery)
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

            // Push to recipient (immediate local delivery)
            state.hub.send_to_user(&recipient.id, event.clone());
            // Push to sender (multi-device echo)
            state.hub.send_to_user(&sender_id, event);

            info!(
                sender = %sender.federated_address(domain),
                recipient = %recipient.federated_address(domain),
                "dm sent via websocket"
            );
        }
    }
}
