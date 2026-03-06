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
}

/// GET /ws?token=<jwt> — validate the token, then upgrade to WebSocket.
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

    ws.on_upgrade(move |socket| handle_socket(socket, user_id, state))
}

/// Runs after the WebSocket handshake completes.
async fn handle_socket(socket: WebSocket, user_id: Uuid, state: AppState) {
    let (rx, _handle) = state.hub.subscribe(user_id);
    let (ws_sink, ws_stream) = socket.split();

    info!(%user_id, "websocket connected");

    // Task: hub events → WebSocket out
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

            let recipient = match users::find_by_handle(&state.pool, &payload.recipient_handle).await {
                Ok(Some(u)) => u,
                _ => {
                    warn!(handle = %payload.recipient_handle, "recipient not found");
                    return;
                }
            };

            if recipient.id == sender_id {
                return;
            }

            let note_id = format!(
                "{}/users/{}/notes/{}",
                state.config.issuer(),
                sender.handle(),
                Uuid::new_v4(),
            );

            let msg = match messages::create_message(
                &state.pool,
                sender_id,
                recipient.id,
                &payload.content,
                Some(&note_id),
            )
            .await
            {
                Ok(m) => m,
                Err(e) => {
                    warn!(%sender_id, "failed to create dm: {e}");
                    return;
                }
            };

            let event = WsEvent::NewDm(DmPayload {
                message_id: msg.id,
                sender_handle: sender.handle(),
                content: msg.content,
                created_at: msg.created_at,
            });

            // Push to recipient
            state.hub.send_to_user(&recipient.id, event.clone());
            // Push to sender (multi-device echo)
            state.hub.send_to_user(&sender_id, event);

            info!(
                sender = %sender.handle(),
                recipient = %recipient.handle(),
                "dm sent via websocket"
            );
        }
    }
}
