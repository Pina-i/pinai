//! `GET /ws?token=` — a client's live connection: events out, frames in. See
//! identity-provider/specs/presence.md.

mod frames;

use application::messaging::DirectMessageCommand;
use application::presence::Session;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use connections::Frame;
use domain::identity::TokenError;
use domain::messaging::{MessagingError, MlsCiphertext};
use domain::presence::{PresenceError, PresenceState};
use domain::{ConnectionId, UserId};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::AppState;
use frames::{HEARTBEAT_ACK, SendDmPayload, WsClientMessage};

#[derive(Deserialize)]
pub struct WsQuery {
    token: String,
    /// The last durable event the client saw: those after it are replayed first.
    last_event_id: Option<String>,
}

/// A browser cannot set headers on a WebSocket, so the token rides in the query.
pub async fn upgrade(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let user = match state.auth.verify(&query.token) {
        Ok(user) => user,
        Err(TokenError::Invalid) => {
            return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response();
        }
        Err(TokenError::BadSubject) => {
            return (StatusCode::UNAUTHORIZED, "Invalid subject claim").into_response();
        }
    };
    ws.on_upgrade(move |socket| run(socket, user, query.last_event_id, state))
}

async fn run(socket: WebSocket, user: UserId, last_event_id: Option<String>, state: AppState) {
    let (events, handle, first) = state.hub.subscribe(user.as_uuid());
    let connection = ConnectionId::from(handle.conn_id());
    let session = match state
        .connect
        .execute(user, connection, first, OffsetDateTime::now_utc())
        .await
    {
        Ok(session) => session,
        Err(e) => {
            tracing::warn!(%user, error = ?e, "websocket refused: no session");
            return;
        }
    };
    tracing::info!(%user, "websocket connected");
    let (mut sink, stream) = socket.split();
    let replayed = match last_event_id {
        Some(last) => replay(&state, user, &last, &mut sink).await,
        None => true,
    };
    if replayed {
        let forwarding = tokio::spawn(forward(events, sink, state.shutdown.clone()));
        receive(stream, &state, &session).await;
        if state.shutdown.is_cancelled() {
            // It closes the socket, telling the client to reconnect.
            let _ = forwarding.await;
        } else {
            forwarding.abort();
        }
    }
    // Out of the hub first, so the count below no longer holds this connection.
    drop(handle);
    let last = state.hub.connection_count(&user.as_uuid()) == 0;
    if let Err(e) = state
        .disconnect
        .execute(&session, last, OffsetDateTime::now_utc())
        .await
    {
        tracing::warn!(%user, error = ?e, "disconnect not announced");
    }
    tracing::info!(%user, "websocket disconnected");
}

/// `false` when the socket closed mid-way.
async fn replay(
    state: &AppState,
    user: UserId,
    last_id: &str,
    sink: &mut SplitSink<WebSocket, Message>,
) -> bool {
    let missed = match state.missed_events.after(user, last_id).await {
        Ok(missed) => missed,
        Err(e) => {
            tracing::warn!(%user, error = ?e, "missed events not replayed");
            return true;
        }
    };
    let count = missed.len();
    for event in missed {
        // The payload is already an event's JSON.
        let envelope = format!(r#"{{"id":"{}","event":{}}}"#, event.id, event.payload);
        if sink.send(Message::Text(envelope.into())).await.is_err() {
            return false;
        }
    }
    if count > 0 {
        tracing::info!(%user, count, "replayed missed events");
    }
    true
}

/// The frames pushed to the account, to the socket, until the instance stops: the socket is
/// then closed as going away.
async fn forward(
    mut frames: mpsc::UnboundedReceiver<Frame>,
    mut sink: SplitSink<WebSocket, Message>,
    stop: CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            () = stop.cancelled() => {
                let _ = sink
                    .send(Message::Close(Some(CloseFrame {
                        code: close_code::AWAY,
                        reason: "the instance is stopping".into(),
                    })))
                    .await;
                return;
            }
                        frame = frames.recv() => frame,
        };
        let Some(frame) = frame else { return };
        if sink.send(Message::Text((*frame).into())).await.is_err() {
            break;
        }
    }
}

async fn receive(mut stream: SplitStream<WebSocket>, state: &AppState, session: &Session) {
    loop {
        let frame = tokio::select! {
            () = state.shutdown.cancelled() => return,
            frame = stream.next() => frame,
        };
        let Some(Ok(frame)) = frame else { return };
        let text = match frame {
            Message::Text(text) => text,
            Message::Close(_) => break,
            _ => continue,
        };
        let message: WsClientMessage = match serde_json::from_str(&text) {
            Ok(message) => message,
            Err(e) => {
                tracing::warn!(user = %session.user, "invalid ws message: {e}");
                continue;
            }
        };
        // A frame has no answer: a failure is only logged.
        if let Err(e) = handle(state, session, message).await {
            tracing::warn!(user = %session.user, error = ?e, "ws frame failed");
        }
    }
}

async fn handle(
    state: &AppState,
    session: &Session,
    message: WsClientMessage,
) -> Result<(), PresenceError> {
    let now = OffsetDateTime::now_utc();
    match message {
        WsClientMessage::Heartbeat => {
            state.heartbeat.execute(session, now).await?;
            state
                .hub
                .send_to_user(&session.user.as_uuid(), Frame::from(HEARTBEAT_ACK));
        }
        WsClientMessage::TypingStart(typing) => {
            // At most one a second an account: more would only flood the bus.
            if state.typing_limiter.allow(&session.user.to_string()) {
                state
                    .start_typing
                    .execute(session, typing.conversation_id.into(), now)
                    .await?;
            }
        }
        WsClientMessage::SetPresence(choice) => match choice.state.parse::<PresenceState>() {
            Ok(chosen) => state.set_presence.execute(session, chosen, now).await?,
            Err(_) => {
                tracing::warn!(user = %session.user, state = %choice.state, "ignoring unknown presence state")
            }
        },
        WsClientMessage::WatchConversation(watch) => {
            state
                .watch_conversation
                .execute(watch.conversation_id.into())
                .await?;
        }
        WsClientMessage::UnwatchConversation(watch) => {
            state
                .watch_conversation
                .stop(watch.conversation_id.into())
                .await;
        }
        WsClientMessage::SendDm(dm) => send_dm(state, session.user, dm).await,
    }
    Ok(())
}

/// The same flow as `POST /api/dm`, without replies, attachments or a pinned conversation.
async fn send_dm(state: &AppState, sender: UserId, dm: SendDmPayload) {
    let Ok(bytes) = B64.decode(&dm.mls_ciphertext) else {
        tracing::warn!(%sender, "invalid mls_ciphertext base64");
        return;
    };
    let ciphertext = match MlsCiphertext::parse(bytes) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            tracing::warn!(%sender, reason = %e.reason, "invalid mls_ciphertext");
            return;
        }
    };
    let Ok(recipient) = state.origin.resolve(&dm.recipient_address) else {
        tracing::warn!(address = %dm.recipient_address, "recipient not found");
        return;
    };
    let command = DirectMessageCommand {
        recipient,
        ciphertext,
        reply_to: None,
        attachments: Vec::new(),
        pinned: None,
        client_id: dm.client_id,
    };
    match state.send_direct_message.execute(sender, command).await {
        Ok(sent) => {
            tracing::info!(%sender, message_id = %sent.message.id, "dm sent via websocket");
            if let Some(delivery) = sent.delivery {
                let deliver = std::sync::Arc::clone(&state.deliver_direct_message);
                tokio::spawn(async move { deliver.execute(delivery).await });
            }
        }
        Err(MessagingError::SelfMessage) => {}
        // The socket has no error channel: a refusal is dropped, as `POST /api/dm` would refuse it.
        Err(e @ (MessagingError::YouBlocked | MessagingError::Undeliverable)) => {
            tracing::debug!(%sender, reason = %e, "dm not sent")
        }
        Err(e) => {
            tracing::warn!(%sender, address = %dm.recipient_address, error = ?e, "dm not sent")
        }
    }
}
