//! WebSocket upgrade endpoint and per-connection message loop.

use std::time::Instant;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use idp_db::repos::{conversations, messages, remote_actors, users};
use jwt_utils::validate_access_token;

use idp_federation::delivery;
use idp_federation::mls as federation_mls;
use idp_presence::types::{PresenceEvent, PresenceState, TypingEvent};

use crate::AppState;
use idp_realtime::{ConnectionHandle, DmPayload, HeartbeatAckPayload, WsClientMessage, WsEvent};

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    token: String,
    /// Optional: last event ID received by the client.
    /// When provided, the server replays all events after this ID from the
    /// broker stream before switching to live delivery.
    last_event_id: Option<String>,
}

/// Per-user typing rate limiter: tracks last typing_start timestamp per user.
static TYPING_RATE_LIMIT: std::sync::LazyLock<DashMap<Uuid, Instant>> =
    std::sync::LazyLock::new(DashMap::new);

/// GET /ws?token=<jwt>&last_event_id=<id> — validate the token, then upgrade to WebSocket.
pub async fn ws_upgrade(
    State(state): State<AppState>,
    Query(params): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let issuer = state.config.issuer();
    let claims = match validate_access_token(&params.token, &state.keypair, &issuer, "web-client") {
        Ok(c) => c,
        Err(_) => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid or expired token",
            )
                .into_response();
        }
    };

    let user_id = match claims.sub.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid subject claim",
            )
                .into_response();
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
    let (rx, handle, is_first_connection) = state.hub.subscribe(user_id);
    let conn_id = handle.conn_id();
    let (mut ws_sink, ws_stream) = socket.split();

    info!(%user_id, "websocket connected");

    // Look up user's actor_uri for presence publishing.
    let actor_uri = match users::find_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => u.actor_uri.unwrap_or_default(),
        _ => String::new(),
    };

    // Register in heartbeat tracker.
    if let Some(ref tracker) = state.heartbeat_tracker {
        tracker.register(user_id, conn_id, actor_uri.clone());
    }

    // Publish `online` presence iff this connection is the user's first.
    // `is_first_connection` is decided atomically inside `subscribe`, so two
    // simultaneous subscribes for the same user can't both observe `false`.
    if !actor_uri.is_empty() && is_first_connection {
        publish_presence(&state, &actor_uri, PresenceState::Online).await;
    }

    // Replay missed events from broker if the client provided a last_event_id.
    if let Some(ref last_id) = last_event_id {
        match state.broker.read_after(user_id, last_id).await {
            Ok(entries) => {
                let count = entries.len();
                for entry in entries {
                    let envelope = format!(r#"{{"id":"{}","event":{}}}"#, entry.id, entry.payload);
                    if ws_sink.send(Message::Text(envelope.into())).await.is_err() {
                        info!(%user_id, "websocket closed during catch-up replay");
                        // Cleanup happens inside receive_messages; just return here.
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

    // Task: hub events → WebSocket out (live delivery).
    let send_task = tokio::spawn(forward_events(rx, ws_sink));

    // Task: WebSocket in → handle client messages.
    // `handle` moves into receive_messages; cleanup (offline publish, HB unregister)
    // happens there after the loop exits, ensuring the handle is dropped before we check counts.
    let recv_task = tokio::spawn(receive_messages(
        ws_stream, user_id, conn_id, actor_uri, state, handle,
    ));

    // When either task finishes, drop both JoinHandles.
    // Dropping a JoinHandle detaches the task; recv_task will exit naturally when
    // the WS stream closes, at which point it runs its own cleanup.
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    info!(%user_id, "websocket disconnected");
}

/// Publish a presence event to the local Redis pub-sub channel.
/// Handle a user-chosen presence change (popover status switcher).
///
/// Heartbeat-driven `away` will still override this after 10 min of inactivity
/// — tracking a sticky manual override is a follow-up.
async fn handle_set_presence(state: &AppState, actor_uri: &str, raw: &str) {
    if actor_uri.is_empty() {
        return;
    }
    let next = match raw {
        "online" => PresenceState::Online,
        "away" => PresenceState::Away,
        "offline" => PresenceState::Offline,
        "dnd" => PresenceState::Dnd,
        other => {
            warn!(actor_uri = %actor_uri, %other, "ignoring unknown presence state");
            return;
        }
    };
    publish_presence(state, actor_uri, next).await;
}

async fn publish_presence(state: &AppState, actor_uri: &str, presence: PresenceState) {
    let channel = format!("presence:{}", state.config.domain);
    let event = PresenceEvent {
        kind: "presence".to_string(),
        event: presence,
        actor_uri: actor_uri.to_string(),
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    };

    let payload = match serde_json::to_string(&event) {
        Ok(p) => p,
        Err(e) => {
            warn!("failed to serialize presence event: {e}");
            return;
        }
    };

    if let Err(e) = state.broker.publish_presence(&channel, &payload).await {
        warn!(actor_uri = %actor_uri, "failed to publish presence event: {e}");
    }
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
///
/// Takes ownership of `handle`; on exit it:
/// 1. Drops `handle` (removes connection from hub)
/// 2. Unregisters from heartbeat tracker
/// 3. Publishes `offline` if no more connections remain for this user
async fn receive_messages(
    mut stream: futures_util::stream::SplitStream<WebSocket>,
    user_id: Uuid,
    conn_id: Uuid,
    actor_uri: String,
    state: AppState,
    handle: ConnectionHandle,
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

        match msg {
            WsClientMessage::Heartbeat => {
                handle_heartbeat(&state, user_id, conn_id, &actor_uri).await;
            }
            WsClientMessage::TypingStart(payload) => {
                handle_typing_start(&state, user_id, &actor_uri, payload.conversation_id).await;
            }
            WsClientMessage::SendDm(payload) => {
                handle_send_dm(&state, user_id, payload).await;
            }
            WsClientMessage::WatchConversation(payload) => {
                handle_watch_conversation(&state, payload.conversation_id).await;
            }
            WsClientMessage::UnwatchConversation(payload) => {
                handle_unwatch_conversation(&state, payload.conversation_id).await;
            }
            WsClientMessage::SetPresence(payload) => {
                handle_set_presence(&state, &actor_uri, &payload.state).await;
            }
        }
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    // Drop the handle first so the hub removes our connection before we check the count.
    drop(handle);

    // Unregister from heartbeat tracker.
    if let Some(ref tracker) = state.heartbeat_tracker {
        tracker.unregister(user_id, conn_id);
    }

    // Publish `offline` if this was the user's last connection.
    if !actor_uri.is_empty() && state.hub.connection_count(&user_id) == 0 {
        publish_presence(&state, &actor_uri, PresenceState::Offline).await;
    }
}

/// Handle a heartbeat: touch tracker, ack, and transition away→online if needed.
async fn handle_heartbeat(state: &AppState, user_id: Uuid, conn_id: Uuid, actor_uri: &str) {
    if let Some(ref tracker) = state.heartbeat_tracker {
        tracker.touch(user_id, conn_id);
    }

    // Transition away → online on any heartbeat.
    if let Some(ref store) = state.presence_store {
        if store.get(actor_uri) == PresenceState::Away {
            publish_presence(state, actor_uri, PresenceState::Online).await;
        }
    }

    state
        .hub
        .send_to_user(&user_id, WsEvent::HeartbeatAck(HeartbeatAckPayload {}));
}

/// Group remote conversation members by their domain.
/// Members on the local instance are skipped.
async fn remote_members_by_domain(
    state: &AppState,
    conversation_id: Uuid,
) -> std::collections::HashMap<String, Vec<String>> {
    let mut by_domain: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let local_issuer = state.config.issuer();

    let members =
        match idp_db::repos::conversations::get_members(&state.pool, conversation_id).await {
            Ok(m) => m,
            Err(e) => {
                warn!(%conversation_id, "failed to load members for watch: {e}");
                return by_domain;
            }
        };

    for member in members {
        // Local members do not need an SSE — their presence/typing arrives via
        // local Redis already.
        if member.actor_uri.starts_with(&local_issuer) {
            continue;
        }
        if let Some(host) = url::Url::parse(&member.actor_uri).ok().and_then(|u| {
            match (u.host_str().map(|h| h.to_string()), u.port()) {
                (Some(host), Some(port)) => Some(format!("{host}:{port}")),
                (Some(host), None) => Some(host),
                _ => None,
            }
        }) {
            by_domain.entry(host).or_default().push(member.actor_uri);
        }
    }
    by_domain
}

/// Handle watch_conversation: ensure outbound SSE connections to every remote
/// domain involved in the conversation.
async fn handle_watch_conversation(state: &AppState, conversation_id: Uuid) {
    let Some(registry) = state.remote_registry.as_ref() else {
        return;
    };
    let by_domain = remote_members_by_domain(state, conversation_id).await;
    if by_domain.is_empty() {
        return;
    }
    registry
        .watch_conversation(conversation_id, by_domain)
        .await;
}

/// Handle unwatch_conversation: drop interest; closes outbound SSE for any
/// domain that no longer has a watcher.
async fn handle_unwatch_conversation(state: &AppState, conversation_id: Uuid) {
    let Some(registry) = state.remote_registry.as_ref() else {
        return;
    };
    registry.unwatch_conversation(conversation_id).await;
}

/// Handle a typing_start: rate-limit (1/s per user), then publish to Redis.
async fn handle_typing_start(
    state: &AppState,
    user_id: Uuid,
    actor_uri: &str,
    conversation_id: Uuid,
) {
    let now = Instant::now();
    if let Some(last) = TYPING_RATE_LIMIT.get(&user_id) {
        if now.duration_since(*last).as_secs() < 1 {
            return;
        }
    }
    TYPING_RATE_LIMIT.insert(user_id, now);

    let channel = format!("typing:{conversation_id}");
    let event = TypingEvent {
        kind: "typing".to_string(),
        actor_uri: actor_uri.to_string(),
        conversation_id,
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    };

    let payload = match serde_json::to_string(&event) {
        Ok(p) => p,
        Err(e) => {
            warn!("failed to serialize typing event: {e}");
            return;
        }
    };

    if let Err(e) = state.broker.publish_presence(&channel, &payload).await {
        warn!(%user_id, "failed to publish typing event: {e}");
    }
}

/// 64 KiB ceiling on incoming MLS ciphertexts to bound abuse over WS.
/// Mirrors the REST path's cap.
const MAX_MLS_CIPHERTEXT_BYTES: usize = 64 * 1024;

/// Process a SendDm client-to-server message.
async fn handle_send_dm(state: &AppState, sender_id: Uuid, payload: idp_realtime::SendDmPayload) {
    let mls_ciphertext = match B64.decode(&payload.mls_ciphertext) {
        Ok(b) if !b.is_empty() && b.len() <= MAX_MLS_CIPHERTEXT_BYTES => b,
        Ok(b) => {
            warn!(%sender_id, len = b.len(), "invalid mls_ciphertext length");
            return;
        }
        Err(_) => {
            warn!(%sender_id, "invalid mls_ciphertext base64");
            return;
        }
    };

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
    let address = payload
        .recipient_address
        .strip_prefix('@')
        .unwrap_or(&payload.recipient_address);
    let mut parts = address.splitn(2, '@');
    let username = parts.next().unwrap_or(address);
    let domain_opt = parts.next();

    let is_remote = domain_opt.is_some_and(|d| d != state.config.domain);

    if is_remote {
        let domain = domain_opt.unwrap();
        handle_remote_dm(
            state,
            sender_id,
            &sender,
            sender_actor_uri,
            username,
            domain,
            &mls_ciphertext,
            payload.client_id.clone(),
        )
        .await;
    } else {
        // ── Local delivery ────────────────────────────────────────────────────
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

        let (conversation_id, _created) = match conversations::get_or_create_dm(
            &state.pool,
            sender_actor_uri,
            recipient_actor_uri,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(%sender_id, "failed to get/create conversation: {e}");
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
            conversation_id,
            sender_actor_uri,
            &mls_ciphertext,
            &activity_uri,
            None,
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
        let sender_display_name = Some(
            sender
                .display_name
                .clone()
                .unwrap_or_else(|| sender.username.clone()),
        );
        // Recipient never sees the sender's correlation token.
        let recipient_payload = DmPayload {
            message_id: msg.id,
            conversation_id,
            kind: "dm".to_string(),
            sender_address: sender.federated_address(local_domain),
            sender_display_name: sender_display_name.clone(),
            mls_ciphertext: B64.encode(&msg.mls_ciphertext),
            created_at: msg.created_at,
            reply_to_id: None,
            // WS `send_dm` doesn't carry attachment_ids; attachments only flow
            // through the REST `POST /api/dm` path.
            attachments: Vec::new(),
            client_id: None,
        };
        let sender_payload = DmPayload {
            client_id: payload.client_id.clone(),
            ..recipient_payload.clone()
        };
        let recipient_event = WsEvent::NewDm(recipient_payload);
        let sender_event = WsEvent::NewDm(sender_payload);

        let recipient_json = match serde_json::to_string(&recipient_event) {
            Ok(j) => j,
            Err(e) => {
                warn!(%sender_id, "failed to serialize dm event: {e}");
                return;
            }
        };
        let sender_json = match serde_json::to_string(&sender_event) {
            Ok(j) => j,
            Err(e) => {
                warn!(%sender_id, "failed to serialize dm event: {e}");
                return;
            }
        };
        let broker = state.broker.clone();
        let recipient_id = recipient.id;
        tokio::spawn(async move {
            if let Err(e) = broker.publish(recipient_id, &recipient_json).await {
                warn!(%recipient_id, "broker publish failed: {e}");
            }
            if let Err(e) = broker.publish(sender_id, &sender_json).await {
                warn!(%sender_id, "broker publish failed: {e}");
            }
        });

        state.hub.send_to_user(&recipient.id, recipient_event);
        state.hub.send_to_user(&sender_id, sender_event);

        info!(
            sender = %sender.federated_address(local_domain),
            recipient = %recipient.federated_address(local_domain),
            "dm sent via websocket"
        );
    }
}

/// Deliver a DM to a remote recipient via ActivityPub.
#[allow(clippy::too_many_arguments)]
async fn handle_remote_dm(
    state: &AppState,
    sender_id: Uuid,
    sender: &idp_db::models::User,
    sender_actor_uri: &str,
    username: &str,
    domain: &str,
    mls_ciphertext: &[u8],
    client_id: Option<String>,
) {
    let issuer = state.config.issuer();
    let scheme = state.config.scheme();
    let guessed_actor_uri = format!("{}://{}/users/{}", scheme, domain, username);

    let (recipient_actor_uri, inbox_url) =
        match remote_actors::find_by_actor_uri(&state.pool, &guessed_actor_uri).await {
            Ok(Some(ra)) if ra.inbox_url.is_some() => (ra.actor_uri, ra.inbox_url.unwrap()),
            _ => match delivery::resolve_remote_actor(username, domain, &issuer).await {
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
                    warn!(
                        address = %format!("{}@{}", username, domain),
                        "failed to resolve remote actor: {e:?}"
                    );
                    return;
                }
            },
        };

    let (conversation_id, _created) =
        match conversations::get_or_create_dm(&state.pool, sender_actor_uri, &recipient_actor_uri)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(%sender_id, "failed to get/create conversation: {e}");
                return;
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
        conversation_id,
        sender_actor_uri,
        mls_ciphertext,
        &activity_uri,
        None,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            warn!(%sender_id, "failed to create remote dm: {e}");
            return;
        }
    };

    // Build the MLS-flavored Create{Note} envelope. The conversation UUID
    // travels in the Note's `context` field so the recipient's inbox keeps
    // the same conversation_id on both sides.
    let activity_value = federation_mls::build_application_create_activity(
        &activity_uri,
        &activity_uri,
        sender_actor_uri,
        &recipient_actor_uri,
        conversation_id,
        mls_ciphertext,
        None,
        None,
    );

    let local_domain = &state.config.domain;
    let sender_display_name = Some(
        sender
            .display_name
            .clone()
            .unwrap_or_else(|| sender.username.clone()),
    );
    let event = WsEvent::NewDm(DmPayload {
        message_id: msg.id,
        conversation_id,
        kind: "dm".to_string(),
        sender_address: sender.federated_address(local_domain),
        sender_display_name,
        mls_ciphertext: B64.encode(&msg.mls_ciphertext),
        created_at: msg.created_at,
        reply_to_id: None,
        attachments: Vec::new(),
        client_id,
    });
    state.hub.send_to_user(&sender_id, event);

    federation_mls::deliver_dm_to_remote(
        state,
        &inbox_url,
        activity_value,
        &sender.username,
        sender_id,
        &msg,
    );

    info!(
        sender = %sender.federated_address(local_domain),
        recipient = %format!("{}@{}", username, domain),
        "dm dispatched to remote actor via ActivityPub"
    );
}
