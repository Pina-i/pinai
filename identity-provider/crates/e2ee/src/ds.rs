//! MLS Delivery Service endpoints.
//!
//! Three Bearer-authenticated routes that surface the per-conversation
//! commit log + the welcome dispatch queue to local clients:
//!
//! - `POST /api/mls/groups/:conversation_id/commits` — append a Commit.
//!   Atomic at `(conversation_id, epoch)` thanks to the unique index in the
//!   migration. On race, returns `409` with the winning row attached so the
//!   loser can apply it locally and re-propose.
//! - `GET  /api/mls/groups/:conversation_id/commits?since=:epoch` — catch-up
//!   pagination by epoch.
//! - `GET  /api/mls/welcomes?device_id=:uuid` — atomically claim and return
//!   every pending Welcome targeted at the calling device.
//!
//! All three operate on byte blobs and do no MLS parsing — the server is
//! opaque to message content (see `identity-provider/specs/05-e2ee.md § 4`).
//!
//! Outbound federation is initiated here too: when a local user appends a
//! Commit, every remote member's IdP gets a best-effort `Create{Note}` with
//! `mediaType: application/mls` and `mlsKind: commit` (see
//! [`crate::federation_out`]).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

use idp_db::repos::{conversations, mls_commits, mls_welcomes, remote_actors, users};
use idp_federation::auth::require_auth;
use idp_federation::delivery as federation_delivery;
use idp_federation::mls as federation_mls;
use idp_realtime::{MlsCommitPayload, MlsWelcomeReadyPayload, WsEvent};
use idp_state::{AppState, OidcError};

// ── Shared DTOs ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CommitView {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub epoch: i64,
    pub proposer_actor_uri: String,
    /// TLS-encoded MLS Commit, base64-encoded.
    pub commit_blob: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<mls_commits::MlsCommit> for CommitView {
    fn from(c: mls_commits::MlsCommit) -> Self {
        Self {
            id: c.id,
            conversation_id: c.conversation_id,
            epoch: c.epoch,
            proposer_actor_uri: c.proposer_actor_uri,
            commit_blob: B64.encode(&c.commit_blob),
            created_at: c.created_at,
        }
    }
}

// ── POST /api/mls/groups/:conversation_id/commits ────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PostCommitRequest {
    /// Epoch the proposer believes is next. The server enforces uniqueness
    /// via the migration's `UNIQUE(conversation_id, epoch)` — a duplicate
    /// returns `409` with the winning body, *not* a server error.
    pub epoch: i64,
    /// TLS-encoded MLS Commit message, base64-encoded.
    pub commit_blob: String,
}

#[derive(Debug, Serialize)]
pub struct CommitConflictBody {
    pub error: &'static str,
    pub error_description: String,
    pub winning_commit: CommitView,
}

#[instrument(skip_all, fields(conversation_id = %conversation_id, epoch = body.epoch))]
pub async fn post_commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_id): Path<Uuid>,
    Json(body): Json<PostCommitRequest>,
) -> Result<Response, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("authenticated user not found"))?;
    let proposer_actor_uri = user
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("authenticated user has no actor_uri"))?
        .to_string();

    // Membership gate: only an active member may propose a commit. The server
    // can't validate the MLS proposal cryptographically — that's the clients'
    // job — but it can refuse to even persist a blob from someone outside.
    //
    // First-message bootstrap: when a sender founds a group, this commit
    // arrives BEFORE the corresponding `POST /api/dm` (which is what
    // normally lazy-creates the conversation row + member entries).
    // Without lazy-create here, the founder's commit always 404s. So if
    // the conversation doesn't exist yet AND this is plausibly a founding
    // commit (epoch ≤ 1), create the conversation as a DM with just the
    // proposer. The other member will be added when the proposer hands
    // the welcome to `POST /api/mls/welcomes`.
    let mut members = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if members.is_empty() {
        if body.epoch > 1 {
            return Err(OidcError::not_found("conversation not found"));
        }
        conversations::create_conversation_with_id(&state.pool, conversation_id, "dm", None)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        conversations::add_member(&state.pool, conversation_id, &proposer_actor_uri)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        members = conversations::get_members(&state.pool, conversation_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        tracing::info!(
            conversation_id = %conversation_id,
            proposer = %proposer_actor_uri,
            "lazy-created DM conversation on founding commit"
        );
    }
    if !members.iter().any(|m| m.actor_uri == proposer_actor_uri) {
        return Err(OidcError::access_denied(
            "not a member of this conversation",
        ));
    }

    // Decode the blob upfront — no point taking the unique-index lock if the
    // payload is malformed.
    let blob = B64
        .decode(&body.commit_blob)
        .map_err(|_| OidcError::invalid_request("`commit_blob` is not valid base64"))?;
    if blob.is_empty() {
        return Err(OidcError::invalid_request("`commit_blob` is empty"));
    }

    if body.epoch < 0 {
        return Err(OidcError::invalid_request("`epoch` must be non-negative"));
    }

    let outcome = mls_commits::insert_commit(
        &state.pool,
        conversation_id,
        body.epoch,
        &blob,
        &proposer_actor_uri,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let inserted = match outcome {
        mls_commits::InsertOutcome::Inserted(row) => row,
        mls_commits::InsertOutcome::Conflict(winner) => {
            tracing::info!(
                conversation_id = %conversation_id,
                attempted_epoch = body.epoch,
                winning_epoch = winner.epoch,
                "commit lost the epoch race"
            );
            let body = CommitConflictBody {
                error: "epoch_conflict",
                error_description: format!(
                    "another commit already exists at epoch {} for this conversation",
                    winner.epoch
                ),
                winning_commit: winner.into(),
            };
            return Ok((StatusCode::CONFLICT, Json(body)).into_response());
        }
    };

    // Local fanout: every active member who is a local user gets a WS event.
    fanout_commit_to_local_members(&state, &members, &inserted).await;

    // Federation fanout: every active member on a remote IdP gets a
    // best-effort signed Create{Note} with the commit blob. The message
    // self-heals via clients' catch-up pull on reconnect, so a missed
    // delivery is recoverable without a durable outbox.
    federation_mls::deliver_commit_to_remote_members(
        &state,
        &members,
        &user.username,
        &proposer_actor_uri,
        &inserted.commit_blob,
        inserted.conversation_id,
        inserted.epoch,
    );

    let view: CommitView = inserted.into();
    Ok((StatusCode::CREATED, Json(view)).into_response())
}

/// Push `MlsCommit` WS events to every local member of the conversation.
///
/// We push to the proposer too — the success response carries the same body,
/// but pushing the event keeps a single multi-device user's other tabs in
/// sync without each one having to round-trip the REST endpoint.
async fn fanout_commit_to_local_members(
    state: &AppState,
    members: &[idp_db::models::ConversationMember],
    commit: &mls_commits::MlsCommit,
) {
    let prefix = format!("{}/users/", state.config.issuer());
    let payload = MlsCommitPayload {
        conversation_id: commit.conversation_id,
        epoch: commit.epoch,
        proposer_actor_uri: commit.proposer_actor_uri.clone(),
        commit_blob: B64.encode(&commit.commit_blob),
        created_at: commit.created_at,
    };
    let event = WsEvent::MlsCommit(payload);

    for member in members {
        if !member.actor_uri.starts_with(&prefix) {
            continue;
        }
        match users::find_by_actor_uri(&state.pool, &member.actor_uri).await {
            Ok(Some(u)) => state.hub.send_to_user(&u.id, event.clone()),
            Ok(None) => {
                tracing::warn!(
                    actor_uri = %member.actor_uri,
                    "local-prefix member has no users row — skipping WS push"
                );
            }
            Err(e) => {
                tracing::warn!(
                    actor_uri = %member.actor_uri,
                    error = %e,
                    "user lookup failed during commit fanout"
                );
            }
        }
    }
}

// ── GET /api/mls/groups/:conversation_id/commits?since= ──────────────────────

#[derive(Debug, Deserialize)]
pub struct CommitCatchupQuery {
    /// Return commits with `epoch > since`. Use `0` (or omit) on first sync.
    #[serde(default)]
    pub since: i64,
}

#[derive(Debug, Serialize)]
pub struct CommitCatchupResponse {
    pub commits: Vec<CommitView>,
    /// True if the page hit the cap and a follow-up call may return more.
    pub has_more: bool,
}

const COMMIT_CATCHUP_LIMIT: i64 = 256;

#[instrument(skip_all, fields(conversation_id = %conversation_id, since = query.since))]
pub async fn get_commits_since(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_id): Path<Uuid>,
    Query(query): Query<CommitCatchupQuery>,
) -> Result<Json<CommitCatchupResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("authenticated user not found"))?;
    let actor_uri = user
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("authenticated user has no actor_uri"))?;

    // Members-of-this-conversation gate, identical to post_commit.
    let members = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if members.is_empty() {
        return Err(OidcError::not_found("conversation not found"));
    }
    if !members.iter().any(|m| m.actor_uri == actor_uri) {
        return Err(OidcError::access_denied(
            "not a member of this conversation",
        ));
    }

    if query.since < 0 {
        return Err(OidcError::invalid_request("`since` must be non-negative"));
    }

    let rows = mls_commits::list_since(
        &state.pool,
        conversation_id,
        query.since,
        COMMIT_CATCHUP_LIMIT,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let has_more = rows.len() as i64 == COMMIT_CATCHUP_LIMIT;
    let commits = rows.into_iter().map(CommitView::from).collect();

    Ok(Json(CommitCatchupResponse { commits, has_more }))
}

// ── GET /api/mls/welcomes?device_id= ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WelcomeFetchQuery {
    /// The calling device's UUID. Welcomes are leaf-targeted so each device
    /// must only consume its own — without this filter a multi-device user's
    /// first device would race-claim every sibling's bundles.
    pub device_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct WelcomeView {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub recipient_device_id: Uuid,
    /// TLS-encoded MLS Welcome, base64-encoded.
    pub welcome_blob: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct WelcomeFetchResponse {
    pub welcomes: Vec<WelcomeView>,
}

#[instrument(skip_all, fields(device_id = %query.device_id))]
pub async fn get_welcomes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WelcomeFetchQuery>,
) -> Result<Json<WelcomeFetchResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let claimed = mls_welcomes::claim_pending_for_device(&state.pool, user_id, query.device_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let welcomes = claimed
        .into_iter()
        .map(|w| WelcomeView {
            id: w.id,
            conversation_id: w.conversation_id,
            recipient_device_id: w.recipient_device_id,
            welcome_blob: B64.encode(&w.welcome_blob),
            created_at: w.created_at,
        })
        .collect::<Vec<_>>();

    if !welcomes.is_empty() {
        tracing::info!(
            user_id = %user_id,
            device_id = %query.device_id,
            count = welcomes.len(),
            "delivered pending mls welcomes"
        );
    }

    Ok(Json(WelcomeFetchResponse { welcomes }))
}

// ── POST /api/mls/welcomes (Phase 5b) ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PostWelcomeRequest {
    /// Local recipient — server resolves to a user_id.
    pub recipient_actor_uri: String,
    pub recipient_device_id: Uuid,
    pub conversation_id: Uuid,
    /// TLS-encoded MLS Welcome message, base64-encoded.
    pub welcome_blob: String,
}

#[derive(Debug, Serialize)]
pub struct PostWelcomeResponse {
    pub id: Uuid,
}

/// Deliver a Welcome bundle. The endpoint handles both same-IdP and
/// cross-IdP recipients:
/// - **Local recipient** → insert into `mls_welcomes` + push the
///   existing `MlsWelcomeReady` WS event. Returns the row id.
/// - **Remote recipient** → fan out via signed AP `Create{Note}` with
///   `mlsKind: welcome` to the recipient's IdP inbox. Returns
///   `{ id: nil }` since there's no local row.
///
/// Sender authenticates via Bearer. We don't require membership in
/// the conversation (the new recipient isn't a member yet, and the
/// next commit's epoch validates the sender cryptographically). A
/// malicious peer could queue a forged welcome, but the recipient's
/// MLS join will fail when it tries to apply it — bounded by the
/// per-device welcome queue orphan-sweep + the rate limits on the
/// calling user.
#[instrument(skip_all, fields(
    recipient_actor_uri = %body.recipient_actor_uri,
    recipient_device_id = %body.recipient_device_id,
    conversation_id = %body.conversation_id,
))]
pub async fn post_welcome(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PostWelcomeRequest>,
) -> Result<Json<PostWelcomeResponse>, OidcError> {
    let sender_user_id = require_auth(&state, &headers).await?;

    let blob = B64
        .decode(&body.welcome_blob)
        .map_err(|_| OidcError::invalid_request("`welcome_blob` is not valid base64"))?;
    if blob.is_empty() {
        return Err(OidcError::invalid_request("`welcome_blob` is empty"));
    }

    // Local-vs-remote dispatch. The recipient_actor_uri is local when
    // its prefix matches our own issuer's `<issuer>/users/`.
    let local_prefix = format!("{}/users/", state.config.issuer());
    let is_local = body.recipient_actor_uri.starts_with(&local_prefix);

    if is_local {
        let recipient = users::find_by_actor_uri(&state.pool, &body.recipient_actor_uri)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .ok_or_else(|| {
                OidcError::not_found("recipient_actor_uri matches our issuer but no such user")
            })?;

        // Add the welcome recipient to `conversation_members` so the
        // subsequent `POST /api/dm` finds a 2-member DM via
        // `find_dm_between` and reuses it. Idempotent: `add_member`
        // upserts (ON CONFLICT DO UPDATE SET left_at = NULL). The
        // founding commit (post_commit, above) already lazy-created
        // the conversation row + the proposer's membership.
        conversations::add_member(&state.pool, body.conversation_id, &body.recipient_actor_uri)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        let row = mls_welcomes::insert_welcome(
            &state.pool,
            recipient.id,
            body.recipient_device_id,
            body.conversation_id,
            &blob,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        state.hub.send_to_user(
            &recipient.id,
            WsEvent::MlsWelcomeReady(MlsWelcomeReadyPayload {
                conversation_id: body.conversation_id,
                recipient_device_id: body.recipient_device_id,
            }),
        );

        tracing::info!(
            recipient_user_id = %recipient.id,
            recipient_device_id = %body.recipient_device_id,
            conversation_id = %body.conversation_id,
            "stored local mls welcome"
        );

        return Ok(Json(PostWelcomeResponse { id: row.id }));
    }

    // ── Cross-IdP path ──────────────────────────────────────────────
    //
    // Resolve the recipient's IdP inbox (cache-first, then WebFinger),
    // then deliver an AP `Create{Note}` carrying the welcome blob.
    // Best-effort `tokio::spawn` per `deliver_welcome_to_remote`'s
    // contract — a missed delivery means the receiving client just
    // doesn't see the new group until its next pairing/scan, which
    // matches the rest of our AP semantics.
    let sender = users::find_by_id(&state.pool, sender_user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("sender user_id not found"))?;
    let sender_actor_uri = sender
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("sender has no actor_uri"))?;

    // Mirror the local-recipient path: add the remote recipient to
    // our own `conversation_members` so the subsequent `POST /api/dm`
    // (the message Bob about to type) reuses this conversation_id
    // instead of creating a parallel one. The remote IdP independently
    // tracks its own membership when it processes the incoming AP
    // `Create{Note}` welcome.
    conversations::add_member(&state.pool, body.conversation_id, &body.recipient_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let inbox_url = resolve_remote_inbox(&state, &body.recipient_actor_uri).await?;

    federation_mls::deliver_welcome_to_remote(
        &state,
        &sender.username,
        sender_actor_uri,
        &body.recipient_actor_uri,
        &inbox_url,
        body.recipient_device_id,
        body.conversation_id,
        &blob,
    );

    tracing::info!(
        recipient_actor_uri = %body.recipient_actor_uri,
        recipient_device_id = %body.recipient_device_id,
        conversation_id = %body.conversation_id,
        "dispatched mls welcome to remote inbox"
    );

    Ok(Json(PostWelcomeResponse { id: Uuid::nil() }))
}

/// Resolve a remote actor URI to its inbox URL. Cache-first via
/// `remote_actors`, fallback to a fresh WebFinger + actor doc fetch.
async fn resolve_remote_inbox(state: &AppState, actor_uri: &str) -> Result<String, OidcError> {
    if let Ok(Some(ra)) = remote_actors::find_by_actor_uri(&state.pool, actor_uri).await {
        if let Some(inbox) = ra.inbox_url {
            return Ok(inbox);
        }
    }

    // Cache miss — parse the URI for `username@domain` and resolve.
    let parsed: url::Url = actor_uri
        .parse()
        .map_err(|_| OidcError::invalid_request("recipient_actor_uri is not a valid URL"))?;
    let username = parsed
        .path()
        .trim_start_matches("/users/")
        .trim_end_matches('/');
    if username.is_empty() {
        return Err(OidcError::invalid_request(
            "recipient_actor_uri does not look like /users/<handle>",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| OidcError::invalid_request("recipient_actor_uri missing host"))?;
    let domain = match parsed.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };

    let issuer = state.config.issuer();
    let resolved = federation_delivery::resolve_remote_actor(username, &domain, &issuer)
        .await
        .map_err(|e| OidcError::server_error(format!("WebFinger failed: {e:?}")))?;

    // Cache for next time. `upsert` uses COALESCE to preserve the
    // newly-resolved inbox even on subsequent updates.
    let pool = state.pool.clone();
    let actor_url = resolved.actor_url.clone();
    let inbox_clone = resolved.inbox.clone();
    let domain_clone = domain.clone();
    let display = resolved.display_name.clone();
    let avatar = resolved.avatar_url.clone();
    tokio::spawn(async move {
        if let Err(e) = remote_actors::upsert(
            &pool,
            &actor_url,
            Some(&inbox_clone),
            &domain_clone,
            display.as_deref(),
            avatar.as_deref(),
        )
        .await
        {
            tracing::warn!("failed to cache remote actor: {e}");
        }
    });

    Ok(resolved.inbox)
}
