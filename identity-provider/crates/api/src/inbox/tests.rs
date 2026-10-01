use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use domain::ConversationId;
use domain::identity::testing::{TrustedSignatures, account, remote_actor};
use domain::identity::{Account, ActorUri, RemoteActor};
use domain::messaging::testing::MessageNotice;
use domain::profile::testing::ProfileSeeds;
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING};
use domain::social::{FriendshipStatus, SocialGraph};
use serde_json::{Value, json};

use crate::testing::TestApp;

struct World {
    app: TestApp,
    alice: Account,
    carol: RemoteActor,
}

fn world() -> World {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    World {
        app: TestApp::with([alice.clone()], [carol.clone()]),
        alice,
        carol,
    }
}

impl World {
    async fn deliver(&self, from: &ActorUri, activity: Value) -> (StatusCode, Value) {
        self.app
            .call_as_peer(Method::POST, "/users/alice_t3st0/inbox", from, activity)
            .await
    }

    fn by_carol(&self, kind: &str, object: Value) -> Value {
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{}/activities/{}", self.carol.actor_uri, uuid::Uuid::new_v4()),
            "type": kind,
            "actor": self.carol.actor_uri.as_str(),
            "object": object,
        })
    }

    fn follow(&self) -> Value {
        self.by_carol("Follow", json!(self.alice.actor_uri.as_str()))
    }

    fn mls_note(&self, kind: &str, extra: Value) -> Value {
        let mut note = json!({
            "type": "Note",
            "id": format!("{}/activities/{}", self.carol.actor_uri, uuid::Uuid::new_v4()),
            "mediaType": "application/mls",
            "mlsKind": kind,
            "context": ConversationId::generate().to_string(),
            "content": B64.encode(b"mls bytes"),
        });
        note.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        note
    }
}

// ─── The three inbound checks ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unsigned_delivery_is_refused_before_anything() {
    let w = world();
    let request = axum::http::Request::post("/users/alice_t3st0/inbox")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(w.follow().to_string()))
        .unwrap();

    let (status, body) = w.app.send(request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "missing Signature header");
    assert!(
        w.app
            .peers
            .graph
            .incoming_requests(w.alice.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_body_its_signed_digest_does_not_match_is_refused() {
    let w = world();
    let signed_over = w.follow().to_string();
    let swapped = w.by_carol("Undo", w.follow()).to_string();
    let request = TestApp::signed(
        Method::POST,
        "/users/alice_t3st0/inbox",
        &w.carol.actor_uri,
        &swapped,
        &TrustedSignatures::digest(signed_over.as_bytes()),
    );

    let (status, body) = w.app.send(request).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error_description"],
        "Digest does not match request body"
    );
}

#[tokio::test]
async fn an_activity_whose_actor_is_not_the_signer_is_refused() {
    let w = world();
    let dave = remote_actor("dave_k2m9x@idp.dave.test").actor_uri;

    let (status, body) = w.deliver(&dave, w.follow()).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(
        body["error_description"],
        "activity actor does not match the signing key"
    );
}

#[tokio::test]
async fn an_actor_embedded_as_an_object_is_bound_too() {
    let w = world();
    let mut follow = w.follow();
    follow["actor"] = json!({ "id": w.carol.actor_uri.as_str(), "type": "Person" });

    let (status, body) = w.deliver(&w.carol.actor_uri, follow).await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

#[tokio::test]
async fn a_delivery_that_is_no_activity_is_refused() {
    let w = world();
    let mut actorless = w.follow();
    actorless.as_object_mut().unwrap().remove("actor");
    let raw = "{not json";
    let garbled = TestApp::signed(
        Method::POST,
        "/users/alice_t3st0/inbox",
        &w.carol.actor_uri,
        raw,
        &TrustedSignatures::digest(raw.as_bytes()),
    );

    let (no_actor, no_actor_body) = w.deliver(&w.carol.actor_uri, actorless).await;
    let (bad_json, bad_json_body) = w.app.send(garbled).await;

    assert_eq!(no_actor, StatusCode::BAD_REQUEST);
    assert_eq!(
        no_actor_body["error_description"],
        "activity missing actor field"
    );
    assert_eq!(bad_json, StatusCode::BAD_REQUEST);
    assert!(
        bad_json_body["error_description"]
            .as_str()
            .unwrap()
            .starts_with("malformed activity JSON:"),
        "{bad_json_body}"
    );
}

#[tokio::test]
async fn a_delivery_to_nobody_here_is_not_found() {
    let w = world();

    let (status, body) = w
        .app
        .call_as_peer(
            Method::POST,
            "/users/bob_t3st0/inbox",
            &w.carol.actor_uri,
            w.follow(),
        )
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error_description"], "User not found");
}

#[tokio::test]
async fn an_activity_of_a_kind_not_handled_is_accepted_and_dropped() {
    let w = world();

    let (status, _) = w
        .deliver(&w.carol.actor_uri, w.by_carol("Like", json!("x")))
        .await;

    assert_eq!(status, StatusCode::ACCEPTED);
}

// ─── Friendships ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_follow_is_an_incoming_request() {
    let w = world();

    let (status, body) = w.deliver(&w.carol.actor_uri, w.follow()).await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let incoming = w
        .app
        .peers
        .graph
        .incoming_requests(w.alice.id)
        .await
        .unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].friend, w.carol.actor_uri);
}

#[tokio::test]
async fn a_follow_from_someone_the_recipient_blocked_is_accepted_and_dropped() {
    let w = world();
    w.app.reach.set(w.alice.id, &w.carol.actor_uri, BLOCKED);

    let (status, _) = w.deliver(&w.carol.actor_uri, w.follow()).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, incoming) = w
        .app
        .call(Method::GET, "/api/friends/incoming", Some(w.alice.id), None)
        .await;
    assert_eq!(incoming, json!([]));
}

#[tokio::test]
async fn an_accept_makes_friends_under_the_advertised_dm() {
    let w = world();
    w.app
        .peers
        .graph
        .record_outgoing(w.alice.id, &w.carol.actor_uri, None)
        .await
        .unwrap();
    let dm = ConversationId::generate();
    let mut accept = w.by_carol("Accept", json!({ "type": "Follow" }));
    accept["conversationId"] = json!(dm.to_string());

    let (status, body) = w.deliver(&w.carol.actor_uri, accept).await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let side = w
        .app
        .peers
        .graph
        .between(w.alice.id, &w.carol.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(side.status, FriendshipStatus::Accepted);
    assert_eq!(
        w.app
            .peers
            .graph
            .dm_between(&w.alice.actor_uri, &w.carol.actor_uri)
            .await
            .unwrap(),
        Some(dm)
    );
}

#[tokio::test]
async fn a_reject_drops_the_request() {
    let w = world();
    w.app
        .peers
        .graph
        .record_outgoing(w.alice.id, &w.carol.actor_uri, None)
        .await
        .unwrap();

    let (status, _) = w
        .deliver(
            &w.carol.actor_uri,
            w.by_carol("Reject", json!({ "type": "Follow" })),
        )
        .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        w.app
            .peers
            .graph
            .between(w.alice.id, &w.carol.actor_uri)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn an_undo_of_a_follow_ends_the_friendship_and_of_anything_else_nothing() {
    let w = world();
    w.deliver(&w.carol.actor_uri, w.follow()).await;
    let undo_like = w.by_carol("Undo", json!({ "type": "Like" }));
    let undo_follow = w.by_carol("Undo", w.follow());

    let (kept, _) = w.deliver(&w.carol.actor_uri, undo_like).await;
    let pending = w
        .app
        .peers
        .graph
        .incoming_requests(w.alice.id)
        .await
        .unwrap();
    let (ended, _) = w.deliver(&w.carol.actor_uri, undo_follow).await;

    assert_eq!((kept, pending.len()), (StatusCode::ACCEPTED, 1));
    assert_eq!(ended, StatusCode::ACCEPTED);
    assert!(
        w.app
            .peers
            .graph
            .incoming_requests(w.alice.id)
            .await
            .unwrap()
            .is_empty()
    );
}

// ─── MLS Notes ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_mls_message_reaches_its_recipient() {
    let w = world();
    let note = w.mls_note("application", json!({}));

    let (status, body) = w
        .deliver(&w.carol.actor_uri, w.by_carol("Create", note))
        .await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let sent = w.app.peers.message_notifier.sent();
    assert!(
        matches!(&sent[..], [MessageNotice::Message(to, event)] if *to == w.alice.id && event.message.sender == w.carol.actor_uri),
        "{sent:?}"
    );
}

#[tokio::test]
async fn an_edit_replaces_the_message() {
    let w = world();
    let create = w.by_carol("Create", w.mls_note("application", json!({})));
    let published = create["id"].clone();
    w.deliver(&w.carol.actor_uri, create).await;
    // An edit names the activity that published the message.
    let edit = json!({
        "type": "Note",
        "id": published,
        "mediaType": "application/mls",
        "content": B64.encode(b"edited bytes"),
    });

    let (status, body) = w
        .deliver(&w.carol.actor_uri, w.by_carol("Update", edit))
        .await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(
        w.app
            .peers
            .message_notifier
            .sent()
            .iter()
            .any(|notice| matches!(notice, MessageNotice::Edited(to, _) if *to == w.alice.id)),
    );
}

/// The sending instance only sees a refusal: it marks the message undelivered, as when no one
/// answers.
#[tokio::test]
async fn a_dm_from_someone_who_cannot_reach_the_recipient_is_refused_alike_whatever_the_cause() {
    let mut answers = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let w = world();
        w.app.reach.set(w.alice.id, &w.carol.actor_uri, kept_out);

        answers.push(
            w.deliver(
                &w.carol.actor_uri,
                w.by_carol("Create", w.mls_note("application", json!({}))),
            )
            .await,
        );
        assert!(w.app.peers.message_notifier.sent().is_empty());
    }
    assert_eq!(
        answers,
        vec![
            (
                StatusCode::FORBIDDEN,
                json!({
                    "error": "access_denied",
                    "error_description": "Message could not be delivered",
                })
            );
            2
        ]
    );
}

#[tokio::test]
async fn an_edit_in_a_dm_from_someone_who_cannot_reach_the_recipient_is_refused() {
    let w = world();
    let create = w.by_carol("Create", w.mls_note("application", json!({})));
    let published = create["id"].clone();
    w.deliver(&w.carol.actor_uri, create).await;
    w.app.reach.set(w.alice.id, &w.carol.actor_uri, BLOCKED);
    let edit = json!({
        "type": "Note",
        "id": published,
        "mediaType": "application/mls",
        "content": B64.encode(b"edited bytes"),
    });

    let (status, _) = w
        .deliver(&w.carol.actor_uri, w.by_carol("Update", edit))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_dms_welcome_from_someone_who_cannot_reach_the_recipient_is_refused() {
    let w = world();
    w.app.reach.set(w.alice.id, &w.carol.actor_uri, BLOCKED);
    let welcome = w.mls_note(
        "welcome",
        json!({ "mlsRecipientDeviceId": uuid::Uuid::new_v4().to_string() }),
    );

    let answer = w
        .deliver(&w.carol.actor_uri, w.by_carol("Create", welcome))
        .await;

    assert_eq!(
        answer,
        (
            StatusCode::FORBIDDEN,
            json!({ "error": "access_denied", "error_description": "Can't add this person" })
        )
    );
}

/// No group appears for a stranger's message, and nothing is filed as a 1:1 instead.
#[tokio::test]
async fn a_group_new_here_from_someone_who_cannot_reach_the_recipient_is_accepted_and_dropped() {
    let w = world();
    w.app
        .reach
        .set(w.alice.id, &w.carol.actor_uri, KEPT_OUT_BY_THE_SETTING);
    let note = w.mls_note(
        "application",
        json!({ "mlsGroup": {
            "name": "crew",
            "members": [
                { "actorUri": w.carol.actor_uri.as_str(), "role": "admin" },
                { "actorUri": w.alice.actor_uri.as_str(), "role": "member" },
            ],
        }}),
    );

    let (status, _) = w
        .deliver(&w.carol.actor_uri, w.by_carol("Create", note))
        .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, listed) = w
        .app
        .call(Method::GET, "/api/dm", Some(w.alice.id), None)
        .await;
    assert_eq!(listed, json!([]));
    assert!(w.app.peers.message_notifier.sent().is_empty());
}

#[tokio::test]
async fn a_note_that_is_not_mls_is_dropped() {
    let w = world();
    let plain = json!({ "type": "Note", "content": "hello" });

    let (created, _) = w
        .deliver(&w.carol.actor_uri, w.by_carol("Create", plain.clone()))
        .await;
    let (updated, _) = w
        .deliver(&w.carol.actor_uri, w.by_carol("Update", plain))
        .await;

    assert_eq!(
        (created, updated),
        (StatusCode::ACCEPTED, StatusCode::ACCEPTED)
    );
    assert!(w.app.peers.message_notifier.sent().is_empty());
}

#[tokio::test]
async fn a_malformed_mls_note_is_refused_with_what_it_lacks() {
    let w = world();
    let mut no_context = w.mls_note("application", json!({}));
    no_context.as_object_mut().unwrap().remove("context");

    for (note, reason) in [
        (no_context, "MLS Note missing `context` (conversation_id)"),
        (
            w.mls_note("application", json!({ "content": "***" })),
            "MLS Note `content` is not valid base64",
        ),
        (
            w.mls_note("commit", json!({})),
            "MLS commit Note missing `mlsEpoch`",
        ),
        (
            w.mls_note("commit", json!({ "mlsEpoch": -1 })),
            "MLS commit `mlsEpoch` is negative",
        ),
        (
            w.mls_note("welcome", json!({})),
            "MLS welcome Note missing `mlsRecipientDeviceId`",
        ),
    ] {
        let (status, body) = w
            .deliver(&w.carol.actor_uri, w.by_carol("Create", note))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{reason}");
        assert_eq!(body["error_description"], reason);
    }
}

// ─── Profiles ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_peers_own_profile_update_is_kept_and_anothers_refused() {
    let w = world();
    w.app.profile.profiles.remember(&w.carol).await;
    let person = |id: &ActorUri| json!({ "type": "Person", "id": id.as_str(), "name": "Carol R." });

    let (own, _) = w
        .deliver(
            &w.carol.actor_uri,
            w.by_carol("Update", person(&w.carol.actor_uri)),
        )
        .await;
    let (other, body) = w
        .deliver(
            &w.carol.actor_uri,
            w.by_carol("Update", person(&w.alice.actor_uri)),
        )
        .await;

    assert_eq!(own, StatusCode::ACCEPTED);
    let (cached, _) = w.app.profile.profiles.shown(&w.carol.actor_uri).await;
    assert_eq!(cached.unwrap().display_name.as_deref(), Some("Carol R."));
    assert_eq!(other, StatusCode::FORBIDDEN);
    assert_eq!(
        body["error_description"],
        "an actor may only update its own profile"
    );
}
