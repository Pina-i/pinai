use reqwest::Method;
use serde_json::{Value, json};

use crate::helpers::{Account, TestApp, eventually, spawn_app};

/// `from` on `a` asks `to` on `b`; answers the request as `to` sees it.
async fn ask(a: &TestApp, from: &Account, b: &TestApp, to: &Account) -> Value {
    let (asked, body) = a
        .send(
            Method::POST,
            from,
            "/api/friends/request",
            json!({ "address": to.address(b) }),
        )
        .await;
    assert_eq!(asked, 201, "{body}");
    eventually("the request on the other instance", || async {
        let (_, incoming) = b.get(to, "/api/friends/incoming").await;
        incoming.as_array()?.first().cloned()
    })
    .await
}

async fn friends_of(on: &TestApp, who: &Account) -> Vec<Value> {
    let (_, friends) = on.get(who, "/api/friends").await;
    friends.as_array().cloned().unwrap_or_default()
}

fn encoded(actor_uri: &str) -> String {
    url::form_urlencoded::byte_serialize(actor_uri.as_bytes()).collect()
}

#[tokio::test]
async fn a_block_ends_a_friendship_across_instances_as_an_unfriend_and_stays_until_lifted() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let (alice, bob) = (a.sign_up("alice").await, b.sign_up("bob").await);
    let request = ask(&b, &bob, &a, &alice).await;
    let accept = format!(
        "/api/friends/{}/accept",
        request["friendship_id"].as_str().unwrap()
    );
    let (accepted, body) = a.send(Method::POST, &alice, &accept, json!({})).await;
    assert!(accepted.is_success(), "{accepted}: {body}");
    eventually("alice among bob's friends", || async {
        (friends_of(&b, &bob).await.len() == 1).then_some(())
    })
    .await;

    let (blocked, body) = a
        .send(
            Method::POST,
            &alice,
            "/api/blocks",
            json!({ "actor_uri": bob.actor_uri.as_str() }),
        )
        .await;

    assert_eq!(blocked, 204, "{body}");
    assert!(friends_of(&a, &alice).await.is_empty());
    eventually("the friendship gone from bob's instance", || async {
        friends_of(&b, &bob).await.is_empty().then_some(())
    })
    .await;
    let (_, listed) = a.get(&alice, "/api/blocks").await;
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(listed[0]["actor_uri"], bob.actor_uri.as_str());
    assert_eq!(listed[0]["display_name"], "bob");

    let (lifted, body) = a
        .send(
            Method::DELETE,
            &alice,
            &format!("/api/blocks/{}", encoded(bob.actor_uri.as_str())),
            json!({}),
        )
        .await;
    assert_eq!(lifted, 204, "{body}");
    let (_, listed) = a.get(&alice, "/api/blocks").await;
    assert_eq!(listed, json!([]));
    assert!(
        friends_of(&a, &alice).await.is_empty(),
        "an unblock restores nothing"
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

#[tokio::test]
async fn blocking_someone_who_asked_to_be_friends_declines_their_request_on_their_instance() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let (alice, bob) = (a.sign_up("alice").await, b.sign_up("bob").await);
    ask(&b, &bob, &a, &alice).await;
    assert_eq!(b.count("SELECT count(*) FROM friendships").await, 1);

    let (blocked, body) = a
        .send(
            Method::POST,
            &alice,
            "/api/blocks",
            json!({ "actor_uri": bob.actor_uri.as_str() }),
        )
        .await;

    assert_eq!(blocked, 204, "{body}");
    let (_, incoming) = a.get(&alice, "/api/friends/incoming").await;
    assert_eq!(incoming, json!([]));
    // A decline is silent, so no route of bob's shows his request gone.
    eventually("bob's request dropped on his instance", || async {
        (b.count("SELECT count(*) FROM friendships").await == 0).then_some(())
    })
    .await;

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

/// The DM `from` sends `to`, and how its delivery ended on `from`'s instance.
async fn dm_outcome(on: &TestApp, from: &Account, to: &str) -> String {
    let (sent, message) = on
        .send(
            Method::POST,
            from,
            "/api/dm",
            json!({ "recipient_address": to, "mls_ciphertext": "AQID" }),
        )
        .await;
    assert_eq!(sent, 201, "{message}");
    let (conversation, id) = (
        message["conversation_id"].as_str().unwrap().to_owned(),
        message["id"].clone(),
    );
    eventually("the delivery's outcome", || async {
        let (_, history) = on.get(from, &format!("/api/dm/{conversation}")).await;
        let status = history.as_array()?.iter().find(|m| m["id"] == id)?["federation_status"]
            .as_str()?
            .to_owned();
        (status != "pending").then_some(status)
    })
    .await
}

#[tokio::test]
async fn a_dm_from_someone_who_cannot_reach_the_recipient_ends_undelivered_whatever_the_cause() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let alice = a.sign_up("alice").await;
    let (bob, carol) = (b.sign_up("bob").await, b.sign_up("carol").await);
    let request = ask(&b, &bob, &a, &alice).await;
    let accept = format!(
        "/api/friends/{}/accept",
        request["friendship_id"].as_str().unwrap()
    );
    a.send(Method::POST, &alice, &accept, json!({})).await;
    eventually("alice among bob's friends", || async {
        (friends_of(&b, &bob).await.len() == 1).then_some(())
    })
    .await;
    assert_eq!(dm_outcome(&b, &bob, &alice.address(&a)).await, "delivered");
    a.send(
        Method::POST,
        &alice,
        "/api/blocks",
        json!({ "actor_uri": bob.actor_uri.as_str() }),
    )
    .await;

    assert_eq!(dm_outcome(&b, &bob, &alice.address(&a)).await, "failed");
    assert_eq!(
        dm_outcome(&b, &carol, &alice.address(&a)).await,
        "failed",
        "a stranger, under the default setting"
    );
    let (opened, body) = a
        .send(
            Method::PATCH,
            &alice,
            "/api/privacy",
            json!({ "contact_policy": "everyone" }),
        )
        .await;
    assert_eq!(opened, 200, "{body}");
    assert_eq!(
        dm_outcome(&b, &carol, &alice.address(&a)).await,
        "delivered"
    );
    assert_eq!(
        dm_outcome(&b, &bob, &alice.address(&a)).await,
        "failed",
        "a block wins over the setting"
    );
    assert_eq!(
        a.count("SELECT count(*) FROM direct_messages").await,
        2,
        "bob's first message and carol's last only"
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

#[tokio::test]
async fn a_request_from_someone_the_recipient_blocked_stays_pending_on_their_side_only() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let alice = a.sign_up("alice").await;
    let (bob, carol) = (b.sign_up("bob").await, b.sign_up("carol").await);
    a.send(
        Method::POST,
        &alice,
        "/api/blocks",
        json!({ "actor_uri": bob.actor_uri.as_str() }),
    )
    .await;

    let (asked, body) = b
        .send(
            Method::POST,
            &bob,
            "/api/friends/request",
            json!({ "address": alice.address(&a) }),
        )
        .await;

    assert_eq!(asked, 201, "{body}");
    assert_eq!(body["status"], "pending");
    // Carol asks after Bob: once hers is in, his Follow had its turn.
    let request = ask(&b, &carol, &a, &alice).await;
    assert_eq!(request["actor_uri"], carol.actor_uri.as_str());
    let (_, incoming) = a.get(&alice, "/api/friends/incoming").await;
    assert_eq!(incoming.as_array().unwrap().len(), 1, "{incoming}");
    assert_eq!(
        b.count(
            "SELECT count(*) FROM friendships \
             WHERE status = 'pending' AND direction = 'outgoing'"
        )
        .await,
        2,
        "bob's request and carol's, both waiting"
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

#[tokio::test]
async fn a_claim_for_someone_who_does_not_admit_the_claimer_is_refused_across_instances() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let alice = a.sign_up("alice").await;
    let (bob, carol) = (b.sign_up("bob").await, b.sign_up("carol").await);
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::days(7))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (uploaded, body) = a
        .send(
            Method::POST,
            &alice,
            "/api/keys/packages",
            json!({
                "device_id": uuid::Uuid::new_v4(),
                "packages": (1..=3)
                    .map(|i| json!({ "key_package": format!("AQID{i}A=="), "expires_at": expires_at }))
                    .collect::<Vec<_>>(),
            }),
        )
        .await;
    assert!(uploaded.is_success(), "{uploaded}: {body}");
    a.send(
        Method::POST,
        &alice,
        "/api/blocks",
        json!({ "actor_uri": bob.actor_uri.as_str() }),
    )
    .await;
    let claim = |who: &Account| {
        let (b, who, target) = (&b, who.clone(), alice.actor_uri.clone());
        async move {
            b.send(
                Method::POST,
                &who,
                "/api/keys/packages/claim",
                json!({ "actor_uri": target }),
            )
            .await
        }
    };
    let refused = (
        reqwest::StatusCode::FORBIDDEN,
        json!({ "error": "access_denied", "error_description": "Can't add this person" }),
    );

    assert_eq!(claim(&bob).await, refused, "blocked");
    assert_eq!(
        claim(&carol).await,
        refused,
        "a stranger, under the default setting"
    );
    assert_eq!(
        a.count("SELECT count(*) FROM key_packages WHERE consumed_at IS NULL")
            .await,
        3,
        "no package of hers used"
    );
    a.send(
        Method::PATCH,
        &alice,
        "/api/privacy",
        json!({ "contact_policy": "everyone" }),
    )
    .await;
    let (claimed, body) = claim(&carol).await;
    assert_eq!(claimed, 200, "{body}");
    assert_eq!(claim(&bob).await, refused, "a block wins over the setting");

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}
