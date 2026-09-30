use base64::Engine as _;
use reqwest::Method;
use serde_json::json;

use crate::helpers::{eventually, spawn_app};

#[tokio::test]
async fn two_instances_make_friends_exchange_a_message_and_follow_a_profile_change() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let (alice, bob) = (a.sign_up("alice").await, b.sign_up("bob").await);

    let (asked, body) = a
        .send(
            Method::POST,
            &alice,
            "/api/friends/request",
            json!({ "address": bob.address(&b) }),
        )
        .await;
    assert_eq!(asked, 201, "{body}");
    let request = eventually("alice's request on bob's instance", || async {
        let (_, incoming) = b.get(&bob, "/api/friends/incoming").await;
        incoming.as_array()?.first().cloned()
    })
    .await;
    assert_eq!(request["actor_uri"], alice.actor_uri.as_str());
    let accept = format!(
        "/api/friends/{}/accept",
        request["friendship_id"].as_str().unwrap()
    );
    let (accepted, body) = b.send(Method::POST, &bob, &accept, json!({})).await;
    assert!(accepted.is_success(), "{accepted}: {body}");
    eventually("bob among alice's friends", || async {
        let (_, friends) = a.get(&alice, "/api/friends").await;
        friends
            .as_array()?
            .iter()
            .any(|f| f["friend_actor_uri"] == bob.actor_uri.as_str())
            .then_some(())
    })
    .await;

    let ciphertext = base64::engine::general_purpose::STANDARD.encode(b"an opaque mls message");
    let (sent, message) = a
        .send(
            Method::POST,
            &alice,
            "/api/dm",
            json!({ "recipient_address": bob.address(&b), "mls_ciphertext": ciphertext }),
        )
        .await;
    assert!(sent.is_success(), "{sent}: {message}");
    let conversation = message["conversation_id"].as_str().unwrap().to_owned();
    let received = eventually("alice's message on bob's instance", || async {
        let (_, history) = b.get(&bob, &format!("/api/dm/{conversation}")).await;
        history.as_array()?.first().cloned()
    })
    .await;
    assert_eq!(received["mls_ciphertext"], ciphertext.as_str());
    assert_eq!(received["sender_actor_uri"], alice.actor_uri.as_str());
    eventually("the delivery recorded on alice's instance", || async {
        let (_, history) = a.get(&alice, &format!("/api/dm/{conversation}")).await;
        (history[0]["federation_status"] == "delivered").then_some(())
    })
    .await;

    let (renamed, body) = b
        .send(
            Method::PATCH,
            &bob,
            "/api/profile",
            json!({ "display_name": "Bob R.", "pronouns": null, "bio": "" }),
        )
        .await;
    assert_eq!(renamed, 200, "{body}");
    eventually("bob's new name on alice's instance", || async {
        let (_, friends) = a.get(&alice, "/api/friends").await;
        friends
            .as_array()?
            .iter()
            .any(|f| f["display_name"] == "Bob R.")
            .then_some(())
    })
    .await;

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}
