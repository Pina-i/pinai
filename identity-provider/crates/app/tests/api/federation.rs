use base64::Engine as _;
use reqwest::Method;
use serde_json::json;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::helpers::{Account, TestApp, eventually, spawn_app};

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
    let bob_since = eventually("bob among alice's friends", || async {
        let (_, friends) = a.get(&alice, "/api/friends").await;
        friends
            .as_array()?
            .iter()
            .find(|f| f["friend_actor_uri"] == bob.actor_uri.as_str())
            .map(|f| f["since"].clone())
    })
    .await;
    let (_, bobs_friends) = b.get(&bob, "/api/friends").await;
    assert!(bob_since.is_string(), "{bob_since}");
    assert!(bobs_friends[0]["since"].is_string(), "{bobs_friends}");

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
    let renamed = eventually("bob's new name on alice's instance", || async {
        let (_, friends) = a.get(&alice, "/api/friends").await;
        friends
            .as_array()?
            .iter()
            .find(|f| f["display_name"] == "Bob R.")
            .cloned()
    })
    .await;
    assert_eq!(
        renamed["since"], bob_since,
        "a profile change keeps the date"
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

fn card_of(actor: &Account) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("actor", actor.actor_uri.as_str())
        .finish();
    format!("/api/profiles?{query}")
}

async fn set_profile(app: &TestApp, who: &Account, name: &str, pronouns: &str, bio: &str) {
    let form = json!({ "display_name": name, "pronouns": pronouns, "bio": bio });
    let (saved, body) = app.send(Method::PATCH, who, "/api/profile", form).await;
    assert_eq!(saved, 200, "{body}");
}

#[tokio::test]
async fn a_profile_edited_while_a_request_is_pending_reaches_the_new_friend() {
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

    set_profile(&a, &alice, "Alice", "she", "Kia ora <3 & welcome").await;
    set_profile(&b, &bob, "Bob", "he", "Line one\nline two").await;
    let (pending, _) = a.get(&alice, &card_of(&bob)).await;
    assert_eq!(pending, 404, "a request alone shows nothing of bob");
    let accept = format!(
        "/api/friends/{}/accept",
        request["friendship_id"].as_str().unwrap()
    );
    let (accepted, body) = b.send(Method::POST, &bob, &accept, json!({})).await;
    assert!(accepted.is_success(), "{accepted}: {body}");

    let bobs = eventually("bob's pronouns and bio on alice's instance", || async {
        let (_, card) = a.get(&alice, &card_of(&bob)).await;
        (card["bio"] == "Line one\nline two" && card["friends_since"].is_string()).then_some(card)
    })
    .await;
    assert_eq!(bobs["pronouns"], "he");
    let alices = eventually("alice's pronouns and bio on bob's instance", || async {
        let (_, card) = b.get(&bob, &card_of(&alice)).await;
        (card["bio"] == "Kia ora <3 & welcome").then_some(card)
    })
    .await;
    assert_eq!(alices["pronouns"], "she");
    assert!(alices["friends_since"].is_string(), "{alices}");

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

/// An instance whose WebFinger names its own `mallory`, whose document says it is `victim`.
async fn an_instance_passing_off(victim: &Account) -> MockServer {
    let peer = MockServer::start().await;
    let mallory = format!("{}/users/mallory", peer.uri());
    Mock::given(path("/.well-known/webfinger"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "subject": format!("acct:mallory@{}", peer.address()),
            "links": [{ "rel": "self", "type": "application/activity+json", "href": mallory }],
        })))
        .mount(&peer)
        .await;
    Mock::given(path("/users/mallory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": victim.actor_uri,
            "type": "Person",
            "preferredUsername": "mallory",
            "name": "Not Bob",
            "inbox": format!("{}/inbox", peer.uri()),
            "outbox": format!("{mallory}/outbox"),
            "followers": format!("{mallory}/followers"),
            "following": format!("{mallory}/following"),
            "publicKey": {
                "id": format!("{mallory}#main-key"),
                "owner": mallory,
                "publicKeyPem": "-----BEGIN PUBLIC KEY-----",
            },
        })))
        .mount(&peer)
        .await;
    peer
}

#[tokio::test]
async fn an_instance_passing_off_another_instances_account_is_a_bad_gateway_and_changes_nothing() {
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
    let bob_as_held = format!(
        "SELECT count(*) FROM remote_actors WHERE actor_uri = '{0}' \
         AND inbox_url = '{0}/inbox' AND display_name = 'bob'",
        bob.actor_uri
    );
    assert_eq!(a.count(&bob_as_held).await, 1);
    let evil = an_instance_passing_off(&bob).await;

    let (refused, body) = a
        .send(
            Method::POST,
            &alice,
            "/api/friends/request",
            json!({ "address": format!("mallory@{}", evil.address()) }),
        )
        .await;

    assert_eq!(refused, 502, "{body}");
    let fetched = evil.received_requests().await.unwrap();
    assert!(
        fetched.iter().any(|r| r.url.path() == "/users/mallory"),
        "the document was read"
    );
    assert_eq!(a.count(&bob_as_held).await, 1);
    assert_eq!(a.count("SELECT count(*) FROM remote_actors").await, 1);
    a.stop().await.unwrap();
    b.stop().await.unwrap();
}
