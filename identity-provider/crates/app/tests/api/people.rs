use reqwest::Method;
use serde_json::json;

use crate::helpers::{eventually, spawn_app};

fn lookup_of(address: &str) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("address", address)
        .finish();
    format!("/api/users/lookup?{query}")
}

#[tokio::test]
async fn an_address_on_another_instance_is_looked_up_there_with_the_relation() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let (alice, bob) = (a.sign_up("alice").await, b.sign_up("bob").await);

    let (found, stranger) = a.get(&alice, &lookup_of(&bob.address(&b))).await;
    assert_eq!(found, 200, "{stranger}");
    assert_eq!(stranger["actor_uri"], bob.actor_uri.as_str());
    assert_eq!(stranger["address"], bob.address(&b));
    assert_eq!(stranger["display_name"], "bob");
    assert_eq!(stranger["relation"], "none");

    let (asked, body) = a
        .send(
            Method::POST,
            &alice,
            "/api/friends/request",
            json!({ "address": bob.address(&b) }),
        )
        .await;
    assert_eq!(asked, 201, "{body}");
    let (_, asked) = a.get(&alice, &lookup_of(&bob.address(&b))).await;
    assert_eq!(asked["relation"], "request_sent");
    let asking = eventually("alice's request on bob's instance", || async {
        let (_, alice_seen) = b.get(&bob, &lookup_of(&alice.address(&a))).await;
        (alice_seen["relation"] == "request_received").then_some(alice_seen)
    })
    .await;
    let accept = format!(
        "/api/friends/{}/accept",
        asking["friendship_id"].as_str().unwrap()
    );
    let (accepted, body) = b.send(Method::POST, &bob, &accept, json!({})).await;
    assert!(accepted.is_success(), "{accepted}: {body}");
    let (_, friend) = b.get(&bob, &lookup_of(&alice.address(&a))).await;
    assert_eq!(friend["relation"], "friend");
    assert_eq!(friend["friendship_id"], json!(null));

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

#[tokio::test]
async fn an_address_its_instance_has_no_account_for_is_not_found() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let alice = a.sign_up("alice").await;

    let (missing, body) = a
        .get(&alice, &lookup_of(&format!("nobody_k2m9x@{}", b.domain)))
        .await;

    assert_eq!(missing, 404, "{body}");
    assert_eq!(body["error_description"], "No account at this address");
    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

#[tokio::test]
async fn an_address_whose_instance_stopped_answering_is_a_bad_gateway_though_cached_here() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let (alice, bob) = (a.sign_up("alice").await, b.sign_up("bob").await);
    let bobs = lookup_of(&bob.address(&b));
    let (found, body) = a.get(&alice, &bobs).await;
    assert_eq!(found, 200, "{body}");

    b.stop().await.unwrap();
    let (unreachable, body) = a.get(&alice, &bobs).await;

    assert_eq!(unreachable, 502, "{body}");
    assert_eq!(body["error"], "bad_gateway");
    a.stop().await.unwrap();
}
