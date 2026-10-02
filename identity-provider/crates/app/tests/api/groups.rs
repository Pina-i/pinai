use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::Method;
use serde_json::{Value, json};

use crate::helpers::{eventually, spawn_app};

/// What an invitee's own instance says of them, whether or not anyone here met them before.
#[tokio::test]
async fn a_remote_invitee_is_asked_of_their_instance_and_a_made_up_one_is_refused() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let alice = a.sign_up("alice").await;
    let bob = b.sign_up("bob").await;
    assert_eq!(a.count("SELECT count(*) FROM remote_actors").await, 0);
    let nobody = format!("{}/users/nobody_zz9yy", b.address);

    let (refused, body) = a
        .send(
            Method::POST,
            &alice,
            "/api/groups",
            json!({ "member_actor_uris": [bob.actor_uri.as_str(), nobody] }),
        )
        .await;
    assert_eq!(refused, 404, "{body}");
    assert_eq!(body["actor_uri"], nobody.as_str());

    let (created, group) = a
        .send(
            Method::POST,
            &alice,
            "/api/groups",
            json!({ "name": "crew", "member_actor_uris": [bob.actor_uri.as_str()] }),
        )
        .await;
    assert_eq!(created, 201, "{group}");
    let bobs = group["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["actorUri"] == bob.actor_uri.as_str())
        .cloned()
        .unwrap();
    assert_eq!(bobs["displayName"], "bob");

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

/// Carol's instance learns the group, and Alice and Bob, from Alice's message alone, and still lists
/// Bob after Alice removed him: that copy is older than the removal, so it brings him back nowhere.
#[tokio::test]
async fn a_member_removed_here_is_not_brought_back_by_a_message_from_elsewhere() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let (alice, bob) = (a.sign_up("alice").await, a.sign_up("bob").await);
    let carol = b.sign_up("carol").await;
    for (on, who) in [(&a, &bob), (&b, &carol)] {
        let (opened, body) = on
            .send(
                Method::PATCH,
                who,
                "/api/privacy",
                json!({ "contact_policy": "everyone" }),
            )
            .await;
        assert_eq!(opened, 200, "{body}");
    }
    let (created, group) = a
        .send(
            Method::POST,
            &alice,
            "/api/groups",
            json!({
                "name": "crew",
                "member_actor_uris": [bob.actor_uri.as_str(), carol.actor_uri.as_str()],
            }),
        )
        .await;
    assert_eq!(created, 201, "{group}");
    let id = group["conversationId"].as_str().unwrap().to_owned();
    let messages = format!("/api/groups/{id}/messages");
    let (sent, body) = a
        .send(
            Method::POST,
            &alice,
            &messages,
            json!({ "mls_ciphertext": B64.encode(b"before") }),
        )
        .await;
    assert!(sent.is_success(), "{sent}: {body}");
    eventually("the group on carol's instance", || async {
        let (_, listed) = b.get(&carol, "/api/dm").await;
        listed
            .as_array()?
            .iter()
            .any(|c| c["conversation_id"] == id.as_str())
            .then_some(())
    })
    .await;

    let bobs_membership = format!(
        "/api/groups/{id}/members/{}",
        url::form_urlencoded::byte_serialize(bob.actor_uri.as_bytes()).collect::<String>()
    );
    let (removed, body) = a
        .send(Method::DELETE, &alice, &bobs_membership, json!({}))
        .await;
    assert!(removed.is_success(), "{removed}: {body}");
    let (sent, body) = b
        .send(
            Method::POST,
            &carol,
            &messages,
            json!({ "mls_ciphertext": B64.encode(b"after") }),
        )
        .await;
    assert!(sent.is_success(), "{sent}: {body}");
    eventually("carol's message on alice's instance", || async {
        let (_, history) = a.get(&alice, &format!("/api/dm/{id}")).await;
        history
            .as_array()?
            .iter()
            .any(|m| m["sender_actor_uri"] == carol.actor_uri.as_str())
            .then_some(())
    })
    .await;

    let (_, members) = a.get(&alice, &format!("/api/groups/{id}/members")).await;
    assert!(
        !members
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["actorUri"] == bob.actor_uri.as_str()),
        "{members}"
    );
    let (_, bobs_list) = a.get(&bob, "/api/dm").await;
    assert!(
        bobs_list[0]["removed_at"].is_string(),
        "still out: {bobs_list}"
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

/// Bob keeps the group as he last saw it, and its history up to his removal, until he clears it;
/// being added again brings it back as it is now.
#[tokio::test]
async fn a_removed_member_keeps_the_group_as_he_last_saw_it_until_he_clears_it() {
    let a = spawn_app().await;
    let (alice, bob) = (a.sign_up("alice").await, a.sign_up("bob").await);
    let (opened, body) = a
        .send(
            Method::PATCH,
            &bob,
            "/api/privacy",
            json!({ "contact_policy": "everyone" }),
        )
        .await;
    assert_eq!(opened, 200, "{body}");
    let (_, group) = a
        .send(
            Method::POST,
            &alice,
            "/api/groups",
            json!({ "name": "crew", "member_actor_uris": [bob.actor_uri.as_str()] }),
        )
        .await;
    let id = group["conversationId"].as_str().unwrap().to_owned();
    let post = |text: &'static str| {
        let path = format!("/api/groups/{id}/messages");
        let (a, alice) = (&a, &alice);
        async move {
            let (sent, body) = a
                .send(
                    Method::POST,
                    alice,
                    &path,
                    json!({ "mls_ciphertext": B64.encode(text) }),
                )
                .await;
            assert!(sent.is_success(), "{sent}: {body}");
        }
    };
    let members = format!("/api/groups/{id}/members");
    let bobs = format!(
        "{members}/{}",
        url::form_urlencoded::byte_serialize(bob.actor_uri.as_bytes()).collect::<String>()
    );

    post("before").await;
    let (removed, body) = a.send(Method::DELETE, &alice, &bobs, json!({})).await;
    assert!(removed.is_success(), "{removed}: {body}");
    let (renamed, body) = a
        .send(
            Method::PATCH,
            &alice,
            &format!("/api/groups/{id}"),
            json!({ "name": "new crew" }),
        )
        .await;
    assert!(renamed.is_success(), "{renamed}: {body}");
    post("after").await;

    let (_, listed) = a.get(&bob, "/api/dm").await;
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    let shown = &listed[0];
    assert_eq!(
        (&shown["conversation_id"], &shown["name"]),
        (&json!(id), &json!("crew"))
    );
    assert!(shown["removed_at"].is_string(), "{shown}");
    assert_eq!(shown["members"][0]["actorUri"], alice.actor_uri.as_str());
    let (_, history) = a.get(&bob, &format!("/api/dm/{id}")).await;
    let ciphertexts: Vec<&Value> = history
        .as_array()
        .unwrap()
        .iter()
        .map(|m| &m["mls_ciphertext"])
        .collect();
    assert_eq!(ciphertexts, vec![&json!(B64.encode("before"))]);
    let (_, timeline) = a.get(&bob, &format!("/api/dm/{id}?include=events")).await;
    let lines: Vec<(&Value, &Value)> = timeline
        .as_array()
        .unwrap()
        .iter()
        .map(|item| (&item["kind"], &item["event"]))
        .collect();
    assert_eq!(
        lines,
        vec![
            (&json!("event"), &json!("removed")),
            (&json!("message"), &Value::Null),
            (&json!("event"), &json!("created")),
        ],
        "his removal last, and nothing after it: not the rename"
    );
    let (refused, _) = a
        .send(
            Method::POST,
            &bob,
            &format!("/api/groups/{id}/messages"),
            json!({ "mls_ciphertext": B64.encode("me?") }),
        )
        .await;
    assert_eq!(refused, 404);

    let (cleared, _) = a
        .send(
            Method::DELETE,
            &bob,
            &format!("/api/groups/{id}"),
            json!({}),
        )
        .await;
    assert_eq!(cleared, 204);
    assert_eq!(a.get(&bob, "/api/dm").await.1, json!([]));
    assert_eq!(a.get(&bob, &format!("/api/dm/{id}")).await.0, 404);

    let (added, body) = a
        .send(
            Method::POST,
            &alice,
            &members,
            json!({ "actor_uri": bob.actor_uri.as_str() }),
        )
        .await;
    assert!(added.is_success(), "{added}: {body}");
    let (_, listed) = a.get(&bob, "/api/dm").await;
    assert_eq!(
        (&listed[0]["name"], &listed[0]["removed_at"]),
        (&json!("new crew"), &Value::Null)
    );

    a.stop().await.unwrap();
}

/// Every change to a group made on one instance reaches the other's copy: a rename, a removal, a
/// leave, an add, a role.
#[tokio::test]
async fn a_groups_changes_reach_the_other_instance() {
    let (a, b) = (spawn_app().await, spawn_app().await);
    let (alice, bob) = (a.sign_up("alice").await, a.sign_up("bob").await);
    let (carol, dave) = (b.sign_up("carol").await, b.sign_up("dave").await);
    for (on, who) in [(&a, &bob), (&b, &carol), (&b, &dave)] {
        let (opened, body) = on
            .send(
                Method::PATCH,
                who,
                "/api/privacy",
                json!({ "contact_policy": "everyone" }),
            )
            .await;
        assert_eq!(opened, 200, "{body}");
    }
    let invited = [&bob, &carol, &dave].map(|m| m.actor_uri.clone());
    let (created, group) = a
        .send(
            Method::POST,
            &alice,
            "/api/groups",
            json!({ "name": "crew", "member_actor_uris": invited }),
        )
        .await;
    assert_eq!(created, 201, "{group}");
    let id = group["conversationId"].as_str().unwrap().to_owned();
    let members = format!("/api/groups/{id}/members");
    let member = |who: &crate::helpers::Account| {
        format!(
            "{members}/{}",
            url::form_urlencoded::byte_serialize(who.actor_uri.as_bytes()).collect::<String>()
        )
    };
    let (sent, body) = a
        .send(
            Method::POST,
            &alice,
            &format!("/api/groups/{id}/messages"),
            json!({ "mls_ciphertext": B64.encode(b"hello") }),
        )
        .await;
    assert!(sent.is_success(), "{sent}: {body}");
    let listed_on = |on: &'static str, who: &crate::helpers::Account| {
        let (app, who, id) = (if on == "a" { &a } else { &b }, who.clone(), id.clone());
        async move {
            let (_, listed) = app.get(&who, "/api/dm").await;
            listed
                .as_array()?
                .iter()
                .find(|c| c["conversation_id"] == id.as_str())
                .cloned()
        }
    };
    eventually("the group on carol's instance", || listed_on("b", &carol)).await;

    let (renamed, body) = a
        .send(
            Method::PATCH,
            &alice,
            &format!("/api/groups/{id}"),
            json!({ "name": "new crew" }),
        )
        .await;
    assert!(renamed.is_success(), "{renamed}: {body}");
    eventually("the rename on carol's instance", || async {
        (listed_on("b", &carol).await?["name"] == "new crew").then_some(())
    })
    .await;

    let (removed, body) = a
        .send(Method::DELETE, &alice, &member(&dave), json!({}))
        .await;
    assert!(removed.is_success(), "{removed}: {body}");
    eventually("dave removed on his own instance", || async {
        listed_on("b", &dave).await?["removed_at"]
            .as_str()
            .map(|_| ())
    })
    .await;
    let (_, timeline) = b.get(&dave, &format!("/api/dm/{id}?include=events")).await;
    assert_eq!(
        (
            &timeline[0]["event"],
            &timeline[0]["actor_uri"],
            &timeline[0]["subject_uri"]
        ),
        (
            &json!("removed"),
            &json!(alice.actor_uri),
            &json!(dave.actor_uri)
        ),
        "{timeline}"
    );
    assert!(
        timeline
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["event"] == "renamed"),
        "the rename he saw, made on alice's instance: {timeline}"
    );

    let (left, body) = b
        .send(Method::DELETE, &carol, &member(&carol), json!({}))
        .await;
    assert!(left.is_success(), "{left}: {body}");
    eventually("carol gone from alice's copy", || async {
        let (_, listed) = a.get(&alice, &members).await;
        (!listed
            .as_array()?
            .iter()
            .any(|m| m["actorUri"] == carol.actor_uri.as_str()))
        .then_some(())
    })
    .await;

    let (added, body) = a
        .send(
            Method::POST,
            &alice,
            &members,
            json!({ "actor_uri": dave.actor_uri.as_str() }),
        )
        .await;
    assert!(added.is_success(), "{added}: {body}");
    eventually("dave back on his own instance", || async {
        listed_on("b", &dave).await?["removed_at"]
            .is_null()
            .then_some(())
    })
    .await;

    let (promoted, body) = a
        .send(
            Method::POST,
            &alice,
            &format!("{}/role", member(&bob)),
            json!({ "role": "admin" }),
        )
        .await;
    assert!(promoted.is_success(), "{promoted}: {body}");
    eventually("bob an admin in dave's copy", || async {
        let (_, listed) = b.get(&dave, &members).await;
        listed
            .as_array()?
            .iter()
            .any(|m| m["actorUri"] == bob.actor_uri.as_str() && m["role"] == "admin")
            .then_some(())
    })
    .await;

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}
