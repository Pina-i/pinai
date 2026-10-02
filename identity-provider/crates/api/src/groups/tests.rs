use axum::http::{Method, StatusCode};
use domain::identity::Account;
use domain::identity::testing::{InMemoryRemoteActors, account, remote_actor};
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING};
use serde_json::{Value, json};

use crate::testing::TestApp;

fn refused(description: &str, invitee: &Account) -> (StatusCode, Value) {
    (
        StatusCode::FORBIDDEN,
        json!({
            "error": "access_denied",
            "error_description": description,
            "actor_uri": invitee.actor_uri.as_str(),
        }),
    )
}

async fn create(app: &TestApp, by: &Account, invited: &[&Account]) -> (StatusCode, Value) {
    let invited: Vec<&str> = invited.iter().map(|a| a.actor_uri.as_str()).collect();
    app.call(
        Method::POST,
        "/api/groups",
        Some(by.id),
        Some(json!({ "name": "crew", "member_actor_uris": invited })),
    )
    .await
}

/// The answer names who to take off the list, and nothing of why.
#[tokio::test]
async fn a_group_with_an_invitee_who_does_not_admit_the_creator_is_refused_alike_whatever_the_cause()
 {
    let (alice, bob, carl) = (account("alice"), account("bob"), account("carl"));
    let mut answers = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let app = TestApp::with(
            [alice.clone(), bob.clone(), carl.clone()],
            [remote_actor("dave_k2m9x@idp.dave.test")],
        );
        app.reach.set(bob.id, &alice.actor_uri, kept_out);

        answers.push(create(&app, &alice, &[&carl, &bob]).await);
        let (_, listed) = app.call(Method::GET, "/api/dm", Some(carl.id), None).await;
        assert_eq!(listed, json!([]), "nothing written");
    }
    assert_eq!(answers, vec![refused("Can't add this person", &bob); 2]);
}

#[tokio::test]
async fn adding_someone_to_a_group_follows_the_same_rules() {
    let (alice, bob, carl) = (account("alice"), account("bob"), account("carl"));
    let app = TestApp::with([alice.clone(), bob.clone(), carl.clone()], []);
    let (_, group) = create(&app, &alice, &[&bob]).await;
    let members = format!(
        "/api/groups/{}/members",
        group["conversationId"].as_str().unwrap()
    );
    let add = |who: &Account| Some(json!({ "actor_uri": who.actor_uri.as_str() }));

    app.reach
        .set(carl.id, &alice.actor_uri, KEPT_OUT_BY_THE_SETTING);
    assert_eq!(
        app.call(Method::POST, &members, Some(alice.id), add(&carl))
            .await,
        refused("Can't add this person", &carl)
    );
    app.reach.set(alice.id, &carl.actor_uri, BLOCKED);
    assert_eq!(
        app.call(Method::POST, &members, Some(alice.id), add(&carl))
            .await,
        refused("You blocked this user", &carl)
    );
}

#[tokio::test]
async fn an_invitee_who_names_no_account_is_not_found() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let nobody = "https://idp.dave.test/users/dave_k2m9x";

    let answer = app
        .call(
            Method::POST,
            "/api/groups",
            Some(alice.id),
            Some(json!({ "member_actor_uris": [nobody] })),
        )
        .await;

    assert_eq!(
        answer,
        (
            StatusCode::NOT_FOUND,
            json!({ "error": "not_found", "error_description": "User not found", "actor_uri": nobody })
        )
    );
}

#[tokio::test]
async fn an_invitee_whose_instance_does_not_answer_is_a_bad_gateway_naming_them() {
    let alice = account("alice");
    let app = TestApp::knowing(
        [alice.clone()],
        InMemoryRemoteActors::default().and_down("idp.down.test"),
    );
    let down = "https://idp.down.test/users/dave_k2m9x";

    let answer = app
        .call(
            Method::POST,
            "/api/groups",
            Some(alice.id),
            Some(json!({ "member_actor_uris": [down] })),
        )
        .await;

    assert_eq!(
        answer,
        (
            StatusCode::BAD_GATEWAY,
            json!({
                "error": "bad_gateway",
                "error_description": "the account's instance did not answer",
                "actor_uri": down,
            })
        )
    );
}

#[tokio::test]
async fn a_group_holds_fifty_members_at_most() {
    let alice = account("alice");
    let guests: Vec<_> = (0..50)
        .map(|i| remote_actor(&format!("guest{i}_k2m9x@idp.guests.test")))
        .collect();
    let app = TestApp::with([alice.clone()], guests.clone());
    let create = |guests: &[domain::identity::RemoteActor]| {
        let invited: Vec<&str> = guests.iter().map(|g| g.actor_uri.as_str()).collect();
        Some(json!({ "member_actor_uris": invited }))
    };
    let description =
        |(status, body): (StatusCode, Value)| (status, body["error_description"].clone());

    let too_many = app
        .call(Method::POST, "/api/groups", Some(alice.id), create(&guests))
        .await;
    assert_eq!(
        description(too_many),
        (
            StatusCode::BAD_REQUEST,
            json!("A group holds at most 50 members")
        )
    );
    let (created, group) = app
        .call(
            Method::POST,
            "/api/groups",
            Some(alice.id),
            create(&guests[1..]),
        )
        .await;
    assert_eq!(created, StatusCode::CREATED, "{group}");

    let members = format!(
        "/api/groups/{}/members",
        group["conversationId"].as_str().unwrap()
    );
    let full = app
        .call(
            Method::POST,
            &members,
            Some(alice.id),
            Some(json!({ "actor_uri": guests[0].actor_uri.as_str() })),
        )
        .await;
    assert_eq!(
        description(full),
        (
            StatusCode::CONFLICT,
            json!("The group is full: it holds at most 50 members")
        )
    );
}

#[tokio::test]
async fn someone_removed_from_a_group_sees_it_marked_and_clears_it() {
    let (alice, bob, carl) = (account("alice"), account("bob"), account("carl"));
    let app = TestApp::with([alice.clone(), bob.clone(), carl.clone()], []);
    let (_, group) = create(&app, &alice, &[&bob]).await;
    let group = format!("/api/groups/{}", group["conversationId"].as_str().unwrap());
    let bobs: String =
        url::form_urlencoded::byte_serialize(bob.actor_uri.as_str().as_bytes()).collect();
    let listed = |who: &Account| {
        let id = who.id;
        let app = &app;
        async move { app.call(Method::GET, "/api/dm", Some(id), None).await.1 }
    };

    let (removed, _) = app
        .call(
            Method::DELETE,
            &format!("{group}/members/{bobs}"),
            Some(alice.id),
            None,
        )
        .await;
    assert_eq!(removed, StatusCode::NO_CONTENT);
    let shown = &listed(&bob).await[0];
    assert_eq!(shown["name"], "crew");
    assert!(shown["removed_at"].is_string(), "{shown}");
    assert_eq!(listed(&alice).await[0]["removed_at"], Value::Null);

    assert_eq!(
        app.call(Method::DELETE, &group, Some(alice.id), None).await,
        (
            StatusCode::CONFLICT,
            json!({ "error": "conflict", "error_description": "Leave the group first" })
        )
    );
    assert_eq!(
        app.call(Method::DELETE, &group, Some(carl.id), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.call(Method::DELETE, &group, Some(bob.id), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(listed(&bob).await, json!([]));
}

#[tokio::test]
async fn the_history_shows_the_groups_changes_when_asked_for_them() {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    let (_, group) = create(&app, &alice, &[&bob]).await;
    let id = group["conversationId"].as_str().unwrap();
    let (renamed, _) = app
        .call(
            Method::PATCH,
            &format!("/api/groups/{id}"),
            Some(alice.id),
            Some(json!({ "name": "new crew" })),
        )
        .await;
    assert_eq!(renamed, StatusCode::OK);

    let (_, with) = app
        .call(
            Method::GET,
            &format!("/api/dm/{id}?include=events"),
            Some(bob.id),
            None,
        )
        .await;
    let (_, without) = app
        .call(Method::GET, &format!("/api/dm/{id}"), Some(bob.id), None)
        .await;

    let lines: Vec<_> = with
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["kind"].clone(),
                item["event"].clone(),
                item["actor_display_name"].clone(),
                item["name"].clone(),
            )
        })
        .collect();
    assert_eq!(
        lines,
        vec![
            (
                json!("event"),
                json!("renamed"),
                json!("alice"),
                json!("new crew")
            ),
            (
                json!("event"),
                json!("created"),
                json!("alice"),
                Value::Null
            ),
        ]
    );
    assert_eq!(with[0]["actor_uri"], alice.actor_uri.as_str());
    assert!(with[0]["created_at"].is_string());
    assert_eq!(without, json!([]), "messages only, unless asked");
}
