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
