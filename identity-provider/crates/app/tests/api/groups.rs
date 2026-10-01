use reqwest::Method;
use serde_json::json;

use crate::helpers::spawn_app;

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
