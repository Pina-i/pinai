use axum::http::{Method, StatusCode};
use domain::identity::testing::{InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, ActorUri, FederatedAddress, RemoteActor};
use domain::messaging::ConversationKind;
use domain::social::testing::people::{Admission, PeopleSeeds};
use domain::social::{Direction, Friendship, FriendshipStatus, Ties};
use domain::{FriendshipId, UserId};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::*;
use crate::testing::TestApp;

#[test]
fn each_standing_is_answered_as_its_relation_and_only_a_request_received_with_its_id() {
    use Direction::{Incoming, Outgoing};
    use FriendshipStatus::{Accepted, Pending};

    let actor = ActorUri::parse("https://reef.chat/users/mahealani_q1x8c").unwrap();
    let side = |status, direction| Friendship {
        id: FriendshipId::generate(),
        owner: UserId::generate(),
        friend: actor.clone(),
        status,
        direction,
    };
    let received = side(Pending, Incoming);
    let request = json!(received.id.as_uuid());
    let ties = |blocked, side| Ties { blocked, side };
    let cases = [
        (ties(true, None), "blocked", Value::Null),
        (
            ties(true, Some(side(Pending, Incoming))),
            "blocked",
            Value::Null,
        ),
        (
            ties(false, Some(side(Accepted, Outgoing))),
            "friend",
            Value::Null,
        ),
        (ties(false, Some(received)), "request_received", request),
        (
            ties(false, Some(side(Pending, Outgoing))),
            "request_sent",
            Value::Null,
        ),
        (Ties::default(), "none", Value::Null),
    ];

    for (ties, relation, friendship_id) in cases {
        let body = serde_json::to_value(PersonBody::from(FoundPerson {
            actor: actor.clone(),
            address: FederatedAddress::parse("mahealani_q1x8c@reef.chat").unwrap(),
            display_name: None,
            avatar_url: None,
            ties,
        }))
        .unwrap();

        assert_eq!(body["relation"], relation);
        assert_eq!(body["friendship_id"], friendship_id, "{relation}");
    }
}

#[tokio::test]
async fn a_search_answers_both_sections_with_the_callers_relation_to_each_person() {
    let alice = account("alice");
    let hoku = Account {
        display_name: Some("Hōkū".to_owned()),
        avatar_url: Some("http://localhost:8080/avatars/hoku.webp?v=2".to_owned()),
        ..account("hoku")
    };
    let mahealani = RemoteActor {
        display_name: Some("Mahealani Hoku".to_owned()),
        ..remote_actor("mahealani_q1x8c@reef.chat")
    };
    let app = TestApp::with([alice.clone()], []);
    let people = &app.people;
    people.sign_up(&alice, Admission::Confirmed).await;
    people.sign_up(&hoku, Admission::Confirmed).await;
    people.remember(&mahealani).await;
    let request = people
        .befriend(
            alice.id,
            &hoku.actor_uri,
            FriendshipStatus::Pending,
            Direction::Incoming,
        )
        .await;
    people
        .befriend(
            alice.id,
            &mahealani.actor_uri,
            FriendshipStatus::Accepted,
            Direction::Outgoing,
        )
        .await;
    people
        .converse(
            ConversationKind::Group,
            Some("Federation lab"),
            OffsetDateTime::now_utc(),
            &[&alice.actor_uri, &mahealani.actor_uri],
        )
        .await;

    let (status, body) = app
        .call(
            Method::GET,
            "/api/users/search?q=hoku",
            Some(alice.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "server": [{
                "actor_uri": "http://localhost:8080/users/hoku_t3st0",
                "address": "hoku_t3st0@localhost:8080",
                "display_name": "Hōkū",
                "avatar_url": "http://localhost:8080/avatars/hoku.webp?v=2",
                "relation": "request_received",
                "friendship_id": request.as_uuid(),
            }],
            "groups": [{
                "actor_uri": "https://reef.chat/users/mahealani_q1x8c",
                "address": "mahealani_q1x8c@reef.chat",
                "display_name": "Mahealani Hoku",
                "avatar_url": null,
                "relation": "friend",
                "friendship_id": null,
                "group": "Federation lab",
            }],
        })
    );
}

#[tokio::test]
async fn a_search_answers_twenty_a_section_unless_asked_otherwise() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    app.people.sign_up(&alice, Admission::Confirmed).await;
    for i in 0..25 {
        let kai = account(&format!("kai{i:02}"));
        app.people.sign_up(&kai, Admission::Confirmed).await;
    }

    for (uri, listed) in [
        ("/api/users/search?q=kai", 20),
        ("/api/users/search?q=kai&limit=3", 3),
    ] {
        let (status, body) = app.call(Method::GET, uri, Some(alice.id), None).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["server"].as_array().unwrap().len(), listed, "{uri}");
        assert_eq!(body["groups"], json!([]));
    }
}

#[tokio::test]
async fn a_search_needs_a_signed_in_caller() {
    let app = TestApp::with([account("alice")], []);

    let (status, body) = app
        .call(Method::GET, "/api/users/search?q=lic", None, None)
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
}

#[tokio::test]
async fn a_query_too_short_too_long_or_holding_a_control_character_is_refused() {
    let app = TestApp::with([account("alice")], []);

    let long = "a".repeat(101);
    for q in [
        "",
        "a",
        "%20a%20",
        "%CC%81%CC%81",
        "a%CC%81",
        "ab%00",
        long.as_str(),
    ] {
        let (status, body) = app
            .call(
                Method::GET,
                &format!("/api/users/search?q={q}"),
                Some(UserId::generate()),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{q:?}: {body}");
        assert_eq!(body["error"], "invalid_request");
    }
}

fn lookup_of(address: &str) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("address", address)
        .finish();
    format!("/api/users/lookup?{query}")
}

#[tokio::test]
async fn a_lookup_answers_an_account_here_by_its_handle_or_its_address_with_the_relation() {
    let alice = account("alice");
    let hoku = Account {
        display_name: Some("Hōkū".to_owned()),
        ..account("hoku")
    };
    let app = TestApp::with([alice.clone()], []);
    app.people.sign_up(&alice, Admission::Confirmed).await;
    app.people.sign_up(&hoku, Admission::Admitted).await;
    app.people
        .befriend(
            alice.id,
            &hoku.actor_uri,
            FriendshipStatus::Accepted,
            Direction::Incoming,
        )
        .await;

    for address in ["hoku_t3st0", " @hoku_t3st0 ", "hoku_t3st0@LOCALHOST:8080"] {
        let (status, body) = app
            .call(Method::GET, &lookup_of(address), Some(alice.id), None)
            .await;

        assert_eq!(status, StatusCode::OK, "{address:?}: {body}");
        assert_eq!(
            body,
            json!({
                "actor_uri": "http://localhost:8080/users/hoku_t3st0",
                "address": "hoku_t3st0@localhost:8080",
                "display_name": "Hōkū",
                "avatar_url": null,
                "relation": "friend",
                "friendship_id": null,
            }),
            "{address:?}"
        );
    }
}

#[tokio::test]
async fn the_callers_own_address_is_answered_like_any_other() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    app.people.sign_up(&alice, Admission::Confirmed).await;

    let (status, body) = app
        .call(
            Method::GET,
            &lookup_of("alice_t3st0@localhost:8080"),
            Some(alice.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["actor_uri"], alice.actor_uri.as_str());
    assert_eq!(body["relation"], "none");
}

#[tokio::test]
async fn a_lookup_answers_another_instances_account_as_its_instance_describes_it() {
    let alice = account("alice");
    let mahealani = RemoteActor {
        display_name: None,
        ..remote_actor("mahealani_q1x8c@reef.chat")
    };
    let app = TestApp::knowing(
        [alice.clone()],
        InMemoryRemoteActors::default().and_uncached([mahealani]),
    );
    app.people.sign_up(&alice, Admission::Confirmed).await;

    let (status, body) = app
        .call(
            Method::GET,
            &lookup_of("mahealani_q1x8c@reef.chat"),
            Some(alice.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "actor_uri": "https://reef.chat/users/mahealani_q1x8c",
            "address": "mahealani_q1x8c@reef.chat",
            "display_name": null,
            "avatar_url": null,
            "relation": "none",
            "friendship_id": null,
        })
    );
}

#[tokio::test]
async fn no_account_at_the_address_is_a_404() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    app.people.sign_up(&alice, Admission::Confirmed).await;
    app.people
        .sign_up(&account("kaiah"), Admission::Unconfirmed)
        .await;

    for address in [
        "nobody_t3st0",
        "kaiah_t3st0",
        "nobody_k2m9x@reef.chat",
        "alice",
        "Hoku_T3ST0",
        "alice@localhost:8080",
        "Hoku_T3ST0@LOCALHOST:8080",
    ] {
        let (status, body) = app
            .call(Method::GET, &lookup_of(address), Some(alice.id), None)
            .await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{address:?}: {body}");
        assert_eq!(body["error_description"], "No account at this address");
    }
}

#[tokio::test]
async fn an_instance_that_does_not_answer_is_a_502() {
    let alice = account("alice");
    let app = TestApp::knowing(
        [alice.clone()],
        InMemoryRemoteActors::default().and_down("reef.chat"),
    );

    let (status, body) = app
        .call(
            Method::GET,
            &lookup_of("mahealani_q1x8c@reef.chat"),
            Some(alice.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "bad_gateway");
}

#[tokio::test]
async fn an_instance_this_one_may_not_ask_is_a_502_as_one_that_does_not_answer() {
    let alice = account("alice");
    let app = TestApp::knowing(
        [alice.clone()],
        InMemoryRemoteActors::default().and_refused("reef.chat"),
    );

    let (status, body) = app
        .call(
            Method::GET,
            &lookup_of("mahealani_q1x8c@reef.chat"),
            Some(alice.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(
        body,
        json!({ "error": "bad_gateway", "error_description": "the account's instance did not answer" })
    );
}

#[tokio::test]
async fn what_is_no_address_is_a_400() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);

    for address in [
        "",
        "@",
        "hoku@",
        "a@b@c",
        "not an address",
        "x@reef..chat",
        "x@a.-b",
        "x@reef.123",
        "x@reef.chat:+443",
    ] {
        let (status, body) = app
            .call(Method::GET, &lookup_of(address), Some(alice.id), None)
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{address:?}: {body}");
        assert_eq!(body["error"], "invalid_request");
    }
}

#[tokio::test]
async fn a_lookup_needs_a_signed_in_caller() {
    let app = TestApp::with([account("alice")], []);

    let (status, _) = app
        .call(Method::GET, &lookup_of("alice_t3st0"), None, None)
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn lookups_are_rate_limited_per_caller() {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    for _ in 0..60 {
        app.call(
            Method::GET,
            &lookup_of("nobody_t3st0"),
            Some(alice.id),
            None,
        )
        .await;
    }

    let (limited, body) = app
        .call(
            Method::GET,
            &lookup_of("nobody_t3st0"),
            Some(alice.id),
            None,
        )
        .await;
    let (other, _) = app
        .call(Method::GET, &lookup_of("nobody_t3st0"), Some(bob.id), None)
        .await;

    assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "too_many_requests");
    assert_eq!(other, StatusCode::NOT_FOUND);
}
