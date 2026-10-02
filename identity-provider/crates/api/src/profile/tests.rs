use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::UserId;
use domain::identity::ActorUri;
use domain::identity::testing::remote_actor;
use domain::profile::testing::{ProfileSeeds, own_profile};
use domain::profile::{ImageKind, OwnProfile, Profiles, Pronouns};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

use crate::testing::TestApp;

async fn app_with(alice: &OwnProfile) -> TestApp {
    let app = TestApp::with([], []);
    app.profile.profiles.sign_up(alice).await;
    app
}

fn upload(app: &TestApp, user: UserId, content_type: &str) -> Request<Body> {
    Request::builder()
        .method(Method::PUT)
        .uri("/api/avatar")
        .header(header::AUTHORIZATION, format!("Bearer {}", app.token(user)))
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(&b"\x89PNG\r\n"[..]))
        .unwrap()
}

#[tokio::test]
async fn userinfo_answers_the_account_its_address_and_its_settings() {
    let alice = own_profile("alice");
    let app = app_with(&alice).await;

    let (status, body) = app
        .call(Method::GET, "/userinfo", Some(alice.id), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "sub": alice.id.to_string(),
            "email": "alice@idp.test",
            "email_verified": true,
            "totp_enabled": false,
            "preferred_username": "alice_t3st0",
            "display_name": "alice",
            "address": "alice_t3st0@localhost:8080",
            "actor_uri": "http://localhost:8080/users/alice_t3st0",
            "avatar_url": null,
            "pronouns": null,
            "bio": null,
            "settings": {},
            "privacy": { "contact_policy": "friends_and_groups" },
        })
    );
}

#[tokio::test]
async fn userinfo_carries_the_settings_saved() {
    let alice = own_profile("alice");
    let app = app_with(&alice).await;
    let appearance = json!({ "appearance": { "family": "lagoon" } });
    app.call(
        Method::PATCH,
        "/api/settings",
        Some(alice.id),
        Some(appearance.clone()),
    )
    .await;

    let (_, body) = app
        .call(Method::GET, "/userinfo", Some(alice.id), None)
        .await;

    assert_eq!(body["settings"], appearance);
}

#[tokio::test]
async fn userinfo_without_a_token_is_challenged() {
    let app = TestApp::with([], []);
    let request = Request::get("/userinfo").body(Body::empty()).unwrap();

    let response = app.respond(request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    let (_, body) = TestApp::body_of(response).await;
    assert_eq!(body["error"], "invalid_token");
}

#[tokio::test]
async fn userinfo_for_an_account_gone_is_an_invalid_token() {
    let app = TestApp::with([], []);

    let (status, body) = app
        .call(Method::GET, "/userinfo", Some(UserId::generate()), None)
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(body["error_description"], "User not found");
}

#[tokio::test]
async fn a_profile_edit_answers_the_new_userinfo() {
    let alice = own_profile("alice");
    let app = app_with(&alice).await;

    let (status, body) = app
        .call(
            Method::PATCH,
            "/api/profile",
            Some(alice.id),
            Some(json!({ "display_name": " Aroha ", "pronouns": "she", "bio": "" })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], "Aroha");
    assert_eq!(body["pronouns"], "she");
    assert_eq!(body["bio"], json!(null));
    assert_eq!(body["settings"], json!({}));
}

#[tokio::test]
async fn a_profile_edit_outside_the_rules_is_refused_with_the_rule() {
    let alice = own_profile("alice");
    let app = app_with(&alice).await;

    for (form, rule) in [
        (json!({ "bio": "hi" }), "display_name is required"),
        (
            json!({ "display_name": "  " }),
            "display_name cannot be blank",
        ),
        (
            json!({ "display_name": "Aroha", "pronouns": "they" }),
            "pronouns must be one of: he, she, non-binary",
        ),
        (
            json!({ "display_name": "Aroha", "bio": "x".repeat(191) }),
            "bio must be ≤ 190 characters",
        ),
    ] {
        let (status, body) = app
            .call(Method::PATCH, "/api/profile", Some(alice.id), Some(form))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(body["error_description"], rule);
    }
}

#[tokio::test]
async fn an_uploaded_avatar_is_answered_with_its_url() {
    let alice = own_profile("alice");
    let app = app_with(&alice).await;

    let (status, body) = app.send(upload(&app, alice.id, "image/webp")).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let url = body["avatar_url"].as_str().unwrap();
    assert!(
        url.starts_with(&format!("http://s3.test/avatars/{}.webp?v=", alice.id)),
        "{url}"
    );
    assert_eq!(app.profile.avatars.stored(alice.id), vec![ImageKind::Webp]);
}

#[tokio::test]
async fn an_avatar_that_is_no_image_of_the_kinds_is_refused() {
    let alice = own_profile("alice");
    let app = app_with(&alice).await;

    let (status, body) = app.send(upload(&app, alice.id, "image/svg+xml")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error_description"],
        "Content-Type must be image/jpeg, image/png, image/webp, or image/gif"
    );
    assert!(app.profile.avatars.stored(alice.id).is_empty());
}

#[tokio::test]
async fn a_deleted_avatar_is_no_longer_shown() {
    let alice = own_profile("alice");
    let app = app_with(&alice).await;
    app.send(upload(&app, alice.id, "image/png")).await;

    let (status, _) = app
        .call(Method::DELETE, "/api/avatar", Some(alice.id), None)
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let shown = app.profile.profiles.find(alice.id).await.unwrap().unwrap();
    assert_eq!(shown.avatar_url, None);
}

fn card_of(actor: &ActorUri) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("actor", actor.as_str())
        .finish();
    format!("/api/profiles?{query}")
}

/// `alice` reads the cards; `bob` is an account here with pronouns and a bio.
async fn cards() -> (TestApp, OwnProfile, OwnProfile) {
    let alice = own_profile("alice");
    let bob = OwnProfile {
        pronouns: Some(Pronouns::He),
        bio: Some("kia ora".to_owned()),
        ..own_profile("bob")
    };
    let app = TestApp::with([alice.account().unwrap()], []);
    for profile in [&alice, &bob] {
        app.profile.profiles.sign_up(profile).await;
    }
    (app, alice, bob)
}

#[tokio::test]
async fn a_profile_card_answers_what_the_account_shows() {
    let (app, alice, bob) = cards().await;
    let bob_uri = bob.actor_uri.clone().unwrap();

    let (status, body) = app
        .call(Method::GET, &card_of(&bob_uri), Some(alice.id), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "actor_uri": "http://localhost:8080/users/bob_t3st0",
            "display_name": "bob",
            "avatar_url": null,
            "pronouns": "he",
            "bio": "kia ora",
            "friends_since": null,
        })
    );
}

#[tokio::test]
async fn a_friends_card_dates_the_friendship() {
    let (app, alice, bob) = cards().await;
    let bob_uri = bob.actor_uri.clone().unwrap();
    app.profile
        .profiles
        .befriend(alice.id, &bob_uri, true, None)
        .await;

    let (status, body) = app
        .call(Method::GET, &card_of(&bob_uri), Some(alice.id), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let since = body["friends_since"].as_str().expect("an RFC 3339 date");
    time::OffsetDateTime::parse(since, &Rfc3339).unwrap();
}

#[tokio::test]
async fn a_card_the_viewer_may_not_read_is_not_found() {
    let (app, alice, _) = cards().await;
    let erin = remote_actor("erin_k2m9x@idp.erin.test");
    app.profile.profiles.remember(&erin).await;
    let stranger = remote_actor("zed_k2m9x@idp.far.test");

    for actor in [&erin, &stranger] {
        let (status, body) = app
            .call(
                Method::GET,
                &card_of(&actor.actor_uri),
                Some(alice.id),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{}", actor.actor_uri);
        assert_eq!(body["error_description"], "User not found");
    }
}

#[tokio::test]
async fn a_card_asked_without_an_actor_uri_is_a_bad_request() {
    let (app, alice, _) = cards().await;

    let (status, body) = app
        .call(Method::GET, "/api/profiles?actor=bob", Some(alice.id), None)
        .await;
    let (missing, _) = app
        .call(Method::GET, "/api/profiles", Some(alice.id), None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "`actor` is not an actor URI");
    assert_eq!(missing, StatusCode::BAD_REQUEST);
}
