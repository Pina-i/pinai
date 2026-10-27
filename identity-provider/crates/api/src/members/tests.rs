use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::UserId;
use domain::auth::testing::{SignInSeeds, seeded_actor, signed_up};
use domain::auth::{PasswordResets, ResetToken, SessionKind, Sessions, SignInAccount};
use domain::presence::PresenceState;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::testing::TestApp;

/// `app`, with an admin and a member.
async fn with_people(app: TestApp) -> (TestApp, SignInAccount, SignInAccount) {
    let admin = SignInAccount {
        admin: true,
        display_name: Some("Kahu".to_owned()),
        ..signed_up("kahu")
    };
    let member = signed_up("alice");
    app.sign_in.accounts.sign_up(&admin).await;
    app.sign_in.accounts.sign_up(&member).await;
    (app, admin, member)
}

async fn app() -> (TestApp, SignInAccount, SignInAccount) {
    with_people(TestApp::with([], [])).await
}

fn reset_uri(id: impl std::fmt::Display) -> String {
    format!("/api/admin/members/{id}/password-reset")
}

fn rfc3339(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(
        value.as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
}

fn with_token(method: Method, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn the_members_routes_answer_401_to_anyone_unsigned_and_403_to_a_member() {
    let (app, _, member) = app().await;
    let reset = reset_uri(member.id);

    for (method, uri) in [
        (Method::GET, "/api/admin/members"),
        (Method::POST, reset.as_str()),
    ] {
        let (anonymous, _) = app.call(method.clone(), uri, None, None).await;
        let (signed_in, body) = app.call(method.clone(), uri, Some(member.id), None).await;

        assert_eq!(anonymous, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(signed_in, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(
            body,
            json!({ "error": "access_denied", "error_description": "Only an admin may do this" })
        );
    }
}

#[tokio::test]
async fn a_member_is_refused_whatever_account_they_name() {
    let (app, admin, member) = app().await;

    for id in [
        "not-an-id".to_owned(),
        UserId::generate().to_string(),
        admin.id.to_string(),
    ] {
        let (status, body) = app
            .call(Method::POST, &reset_uri(&id), Some(member.id), None)
            .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{id}: {body}");
        assert_eq!(body["error"], "access_denied");
    }
}

#[tokio::test]
async fn an_admin_lists_the_members_by_display_name_with_their_activity_and_presence() {
    let (app, admin, alice) = app().await;
    let carol = signed_up("carol");
    let bob = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    app.sign_in.accounts.sign_up(&carol).await;
    app.sign_in.accounts.sign_up(&bob).await;
    let an_hour_ago = OffsetDateTime::now_utc() - Duration::hours(1);
    app.sign_in
        .sessions
        .open(alice.id, &SessionKind::Browser, an_hour_ago)
        .await
        .unwrap();
    app.board.set(&seeded_actor(&alice), PresenceState::Away);

    let (status, body) = app
        .call(Method::GET, "/api/admin/members", Some(admin.id), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = body.as_array().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|member| member["display_name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["Kahu", "alice", "carol"],
        "the most recently active first — the admin's own call is a use; bob, unconfirmed, is \
         no member"
    );
    assert_eq!(listed[0]["admin"], true);
    assert_eq!(
        listed[1],
        json!({
            "id": alice.id.to_string(),
            "display_name": "alice",
            "admin": false,
            "last_active_at": listed[1]["last_active_at"],
            "online": true,
        })
    );
    assert_eq!(rfc3339(&listed[1]["last_active_at"]), an_hour_ago);
    assert_eq!(
        listed[2],
        json!({
            "id": carol.id.to_string(),
            "display_name": "carol",
            "admin": false,
            "last_active_at": null,
            "online": false,
        })
    );
    let shown = body.to_string();
    for hidden in [&alice.email, &alice.username, &admin.email, &admin.username] {
        assert!(!shown.contains(hidden.as_str()), "{hidden}: {shown}");
    }
}

#[tokio::test]
async fn an_admin_gets_a_reset_link_whose_token_is_in_this_answer_only() {
    let (app, admin, alice) = app().await;
    let before = OffsetDateTime::now_utc();

    let (status, body) = app
        .call(Method::POST, &reset_uri(alice.id), Some(admin.id), None)
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body.as_object().unwrap().len(),
        2,
        "link and expires_at: {body}"
    );
    let link = body["link"].as_str().unwrap();
    let token = link
        .strip_prefix("http://localhost:8080/r/")
        .unwrap_or_else(|| panic!("{link}"));
    let token = ResetToken::parse(token).unwrap();
    let open = app
        .sign_in
        .resets
        .find_open(&token, OffsetDateTime::now_utc())
        .await
        .unwrap()
        .expect("open");
    assert_eq!(open.member, alice.id);
    let expires_at = rfc3339(&body["expires_at"]);
    assert_eq!(expires_at, open.expires_at);
    assert!(expires_at >= before + Duration::hours(24), "{expires_at}");
    let (_, listed) = app
        .call(Method::GET, "/api/admin/members", Some(admin.id), None)
        .await;
    assert!(!listed.to_string().contains(token.as_str()), "{listed}");
}

#[tokio::test]
async fn an_unknown_or_malformed_account_is_not_found_and_an_admin_is_refused_409() {
    let (app, admin, _) = app().await;
    let other_admin = SignInAccount {
        admin: true,
        ..signed_up("root")
    };
    let signing_up = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    app.sign_in.accounts.sign_up(&other_admin).await;
    app.sign_in.accounts.sign_up(&signing_up).await;

    let (unknown, body) = app
        .call(
            Method::POST,
            &reset_uri(UserId::generate()),
            Some(admin.id),
            None,
        )
        .await;
    let (malformed, _) = app
        .call(Method::POST, &reset_uri("not-an-id"), Some(admin.id), None)
        .await;
    let (unconfirmed, _) = app
        .call(
            Method::POST,
            &reset_uri(signing_up.id),
            Some(admin.id),
            None,
        )
        .await;

    assert_eq!(
        [unknown, malformed, unconfirmed],
        [StatusCode::NOT_FOUND; 3],
        "an account still to confirm its address is no member"
    );
    assert_eq!(
        body,
        json!({ "error": "not_found", "error_description": "Member not found" })
    );
    for target in [admin.id, other_admin.id] {
        let (status, body) = app
            .call(Method::POST, &reset_uri(target), Some(admin.id), None)
            .await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            body,
            json!({
                "error": "admin_account",
                "error_description": "An admin recovers their access through ADMIN_EMAIL and \
                                      ADMIN_PASSWORD, not a reset link",
            })
        );
    }
}

#[tokio::test]
async fn a_reset_link_takes_a_password_typed_in_the_last_ten_minutes() {
    let (app, admin, alice) = app().await;
    let stale = app.token_signed_in_at(admin.id, OffsetDateTime::now_utc() - Duration::minutes(11));

    let refused = app
        .respond(with_token(Method::POST, &reset_uri(alice.id), &stale))
        .await;
    let listed = app
        .respond(with_token(Method::GET, "/api/admin/members", &stale))
        .await;

    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        refused.headers()[header::WWW_AUTHENTICATE],
        r#"Bearer error="insufficient_user_authentication", max_age="600""#
    );
    let (_, body) = TestApp::body_of(refused).await;
    assert_eq!(body["error"], "insufficient_user_authentication");
    assert_eq!(
        listed.status(),
        StatusCode::OK,
        "the list takes no recent password"
    );
}

#[tokio::test]
async fn an_invite_only_instance_lists_its_members_too() {
    let (app, admin, alice) = with_people(TestApp::invite_only()).await;

    let (status, body) = app
        .call(Method::GET, "/api/admin/members", Some(admin.id), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body.as_array()
            .unwrap()
            .iter()
            .map(|member| member["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        vec![admin.id.to_string(), alice.id.to_string()]
    );
}

#[tokio::test]
async fn an_open_and_an_invite_only_instance_both_give_reset_links() {
    for app in [TestApp::with([], []), TestApp::invite_only()] {
        let (app, admin, alice) = with_people(app).await;

        let (status, body) = app
            .call(Method::POST, &reset_uri(alice.id), Some(admin.id), None)
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
}
