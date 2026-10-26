use axum::http::{Method, StatusCode};
use domain::auth::testing::{SignInSeeds, contract, signed_up};
use domain::auth::{InvitationToken, Invitations, SignInAccount, SignUps};
use domain::{InvitationId, UserId};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::testing::TestApp;

/// The instance, invite-only, with an admin and a member.
async fn app() -> (TestApp, UserId, UserId) {
    with_people(TestApp::invite_only()).await
}

async fn with_people(app: TestApp) -> (TestApp, UserId, UserId) {
    let admin = SignInAccount {
        admin: true,
        display_name: Some("Kahu".to_owned()),
        ..signed_up("kahu")
    };
    let member = signed_up("alice");
    app.sign_in.accounts.sign_up(&admin).await;
    app.sign_in.accounts.sign_up(&member).await;
    (app, admin.id, member.id)
}

fn rfc3339(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(
        value.as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
}

#[tokio::test]
async fn an_admin_creates_an_invitation_whose_link_carries_its_token_once() {
    let (app, admin, _) = app().await;
    let before = OffsetDateTime::now_utc();

    let (status, body) = app
        .call(Method::POST, "/api/admin/invitations", Some(admin), None)
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let link = body["link"].as_str().unwrap();
    let token = link
        .strip_prefix("http://localhost:8080/i/")
        .unwrap_or_else(|| panic!("{link}"));
    let token = InvitationToken::parse(token).unwrap();
    let open = app
        .sign_in
        .accounts
        .find_open(&token, OffsetDateTime::now_utc())
        .await
        .unwrap()
        .expect("open");
    assert_eq!(body["id"], open.id.to_string());
    let expires_at = rfc3339(&body["expires_at"]);
    assert_eq!(expires_at, open.expires_at);
    assert!(expires_at >= before + Duration::days(7), "{expires_at}");
    let (_, listed) = app
        .call(Method::GET, "/api/admin/invitations", Some(admin), None)
        .await;
    assert!(!listed.to_string().contains(token.as_str()), "{listed}");
}

#[tokio::test]
async fn the_admin_routes_answer_401_to_anyone_unsigned_and_403_to_a_member() {
    let (app, _, member) = app().await;
    let some_id = InvitationId::generate();
    let revoke = format!("/api/admin/invitations/{some_id}");
    let routes = [
        (Method::POST, "/api/admin/invitations"),
        (Method::GET, "/api/admin/invitations"),
        (Method::DELETE, revoke.as_str()),
    ];

    for (method, uri) in routes {
        let (anonymous, _) = app.call(method.clone(), uri, None, None).await;
        let (signed_in, body) = app.call(method.clone(), uri, Some(member), None).await;

        assert_eq!(anonymous, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(signed_in, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(
            body,
            json!({ "error": "access_denied", "error_description": "Only an admin may do this" })
        );
    }
}

#[tokio::test]
async fn a_member_is_refused_whatever_id_they_name() {
    let (app, _, member) = app().await;

    let (status, body) = app
        .call(
            Method::DELETE,
            "/api/admin/invitations/not-an-id",
            Some(member),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn an_admin_lists_the_open_invitations_newest_first() {
    let (app, admin, _) = app().await;
    let now = OffsetDateTime::now_utc();
    let accounts = &app.sign_in.accounts;
    let issue = async |at: OffsetDateTime, expires_at: OffsetDateTime| {
        accounts.issue(admin, at, expires_at).await.unwrap().0
    };
    let used = issue(now - Duration::hours(4), now + Duration::days(6)).await;
    accounts
        .create_invited(
            &contract::a_new_account("bob"),
            used,
            now - Duration::hours(3),
        )
        .await
        .unwrap();
    issue(now - Duration::days(8), now - Duration::days(1)).await;
    let revoked = issue(now - Duration::hours(2), now + Duration::days(7)).await;
    accounts.revoke(revoked, now).await.unwrap();
    let older = issue(now - Duration::hours(1), now + Duration::days(7)).await;
    let newer = issue(now, now + Duration::days(7)).await;

    let (status, body) = app
        .call(Method::GET, "/api/admin/invitations", Some(admin), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = body.as_array().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|open| open["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        vec![newer.to_string(), older.to_string()]
    );
    assert_eq!(
        listed[1],
        json!({
            "id": older.to_string(),
            "created_at": listed[1]["created_at"],
            "expires_at": listed[1]["expires_at"],
            "created_by": { "display_name": "Kahu" },
        })
    );
    assert_eq!(rfc3339(&listed[1]["created_at"]), now - Duration::hours(1));
    assert_eq!(rfc3339(&listed[1]["expires_at"]), now + Duration::days(7));
}

#[tokio::test]
async fn an_admin_revokes_an_open_invitation_and_nothing_else() {
    let (app, admin, _) = app().await;
    let now = OffsetDateTime::now_utc();
    let (open, token) = app
        .sign_in
        .accounts
        .issue(admin, now, now + Duration::days(7))
        .await
        .unwrap();
    let uri = format!("/api/admin/invitations/{open}");

    let (revoked, _) = app.call(Method::DELETE, &uri, Some(admin), None).await;
    let (again, body) = app.call(Method::DELETE, &uri, Some(admin), None).await;
    let (unknown, _) = app
        .call(
            Method::DELETE,
            &format!("/api/admin/invitations/{}", InvitationId::generate()),
            Some(admin),
            None,
        )
        .await;
    let (malformed, _) = app
        .call(
            Method::DELETE,
            "/api/admin/invitations/not-an-id",
            Some(admin),
            None,
        )
        .await;

    assert_eq!(revoked, StatusCode::NO_CONTENT);
    assert_eq!(
        (again, unknown, malformed),
        (
            StatusCode::NOT_FOUND,
            StatusCode::NOT_FOUND,
            StatusCode::NOT_FOUND
        )
    );
    assert_eq!(
        body,
        json!({ "error": "not_found", "error_description": "Invitation not found" })
    );
    assert_eq!(
        app.sign_in
            .accounts
            .find_open(&token, OffsetDateTime::now_utc())
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn an_open_instance_makes_no_invitation_but_lists_and_revokes_the_ones_left() {
    let (app, admin, member) = with_people(TestApp::with([], [])).await;
    let now = OffsetDateTime::now_utc();
    let (left, _) = app
        .sign_in
        .accounts
        .issue(admin, now, now + Duration::days(7))
        .await
        .unwrap();

    let (created, refusal) = app
        .call(Method::POST, "/api/admin/invitations", Some(admin), None)
        .await;
    let (by_member, _) = app
        .call(Method::POST, "/api/admin/invitations", Some(member), None)
        .await;
    let (listed, open) = app
        .call(Method::GET, "/api/admin/invitations", Some(admin), None)
        .await;
    let (revoked, _) = app
        .call(
            Method::DELETE,
            &format!("/api/admin/invitations/{left}"),
            Some(admin),
            None,
        )
        .await;

    assert_eq!(created, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(
        refusal,
        json!({
            "error": "registrations_open",
            "error_description": "This instance is open: people sign up themselves",
        })
    );
    assert_eq!(
        by_member,
        StatusCode::FORBIDDEN,
        "the admin check comes first"
    );
    assert_eq!(listed, StatusCode::OK);
    assert_eq!(open[0]["id"], left.to_string(), "{open}");
    assert_eq!(open.as_array().unwrap().len(), 1, "none made: {open}");
    assert_eq!(revoked, StatusCode::NO_CONTENT);
}
