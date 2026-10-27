use reqwest::Method;
use serde_json::Value;

use crate::helpers::{
    ADMIN, Account, PASSWORD, TestApp, admin_of, an_admin, closed_as_ended, eventually, location,
    open_socket, query_of, spawn_app_with,
};

const NEW_PASSWORD: &str = "a-new-journey-password";

async fn page(app: &TestApp, path: &str) -> (reqwest::StatusCode, String) {
    let response = app
        .http
        .get(format!("{}{path}", app.address))
        .send()
        .await
        .unwrap();
    (response.status(), response.text().await.unwrap())
}

async fn set_password(app: &TestApp, path: &str, password: &str) -> reqwest::Response {
    app.http
        .post(format!("{}{path}", app.address))
        .form(&[("password", password), ("confirmation", password)])
        .send()
        .await
        .unwrap()
}

/// `name`'s entry in the members list.
async fn member_named(app: &TestApp, admin: &Account, name: &str) -> Option<Value> {
    let (_, members) = app.get(admin, "/api/admin/members").await;
    members
        .as_array()?
        .iter()
        .find(|member| member["display_name"] == name)
        .cloned()
}

#[tokio::test]
async fn a_member_resets_their_password_with_an_admins_link_and_is_signed_out_everywhere() {
    let app = spawn_app_with(an_admin).await;
    let admin = admin_of(&app).await;
    let alice = app.sign_up("alice").await;
    let mut socket = open_socket(&app, &alice.token).await.unwrap();
    // Her socket brings her online, through the presence bus.
    let listed = eventually("alice online in the members list", || async {
        member_named(&app, &admin, "alice")
            .await
            .filter(|member| member["online"] == true)
    })
    .await;

    let (status, issued) = app
        .send(
            Method::POST,
            &admin,
            &format!(
                "/api/admin/members/{}/password-reset",
                listed["id"].as_str().unwrap()
            ),
            Value::Null,
        )
        .await;
    assert_eq!(status, 201, "{issued}");
    let link = issued["link"].as_str().unwrap();
    let path = link
        .strip_prefix(&app.address)
        .unwrap_or_else(|| panic!("{link}"))
        .to_owned();
    let (form_status, form) = page(&app, &path).await;
    let reset = set_password(&app, &path, NEW_PASSWORD).await;
    let reset_status = reset.status();
    let done = reset.text().await.unwrap();
    let closed = closed_as_ended(&mut socket).await;
    let (old_token, _) = app.get(&alice, "/userinfo").await;
    let (renewal, _) = app.refresh(&alice.refresh_token).await;
    let with_the_old = app
        .form("/login", &[("email", &alice.email), ("password", PASSWORD)])
        .await;
    let with_the_new = app
        .form(
            "/login",
            &[("email", &alice.email), ("password", NEW_PASSWORD)],
        )
        .await;
    let (again, refused) = page(&app, &path).await;
    let resubmitted = set_password(&app, &path, "yet-another-password").await;

    assert!(!listed["last_active_at"].is_null(), "{listed}");
    assert_eq!(form_status, 200);
    assert!(form.contains("Set a new password"), "{form}");
    assert_eq!(reset_status, 200);
    assert!(done.contains("Your password is changed."), "{done}");
    assert!(closed, "her socket closed with 1008");
    assert_eq!(
        [old_token, renewal].map(|status| status.as_u16()),
        [401, 400],
        "her tokens went with her session"
    );
    assert_eq!(
        query_of(&location(&with_the_old))["error"],
        "invalid_credentials"
    );
    let landed = location(&with_the_new);
    assert!(landed.starts_with(&app.redirect_uri), "{landed}");
    assert_eq!(again, 404);
    assert!(
        refused.contains("This link can no longer be used"),
        "{refused}"
    );
    assert_eq!(resubmitted.status(), 404);
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE revoked_reason = 'password_reset'")
            .await,
        1
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn an_admin_whose_password_is_older_than_ten_minutes_is_asked_for_it_again() {
    let app = spawn_app_with(an_admin).await;
    let admin = admin_of(&app).await;
    app.sign_up("alice").await;
    let alice = member_named(&app, &admin, "alice").await.unwrap();
    // Typed eleven minutes ago, as the token renewed next carries it.
    app.execute(&format!(
        "UPDATE sessions SET authenticated_at = now() - interval '11 minutes' \
         WHERE user_id = (SELECT id FROM users WHERE email = '{ADMIN}')"
    ))
    .await;
    let (renewed, tokens) = app.refresh(&admin.refresh_token).await;
    let admin = Account {
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        ..admin
    };

    let refused = app
        .http
        .post(format!(
            "{}/api/admin/members/{}/password-reset",
            app.address,
            alice["id"].as_str().unwrap()
        ))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap();

    assert_eq!(renewed, 200, "{tokens}");
    assert_eq!(refused.status(), 401);
    assert_eq!(
        refused.headers()["www-authenticate"],
        r#"Bearer error="insufficient_user_authentication", max_age="600""#
    );
    let body: Value = refused.json().await.unwrap();
    assert_eq!(body["error"], "insufficient_user_authentication");
    assert_eq!(app.count("SELECT count(*) FROM password_resets").await, 0);
    app.stop().await.unwrap();
}
