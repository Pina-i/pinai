use reqwest::Method;
use serde_json::Value;

use crate::helpers::{
    Account, PASSWORD, TestApp, admin_of, invite_only_with_admin, location, query_of,
    spawn_app_with,
};

const INVITEE: &str = "hoku@journey.test";

/// An invitation the admin creates: its link's token.
async fn an_invitation(app: &TestApp) -> String {
    let admin = admin_of(app).await;
    let (status, created) = app
        .send(Method::POST, &admin, "/api/admin/invitations", Value::Null)
        .await;
    assert_eq!(status, 201, "{created}");
    let link = created["link"].as_str().unwrap();
    link.strip_prefix(&format!("{}/i/", app.address))
        .unwrap_or_else(|| panic!("{link}"))
        .to_owned()
}

async fn page(app: &TestApp, path: &str) -> (reqwest::StatusCode, String) {
    let response = app
        .http
        .get(format!("{}{path}", app.address))
        .send()
        .await
        .unwrap();
    (response.status(), response.text().await.unwrap())
}

async fn join(app: &TestApp, token: &str, email: &str) -> reqwest::Response {
    app.http
        .post(format!("{}/i/{token}/sign-up", app.address))
        .form(&[
            ("display_name", "Hōkū"),
            ("email", email),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn someone_invited_lands_signed_in_in_the_web_app_and_is_never_mailed() {
    let app = spawn_app_with(invite_only_with_admin).await;
    let token = an_invitation(&app).await;

    let (status, invitation) = page(&app, &format!("/i/{token}")).await;
    let (form_status, form) = page(&app, &format!("/i/{token}/sign-up")).await;
    let joined = join(&app, &token, INVITEE).await;

    assert_eq!(status, 200, "{invitation}");
    assert!(
        invitation.contains("You've been invited by"),
        "{invitation}"
    );
    assert_eq!(form_status, 200);
    assert!(form.contains("Create your account"), "{form}");
    assert_eq!(joined.status(), 303);
    let web_app = app.client_id.strip_suffix("/oauth-client.json").unwrap();
    let encoded: String = url::form_urlencoded::byte_serialize(app.domain.as_bytes()).collect();
    assert_eq!(location(&joined), format!("{web_app}/?instance={encoded}"));
    let cookie = joined.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("idp_session="), "{cookie}");

    // The web app signs in as it always does: the browser's session answers at once.
    let mut request = vec![("response_type", "code".to_owned())];
    request.extend(app.the_request());
    let authorized = app
        .http
        .get(format!("{}/authorize", app.address))
        .query(&request)
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 303);
    let landed = location(&authorized);
    assert!(landed.starts_with(&app.redirect_uri), "{landed}");
    let tokens = app.tokens_for(&query_of(&landed)["code"]).await;
    let hoku = Account {
        email: INVITEE.into(),
        handle: String::new(),
        actor_uri: String::new(),
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        refresh_token: tokens["refresh_token"].as_str().unwrap().to_owned(),
        cookie,
    };
    let (status, userinfo) = app.get(&hoku, "/userinfo").await;
    assert_eq!(status, 200, "{userinfo}");
    assert_eq!(userinfo["email"], INVITEE);
    assert_eq!(userinfo["display_name"], "Hōkū");
    assert_eq!(userinfo["email_verified"], false);
    assert_eq!(app.mail.count_for(INVITEE), 0, "no code was mailed");
    assert_eq!(
        app.count(
            "SELECT count(*) FROM users u JOIN users a ON a.id = u.invited_by WHERE a.is_admin"
        )
        .await,
        1
    );

    // The same link, once more.
    let (again, refused) = page(&app, &format!("/i/{token}")).await;
    let rejoined = join(&app, &token, "keoni@journey.test").await;
    assert_eq!(again, 404);
    assert!(
        refused.contains("This invitation can no longer be used"),
        "{refused}"
    );
    assert_eq!(rejoined.status(), 404);
    assert_eq!(
        app.count("SELECT count(*) FROM users WHERE email = 'keoni@journey.test'")
            .await,
        0
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn without_a_web_app_someone_invited_is_told_to_sign_in_and_does_so_without_a_code() {
    let app = spawn_app_with(|config| {
        invite_only_with_admin(config);
        config.web_app = None;
    })
    .await;
    let token = an_invitation(&app).await;

    let joined = join(&app, &token, INVITEE).await;

    assert_eq!(joined.status(), 200);
    assert!(joined.headers().get("set-cookie").is_none());
    let ready = joined.text().await.unwrap();
    assert!(ready.contains("is ready."), "{ready}");
    assert!(ready.contains(INVITEE), "{ready}");
    let signed_in = app
        .form("/login", &[("email", INVITEE), ("password", PASSWORD)])
        .await;
    assert_eq!(signed_in.status(), 303);
    let landed = location(&signed_in);
    assert!(landed.starts_with(&app.redirect_uri), "{landed}");
    let tokens = app.tokens_for(&query_of(&landed)["code"]).await;
    assert!(tokens["access_token"].is_string(), "{tokens}");
    assert_eq!(app.mail.count_for(INVITEE), 0, "no code was mailed");
    app.stop().await.unwrap();
}

#[tokio::test]
async fn an_invite_only_instance_refuses_an_uninvited_sign_up_and_says_why() {
    let app = spawn_app_with(invite_only_with_admin).await;
    let typed = [
        ("display_name", "Hōkū"),
        ("email", INVITEE),
        ("password", PASSWORD),
    ];

    let form = app.form("/register-and-login", &typed).await;
    let json = app
        .http
        .post(format!("{}/register", app.address))
        .json(&serde_json::json!({
            "display_name": "Hōkū", "email": INVITEE, "password": PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    let (json_status, refusal) = (json.status(), json.json::<Value>().await.unwrap());

    assert_eq!(form.status(), 303);
    let back = location(&form);
    assert_eq!(query_of(&back)["error"], "invitation_required", "{back}");
    let (status, login) = page(&app, &back).await;
    assert_eq!(status, 200);
    for shown in [
        format!("Accounts on {} are by invitation only", app.domain),
        "invite only</span>".to_owned(),
    ] {
        assert!(login.contains(&shown), "{shown} not in {login}");
    }
    assert!(!login.contains("class=\"tabs\""), "{login}");
    assert!(!login.contains("Create account"), "{login}");
    assert_eq!(json_status, 403);
    assert_eq!(refusal["error"], "invitation_required");
    let (_, nodeinfo) = page(&app, "/nodeinfo/2.1").await;
    let nodeinfo: Value = serde_json::from_str(&nodeinfo).unwrap();
    assert_eq!(nodeinfo["openRegistrations"], false);
    assert_eq!(
        app.count(&format!(
            "SELECT count(*) FROM users WHERE email = '{INVITEE}'"
        ))
        .await,
        0
    );
    assert_eq!(app.mail.count_for(INVITEE), 0);
    app.stop().await.unwrap();
}
