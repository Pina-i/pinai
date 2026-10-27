use crate::helpers::{
    Account, PASSWORD, TestApp, closed_as_ended, location, open_socket, query_of, spawn_app,
};

const NEW_PASSWORD: &str = "a-new-journey-password";

/// "Forgot password?" on the login page, for `email`: the answer's status and page.
async fn forgot(app: &TestApp, email: &str) -> (reqwest::StatusCode, String) {
    let answered = app.form("/forgot-password", &[("email", email)]).await;
    (answered.status(), answered.text().await.unwrap())
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

async fn set_password(app: &TestApp, path: &str, password: &str) -> reqwest::Response {
    app.http
        .post(format!("{}{path}", app.address))
        .form(&[("password", password), ("confirmation", password)])
        .send()
        .await
        .unwrap()
}

/// Where the web app opens on `app`'s instance.
fn web_app_entry(app: &TestApp) -> String {
    let web_app = app.client_id.strip_suffix("/oauth-client.json").unwrap();
    let encoded: String = url::form_urlencoded::byte_serialize(app.domain.as_bytes()).collect();
    format!("{web_app}/?instance={encoded}")
}

#[tokio::test]
async fn someone_who_forgot_their_password_is_mailed_a_link_sets_a_new_one_and_signs_in_with_it() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let mut socket = open_socket(&app, &alice.token).await.unwrap();

    let (status, sent) = forgot(&app, &alice.email).await;
    let (unknown_status, unknown) = forgot(&app, "nobody@journey.test").await;
    let path = app.mail.reset_path_for(&alice.email).await;
    let (form_status, form) = page(&app, &path).await;
    let set = set_password(&app, &path, NEW_PASSWORD).await;

    assert_eq!(status, 200);
    assert!(sent.contains("Check your email"), "{sent}");
    assert!(
        sent.contains(&format!(
            "If <b>alice@journey.test</b> has an account on {}, a reset link is on its way.",
            app.domain
        )),
        "{sent}"
    );
    assert_eq!(unknown_status, 200);
    assert_eq!(
        sent.replace(&alice.email, "{address}"),
        unknown.replace("nobody@journey.test", "{address}"),
        "the same answer whatever the address"
    );
    assert_eq!(form_status, 200);
    assert!(form.contains("Choose a new password"), "{form}");
    assert!(
        form.contains(
            "For <span class=\"lead-address\">alice@journey.test</span>. This link works once."
        ),
        "{form}"
    );

    // Nobody signed in by the link: a forwarded one must not sign anyone into the account.
    assert_eq!(set.status(), 200);
    assert!(set.headers().get("set-cookie").is_none());
    let done = set.text().await.unwrap();
    for shown in [
        "Your password is changed.",
        "Sign in with it.",
        &format!("href=\"{}\"", web_app_entry(&app)),
    ] {
        assert!(done.contains(shown), "{shown}: {done}");
    }

    // Every session ended: the socket, the tokens and the refresh token of the old one.
    assert!(closed_as_ended(&mut socket).await, "closed with 1008");
    let (old_token, _) = app.get(&alice, "/userinfo").await;
    let (renewal, _) = app.refresh(&alice.refresh_token).await;
    assert_eq!([old_token.as_u16(), renewal.as_u16()], [401, 400]);
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE revoked_reason = 'password_reset'")
            .await,
        1
    );
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE revoked_at IS NULL")
            .await,
        0,
        "no session opened by the link"
    );

    // Signing in with the new password, as anyone does.
    let with_the_old = app
        .form("/login", &[("email", &alice.email), ("password", PASSWORD)])
        .await;
    let with_the_new = app
        .form(
            "/login",
            &[("email", &alice.email), ("password", NEW_PASSWORD)],
        )
        .await;
    assert_eq!(
        query_of(&location(&with_the_old))["error"],
        "invalid_credentials"
    );
    let landed = location(&with_the_new);
    assert!(landed.starts_with(&app.redirect_uri), "{landed}");
    let tokens = app.tokens_for(&query_of(&landed)["code"]).await;
    let signed_in = Account {
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        ..alice.clone()
    };
    let (status, userinfo) = app.get(&signed_in, "/userinfo").await;
    assert_eq!(status, 200, "{userinfo}");
    assert_eq!(userinfo["email"], "alice@journey.test");

    let (again, _) = page(&app, &path).await;
    assert_eq!(again, 404, "the link works once");
    assert_eq!(app.mail.count_for("nobody@journey.test"), 0);
    app.stop().await.unwrap();
}

#[tokio::test]
async fn with_a_second_factor_on_the_new_password_still_asks_the_code() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    app.execute(
        "UPDATE users SET totp_enabled = true, totp_secret = '\\x0707070707070707070707070707070707070707' \
         WHERE email = 'alice@journey.test'",
    )
    .await;

    let (status, _) = forgot(&app, &alice.email).await;
    let path = app.mail.reset_path_for(&alice.email).await;
    let set = set_password(&app, &path, NEW_PASSWORD).await;

    assert_eq!(status, 200);
    assert_eq!(set.status(), 200);
    assert!(
        set.headers().get("set-cookie").is_none(),
        "nobody signed in"
    );
    let done = set.text().await.unwrap();
    assert!(done.contains("Sign in with it."), "{done}");
    let (old_token, _) = app.get(&alice, "/userinfo").await;
    assert_eq!(old_token, 401, "every session ended");
    let with_the_new = app
        .form(
            "/login",
            &[("email", &alice.email), ("password", NEW_PASSWORD)],
        )
        .await;
    assert!(
        location(&with_the_new).starts_with("/login/totp?ticket="),
        "the authenticator's code is asked next"
    );
    app.stop().await.unwrap();
}
