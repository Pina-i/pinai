use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use domain::auth::testing::{CHALLENGE, CLIENT_ID, REDIRECT_URI, SignInSeeds, signed_up};
use domain::auth::{
    ClientSignIn, INVITATION_TTL, InvitationToken, Invitations, SignInAccount, SignInAccounts,
};
use time::{Duration, OffsetDateTime};

use crate::testing::{TestApp, assert_page};

/// The instance's admin, signed up.
async fn an_admin(app: &TestApp) -> SignInAccount {
    let admin = SignInAccount {
        admin: true,
        display_name: Some("Kahu".to_owned()),
        ..signed_up("kahu")
    };
    app.sign_in.accounts.sign_up(&admin).await;
    admin
}

/// An open invitation of the instance's admin.
async fn invited(app: &TestApp) -> InvitationToken {
    let admin = an_admin(app).await;
    let now = OffsetDateTime::now_utc();
    app.sign_in
        .accounts
        .issue(admin.id, now, now + INVITATION_TTL)
        .await
        .unwrap()
        .1
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().method(Method::GET).uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::empty()).unwrap()
}

fn sign_up(token: &str, display_name: &str, email: &str, password: &str) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("display_name", display_name),
            ("email", email),
            ("password", password),
        ])
        .finish();
    Request::builder()
        .method(Method::POST)
        .uri(format!("/i/{token}/sign-up"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn hoku(token: &InvitationToken) -> Request<Body> {
    sign_up(token.as_str(), "Hōkū", "hoku@idp.test", "hoku-password")
}

/// A page whose URL carries a token: never cached, never sent on as a `Referer`.
fn assert_unreferred(response: &Response) {
    assert_page(response, "no-referrer");
}

/// The form's page: its `Referer` goes nowhere but this instance, so the form posts its `Origin`.
fn assert_kept_here(response: &Response) {
    assert_page(response, "same-origin");
}

#[tokio::test]
async fn an_open_invitation_opens_its_doorway_and_leads_to_its_form() {
    let app = TestApp::with([], []);
    let token = invited(&app).await;

    let response = app
        .respond(get(&format!("/i/{}", token.as_str()), None))
        .await;

    assert_unreferred(&response);
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    for shown in [
        r#"<div class="door-ini" aria-hidden="true">A</div>"#,
        r#"<main class="door-body auth-rise">"#,
        "Self-hosted · Federated · Open-source",
        "— localhost:8080",
        r#"You've been invited by <em class="door-by">Kahu</em> to join <em class="door-to">Aotearoa</em>."#,
        "Design and type people. This link lets one person create an account and expires in 7 days.",
        &format!(r#"href="/i/{}/sign-up""#, token.as_str()),
        "Only the admins of localhost:8080 make invitations",
        r#"<a href="https://codeberg.org/aotearoa/pinai" target="_blank" rel="noopener">↳ Source</a>"#,
    ] {
        assert!(page.contains(shown), "{shown}: {page}");
    }
    assert!(!page.contains("<form"), "{page}");
}

#[tokio::test]
async fn an_inviter_is_named_by_their_display_name_only() {
    let app = TestApp::with([], []);
    let nameless = SignInAccount {
        admin: true,
        display_name: None,
        ..signed_up("kahu")
    };
    app.sign_in.accounts.sign_up(&nameless).await;
    let now = OffsetDateTime::now_utc();
    let (_, token) = app
        .sign_in
        .accounts
        .issue(nameless.id, now, now + INVITATION_TTL)
        .await
        .unwrap();

    for uri in [
        format!("/i/{}", token.as_str()),
        format!("/i/{}/sign-up", token.as_str()),
    ] {
        let (_, page) = TestApp::html_of(app.respond(get(&uri, None)).await).await;
        assert!(!page.contains(&nameless.username), "{page}");
        assert!(!page.contains(&nameless.email), "{page}");
        assert!(!page.contains("Invited by"), "{page}");
    }
    let (_, door) = TestApp::html_of(
        app.respond(get(&format!("/i/{}", token.as_str()), None))
            .await,
    )
    .await;
    assert!(
        door.contains(r#"You've been invited to join <em class="door-to">Aotearoa</em>."#),
        "{door}"
    );
}

#[tokio::test]
async fn an_invitation_unknown_used_revoked_or_expired_gets_one_answer() {
    let app = TestApp::with([], []);
    let admin = an_admin(&app).await;
    let now = OffsetDateTime::now_utc();
    let (_, used) = app
        .sign_in
        .accounts
        .issue(admin.id, now, now + INVITATION_TTL)
        .await
        .unwrap();
    app.respond(hoku(&used)).await;
    let (revoked_id, revoked) = app
        .sign_in
        .accounts
        .issue(admin.id, now, now + INVITATION_TTL)
        .await
        .unwrap();
    app.sign_in.accounts.revoke(revoked_id, now).await.unwrap();
    let (_, expired) = app
        .sign_in
        .accounts
        .issue(admin.id, now - Duration::days(8), now - Duration::days(1))
        .await
        .unwrap();

    for token in [
        used.as_str(),
        revoked.as_str(),
        expired.as_str(),
        InvitationToken::from_bytes([5; 32]).as_str(),
        "not-a-token",
    ] {
        for uri in [format!("/i/{token}"), format!("/i/{token}/sign-up")] {
            let response = app.respond(get(&uri, None)).await;
            assert_unreferred(&response);
            let (status, page) = TestApp::html_of(response).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(
                page.contains("This invitation can no longer be used"),
                "{page}"
            );
            assert!(
                page.contains("Ask the person who sent it for a new one."),
                "{page}"
            );
            assert!(!page.contains("<form"), "{page}");
        }
    }
}

#[tokio::test]
async fn every_page_of_an_invitation_wears_tapa_2() {
    let app = TestApp::without_web_app();
    let token = invited(&app).await;
    let unknown = InvitationToken::from_bytes([5; 32]);

    let pages = [
        app.respond(get(&format!("/i/{}", token.as_str()), None))
            .await,
        app.respond(get(&format!("/i/{}/sign-up", token.as_str()), None))
            .await,
        app.respond(hoku(&token)).await,
        app.respond(get(&format!("/i/{}", unknown.as_str()), None))
            .await,
    ];

    for response in pages {
        let (_, page) = TestApp::html_of(response).await;
        assert!(
            page.contains(r#"data-theme="pearl-dark" data-motif="tapa2""#),
            "{page}"
        );
    }
}

#[tokio::test]
async fn the_form_page_shows_the_instance_who_invited_and_where_to_sign_in_instead() {
    let app = TestApp::with([], []);
    let token = invited(&app).await;

    let response = app
        .respond(get(&format!("/i/{}/sign-up", token.as_str()), None))
        .await;

    assert_kept_here(&response);
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        policy.contains("form-action 'self' http://localhost:5173;"),
        "the answer's redirect to the web app is let through: {policy}"
    );
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    let (aside, column) = page.split_at(page.find("<main").unwrap());
    for shown in [
        r#"<span class="inst-ini">A</span><span class="brand-name">Aotearoa</span>"#,
        "Design and type people.",
        r#"<span class="inv-av">K</span><span class="invited-by">Invited by <span class="invited-name">Kahu</span></span>"#,
    ] {
        assert!(aside.contains(shown), "{shown}: {aside}");
    }
    for shown in [
        "— localhost:8080",
        &format!(
            r#"href="/i/{}">← Back to the invitation</a>"#,
            token.as_str()
        ),
        "Create your account",
        &format!(r#"method="post" action="/i/{}/sign-up""#, token.as_str()),
        r#"name="display_name""#,
        r#"name="email""#,
        r#"name="password""#,
        "Create account",
        "Your password goes to localhost:8080, never to Pīna'i",
        r#"Already have an account on localhost:8080? <a class="tlink" href="http://localhost:5173/?instance=localhost%3A8080">Sign in instead</a>"#,
    ] {
        assert!(column.contains(shown), "{shown}: {column}");
    }
    assert!(
        !column.contains("tab"),
        "no Sign in / Register tabs: {column}"
    );
}

#[tokio::test]
async fn joining_lands_signed_in_in_the_web_app_with_nothing_mailed() {
    let app = TestApp::with([], []);
    let token = invited(&app).await;

    let response = app.respond(hoku(&token)).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost:5173/?instance=localhost%3A8080"
    );
    assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("idp_session="), "{cookie}");
    let account = app
        .sign_in
        .accounts
        .by_email(&domain::auth::Email::parse("hoku@idp.test").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(account.admitted && !account.email_verified);
    assert_eq!(
        app.sign_in.sign_ins.remembered(),
        vec![ClientSignIn {
            user: account.id,
            client: domain::auth::testing::web_client().id,
            offline_access: false,
        }]
    );
    assert!(app.sign_in.mailer.sent().is_empty());
}

#[tokio::test]
async fn the_web_app_then_gets_a_code_without_the_login_page() {
    let app = TestApp::with([], []);
    let token = invited(&app).await;
    let joined = app.respond(hoku(&token)).await;
    let cookie = joined.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid profile email"),
            ("state", "the-clients-state"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .finish();

    let authorized = app
        .respond(get(&format!("/authorize?{query}"), Some(&cookie)))
        .await;

    assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
    let location = authorized.headers()[header::LOCATION].to_str().unwrap();
    assert!(
        location.starts_with(&format!("{REDIRECT_URI}?code=")),
        "{location}"
    );
}

#[tokio::test]
async fn without_a_web_app_joining_ends_on_a_page_saying_where_to_sign_in() {
    let app = TestApp::without_web_app();
    let token = invited(&app).await;

    let form = app
        .respond(get(&format!("/i/{}/sign-up", token.as_str()), None))
        .await;
    let response = app.respond(hoku(&token)).await;

    let (_, form) = TestApp::html_of(form).await;
    assert!(form.contains("Create account"), "{form}");
    assert!(!form.contains("Sign in instead"), "{form}");
    assert_unreferred(&response);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("Your account on Aotearoa is ready."),
        "{page}"
    );
    assert!(
        page.contains("Open the Pīna'i app and sign in with"),
        "{page}"
    );
    assert!(page.contains("hoku@idp.test"), "{page}");
    assert!(app.sign_in.sessions.all().is_empty());
    assert!(app.sign_in.mailer.sent().is_empty());
}

#[tokio::test]
async fn a_broken_rule_or_a_taken_address_shows_the_form_again_with_what_was_typed() {
    let app = TestApp::with([], []);
    let token = invited(&app).await;
    app.sign_in.accounts.sign_up(&signed_up("alice")).await;

    let short_name = app
        .respond(sign_up(
            token.as_str(),
            &"n".repeat(51),
            "hoku@idp.test",
            "hoku-password",
        ))
        .await;
    let taken = app
        .respond(sign_up(
            token.as_str(),
            "Hōkū",
            "alice@idp.test",
            "hoku-password",
        ))
        .await;

    assert_kept_here(&short_name);
    let (status, page) = TestApp::html_of(short_name).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("Display name: 1–50 characters"), "{page}");
    assert!(page.contains(r#"value="hoku@idp.test""#), "{page}");
    assert!(!page.contains("hoku-password"), "{page}");
    let (status, page) = TestApp::html_of(taken).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("Email already registered"), "{page}");
    assert!(page.contains(r#"value="Hōkū""#), "{page}");
    assert!(
        app.sign_in
            .accounts
            .find_open(&token, OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some(),
        "still open"
    );
}

#[tokio::test]
async fn an_invitation_used_already_lets_nobody_else_in() {
    let app = TestApp::with([], []);
    let token = invited(&app).await;
    app.respond(hoku(&token)).await;

    let again = app
        .respond(sign_up(
            token.as_str(),
            "Keoni",
            "keoni@idp.test",
            "keoni-password",
        ))
        .await;

    let (status, page) = TestApp::html_of(again).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        page.contains("This invitation can no longer be used"),
        "{page}"
    );
    assert_eq!(app.sign_in.accounts.created().len(), 1);
}

#[tokio::test]
async fn the_form_posted_from_another_site_is_refused() {
    let app = TestApp::with([], []);
    let token = invited(&app).await;
    let from = |pairs: &[(&str, &str)]| {
        let mut request = hoku(&token);
        for (name, value) in pairs {
            request.headers_mut().insert(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        request
    };

    let elsewhere = app.respond(from(&[("origin", "https://evil.test")])).await;
    let cross_site = app.respond(from(&[("sec-fetch-site", "cross-site")])).await;
    // What a browser sends from the form's own page.
    let ours = app
        .respond(from(&[("origin", "http://localhost:8080")]))
        .await;

    assert_eq!(elsewhere.status(), StatusCode::FORBIDDEN);
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert_eq!(ours.status(), StatusCode::SEE_OTHER);
    assert_eq!(app.sign_in.accounts.created().len(), 1);
}
