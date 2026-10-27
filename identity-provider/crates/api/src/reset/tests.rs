use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::auth::testing::{PlainHasher, SignInSeeds, signed_up};
use domain::auth::{
    PasswordResets, RESET_TTL, ResetToken, RevokedReason, SignInAccount, SignInAccounts,
};
use time::{Duration, OffsetDateTime};

use crate::testing::{TestApp, assert_page};

const NEW: &str = "a-new-password";

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

/// `name`, signed up, and a link the instance's admin made for them at `at`, open until
/// `at + RESET_TTL`.
async fn a_link_for(
    app: &TestApp,
    admin: &SignInAccount,
    name: &str,
    at: OffsetDateTime,
) -> (SignInAccount, ResetToken) {
    let member = signed_up(name);
    app.sign_in.accounts.sign_up(&member).await;
    let token = app
        .sign_in
        .resets
        .issue(member.id, admin.id, at, at + RESET_TTL)
        .await
        .unwrap();
    (member, token)
}

/// Alice — "Alice Kealoha" — and an open link for her.
async fn alices_link(app: &TestApp) -> (SignInAccount, ResetToken) {
    let admin = an_admin(app).await;
    let alice = SignInAccount {
        display_name: Some("Alice Kealoha".to_owned()),
        ..signed_up("alice")
    };
    app.sign_in.accounts.sign_up(&alice).await;
    let now = OffsetDateTime::now_utc();
    let token = app
        .sign_in
        .resets
        .issue(alice.id, admin.id, now, now + RESET_TTL)
        .await
        .unwrap();
    (alice, token)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn post(token: &str, password: &str, confirmation: &str) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("password", password), ("confirmation", confirmation)])
        .finish();
    Request::builder()
        .method(Method::POST)
        .uri(format!("/r/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

async fn password_of(app: &TestApp, account: &SignInAccount) -> domain::auth::PasswordHash {
    app.sign_in
        .accounts
        .by_id(account.id)
        .await
        .unwrap()
        .unwrap()
        .password_hash
}

#[tokio::test]
async fn an_open_link_shows_the_form_for_its_member_beside_the_instance() {
    let app = TestApp::with([], []);
    let (alice, token) = alices_link(&app).await;

    let response = app.respond(get(&format!("/r/{}", token.as_str()))).await;

    // Its form posts its `Origin`, and the token stays on the instance.
    assert_page(&response, "same-origin");
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    let (aside, column) = page.split_at(page.find("<main").unwrap());
    for shown in ["Aotearoa", "Design and type people."] {
        assert!(aside.contains(shown), "{shown}: {aside}");
    }
    for shown in [
        "— localhost:8080",
        r#"<h2 class="auth-title">Set a new password</h2>"#,
        r#"<p class="for">for <span class="for-name">Alice Kealoha</span></p>"#,
        &format!(r#"method="post" action="/r/{}""#, token.as_str()),
        r#"<input id="password" name="password" type="password" placeholder="••••••••••" autocomplete="new-password" minlength="8" required autofocus>"#,
        r#"<input id="confirmation" name="confirmation" type="password" placeholder="••••••••••" autocomplete="new-password" minlength="8" required>"#,
        "Your password goes to localhost:8080, never to Pīna'i",
    ] {
        assert!(column.contains(shown), "{shown}: {column}");
    }
    assert!(page.contains("<title>Set a new password · Aotearoa</title>"));
    for hidden in [&alice.email, &alice.username] {
        assert!(!page.contains(hidden.as_str()), "{hidden}");
    }
}

#[tokio::test]
async fn a_link_unknown_used_replaced_or_expired_gets_one_answer() {
    let app = TestApp::with([], []);
    let admin = an_admin(&app).await;
    let now = OffsetDateTime::now_utc();
    let (_, used) = a_link_for(&app, &admin, "alice", now).await;
    app.respond(post(used.as_str(), NEW, NEW)).await;
    let (bob, replaced) = a_link_for(&app, &admin, "bob", now).await;
    app.sign_in
        .resets
        .issue(bob.id, admin.id, now, now + RESET_TTL)
        .await
        .unwrap();
    let (_, expired) = a_link_for(&app, &admin, "carol", now - Duration::days(2)).await;

    for token in [
        used.as_str(),
        replaced.as_str(),
        expired.as_str(),
        ResetToken::from_bytes([5; 32]).as_str(),
        "not-a-token",
    ] {
        for request in [get(&format!("/r/{token}")), post(token, NEW, NEW)] {
            let response = app.respond(request).await;
            assert_page(&response, "no-referrer");
            let (status, page) = TestApp::html_of(response).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{token}");
            assert!(page.contains("This link can no longer be used"), "{page}");
            assert!(
                page.contains("Ask an admin of localhost:8080 for a new one."),
                "{page}"
            );
            assert!(!page.contains("<form"), "{page}");
        }
    }
    assert_eq!(password_of(&app, &bob).await, bob.password_hash);
}

#[tokio::test]
async fn setting_the_password_signs_the_member_out_everywhere_and_points_to_the_web_app() {
    let app = TestApp::with([], []);
    let (alice, token) = alices_link(&app).await;
    let session = app.sign_in.sessions.live(alice.id);

    let response = app.respond(post(token.as_str(), NEW, NEW)).await;

    assert_page(&response, "no-referrer");
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    for shown in [
        "Your password is changed.",
        "Sign in again from the Pīna'i app.",
        r#"href="http://localhost:5173/?instance=localhost%3A8080""#,
    ] {
        assert!(page.contains(shown), "{shown}: {page}");
    }
    assert!(!page.contains(NEW), "{page}");
    assert_eq!(password_of(&app, &alice).await, PlainHasher::hash(NEW));
    assert_eq!(
        app.sign_in.sessions.reason(session),
        Some(RevokedReason::PasswordReset)
    );
    assert_eq!(
        app.sign_in.ended.ended(),
        vec![session],
        "its sockets close"
    );
}

#[tokio::test]
async fn without_a_web_app_the_page_says_to_sign_in_from_the_app() {
    let app = TestApp::without_web_app();
    let (_, token) = alices_link(&app).await;

    let response = app.respond(post(token.as_str(), NEW, NEW)).await;

    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("Sign in again from the Pīna'i app."),
        "{page}"
    );
    assert!(!page.contains("localhost:5173"), "{page}");
}

#[tokio::test]
async fn a_short_or_mismatched_password_shows_the_form_again_without_echoing_it() {
    let app = TestApp::with([], []);
    let (alice, token) = alices_link(&app).await;
    let session = app.sign_in.sessions.live(alice.id);

    let short = app.respond(post(token.as_str(), "short", "short")).await;
    let mismatched = app
        .respond(post(token.as_str(), NEW, "another-password"))
        .await;

    for (response, said, field) in [
        (short, "Password must be at least 8 characters", "password"),
        (mismatched, "The two passwords differ", "confirmation"),
    ] {
        assert_page(&response, "same-origin");
        let (status, page) = TestApp::html_of(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(page.contains(said), "{said}: {page}");
        let wrong = &page[page.find("field--err").expect("a field marked")..];
        assert!(
            wrong
                .split(r#"<input id=""#)
                .nth(1)
                .is_some_and(|input| input.starts_with(field)),
            "{field}: {wrong}"
        );
        assert!(page.contains("Alice Kealoha"), "{page}");
        for typed in ["short\"", NEW, "another-password", "value="] {
            assert!(!page.contains(typed), "{typed}: {page}");
        }
    }
    assert_eq!(password_of(&app, &alice).await, alice.password_hash);
    assert!(
        app.sign_in
            .resets
            .find_open(&token, OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some(),
        "still open"
    );
    assert_eq!(app.sign_in.sessions.reason(session), None);
}

#[tokio::test]
async fn a_second_submission_of_a_link_gets_the_page_saying_it_can_no_longer_be_used() {
    let app = TestApp::with([], []);
    let (alice, token) = alices_link(&app).await;

    let first = app.respond(post(token.as_str(), NEW, NEW)).await;
    let second = app
        .respond(post(token.as_str(), "another-password", "another-password"))
        .await;

    assert_eq!(first.status(), StatusCode::OK);
    let (status, page) = TestApp::html_of(second).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("This link can no longer be used"), "{page}");
    assert_eq!(password_of(&app, &alice).await, PlainHasher::hash(NEW));
}

#[tokio::test]
async fn the_form_posted_from_another_site_is_refused() {
    let app = TestApp::with([], []);
    let (alice, token) = alices_link(&app).await;
    let from = |password: &str, pairs: &[(&str, &str)]| {
        let mut request = post(token.as_str(), password, password);
        for (name, value) in pairs {
            request.headers_mut().insert(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        request
    };

    let elsewhere = app
        .respond(from("evil-password", &[("origin", "https://evil.test")]))
        .await;
    let cross_site = app
        .respond(from("evil-password", &[("sec-fetch-site", "cross-site")]))
        .await;
    // What a browser sends from the form's own page.
    let ours = app
        .respond(from(NEW, &[("origin", "http://localhost:8080")]))
        .await;

    assert_eq!(elsewhere.status(), StatusCode::FORBIDDEN);
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert_eq!(ours.status(), StatusCode::OK);
    assert_eq!(password_of(&app, &alice).await, PlainHasher::hash(NEW));
}
