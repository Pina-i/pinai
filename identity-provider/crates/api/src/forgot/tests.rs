use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use domain::auth::testing::{CHALLENGE, CLIENT_ID, REDIRECT_URI, SignInSeeds, signed_up};
use domain::auth::{RESET_REQUEST_LIMIT, SignInAccount};

use crate::testing::{TestApp, assert_page};

fn query(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn the_request() -> Vec<(&'static str, &'static str)> {
    vec![
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid profile email"),
        ("state", "the-clients-state"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("nonce", "the-nonce"),
    ]
}

fn get(path: &str, extra: &[(&str, &str)]) -> Request<Body> {
    let mut pairs = the_request();
    pairs.extend_from_slice(extra);
    Request::builder()
        .method(Method::GET)
        .uri(format!("{path}?{}", query(&pairs)))
        .body(Body::empty())
        .unwrap()
}

fn posted(pairs: &[(&str, &str)]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/forgot-password")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(query(pairs)))
        .unwrap()
}

/// The reset request for `email`, with the sign-in it was opened for.
fn forgot(email: &str) -> Request<Body> {
    let mut pairs = the_request();
    pairs.push(("email", email));
    posted(&pairs)
}

/// Every URL a page links or posts to.
fn urls_of(page: &str) -> Vec<&str> {
    ["href=\"", "action=\""]
        .into_iter()
        .flat_map(|attribute| page.split(attribute).skip(1))
        .map(|rest| rest.split('"').next().unwrap())
        .collect()
}

/// The account still to confirm its address, and the instance with alice and it.
async fn app_with_alice_and_bob() -> (TestApp, SignInAccount, SignInAccount) {
    let app = TestApp::with([], []);
    let (alice, bob) = (
        signed_up("alice"),
        SignInAccount {
            email_verified: false,
            ..signed_up("bob")
        },
    );
    app.sign_in.accounts.sign_up(&alice).await;
    app.sign_in.accounts.sign_up(&bob).await;
    (app, alice, bob)
}

fn mailed_to(app: &TestApp) -> Vec<String> {
    app.sign_in
        .mailer
        .reset_mails()
        .into_iter()
        .map(|mail| mail.to)
        .collect()
}

#[tokio::test]
async fn an_open_instances_sign_in_tab_links_forgot_password_beside_the_password_label() {
    let app = TestApp::with([], []);

    let (status, page) = TestApp::html_of(app.respond(get("/login", &[])).await).await;

    assert_eq!(status, StatusCode::OK);
    for shown in [
        r#"data-view="sign-in""#,
        r#"<div class="lrow"><label class="eye" for="password">Password</label><a class="forgot" href="/forgot-password?client_id="#,
        r#"data-to="forgot">Forgot password?</a>"#,
        r#"action="/login" data-sign-in="/login" data-forgot="/forgot-password""#,
        r#"<span class="btn-label only-sign-in">Sign in</span>"#,
        r#"data-sign-in-title="Sign in · Aotearoa" data-forgot-title="Reset your password · Aotearoa""#,
        r#"<a class="back only-sign-in" href="http://localhost:5173/callback?error=access_denied"#,
    ] {
        assert!(page.contains(shown), "{shown}: {page}");
    }
    assert!(!page.contains(" disabled"), "{page}");
}

#[tokio::test]
async fn the_forgot_page_opens_on_the_reset_request_without_script() {
    let app = TestApp::with([], []);

    let response = app
        .respond(get("/forgot-password", &[("theme", "lagoon-light")]))
        .await;

    assert_page(&response, "same-origin");
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    let column = &page[page.find("<main").unwrap()..];
    for shown in [
        r#"data-view="forgot""#,
        r#"<span class="only-forgot">Reset your password</span>"#,
        r#"<a class="back only-forgot" href="/login?client_id="#,
        "data-to=\"sign-in\">← Sign in</a>",
        r#"action="/forgot-password" data-sign-in="/login""#,
        r#"autocomplete="current-password" required disabled>"#,
        r#"<span class="btn-label only-forgot">Send reset link"#,
        "Aotearoa will email a link to choose a new password. It works once, for 30 minutes.",
        "localhost:8080 sends the link. Pīna'i never sees your email.",
        r#"<input type="hidden" name="state" value="the-clients-state">"#,
        r#"<input type="hidden" name="theme" value="lagoon-light">"#,
    ] {
        assert!(column.contains(shown), "{shown}: {column}");
    }
    assert!(page.contains("<title>Reset your password · Aotearoa</title>"));
    assert!(page.contains(r#"data-theme="lagoon-light""#));
}

#[tokio::test]
async fn the_register_tab_links_no_forgotten_password() {
    let app = TestApp::with([], []);

    let (_, page) =
        TestApp::html_of(app.respond(get("/login", &[("tab", "register")])).await).await;

    assert!(page.contains("action=\"/register-and-login\""), "{page}");
    assert!(!page.contains("Forgot password?"), "{page}");
    assert!(!page.contains("data-view"), "{page}");
}

#[tokio::test]
async fn an_invite_only_instance_has_no_forgot_link_no_page_and_no_request() {
    let app = TestApp::invite_only();
    let alice = signed_up("alice");
    app.sign_in.accounts.sign_up(&alice).await;

    let (_, login) = TestApp::html_of(app.respond(get("/login", &[])).await).await;
    let page = app.respond(get("/forgot-password", &[])).await;
    let request = app.respond(forgot(&alice.email)).await;
    app.serve_reset_requests().await;

    assert!(!login.contains("Forgot password?"), "{login}");
    assert!(!login.contains("data-view"), "{login}");
    assert!(
        login.contains("Your password goes to localhost:8080, never to Pīna"),
        "{login}"
    );
    for response in [page, request] {
        assert_page(&response, "same-origin");
        let (status, said) = TestApp::html_of(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        for shown in [
            "No password reset by mail here",
            "Ask an admin of localhost:8080 for a reset link.",
        ] {
            assert!(said.contains(shown), "{shown}: {said}");
        }
    }
    assert!(mailed_to(&app).is_empty());
}

#[tokio::test]
async fn the_answer_says_a_link_is_on_its_way_in_this_page_only() {
    let (app, alice, _) = app_with_alice_and_bob().await;

    let response = app.respond(forgot(&alice.email)).await;

    assert!(response.headers().get(header::LOCATION).is_none());
    assert_page(&response, "same-origin");
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    let column = &page[page.find("<main").unwrap()..];
    for shown in [
        r#"<h2 class="auth-title">Check your email</h2>"#,
        "If <b>alice@idp.test</b> has an account on localhost:8080, a reset link is on its way. \
         It works once and expires in 30 minutes.",
        r#"<form class="resend" method="post" action="/forgot-password">"#,
        r#"<input type="hidden" name="email" value="alice@idp.test">"#,
        r#"<input type="hidden" name="again" value="1">"#,
        r#"<input type="hidden" name="state" value="the-clients-state">"#,
        r#"Nothing yet? Check spam, or <button class="tlink" type="submit">send it again</button>."#,
        r#"<a class="back" href="/login?client_id="#,
        "← Back to sign in</a>",
    ] {
        assert!(column.contains(shown), "{shown}: {column}");
    }
    for url in urls_of(&page) {
        assert!(!url.contains("alice"), "{url}");
    }
    app.serve_reset_requests().await;
    assert_eq!(mailed_to(&app), vec![alice.email]);
}

#[tokio::test]
async fn every_address_gets_the_same_answer_and_only_one_that_may_get_a_link_is_mailed() {
    let (app, alice, bob) = app_with_alice_and_bob().await;
    let carol = signed_up("carol");
    app.sign_in.accounts.sign_up(&carol).await;
    for _ in 0..RESET_REQUEST_LIMIT {
        app.respond(forgot(&carol.email)).await;
    }
    app.serve_reset_requests().await;
    let before = mailed_to(&app).len();

    let mut answers = Vec::new();
    for address in [
        alice.email.as_str(),
        "nobody@idp.test",
        bob.email.as_str(),
        carol.email.as_str(),
    ] {
        let response = app.respond(forgot(address)).await;
        let headers = response.headers().clone();
        let (status, page) = TestApp::html_of(response).await;
        answers.push((status, headers.len(), page.replace(address, "{address}")));
    }
    app.serve_reset_requests().await;

    assert_eq!(before, RESET_REQUEST_LIMIT);
    let (first, rest) = answers.split_first().unwrap();
    assert_eq!(first.0, StatusCode::OK);
    for answer in rest {
        assert_eq!(answer, first, "the same answer whatever the address");
    }
    let mailed = mailed_to(&app);
    assert_eq!(mailed.len(), before + 1, "{mailed:?}");
    assert_eq!(mailed.last(), Some(&alice.email));
}

#[tokio::test]
async fn a_request_from_another_site_is_refused_and_nothing_is_mailed() {
    let (app, alice, _) = app_with_alice_and_bob().await;
    let from = |name: &str, value: &str| {
        let mut request = forgot(&alice.email);
        request.headers_mut().insert(
            header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        request
    };

    let elsewhere = app.respond(from("origin", "https://evil.test")).await;
    let cross_site = app.respond(from("sec-fetch-site", "cross-site")).await;
    app.serve_reset_requests().await;

    assert_eq!(elsewhere.status(), StatusCode::FORBIDDEN);
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert!(mailed_to(&app).is_empty());
    let ours = app.respond(from("origin", "http://localhost:8080")).await;
    assert_eq!(ours.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_request_with_no_sign_in_left_is_told_it_expired_and_mails_nothing() {
    let (app, alice, _) = app_with_alice_and_bob().await;

    let response = app.respond(posted(&[("email", &alice.email)])).await;
    app.serve_reset_requests().await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/login");
    assert!(mailed_to(&app).is_empty());
}

#[tokio::test]
async fn a_request_for_a_client_that_cant_be_verified_is_answered_with_that() {
    let (app, alice, _) = app_with_alice_and_bob().await;
    let mut pairs: Vec<(&str, &str)> = the_request()
        .into_iter()
        .filter(|(name, _)| *name != "client_id")
        .collect();
    pairs.push(("client_id", "http://localhost:5173/x.json"));
    pairs.push(("email", &alice.email));

    let (status, page) = TestApp::html_of(app.respond(posted(&pairs)).await).await;
    app.serve_reset_requests().await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(page.contains("This app couldn&#39;t be verified"), "{page}");
    assert!(mailed_to(&app).is_empty());
}

#[tokio::test]
async fn what_is_no_address_shows_the_request_again_saying_why() {
    let (app, _, _) = app_with_alice_and_bob().await;

    let response = app.respond(forgot("alice")).await;
    app.serve_reset_requests().await;

    assert_page(&response, "same-origin");
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for shown in [
        r#"data-view="forgot""#,
        r#"<p class="alert only-forgot" role="alert">Enter a valid email address</p>"#,
        r#"<span class="field field--err">"#,
        r#"name="email" type="email" value="alice""#,
        r#"action="/forgot-password""#,
    ] {
        assert!(page.contains(shown), "{shown}: {page}");
    }
    for url in urls_of(&page) {
        assert!(!url.contains("email="), "{url}");
    }
    assert!(mailed_to(&app).is_empty());
}

#[tokio::test]
async fn an_alert_of_the_sign_in_tab_folds_away_with_it() {
    let app = TestApp::with([], []);

    let (_, page) = TestApp::html_of(
        app.respond(get("/login", &[("error", "invalid_credentials")]))
            .await,
    )
    .await;

    assert!(
        page.contains(
            r#"<p class="alert only-sign-in" role="alert">Invalid email or password</p>"#
        ),
        "{page}"
    );
}

#[tokio::test]
async fn send_it_again_opens_the_request_once_more_with_the_address_and_sends_nothing() {
    let (app, alice, _) = app_with_alice_and_bob().await;
    let mut pairs = the_request();
    pairs.extend([("email", alice.email.as_str()), ("again", "1")]);

    let response = app.respond(posted(&pairs)).await;
    app.serve_reset_requests().await;

    assert!(response.headers().get(header::LOCATION).is_none());
    assert_page(&response, "same-origin");
    let (status, page) = TestApp::html_of(response).await;
    assert_eq!(status, StatusCode::OK);
    for shown in [
        r#"data-view="forgot""#,
        r#"name="email" type="email" value="alice@idp.test""#,
        r#"action="/forgot-password""#,
    ] {
        assert!(page.contains(shown), "{shown}: {page}");
    }
    assert!(!page.contains("role=\"alert\""), "{page}");
    for url in urls_of(&page) {
        assert!(!url.contains("alice"), "{url}");
    }
    assert!(mailed_to(&app).is_empty(), "nothing sent until asked again");
}

fn location(response: &Response) -> &str {
    response.headers()[header::LOCATION].to_str().unwrap()
}
