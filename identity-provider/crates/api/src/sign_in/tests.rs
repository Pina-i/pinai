use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use domain::auth::SignInAccount;
use domain::auth::testing::{CHALLENGE, REDIRECT_URI, SignInSeeds, VERIFIER, signed_up};
use serde_json::json;

use crate::testing::TestApp;

async fn app_with(accounts: &[SignInAccount]) -> TestApp {
    let app = TestApp::with([], []);
    for account in accounts {
        app.sign_in.accounts.sign_up(account).await;
    }
    app
}

fn query(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn the_request() -> Vec<(&'static str, &'static str)> {
    vec![
        ("client_id", "web-client"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid profile email"),
        ("state", "the-clients-state"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("nonce", "the-nonce"),
    ]
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().method(Method::GET).uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::empty()).unwrap()
}

fn post_form(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(query(pairs)))
        .unwrap()
}

fn authorize_uri(extra: &[(&str, &str)]) -> String {
    let mut pairs = vec![("response_type", "code")];
    pairs.extend(the_request());
    pairs.extend_from_slice(extra);
    format!("/authorize?{}", query(&pairs))
}

fn login(email: &str, password: &str) -> Request<Body> {
    let mut pairs = vec![("email", email), ("password", password)];
    pairs.extend(the_request());
    post_form("/login", &pairs)
}

fn location(response: &Response) -> &str {
    response.headers()[header::LOCATION].to_str().unwrap()
}

fn set_cookie(response: &Response) -> &str {
    response.headers()[header::SET_COOKIE].to_str().unwrap()
}

const CARRIED: &str = "client_id=web-client&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback\
    &scope=openid%20profile%20email&state=the-clients-state\
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

#[tokio::test]
async fn a_browser_without_a_session_is_sent_to_the_login_page_carrying_the_request() {
    let app = app_with(&[]).await;

    let response = app.respond(get(&authorize_uri(&[]), None)).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("http://localhost:5173/login?{CARRIED}&nonce=the-nonce")
    );
}

#[tokio::test]
async fn the_login_form_goes_back_with_a_code_and_a_session_that_signs_the_browser_in_next_time() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;

    let signed_in = app.respond(login(&alice.email, "alice-password")).await;
    let cookie = set_cookie(&signed_in).to_owned();
    let again = app
        .respond(get(&authorize_uri(&[]), cookie.split(';').next()))
        .await;

    assert_eq!(signed_in.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&signed_in),
        format!("{REDIRECT_URI}?code=code-1&state=the-clients-state")
    );
    assert!(cookie.starts_with("idp_session="), "{cookie}");
    for attribute in ["HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=2592000"] {
        assert!(cookie.contains(attribute), "{cookie}");
    }
    assert!(!cookie.contains("Secure"), "{cookie}");
    assert_eq!(
        location(&again),
        format!("{REDIRECT_URI}?code=code-2&state=the-clients-state")
    );
}

#[tokio::test]
async fn a_wrong_password_goes_back_to_the_login_form_with_the_reason() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;

    let response = app.respond(login(&alice.email, "not-it")).await;

    assert_eq!(
        location(&response),
        format!(
            "http://localhost:5173/login?{CARRIED}&error=Invalid%20email%20or%20password&nonce=the-nonce"
        )
    );
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn an_unconfirmed_address_goes_to_the_confirmation_page_and_is_mailed_a_code() {
    let bob = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    let app = app_with(std::slice::from_ref(&bob)).await;

    let response = app.respond(login(&bob.email, "bob-password")).await;

    assert_eq!(
        location(&response),
        format!(
            "http://localhost:5173/verify-email?pending_user_id={}&pending_email=bob%40idp.test&{CARRIED}\
             &error=Confirm%20your%20email%20to%20finish%20signing%20in&nonce=the-nonce",
            bob.id
        )
    );
    assert_eq!(app.sign_in.mailer.sent().len(), 1);
}

#[tokio::test]
async fn an_account_with_an_authenticator_goes_to_the_code_page_with_its_ticket() {
    let bob = SignInAccount {
        totp_enabled: true,
        ..signed_up("bob")
    };
    let app = app_with(std::slice::from_ref(&bob)).await;

    let response = app.respond(login(&bob.email, "bob-password")).await;

    let ticket = app.sign_in.tickets.opened()[0].0;
    assert_eq!(
        location(&response),
        format!("http://localhost:5173/login/totp?ticket={ticket}")
    );
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

fn exchange(code: &str, verifier: &str) -> Request<Body> {
    post_form(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", "web-client"),
            ("code_verifier", verifier),
        ],
    )
}

#[tokio::test]
async fn a_code_is_exchanged_once_for_the_accounts_tokens() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;
    app.respond(login(&alice.email, "alice-password")).await;

    let (status, tokens) = app.send(exchange("code-1", VERIFIER)).await;
    let (again, refused) = app.send(exchange("code-1", VERIFIER)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        tokens,
        json!({
            "access_token": format!("access:{}:web-client", alice.id),
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": format!("id:{}:web-client:{}:the-nonce", alice.id, alice.email),
        })
    );
    assert_eq!(again, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused,
        json!({
            "error": "invalid_grant",
            "error_description": "Authorization code is invalid, expired, or already used",
        })
    );
}

#[tokio::test]
async fn a_request_from_an_unknown_client_or_to_an_unregistered_redirect_is_answered_here() {
    let app = app_with(&[]).await;

    let (stranger, stranger_body) = app
        .send(get(
            &authorize_uri(&[]).replace("client_id=web-client", "client_id=stranger"),
            None,
        ))
        .await;
    let (elsewhere, elsewhere_body) = app
        .send(get(
            &authorize_uri(&[]).replace("localhost%3A5173", "evil.test"),
            None,
        ))
        .await;

    assert_eq!(
        (stranger, stranger_body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client"))
    );
    assert_eq!(
        (elsewhere, elsewhere_body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
}

#[tokio::test]
async fn signing_out_drops_the_session_and_goes_back_where_asked() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;
    let signed_in = app.respond(login(&alice.email, "alice-password")).await;
    let session = set_cookie(&signed_in).split(';').next().unwrap().to_owned();

    let back = app
        .respond(get(
            "/logout?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A5173",
            Some(&session),
        ))
        .await;
    let refused = app
        .respond(get(
            "/logout?post_logout_redirect_uri=javascript%3Aalert(1)",
            Some(&session),
        ))
        .await;

    assert_eq!(back.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&back), "http://localhost:5173");
    assert!(
        set_cookie(&back).starts_with("idp_session=;"),
        "{}",
        set_cookie(&back)
    );
    assert!(
        set_cookie(&back).contains("Max-Age=0"),
        "{}",
        set_cookie(&back)
    );
    assert_eq!(location(&refused), "/");
}

#[tokio::test]
async fn signing_out_never_sends_the_browser_where_no_client_lives() {
    let app = app_with(&[]).await;

    let response = app
        .respond(get(
            "/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.test%2F",
            None,
        ))
        .await;

    assert_eq!(location(&response), "/");
}

#[tokio::test]
async fn the_login_form_never_sends_a_code_to_an_unregistered_redirect() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;
    let mut pairs = vec![
        ("email", alice.email.as_str()),
        ("password", "alice-password"),
    ];
    pairs.extend(the_request().into_iter().map(|(k, v)| {
        if k == "redirect_uri" {
            (k, "https://evil.test/callback")
        } else {
            (k, v)
        }
    }));

    let response = app.respond(post_form("/login", &pairs)).await;
    let status = response.status();
    let has_location = response.headers().contains_key(header::LOCATION);
    let (_, body) = TestApp::body_of(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!has_location);
    assert_eq!(
        body["error_description"],
        "redirect_uri is not registered for this client"
    );
    assert!(app.sign_in.codes.issued().is_empty());
}

#[tokio::test]
async fn a_client_discovers_the_endpoints_and_the_keys() {
    let app = app_with(&[]).await;

    let (_, discovery) = app
        .send(get("/.well-known/openid-configuration", None))
        .await;
    let (_, keys) = app.send(get("/.well-known/jwks.json", None)).await;

    assert_eq!(discovery["issuer"], "http://localhost:8080");
    assert_eq!(discovery["token_endpoint"], "http://localhost:8080/token");
    assert_eq!(
        discovery["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(keys, json!({ "keys": [{ "kid": "test-key" }] }));
}

#[tokio::test]
async fn a_bad_flow_from_a_known_client_goes_back_to_it_with_the_error() {
    let app = app_with(&[]).await;

    let implicit = app
        .respond(get(
            &authorize_uri(&[]).replace("response_type=code", "response_type=token"),
            None,
        ))
        .await;
    let plain = app
        .respond(get(
            &authorize_uri(&[])
                .replace("code_challenge_method=S256", "code_challenge_method=plain"),
            None,
        ))
        .await;

    assert_eq!(implicit.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&implicit),
        format!(
            "{REDIRECT_URI}?error=unsupported_response_type\
             &error_description=response_type%20must%20be%20%27code%27&state=the-clients-state"
        )
    );
    assert_eq!(
        location(&plain),
        format!(
            "{REDIRECT_URI}?error=invalid_request\
             &error_description=code_challenge_method%20must%20be%20%27S256%27&state=the-clients-state"
        )
    );
}

#[tokio::test]
async fn a_token_answer_is_never_cached_and_another_grant_type_is_unsupported() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;
    app.respond(login(&alice.email, "alice-password")).await;

    let issued = app.respond(exchange("code-1", VERIFIER)).await;
    let refused = app
        .respond(post_form(
            "/token",
            &[
                ("grant_type", "password"),
                ("code", "code-1"),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", "web-client"),
                ("code_verifier", VERIFIER),
            ],
        ))
        .await;

    for response in [&issued, &refused] {
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    }
    let (status, body) = TestApp::body_of(refused).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("unsupported_grant_type"))
    );
}

#[tokio::test]
async fn ten_wrong_passwords_hold_an_email_off_for_a_while_whatever_its_case() {
    let (alice, bob) = (signed_up("alice"), signed_up("bob"));
    let app = app_with(&[alice.clone(), bob.clone()]).await;

    for _ in 0..10 {
        let wrong = app.respond(login(&alice.email, "not-it")).await;
        assert!(
            location(&wrong).contains("error=Invalid%20email"),
            "{}",
            location(&wrong)
        );
    }
    let held = app
        .respond(login(&alice.email.to_uppercase(), "alice-password"))
        .await;
    let right = app.respond(login(&alice.email, "alice-password")).await;
    let other = app.respond(login(&bob.email, "bob-password")).await;

    for response in [&held, &right] {
        assert!(
            location(response).contains("error=Too%20many%20attempts"),
            "{}",
            location(response)
        );
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    assert!(
        location(&other).starts_with(REDIRECT_URI),
        "{}",
        location(&other)
    );
}
