use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use domain::auth::SignInAccount;
use domain::auth::testing::{
    CHALLENGE, CLIENT_ID, POST_LOGOUT_URI, REDIRECT_URI, SignInSeeds, VERIFIER, signed_up,
};
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
        ("client_id", CLIENT_ID),
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

const CARRIED: &str = "client_id=http%3A%2F%2Flocalhost%3A5173%2Foauth-client.json&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback\
    &scope=openid%20profile%20email&state=the-clients-state\
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

#[tokio::test]
async fn a_browser_without_a_session_is_sent_to_the_login_page_carrying_the_request() {
    let app = app_with(&[]).await;

    let response = app.respond(get(&authorize_uri(&[]), None)).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("/login?{CARRIED}&nonce=the-nonce")
    );
}

#[tokio::test]
async fn the_theme_and_motif_a_client_paints_go_along_and_unknown_ones_are_dropped() {
    let app = app_with(&[]).await;

    let painted = app
        .respond(get(
            &authorize_uri(&[("theme", "sand-light"), ("motif", "raranga")]),
            None,
        ))
        .await;
    let unknown = app
        .respond(get(
            &authorize_uri(&[("theme", "neon-dark"), ("motif", "<b>")]),
            None,
        ))
        .await;

    assert_eq!(
        location(&painted),
        format!("/login?{CARRIED}&theme=sand-light&motif=raranga&nonce=the-nonce")
    );
    assert_eq!(
        location(&unknown),
        format!("/login?{CARRIED}&nonce=the-nonce")
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
        format!("/login?{CARRIED}&nonce=the-nonce&error=invalid_credentials")
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
            "/verify-email?{CARRIED}&nonce=the-nonce&pending_user_id={}\
             &pending_email=bob%40idp.test&notice=confirm_email",
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
    assert_eq!(location(&response), format!("/login/totp?ticket={ticket}"));
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

fn exchange(code: &str, verifier: &str) -> Request<Body> {
    post_form(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
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
            "access_token": format!("access:{}:{CLIENT_ID}", alice.id),
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": format!("id:{}:{CLIENT_ID}:{}:the-nonce", alice.id, alice.email),
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

    let stranger = app
        .respond(get(
            &authorize_uri(&[]).replace("%2Foauth-client.json", "%2Fstranger.json"),
            None,
        ))
        .await;
    let elsewhere = app
        .respond(get(
            &authorize_uri(&[]).replace(
                "redirect_uri=http%3A%2F%2Flocalhost%3A5173",
                "redirect_uri=http%3A%2F%2Fevil.test",
            ),
            None,
        ))
        .await;

    for (response, status) in [
        (stranger, StatusCode::UNAUTHORIZED),
        (elsewhere, StatusCode::BAD_REQUEST),
    ] {
        assert!(!response.headers().contains_key(header::LOCATION));
        let (answered, page) = TestApp::html_of(response).await;
        assert_eq!(answered, status);
        assert!(page.contains("This app couldn&#39;t be verified"), "{page}");
    }
}

fn logout(client: &str, return_to: &str) -> String {
    format!(
        "/logout?{}",
        query(&[
            ("client_id", client),
            ("post_logout_redirect_uri", return_to),
        ])
    )
}

#[tokio::test]
async fn signing_out_drops_the_session_and_goes_back_where_the_client_listed() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;
    let signed_in = app.respond(login(&alice.email, "alice-password")).await;
    let session = set_cookie(&signed_in).split(';').next().unwrap().to_owned();

    let back = app
        .respond(get(&logout(CLIENT_ID, POST_LOGOUT_URI), Some(&session)))
        .await;
    let refused = app
        .respond(get(
            &logout(CLIENT_ID, "javascript:alert(1)"),
            Some(&session),
        ))
        .await;

    assert_eq!(back.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&back), POST_LOGOUT_URI);
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
    assert_eq!(location(&refused), "/signed-out");
}

#[tokio::test]
async fn signing_out_never_sends_the_browser_where_its_client_didnt_list() {
    let app = app_with(&[]).await;

    for uri in [
        logout(CLIENT_ID, "https://evil.test/"),
        logout("http://localhost:5173/stranger.json", POST_LOGOUT_URI),
        format!(
            "/logout?{}",
            query(&[("post_logout_redirect_uri", POST_LOGOUT_URI)])
        ),
    ] {
        let response = app.respond(get(&uri, None)).await;

        assert_eq!(location(&response), "/signed-out", "{uri}");
    }
}

#[tokio::test]
async fn a_browser_signed_out_without_a_return_is_told_so_here() {
    let app = app_with(&[]).await;

    let (status, page) = TestApp::html_of(app.respond(get("/signed-out", None)).await).await;

    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("You&#39;re signed out"), "{page}");
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
    let has_location = response.headers().contains_key(header::LOCATION);
    let (status, page) = TestApp::html_of(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!has_location);
    assert!(page.contains("This app couldn&#39;t be verified"), "{page}");
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
    assert_eq!(discovery["client_id_metadata_document_supported"], true);
    assert!(discovery.get("registration_endpoint").is_none());
    assert_eq!(keys, json!({ "keys": [{ "kid": "test-key" }] }));
}

#[tokio::test]
async fn every_instance_publishes_the_desktop_apps_document() {
    let app = app_with(&[]).await;

    let response = app.respond(get("/clients/desktop.json", None)).await;
    let cache = response.headers()[header::CACHE_CONTROL].clone();
    let (status, document) = TestApp::body_of(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache, "public, max-age=86400");
    assert_eq!(
        document,
        json!({
            "client_id": "http://localhost:8080/clients/desktop.json",
            "client_name": "Pīna'i desktop",
            "application_type": "native",
            "redirect_uris": ["io.github.pina-i:/callback"],
            "scope": "openid profile email offline_access",
            "token_endpoint_auth_method": "none",
        })
    );
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
                ("client_id", CLIENT_ID),
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
            location(&wrong).ends_with("error=invalid_credentials"),
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
            location(response).ends_with("error=rate_limited"),
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

fn login_page(extra: &[(&str, &str)]) -> Request<Body> {
    let mut pairs = the_request();
    pairs.extend_from_slice(extra);
    get(&format!("/login?{}", query(&pairs)), None)
}

#[tokio::test]
async fn the_login_page_shows_the_instance_and_posts_the_request_to_itself() {
    let app = app_with(&[]).await;

    let response = app.respond(login_page(&[])).await;
    let headers = response.headers().clone();
    let (status, page) = TestApp::html_of(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(headers[header::REFERRER_POLICY], "same-origin");
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; \
         form-action 'self' http://localhost:5173; frame-ancestors 'none'; base-uri 'none'"
    );
    for shown in [
        "<span class=\"brand-name\">Aotearoa</span>",
        "<h1 class=\"auth-h\">Design and type people.</h1>",
        "0 people",
        "open registration",
        "— localhost:8080",
        "Sign in to Aotearoa",
        "action=\"/login\"",
        "<input type=\"hidden\" name=\"state\" value=\"the-clients-state\">",
        "<input type=\"hidden\" name=\"nonce\" value=\"the-nonce\">",
        "href=\"http://localhost:5173/callback?error=access_denied&#38;state=the-clients-state\"",
        "Your password goes to localhost:8080, never to Pīna'i",
        "data-theme=\"pearl-dark\" data-motif=\"tapa1\" class=\"dark\"",
    ] {
        assert!(page.contains(shown), "{shown} not in {page}");
    }
    assert!(!page.contains("name=\"display_name\""));
}

#[tokio::test]
async fn the_register_tab_asks_a_display_name_and_posts_to_sign_up() {
    let app = app_with(&[]).await;

    let (_, page) = TestApp::html_of(app.respond(login_page(&[("tab", "register")])).await).await;

    assert!(page.contains("action=\"/register-and-login\""), "{page}");
    assert!(
        page.contains("Create account<span class=\"spin\">"),
        "the button's spinner, shown while the form is on its way: {page}"
    );
    assert!(page.contains("name=\"display_name\""), "{page}");
    assert!(page.contains("Create account"), "{page}");
}

#[tokio::test]
async fn a_known_error_code_shows_its_sentence_and_anything_else_nothing() {
    let app = app_with(&[]).await;

    let (_, known) = TestApp::html_of(
        app.respond(login_page(&[("error", "invalid_credentials")]))
            .await,
    )
    .await;
    let (_, made_up) = TestApp::html_of(
        app.respond(login_page(&[(
            "error",
            "Your account is locked: call PHISHY",
        )]))
        .await,
    )
    .await;

    assert!(known.contains("Invalid email or password"), "{known}");
    assert!(!made_up.contains("PHISHY"), "{made_up}");
    assert!(!made_up.contains("role=\"alert\""), "{made_up}");
}

#[tokio::test]
async fn whatever_the_request_carries_is_escaped_on_the_page() {
    let app = app_with(&[]).await;
    let pairs: Vec<(&str, &str)> = the_request()
        .into_iter()
        .map(|(k, v)| {
            if k == "state" {
                (k, "\"><script>x</script>")
            } else {
                (k, v)
            }
        })
        .collect();

    let (_, page) = TestApp::html_of(
        app.respond(get(&format!("/login?{}", query(&pairs)), None))
            .await,
    )
    .await;

    assert!(!page.contains("<script>"), "{page}");
    assert!(page.contains("&#34;&#62;&#60;script&#62;"), "{page}");
}

#[tokio::test]
async fn the_page_is_painted_in_the_clients_theme_and_motif() {
    let app = app_with(&[]).await;

    let (_, page) = TestApp::html_of(
        app.respond(login_page(&[
            ("theme", "lagoon-light"),
            ("motif", "raranga"),
        ]))
        .await,
    )
    .await;

    assert!(
        page.contains("data-theme=\"lagoon-light\" data-motif=\"raranga\" class=\"light\""),
        "{page}"
    );
    assert!(
        page.contains("name=\"theme\" value=\"lagoon-light\""),
        "{page}"
    );
}

#[tokio::test]
async fn a_login_link_with_no_request_left_is_told_it_expired() {
    let app = app_with(&[]).await;

    let (none, page) = TestApp::html_of(app.respond(get("/login", None)).await).await;
    let (_, ended) = TestApp::html_of(
        app.respond(get("/login?error=ticket_exhausted", None))
            .await,
    )
    .await;

    assert_eq!(none, StatusCode::BAD_REQUEST);
    assert!(page.contains("This sign-in link has expired"), "{page}");
    assert!(!page.contains("Another home"), "{page}");
    assert!(ended.contains("Too many attempts"), "{ended}");
}

#[tokio::test]
async fn a_login_page_for_a_client_that_cant_be_verified_is_answered_with_that() {
    let app = app_with(&[]).await;

    let response = app
        .respond(get(
            &format!("/login?{}", query(&the_request()))
                .replace("%2Foauth-client.json", "%2Fx.json"),
            None,
        ))
        .await;
    let (status, page) = TestApp::html_of(response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(page.contains("This app couldn&#39;t be verified"), "{page}");
    assert!(!page.contains("action="), "{page}");
}

#[tokio::test]
async fn a_form_posted_from_another_site_is_refused() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;
    let from = |header_name: &str, value: &str| {
        let mut request = login(&alice.email, "alice-password");
        request.headers_mut().insert(
            header::HeaderName::from_bytes(header_name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        request
    };

    let elsewhere = app.respond(from("origin", "https://evil.test")).await;
    let cross_site = app.respond(from("sec-fetch-site", "cross-site")).await;
    let null_alone = app.respond(from("origin", "null")).await;
    let ours = app.respond(from("origin", "http://localhost:8080")).await;
    let mut null_same_origin = from("origin", "null");
    null_same_origin
        .headers_mut()
        .insert("sec-fetch-site", "same-origin".parse().unwrap());
    let null_same_origin = app.respond(null_same_origin).await;

    for refused in [&elsewhere, &cross_site, &null_alone] {
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(ours.status(), StatusCode::SEE_OTHER);
    assert_eq!(null_same_origin.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        app.sign_in.codes.issued().len(),
        2,
        "the refused ones issued nothing"
    );
}

fn desktop_request() -> Vec<(&'static str, &'static str)> {
    the_request()
        .into_iter()
        .map(|(k, v)| match k {
            "client_id" => (k, "http://localhost:8080/clients/desktop.json"),
            "redirect_uri" => (k, "io.github.pina-i:/callback"),
            _ => (k, v),
        })
        .collect()
}

#[tokio::test]
async fn a_session_signs_in_silently_only_to_the_apps_its_account_signed_in_to() {
    let alice = signed_up("alice");
    let app = app_with(std::slice::from_ref(&alice)).await;
    let signed_in = app.respond(login(&alice.email, "alice-password")).await;
    let session = set_cookie(&signed_in).split(';').next().unwrap().to_owned();
    let mut desktop = vec![("response_type", "code")];
    desktop.extend(desktop_request());

    let same_app = app.respond(get(&authorize_uri(&[]), Some(&session))).await;
    let other_app = app
        .respond(get(
            &format!("/authorize?{}", query(&desktop)),
            Some(&session),
        ))
        .await;

    assert!(
        location(&same_app).starts_with(REDIRECT_URI),
        "{}",
        location(&same_app)
    );
    assert!(
        location(&other_app)
            .starts_with("/login?client_id=http%3A%2F%2Flocalhost%3A8080%2Fclients%2Fdesktop.json"),
        "the password first: {}",
        location(&other_app)
    );
    assert_eq!(
        app.sign_in.codes.issued().len(),
        2,
        "the sign-in's and the same app's"
    );
}

#[tokio::test]
async fn the_login_page_names_the_app_and_where_it_lives() {
    let app = app_with(&[]).await;

    let (_, web) = TestApp::html_of(app.respond(login_page(&[])).await).await;
    let (_, desktop) = TestApp::html_of(
        app.respond(get(&format!("/login?{}", query(&desktop_request())), None))
            .await,
    )
    .await;

    assert!(
        web.contains(
            "to continue to <span class=\"for-name\">Pīna&#39;i</span> \
             <span class=\"fact fact--plain\">localhost:5173</span>"
        ),
        "{web}"
    );
    assert!(
        desktop.contains("to continue to <span class=\"for-name\">Pīna&#39;i desktop</span></p>"),
        "the instance's own document names no other place: {desktop}"
    );
}
