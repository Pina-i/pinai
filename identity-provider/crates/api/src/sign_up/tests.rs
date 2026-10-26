use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use domain::auth::testing::{CHALLENGE, CLIENT_ID, Mail, REDIRECT_URI, SignInSeeds, signed_up};
use domain::auth::{SignInAccount, SignupCodes};
use serde_json::json;

use crate::testing::TestApp;

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

const CARRIED: &str = "client_id=http%3A%2F%2Flocalhost%3A5173%2Foauth-client.json&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback\
    &scope=openid%20profile%20email&state=the-clients-state\
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

fn post_form(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(query(pairs)))
        .unwrap()
}

fn sign_up(display_name: &str, password: &str) -> Request<Body> {
    let mut pairs = vec![
        ("display_name", display_name),
        ("email", "bob@idp.test"),
        ("password", password),
    ];
    pairs.extend(the_request());
    post_form("/register-and-login", &pairs)
}

fn verify(user: &str, code: &str) -> Request<Body> {
    let mut pairs = vec![
        ("pending_user_id", user),
        ("pending_email", "bob@idp.test"),
        ("code", code),
    ];
    pairs.extend(the_request());
    post_form("/verify-email-and-login", &pairs)
}

fn location(response: &Response) -> &str {
    response.headers()[header::LOCATION].to_str().unwrap()
}

/// Bob signed up through the form: his id, and the code mailed to him.
async fn signed_up_bob(app: &TestApp) -> (String, String) {
    app.respond(sign_up("Bob", "bob-password")).await;
    let (user, code, _) = app.sign_in.signup_codes.issued()[0].clone();
    (user.to_string(), code.as_str().to_owned())
}

#[tokio::test]
async fn registering_answers_the_new_account_and_mails_its_code() {
    let app = TestApp::with([], []);

    let (status, body) = app
        .call(
            Method::POST,
            "/register",
            None,
            Some(json!({ "display_name": "Bōb", "email": "bob@idp.test", "password": "bob-password" })),
        )
        .await;

    let user = app.sign_in.accounts.created()[0].id.to_string();
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body,
        json!({
            "id": user,
            "pending_user_id": user,
            "username": "bob_sfx01",
            "display_name": "Bōb",
            "address": "bob_sfx01@localhost:8080",
            "email": "bob@idp.test",
            "email_verified": false,
        })
    );
    assert_eq!(app.sign_in.mailer.sent()[0].to, "bob@idp.test");
}

#[tokio::test]
async fn a_registration_is_refused_with_the_rule_it_breaks() {
    let app = TestApp::with([], []);
    app.sign_in.accounts.sign_up(&signed_up("alice")).await;
    let refused = async |display_name: &str, email: &str, password: &str| {
        let (status, body) = app
            .call(
                Method::POST,
                "/register",
                None,
                Some(json!({ "display_name": display_name, "email": email, "password": password })),
            )
            .await;
        (
            status,
            body["error_description"].as_str().unwrap().to_owned(),
        )
    };

    let answers = [
        refused("Bob", "", "bob-password").await,
        refused("   ", "bob@idp.test", "bob-password").await,
        refused("Bob", "bob", "bob-password").await,
        refused("Bob", "bob@idp.test", "short").await,
        refused("Bob", "ALICE@idp.test", "bob-password").await,
    ];

    assert_eq!(
        answers.map(|(status, description)| (status.as_u16(), description)),
        [
            (
                400,
                "display_name, email, and password are required".to_owned()
            ),
            (400, "display_name: display_name cannot be blank".to_owned()),
            (400, "email: an address like name@example.com".to_owned()),
            (400, "password must be at least 8 characters".to_owned()),
            (400, "Email already registered".to_owned()),
        ]
    );
}

#[tokio::test]
async fn the_sign_up_form_goes_on_to_confirming_the_address_carrying_the_request() {
    let app = TestApp::with([], []);

    let response = app.respond(sign_up("Hōkū Tane", "bob-password")).await;

    let account = &app.sign_in.accounts.created()[0];
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!(
            "/verify-email?{CARRIED}&nonce=the-nonce&pending_user_id={}\
             &pending_email=bob%40idp.test",
            account.id
        )
    );
    assert_eq!(
        (account.username.as_str(), account.display_name.as_str()),
        ("hoku_tane_sfx01", "Hōkū Tane")
    );
}

#[tokio::test]
async fn a_refused_sign_up_goes_back_to_the_register_tab_with_the_reasons_code() {
    let app = TestApp::with([], []);
    app.sign_in
        .accounts
        .sign_up(&SignInAccount {
            email: "bob@idp.test".to_owned(),
            ..signed_up("robert")
        })
        .await;

    let back = |code: &str| format!("/login?{CARRIED}&nonce=the-nonce&tab=register&error={code}");
    for (request, code) in [
        (sign_up(" ", "bob-password"), "invalid_display_name"),
        (sign_up("Bob", "short"), "weak_password"),
        (sign_up("Bob", "bob-password"), "email_taken"),
    ] {
        assert_eq!(location(&app.respond(request).await), back(code));
    }
    assert!(app.sign_in.accounts.created().is_empty());
}

#[tokio::test]
async fn the_mailed_code_goes_back_to_the_client_with_a_session() {
    let app = TestApp::with([], []);
    let (bob, code) = signed_up_bob(&app).await;

    let response = app.respond(verify(&bob, &code)).await;

    assert_eq!(
        location(&response),
        format!("{REDIRECT_URI}?code=code-1&state=the-clients-state")
    );
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .starts_with("idp_session=")
    );
}

#[tokio::test]
async fn a_wrong_code_goes_back_to_the_page_with_the_guesses_left() {
    let app = TestApp::with([], []);
    let (bob, code) = signed_up_bob(&app).await;
    let wrong = if code == "999999" { "111111" } else { "999999" };

    let guessed = app.respond(verify(&bob, wrong)).await;
    let malformed = app.respond(verify(&bob, "12a456")).await;

    let back = |said: &str| {
        format!(
            "/verify-email?{CARRIED}&nonce=the-nonce&pending_user_id={bob}\
             &pending_email=bob%40idp.test&{said}"
        )
    };
    assert_eq!(location(&guessed), back("error=code_incorrect&left=4"));
    assert_eq!(location(&malformed), back("error=code_format"));
}

#[tokio::test]
async fn a_confirmed_account_goes_to_sign_in_and_an_unknown_one_to_signing_up_again() {
    let app = TestApp::with([], []);
    let alice = signed_up("alice");
    app.sign_in.accounts.sign_up(&alice).await;

    let confirmed = app.respond(verify(&alice.id.to_string(), "123456")).await;
    let unknown = app
        .respond(verify(&uuid::Uuid::new_v4().to_string(), "123456"))
        .await;

    assert_eq!(
        location(&confirmed),
        format!("/login?{CARRIED}&nonce=the-nonce&notice=already_verified")
    );
    assert_eq!(
        location(&unknown),
        format!("/login?{CARRIED}&nonce=the-nonce&tab=register&error=signup_expired")
    );
}

fn resend(user: &str) -> Request<Body> {
    let mut pairs = vec![("pending_user_id", user), ("pending_email", "bob@idp.test")];
    pairs.extend(the_request());
    post_form("/verify-email/resend", &pairs)
}

#[tokio::test]
async fn resending_says_so_on_the_code_page_until_the_limit_then_to_wait() {
    let app = TestApp::with([], []);
    let (bob, _) = signed_up_bob(&app).await;

    let mut answers = Vec::new();
    for _ in 0..5 {
        answers.push(location(&app.respond(resend(&bob)).await).to_owned());
    }

    let page = |said: &str| {
        format!(
            "/verify-email?{CARRIED}&nonce=the-nonce&pending_user_id={bob}\
             &pending_email=bob%40idp.test&{said}"
        )
    };
    let sent = page("notice=code_resent");
    assert_eq!(
        answers,
        vec![
            sent.clone(),
            sent.clone(),
            sent.clone(),
            sent,
            page("error=too_many_codes"),
        ]
    );
}

#[tokio::test]
async fn resending_to_a_confirmed_or_unknown_account_goes_to_sign_in_or_up() {
    let app = TestApp::with([], []);
    let alice = signed_up("alice");
    app.sign_in.accounts.sign_up(&alice).await;

    let confirmed = app.respond(resend(&alice.id.to_string())).await;
    let unknown = app.respond(resend(&uuid::Uuid::new_v4().to_string())).await;

    assert_eq!(
        location(&confirmed),
        format!("/login?{CARRIED}&nonce=the-nonce&notice=already_verified")
    );
    assert_eq!(
        location(&unknown),
        format!("/login?{CARRIED}&nonce=the-nonce&tab=register&error=signup_expired")
    );
}

#[tokio::test]
async fn an_admitted_account_gets_no_code_and_never_signs_in_through_one() {
    let app = TestApp::with([], []);
    let carol = SignInAccount {
        email_verified: false,
        admitted: true,
        ..signed_up("carol")
    };
    app.sign_in.accounts.sign_up(&carol).await;
    let code = app
        .sign_in
        .signup_codes
        .issue(
            carol.id,
            time::OffsetDateTime::now_utc() + domain::auth::SIGNUP_CODE_TTL,
        )
        .await
        .unwrap();
    let carol_id = carol.id.to_string();

    let resent = app.respond(resend(&carol_id)).await;
    let verified = app.respond(verify(&carol_id, code.as_str())).await;

    let to_sign_in = format!("/login?{CARRIED}&nonce=the-nonce&notice=no_code_needed");
    assert_eq!(location(&resent), to_sign_in);
    assert_eq!(location(&verified), to_sign_in);
    assert!(verified.headers().get(header::SET_COOKIE).is_none());
    assert!(app.sign_in.mailer.sent().is_empty());
    assert!(app.sign_in.codes.issued().is_empty());
    assert!(app.sign_in.sessions.all().is_empty());
}

fn code_page(extra: &[(&str, &str)]) -> Request<Body> {
    let mut pairs = the_request();
    pairs.extend_from_slice(extra);
    Request::builder()
        .uri(format!("/verify-email?{}", query(&pairs)))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn the_code_page_shows_the_address_and_posts_the_code_with_the_request() {
    let app = TestApp::with([], []);
    let user = uuid::Uuid::new_v4().to_string();

    let response = app
        .respond(code_page(&[
            ("pending_user_id", &user),
            ("pending_email", "bob@idp.test"),
            ("error", "code_incorrect"),
            ("left", "1"),
        ]))
        .await;
    let (status, page) = TestApp::html_of(response).await;

    assert_eq!(status, StatusCode::OK);
    for shown in [
        "<span>bob@idp.test</span>",
        "action=\"/verify-email-and-login\"",
        "action=\"/verify-email/resend\"",
        &format!("name=\"pending_user_id\" value=\"{user}\""),
        "Incorrect code — 1 attempt left",
        "autocomplete=\"one-time-code\"",
    ] {
        assert!(page.contains(shown), "{shown} not in {page}");
    }
}

#[tokio::test]
async fn the_code_page_shows_an_address_only() {
    let app = TestApp::with([], []);
    let user = uuid::Uuid::new_v4().to_string();

    let (_, page) = TestApp::html_of(
        app.respond(code_page(&[
            ("pending_user_id", &user),
            ("pending_email", "Your account is locked, call PHISHY"),
        ]))
        .await,
    )
    .await;
    let (expired, _) = TestApp::html_of(app.respond(code_page(&[])).await).await;

    assert!(!page.contains("PHISHY"), "{page}");
    assert!(page.contains("Codes expire in 10 minutes."), "{page}");
    assert_eq!(expired, StatusCode::BAD_REQUEST, "no account to confirm");
}

#[tokio::test]
async fn a_test_mail_goes_to_the_address_given() {
    let app = TestApp::with([], []);

    let (status, _) = app
        .call(
            Method::POST,
            "/dev/send-test-email",
            None,
            Some(json!({ "to": "dev@idp.test" })),
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        app.sign_in.mailer.sent(),
        vec![Mail {
            to: "dev@idp.test".to_owned(),
            name: "Tester".to_owned(),
            code: domain::auth::OtpCode::parse("123456").unwrap(),
        }]
    );
}

#[tokio::test]
async fn registering_on_an_invite_only_instance_is_refused_creating_and_mailing_nothing() {
    let app = TestApp::invite_only();

    let (status, body) = app
        .call(
            Method::POST,
            "/register",
            None,
            Some(json!({ "display_name": "Bōb", "email": "bob@idp.test", "password": "bob-password" })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        json!({
            "error": "invitation_required",
            "error_description": "Accounts on localhost:8080 are by invitation only",
        })
    );
    assert!(app.sign_in.accounts.created().is_empty());
    assert!(app.sign_in.mailer.sent().is_empty());
}

#[tokio::test]
async fn the_sign_up_form_on_an_invite_only_instance_goes_back_to_the_login_page_saying_so() {
    let app = TestApp::invite_only();

    let response = app.respond(sign_up("Bob", "bob-password")).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("/login?{CARRIED}&nonce=the-nonce&error=invitation_required")
    );
    assert!(app.sign_in.accounts.created().is_empty());
    assert!(app.sign_in.mailer.sent().is_empty());
}
