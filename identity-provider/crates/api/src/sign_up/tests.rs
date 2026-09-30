use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use domain::auth::testing::{CHALLENGE, Mail, REDIRECT_URI, SignInSeeds, signed_up};
use serde_json::json;

use crate::testing::TestApp;

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

const CARRIED: &str = "client_id=web-client&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback\
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

fn sign_up(username: &str, password: &str) -> Request<Body> {
    let mut pairs = vec![
        ("username", username),
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
    app.respond(sign_up("bob", "bob-password")).await;
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
            Some(json!({ "username": "bob", "email": "bob@idp.test", "password": "bob-password" })),
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
            "display_name": "bob",
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
    let refused = async |username: &str, email: &str, password: &str| {
        let (status, body) = app
            .call(
                Method::POST,
                "/register",
                None,
                Some(json!({ "username": username, "email": email, "password": password })),
            )
            .await;
        (
            status,
            body["error_description"].as_str().unwrap().to_owned(),
        )
    };

    let answers = [
        refused("bob", "", "bob-password").await,
        refused("Bob", "bob@idp.test", "bob-password").await,
        refused("bob", "bob", "bob-password").await,
        refused("bob", "bob@idp.test", "short").await,
        refused("bob", "ALICE@idp.test", "bob-password").await,
    ];

    assert_eq!(
        answers.map(|(status, description)| (status.as_u16(), description)),
        [
            (400, "username, email, and password are required".to_owned()),
            (
                400,
                "username: 2–32 characters: lowercase letters, digits, _ and . \
                 (no dot at the ends or twice in a row)"
                    .to_owned()
            ),
            (400, "email: an address like name@example.com".to_owned()),
            (400, "password must be at least 8 characters".to_owned()),
            (400, "Email already registered".to_owned()),
        ]
    );
}

#[tokio::test]
async fn the_sign_up_form_goes_on_to_confirming_the_address_carrying_the_request() {
    let app = TestApp::with([], []);

    let response = app.respond(sign_up("bob", "bob-password")).await;

    let user = app.sign_in.accounts.created()[0].id;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!(
            "http://localhost:5173/verify-email?pending_user_id={user}\
             &pending_email=bob%40idp.test&{CARRIED}&nonce=the-nonce"
        )
    );
}

#[tokio::test]
async fn a_refused_sign_up_goes_back_to_the_register_tab_with_the_reason() {
    let app = TestApp::with([], []);

    let response = app.respond(sign_up("Bob", "bob-password")).await;

    assert_eq!(
        location(&response),
        format!(
            "http://localhost:5173/login?tab=register&{CARRIED}\
             &error=Username%3A%202%E2%80%9332%20characters%3A%20lowercase%20letters%2C%20digits%2C\
             %20_%20and%20.%20%28no%20dot%20at%20the%20ends%20or%20twice%20in%20a%20row%29\
             &nonce=the-nonce"
        )
    );
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

    let back = |error: &str| {
        format!(
            "http://localhost:5173/verify-email?pending_user_id={bob}&pending_email=bob%40idp.test\
             &{CARRIED}&error={error}&nonce=the-nonce"
        )
    };
    assert_eq!(
        location(&guessed),
        back("Incorrect%20code%20%E2%80%94%204%20attempt%28s%29%20left")
    );
    assert_eq!(location(&malformed), back("Enter%20the%206-digit%20code"));
}

#[tokio::test]
async fn a_confirmed_account_goes_to_sign_in_and_an_unknown_one_is_refused_here() {
    let app = TestApp::with([], []);
    let alice = signed_up("alice");
    app.sign_in.accounts.sign_up(&alice).await;

    let confirmed = app.respond(verify(&alice.id.to_string(), "123456")).await;
    let (status, body) = app
        .send(verify(&uuid::Uuid::new_v4().to_string(), "123456"))
        .await;

    assert_eq!(location(&confirmed), "http://localhost:5173/login");
    assert_eq!(
        (status, body["error_description"].as_str()),
        (StatusCode::BAD_REQUEST, Some("Unknown user"))
    );
}

fn resend(user: &str) -> Request<Body> {
    post_form("/verify-email/resend", &[("pending_user_id", user)])
}

#[tokio::test]
async fn resending_answers_204_until_the_limit_then_429_and_410_once_confirmed() {
    let app = TestApp::with([], []);
    let (bob, code) = signed_up_bob(&app).await;

    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(app.respond(resend(&bob)).await.status().as_u16());
    }
    let latest = app.sign_in.signup_codes.issued().last().unwrap().1.clone();
    app.respond(verify(&bob, latest.as_str())).await;
    let confirmed = app.respond(resend(&bob)).await.status();
    let unknown = app
        .respond(resend(&uuid::Uuid::new_v4().to_string()))
        .await
        .status();

    assert_ne!(code, "");
    assert_eq!(statuses, vec![204, 204, 204, 204, 429]);
    assert_eq!(
        (confirmed, unknown),
        (StatusCode::GONE, StatusCode::NOT_FOUND)
    );
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
