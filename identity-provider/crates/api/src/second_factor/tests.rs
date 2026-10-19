use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use domain::auth::testing::{
    CHALLENGE, CLIENT_ID, REDIRECT_URI, SignInSeeds, StepAuthenticator, signed_up,
};
use domain::auth::{SecondFactors, SignInAccount, TotpSecret};
use serde_json::json;
use time::OffsetDateTime;

use crate::testing::TestApp;

fn query(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn post_form(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(query(pairs)))
        .unwrap()
}

fn location(response: &Response) -> &str {
    response.headers()[header::LOCATION].to_str().unwrap()
}

fn secret() -> TotpSecret {
    TotpSecret::parse(vec![7; TotpSecret::LEN]).unwrap()
}

fn app_code() -> String {
    StepAuthenticator::code_at(&secret(), OffsetDateTime::now_utc())
}

fn another_than(code: &str) -> &'static str {
    if code == "000000" { "111111" } else { "000000" }
}

/// Bob, whose second factor is on, past his password: the ticket from the login form.
async fn bob_at_the_code_page(app: &TestApp) -> (SignInAccount, String, Vec<String>) {
    let bob = SignInAccount {
        totp_enabled: true,
        ..signed_up("bob")
    };
    app.sign_in.accounts.sign_up(&bob).await;
    let recovery = app
        .sign_in
        .factors
        .enable(bob.id, &secret(), 0)
        .await
        .unwrap();
    let mut pairs = vec![("email", "bob@idp.test"), ("password", "bob-password")];
    pairs.extend([
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid profile email"),
        ("state", "the-clients-state"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    app.respond(post_form("/login", &pairs)).await;
    let ticket = app.sign_in.tickets.opened()[0].0.to_string();
    (bob, ticket, recovery)
}

#[tokio::test]
async fn the_apps_code_goes_back_to_the_client_with_a_session() {
    let app = TestApp::with([], []);
    let (_, ticket, _) = bob_at_the_code_page(&app).await;

    let response = app
        .respond(post_form(
            "/login/totp",
            &[("ticket", &ticket), ("code", &app_code())],
        ))
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
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
async fn a_refused_code_stays_on_the_code_page_with_the_reason() {
    let app = TestApp::with([], []);
    let (_, ticket, _) = bob_at_the_code_page(&app).await;
    let code = app_code();
    let send = async |pairs: &[(&str, &str)]| {
        let mut all = vec![("ticket", ticket.as_str())];
        all.extend_from_slice(pairs);
        location(&app.respond(post_form("/login/totp", &all)).await).to_owned()
    };

    let wrong = send(&[("code", another_than(&code))]).await;
    let unknown = send(&[("recovery_code", "NOPE0-NOPE0")]).await;
    let nothing = send(&[("code", "")]).await;

    let page = |said: &str| format!("/login/totp?ticket={ticket}&{said}");
    assert_eq!(wrong, page("error=totp_incorrect"));
    assert_eq!(unknown, page("mode=recovery&error=recovery_unknown"));
    assert_eq!(nothing, page("error=totp_missing"));
}

#[tokio::test]
async fn a_ticket_gone_or_out_of_guesses_goes_back_to_the_login_page() {
    let app = TestApp::with([], []);
    let (_, ticket, _) = bob_at_the_code_page(&app).await;
    let wrong = another_than(&app_code());

    for _ in 0..5 {
        app.respond(post_form(
            "/login/totp",
            &[("ticket", &ticket), ("code", wrong)],
        ))
        .await;
    }
    let spent = app
        .respond(post_form(
            "/login/totp",
            &[("ticket", &ticket), ("code", &app_code())],
        ))
        .await;
    let unknown = app
        .respond(post_form(
            "/login/totp",
            &[
                ("ticket", &uuid::Uuid::new_v4().to_string()),
                ("code", "123456"),
            ],
        ))
        .await;

    assert_eq!(location(&spent), "/login?error=ticket_exhausted");
    assert_eq!(location(&unknown), "/login?error=ticket_expired");
}

fn code_page(ticket: &str, extra: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/login/totp?ticket={ticket}{extra}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn the_code_page_asks_the_apps_code_or_a_recovery_code_and_can_cancel() {
    let app = TestApp::with([], []);
    let (_, ticket, _) = bob_at_the_code_page(&app).await;

    let (status, apps) = TestApp::html_of(
        app.respond(code_page(
            &ticket,
            "&theme=jungle-dark&error=totp_incorrect",
        ))
        .await,
    )
    .await;
    let (_, recovery) =
        TestApp::html_of(app.respond(code_page(&ticket, "&mode=recovery")).await).await;

    assert_eq!(status, StatusCode::OK);
    for shown in [
        "Enter the 6-digit code",
        "Incorrect code",
        "action=\"/login/totp\"",
        &format!("name=\"ticket\" value=\"{ticket}\""),
        "name=\"theme\" value=\"jungle-dark\"",
        &format!("href=\"/login/totp?ticket={ticket}&#38;theme=jungle-dark&#38;mode=recovery\""),
        "href=\"http://localhost:5173/callback?error=access_denied&#38;state=the-clients-state\"",
    ] {
        assert!(apps.contains(shown), "{shown} not in {apps}");
    }
    assert!(recovery.contains("name=\"recovery_code\""), "{recovery}");
    assert!(recovery.contains("Use my authenticator app"), "{recovery}");
}

#[tokio::test]
async fn the_code_page_of_a_ticket_gone_says_the_sign_in_expired() {
    let app = TestApp::with([], []);

    let (status, page) = TestApp::html_of(
        app.respond(code_page(&uuid::Uuid::new_v4().to_string(), ""))
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("This sign-in has expired"), "{page}");
}

#[tokio::test]
async fn enrolling_answers_a_secret_then_its_confirmation_the_recovery_codes() {
    let app = TestApp::with([], []);
    let alice = signed_up("alice");
    app.sign_in.accounts.sign_up(&alice).await;

    let (status, enrollment) = app
        .call(Method::POST, "/api/totp/enroll", Some(alice.id), None)
        .await;
    let pending = app
        .sign_in
        .factors
        .pending(alice.id)
        .await
        .unwrap()
        .unwrap();
    let code = StepAuthenticator::code_at(&pending, OffsetDateTime::now_utc());
    let (confirmed, codes) = app
        .call(
            Method::POST,
            "/api/totp/enroll/verify",
            Some(alice.id),
            Some(json!({ "code": code })),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        enrollment,
        json!({
            "secret_base32": "SECRET1",
            "provisioning_url": "otpauth://totp/Pina'i (localhost:8080):alice@idp.test?secret=SECRET1",
        })
    );
    assert_eq!(confirmed, StatusCode::OK);
    assert_eq!(codes["recovery_codes"].as_array().unwrap().len(), 10);
}

#[tokio::test]
async fn the_settings_are_refused_with_the_reason() {
    let app = TestApp::with([], []);
    let alice = signed_up("alice");
    app.sign_in.accounts.sign_up(&alice).await;
    let (bob, _, _) = bob_at_the_code_page(&app).await;
    let refused = async |uri: &str, user, body| {
        let (status, body) = app.call(Method::POST, uri, Some(user), body).await;
        (
            status.as_u16(),
            body["error"].as_str().unwrap().to_owned(),
            body["error_description"].as_str().unwrap().to_owned(),
        )
    };
    let wrong = json!({ "code": another_than(&app_code()) });

    let answers = [
        refused("/api/totp/enroll", bob.id, None).await,
        refused(
            "/api/totp/enroll/verify",
            alice.id,
            Some(json!({ "code": "123456" })),
        )
        .await,
        refused(
            "/api/totp/disable",
            alice.id,
            Some(json!({ "code": "123456" })),
        )
        .await,
        refused("/api/totp/disable", bob.id, Some(wrong.clone())).await,
        refused("/api/totp/recovery-codes/regenerate", bob.id, Some(wrong)).await,
        refused("/api/totp/enroll", domain::UserId::generate(), None).await,
    ];

    let owned = |status: u16, error: &str, description: &str| {
        (status, error.to_owned(), description.to_owned())
    };
    assert_eq!(
        answers,
        [
            owned(
                400,
                "invalid_request",
                "TOTP already enabled — disable it first to re-enroll"
            ),
            owned(
                400,
                "invalid_request",
                "No pending enrollment — call /api/totp/enroll first"
            ),
            owned(400, "invalid_request", "TOTP is not enabled"),
            owned(400, "invalid_grant", "Incorrect code"),
            owned(400, "invalid_grant", "Incorrect code"),
            owned(401, "invalid_client", "User not found"),
        ]
    );
}

#[tokio::test]
async fn turning_off_answers_204_and_new_recovery_codes_replace_the_old() {
    let app = TestApp::with([], []);
    let (bob, _, old) = bob_at_the_code_page(&app).await;
    let code = json!({ "code": app_code() });
    // A code is good once: the next one the app shows.
    let next = json!({
        "code": StepAuthenticator::code_at(&secret(), OffsetDateTime::now_utc() + time::Duration::seconds(30))
    });

    let (regenerated, fresh) = app
        .call(
            Method::POST,
            "/api/totp/recovery-codes/regenerate",
            Some(bob.id),
            Some(code.clone()),
        )
        .await;
    let (disabled, _) = app
        .call(Method::POST, "/api/totp/disable", Some(bob.id), Some(next))
        .await;

    assert_eq!(regenerated, StatusCode::OK);
    assert_ne!(fresh["recovery_codes"][0], json!(old[0]));
    assert_eq!(disabled, StatusCode::NO_CONTENT);
    assert_eq!(app.sign_in.factors.state_of(bob.id), (false, 0, false));
}
