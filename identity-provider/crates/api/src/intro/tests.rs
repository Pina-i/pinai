use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::auth::SignInAccount;
use domain::auth::testing::{CHALLENGE, CLIENT_ID, REDIRECT_URI, SignInSeeds, signed_up};
use serde_json::{Value, json};

use crate::testing::TestApp;

/// An instance named Aotearoa by its `.env`, with an admin and a member.
async fn app() -> (TestApp, SignInAccount, SignInAccount) {
    let app = TestApp::with([], []);
    let admin = SignInAccount {
        admin: true,
        ..signed_up("kahu")
    };
    let member = signed_up("alice");
    app.sign_in.accounts.sign_up(&admin).await;
    app.sign_in.accounts.sign_up(&member).await;
    (app, admin, member)
}

async fn save(app: &TestApp, caller: &SignInAccount, body: Value) -> (StatusCode, Value) {
    app.call(Method::PUT, "/api/admin/intro", Some(caller.id), Some(body))
        .await
}

#[tokio::test]
async fn the_intro_routes_answer_401_to_anyone_unsigned_and_403_to_a_member() {
    let (app, _, member) = app().await;

    for (method, body) in [
        (Method::GET, None),
        // A text the rule refuses: 403 all the same.
        (
            Method::PUT,
            Some(json!({ "name": "ō".repeat(41), "description": null })),
        ),
    ] {
        let (anonymous, _) = app
            .call(method.clone(), "/api/admin/intro", None, body.clone())
            .await;
        let (signed_in, refused) = app
            .call(method.clone(), "/api/admin/intro", Some(member.id), body)
            .await;

        assert_eq!(anonymous, StatusCode::UNAUTHORIZED, "{method}");
        assert_eq!(signed_in, StatusCode::FORBIDDEN, "{method}");
        assert_eq!(
            refused,
            json!({ "error": "access_denied", "error_description": "Only an admin may do this" })
        );
    }
}

/// A `PUT` whose body is sent as it is, with `content_type` when there is one.
async fn put_raw(
    app: &TestApp,
    caller: &SignInAccount,
    content_type: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri("/api/admin/intro")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", app.token(caller.id)),
        );
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    app.send(request.body(Body::from(body.to_owned())).unwrap())
        .await
}

#[tokio::test]
async fn a_body_that_is_no_draft_is_403_for_a_member_and_400_for_an_admin() {
    let (app, admin, member) = app().await;
    let json = Some("application/json");

    for (content_type, body) in [
        (json, "not json"),
        (None, r#"{ "name": "Kāinga", "description": null }"#),
        (json, r#"{ "name": "Kāinga" }"#),
        (json, r#"{ "nmae": "Kāinga", "description": null }"#),
        (json, "{}"),
    ] {
        let (as_member, refused) = put_raw(&app, &member, content_type, body).await;
        let (as_admin, invalid) = put_raw(&app, &admin, content_type, body).await;

        assert_eq!(as_member, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(refused["error"], "access_denied", "{body}");
        assert_eq!(as_admin, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            invalid,
            json!({
                "error": "invalid_request",
                "error_description": "instance intro: a name and a description, each a string or null",
            }),
            "{body}"
        );
    }
    let (_, kept) = app
        .call(Method::GET, "/api/admin/intro", Some(admin.id), None)
        .await;
    assert_eq!(
        kept,
        json!({ "name": "Aotearoa", "description": "Design and type people." }),
        "nothing saved"
    );
}

#[tokio::test]
async fn an_admin_is_shown_the_text_in_force_as_written() {
    let (app, admin, _) = app().await;

    let (status, body) = app
        .call(Method::GET, "/api/admin/intro", Some(admin.id), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "name": "Aotearoa", "description": "Design and type people." })
    );
}

#[tokio::test]
async fn a_field_past_its_limit_is_400_naming_the_rule() {
    let (app, admin, _) = app().await;

    let (status, body) = save(
        &app,
        &admin,
        json!({ "name": "ō".repeat(41), "description": null }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "error": "invalid_request",
            "error_description": "instance name: 40 characters at most",
        })
    );
}

#[tokio::test]
async fn an_admins_text_is_answered_trimmed_with_blanks_as_null_and_read_back() {
    let (app, admin, _) = app().await;

    let (status, saved) = save(
        &app,
        &admin,
        json!({ "name": "   ", "description": "  Weavers of Te Whanganui-a-Tara.  " }),
    )
    .await;
    let (_, shown) = app
        .call(Method::GET, "/api/admin/intro", Some(admin.id), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    let expected = json!({ "name": null, "description": "Weavers of Te Whanganui-a-Tara." });
    assert_eq!(saved, expected);
    assert_eq!(shown, expected);
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn a_new_name_shows_at_once_in_nodeinfo_and_on_the_login_page() {
    let (app, admin, _) = app().await;

    let (status, _) = save(
        &app,
        &admin,
        json!({ "name": "Kāinga", "description": "Weavers." }),
    )
    .await;
    let (_, nodeinfo) = app.send(get("/nodeinfo/2.1")).await;
    let login = format!(
        "/login?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", CLIENT_ID),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("state", "s"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
            .finish()
    );
    let (page_status, page) = TestApp::html_of(app.respond(get(&login)).await).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        nodeinfo["metadata"],
        json!({ "nodeName": "Kāinga", "nodeDescription": "Weavers." })
    );
    assert_eq!(page_status, StatusCode::OK);
    for shown in [
        "<span class=\"brand-name\">Kāinga</span>",
        "<h1 class=\"auth-h\">Weavers.</h1>",
        "Sign in to Kāinga",
    ] {
        assert!(page.contains(shown), "{shown} not in {page}");
    }
    assert!(!page.contains("Aotearoa"), "{page}");
}
