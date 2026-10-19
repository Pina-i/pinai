use axum::body::Body;
use axum::http::Request;

use crate::testing::TestApp;

use super::*;

#[test]
fn a_count_of_people_is_grouped_by_thousands() {
    for (count, said) in [
        (0, "0 people"),
        (1, "1 person"),
        (999, "999 people"),
        (1_204, "1,204 people"),
        (1_234_567, "1,234,567 people"),
    ] {
        assert_eq!(people(count), said);
    }
}

#[test]
fn an_appearance_keeps_only_the_themes_and_motifs_it_knows() {
    let given = Appearance::parse(Some("sand-light"), Some("tapa3"));
    let unknown = Appearance::parse(Some("sand-neon"), Some("../x"));

    assert_eq!(
        (given.theme(), given.mode(), given.motif()),
        ("sand-light", "light", "tapa3")
    );
    assert_eq!(
        given.pairs(),
        vec![("theme", "sand-light"), ("motif", "tapa3")]
    );
    assert_eq!(
        (unknown.theme(), unknown.mode(), unknown.motif()),
        ("pearl-dark", "dark", "tapa1"),
        "Black Pearl dark with Tapa 1"
    );
    assert!(unknown.pairs().is_empty(), "nothing made up travels on");
}

#[test]
fn the_code_page_says_a_failure_first_then_a_notice_then_the_codes_lifetime() {
    assert_eq!(
        verify_status(Some("code_incorrect"), Some("code_resent"), Some("3")),
        ("Incorrect code — 3 attempts left".to_owned(), true)
    );
    assert_eq!(
        verify_status(Some("made up"), Some("code_resent"), None),
        (
            "New code sent. The previous one no longer works.".to_owned(),
            false
        )
    );
    assert_eq!(
        verify_status(None, None, None),
        ("Codes expire in 10 minutes.".to_owned(), false)
    );
}

#[derive(Template)]
#[template(source = "<p>{{ text }}</p>", ext = "html")]
struct Plain {
    text: &'static str,
}

#[test]
fn a_page_ending_at_a_client_lets_its_forms_redirect_there_only() {
    let page = Plain { text: "hi" };
    let policy = |returns_to: Option<&str>| {
        render(StatusCode::OK, &page, returns_to).headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_owned()
    };

    assert!(
        policy(Some("https://app.example/callback"))
            .contains("form-action 'self' https://app.example;")
    );
    assert!(
        policy(Some("io.github.pina-i:/callback"))
            .contains("form-action 'self' io.github.pina-i:;")
    );
    assert!(policy(None).contains("form-action 'self';"));
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn the_pages_assets_are_served_from_the_binary_and_kept_a_day() {
    let app = TestApp::with([], []);

    let stylesheet = app.respond(get("/assets/sign-in.css")).await;
    let font = app.respond(get("/assets/fonts/dm-sans.woff2")).await;
    let motif = app.respond(get("/assets/motifs/tapa1.svg")).await;
    let outside = app.respond(get("/assets/../Cargo.toml")).await;
    let unknown = app.respond(get("/assets/sign-in.js.map")).await;

    assert_eq!(stylesheet.status(), StatusCode::OK);
    assert_eq!(
        stylesheet.headers()[header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
    assert_eq!(
        stylesheet.headers()[header::CACHE_CONTROL],
        "public, max-age=86400"
    );
    assert_eq!(font.headers()[header::CONTENT_TYPE], "font/woff2");
    assert_eq!(motif.headers()[header::CONTENT_TYPE], "image/svg+xml");
    assert_eq!(outside.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_page_links_the_stylesheet_and_the_script_by_their_content() {
    let app = TestApp::with([], []);

    let (_, page) = TestApp::html_of(app.respond(get("/signed-out")).await).await;
    let script = app.respond(get("/assets/sign-in.js")).await;

    assert!(STYLESHEET.starts_with("/assets/sign-in.css?v="));
    assert!(SCRIPT.starts_with("/assets/sign-in.js?v="));
    assert!(
        page.contains(&format!(
            "<link rel=\"stylesheet\" href=\"{}\">",
            *STYLESHEET
        )),
        "{page}"
    );
    assert!(
        page.contains(&format!("<script src=\"{}\" defer></script>", *SCRIPT)),
        "{page}"
    );
    assert!(!page.contains("<script>"), "no inline script: {page}");
    assert_eq!(
        script.headers()[header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
}

#[test]
fn every_motif_and_font_the_stylesheet_names_is_served() {
    let css = std::str::from_utf8(ASSETS[0].2).unwrap();
    let named: Vec<&str> = css
        .split("url(\"/assets/")
        .skip(1)
        .map(|rest| &rest[..rest.find('"').unwrap()])
        .collect();

    assert!(named.len() > 20, "{named:?}");
    for path in named {
        assert!(
            ASSETS.iter().any(|(served, _, _)| *served == path),
            "{path} is named but not served"
        );
    }
    for motif in MOTIFS {
        assert!(
            css.contains(&format!("[data-motif=\"{motif}\"] .auth-l-motif")),
            "{motif}"
        );
    }
}
