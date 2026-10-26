use super::*;

#[test]
fn a_web_app_is_an_http_or_https_origin_kept_normalised() {
    for (raw, origin) in [
        ("http://localhost:5173", "http://localhost:5173"),
        ("https://App.Example.org/", "https://app.example.org"),
        ("https://app.example.org:443", "https://app.example.org"),
        (" http://127.0.0.1:5173 ", "http://127.0.0.1:5173"),
    ] {
        assert_eq!(WebApp::parse(raw).unwrap().origin(), origin, "{raw}");
    }
}

#[test]
fn anything_but_an_origin_is_refused() {
    for refused in [
        "",
        "localhost:5173",
        "ftp://app.example.org",
        "https://app.example.org/app",
        "https://app.example.org/?instance=x",
        "https://app.example.org/#top",
        "https://someone@app.example.org",
        "javascript:alert(1)",
    ] {
        assert!(WebApp::parse(refused).is_err(), "{refused:?}");
    }
}

#[test]
fn an_origin_whose_document_url_is_no_client_id_is_refused() {
    let too_long = format!("https://{}.test", "a".repeat(2_100));

    assert!(WebApp::parse(&too_long).is_err());
}

#[test]
fn the_web_app_presents_its_document_as_its_client_id() {
    let app = WebApp::parse("https://app.example.org").unwrap();

    assert_eq!(
        app.client_id().as_str(),
        "https://app.example.org/oauth-client.json"
    );
}

#[test]
fn the_web_app_opens_on_an_instance_named_by_its_domain() {
    let app = WebApp::parse("http://localhost:5173").unwrap();
    let instance = InstanceOrigin::parse("http://localhost:8080").unwrap();

    assert_eq!(
        app.entry(&instance),
        "http://localhost:5173/?instance=localhost%3A8080"
    );
}
