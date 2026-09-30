use super::*;

fn web_client() -> Client {
    Client {
        id: ClientId::parse("web-client").unwrap(),
        redirect_uris: vec!["http://localhost:5173/callback".to_owned()],
    }
}

#[test]
fn a_client_allows_only_its_registered_redirect_uris_exactly() {
    let client = web_client();

    assert!(client.allows("http://localhost:5173/callback"));
    for other in [
        "http://localhost:5173/callback/",
        "http://LOCALHOST:5173/callback",
        "http://localhost:5173/callback?next=/",
        "http://localhost:5174/callback",
        "https://evil.test/callback",
        "",
    ] {
        assert!(!client.allows(other), "{other}");
    }
}

#[test]
fn after_signing_out_a_browser_goes_back_only_to_where_a_client_lives() {
    let clients = [web_client()];

    for allowed in [
        "http://localhost:5173",
        "http://localhost:5173/",
        "http://localhost:5173/login?next=/",
    ] {
        assert!(may_return_after_logout(allowed, &clients), "{allowed}");
    }
    for refused in [
        "https://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5173.evil.test",
        "https://evil.test",
        "javascript:alert(1)",
        "//localhost:5173",
        "/relative",
        "",
    ] {
        assert!(!may_return_after_logout(refused, &clients), "{refused}");
    }
    assert!(!may_return_after_logout("http://localhost:5173", &[]));
}
