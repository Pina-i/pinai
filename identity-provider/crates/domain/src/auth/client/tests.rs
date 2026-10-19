use super::*;

const PRODUCTION: ClientPolicy = ClientPolicy { allow_http: false };
const DEVELOPMENT: ClientPolicy = ClientPolicy { allow_http: true };

fn id(raw: &str) -> ClientId {
    ClientId::parse(raw).unwrap()
}

fn document(client_id: &str, redirect_uris: &[&str]) -> ClientDocument {
    ClientDocument {
        client_id: client_id.to_owned(),
        client_name: Some("Pīna'i".to_owned()),
        application_type: None,
        redirect_uris: redirect_uris.iter().map(|uri| (*uri).to_owned()).collect(),
        post_logout_redirect_uris: Vec::new(),
        scope: None,
        token_endpoint_auth_method: None,
    }
}

fn native(client_id: &str, redirect_uris: &[&str]) -> ClientDocument {
    ClientDocument {
        application_type: Some("native".to_owned()),
        ..document(client_id, redirect_uris)
    }
}

fn take(document: ClientDocument, policy: ClientPolicy) -> Result<Client, ValidationError> {
    Client::from_document(id(&document.client_id.clone()), document, policy)
}

const WEB: &str = "https://app.example/oauth-client.json";

#[test]
fn a_client_id_is_a_normalised_http_url_with_a_path() {
    for good in [
        WEB,
        "http://localhost:5173/oauth-client.json",
        "https://app.example/clients/web.json?v=2",
    ] {
        assert!(ClientId::parse(good).is_ok(), "{good}");
    }
    for bad in [
        "web-client",
        "https://app.example",
        "https://app.example/",
        "https://app.example/client.json#frag",
        "https://user@app.example/client.json",
        "https://APP.example/client.json",
        "https://app.example/a/../client.json",
        "https://app.example:443/client.json",
        "ftp://app.example/client.json",
        "/oauth-client.json",
        "",
    ] {
        assert!(ClientId::parse(bad).is_err(), "{bad}");
    }
    let long = format!("https://app.example/{}", "a".repeat(ClientId::MAX_LEN));
    assert!(ClientId::parse(&long).is_err());
}

#[test]
fn a_web_document_becomes_a_client() {
    let client = take(
        ClientDocument {
            post_logout_redirect_uris: vec!["https://app.example/".to_owned()],
            ..document(WEB, &["https://app.example/callback"])
        },
        PRODUCTION,
    )
    .unwrap();

    assert_eq!(client.id, id(WEB));
    assert_eq!(client.name, "Pīna'i");
    assert_eq!(client.kind, ClientKind::Web);
    assert!(client.allows("https://app.example/callback"));
    assert!(client.may_return_to("https://app.example/"));
    assert!(!client.offline_access);
}

#[test]
fn a_document_must_name_the_url_it_was_fetched_from() {
    let mut forged = document(WEB, &["https://app.example/callback"]);
    forged.client_id = "https://other.example/oauth-client.json".to_owned();

    assert!(Client::from_document(id(WEB), forged, PRODUCTION).is_err());
}

#[test]
fn a_plain_http_client_is_taken_only_by_a_development_instance() {
    let local = document(
        "http://localhost:5173/oauth-client.json",
        &["http://localhost:5173/callback"],
    );

    assert!(take(local.clone(), PRODUCTION).is_err());
    assert!(take(local, DEVELOPMENT).is_ok());
}

#[test]
fn only_public_clients_are_taken() {
    let mut confidential = document(WEB, &["https://app.example/callback"]);
    confidential.token_endpoint_auth_method = Some("client_secret_basic".to_owned());
    assert!(take(confidential, PRODUCTION).is_err());

    let mut public = document(WEB, &["https://app.example/callback"]);
    public.token_endpoint_auth_method = Some("none".to_owned());
    assert!(take(public, PRODUCTION).is_ok());
}

#[test]
fn an_application_type_is_web_or_native() {
    let mut other = document(WEB, &["https://app.example/callback"]);
    other.application_type = Some("browser".to_owned());

    assert!(take(other, PRODUCTION).is_err());
}

#[test]
fn a_client_without_a_name_is_shown_by_its_host_and_a_long_name_is_refused() {
    let mut unnamed = document(WEB, &["https://app.example/callback"]);
    unnamed.client_name = Some("   ".to_owned());
    assert_eq!(take(unnamed, PRODUCTION).unwrap().name, "app.example");

    let mut long = document(WEB, &["https://app.example/callback"]);
    long.client_name = Some("é".repeat(Client::MAX_NAME + 1));
    assert!(take(long, PRODUCTION).is_err());

    let mut longest = document(WEB, &["https://app.example/callback"]);
    longest.client_name = Some("é".repeat(Client::MAX_NAME));
    assert!(take(longest, PRODUCTION).is_ok());
}

#[test]
fn a_web_client_is_called_back_on_its_own_origin_only() {
    for elsewhere in [
        "https://other.example/callback",
        "https://app.example:8443/callback",
        "http://app.example/callback",
        "io.github.pina-i:/callback",
        "https://app.example/callback#x",
        "https://APP.example/callback",
    ] {
        assert!(
            take(document(WEB, &[elsewhere]), PRODUCTION).is_err(),
            "{elsewhere}"
        );
    }
}

#[test]
fn a_native_client_is_called_back_on_the_loopback_interface_or_its_own_reversed_domain() {
    let app = "https://pina-i.github.io/clients/desktop.json";
    for allowed in [
        "http://127.0.0.1:7777/callback",
        "http://[::1]:7777/callback",
        "io.github.pina-i:/callback",
    ] {
        assert!(
            take(native(app, &[allowed]), PRODUCTION).is_ok(),
            "{allowed}"
        );
    }
    for refused in [
        "http://localhost:7777/callback",
        "https://pina-i.github.io/callback",
        "io.github.someone-else:/callback",
        "pinai://callback",
        "javascript:/callback",
    ] {
        assert!(
            take(native(app, &[refused]), PRODUCTION).is_err(),
            "{refused}"
        );
    }
}

#[test]
fn a_development_instance_lets_a_native_client_use_any_scheme_but_a_reserved_one() {
    let local = "http://localhost:5173/desktop-client.json";

    assert!(take(native(local, &["pinai://callback"]), DEVELOPMENT).is_ok());
    for reserved in ["javascript:/callback", "data:/callback", "file:///callback"] {
        assert!(
            take(native(local, &[reserved]), DEVELOPMENT).is_err(),
            "{reserved}"
        );
    }
}

#[test]
fn a_client_lists_one_to_ten_redirect_uris() {
    assert!(take(document(WEB, &[]), PRODUCTION).is_err());

    let eleven: Vec<String> = (0..11)
        .map(|i| format!("https://app.example/callback/{i}"))
        .collect();
    let refs: Vec<&str> = eleven.iter().map(String::as_str).collect();
    assert!(take(document(WEB, &refs), PRODUCTION).is_err());
    assert!(take(document(WEB, &refs[..10]), PRODUCTION).is_ok());
}

#[test]
fn a_post_logout_uri_follows_the_redirect_rules() {
    let mut elsewhere = document(WEB, &["https://app.example/callback"]);
    elsewhere.post_logout_redirect_uris = vec!["https://evil.example/".to_owned()];

    assert!(take(elsewhere, PRODUCTION).is_err());
}

#[test]
fn only_a_native_client_may_stay_signed_in() {
    let app = "https://pina-i.github.io/clients/desktop.json";
    let mut desktop = native(app, &["io.github.pina-i:/callback"]);
    desktop.scope = Some("openid profile email offline_access".to_owned());
    assert!(take(desktop, PRODUCTION).unwrap().offline_access);

    let mut web = document(WEB, &["https://app.example/callback"]);
    web.scope = Some("openid offline_access".to_owned());
    assert!(!take(web, PRODUCTION).unwrap().offline_access);
}

#[test]
fn a_client_allows_only_its_listed_uris_exactly() {
    let client = take(
        ClientDocument {
            post_logout_redirect_uris: vec!["https://app.example/".to_owned()],
            ..document(WEB, &["https://app.example/callback"])
        },
        PRODUCTION,
    )
    .unwrap();

    for other in [
        "https://app.example/callback/",
        "https://app.example/callback?next=/",
        "https://app.example",
        "",
    ] {
        assert!(!client.allows(other), "{other}");
        assert!(!client.may_return_to(other), "{other}");
    }
}

#[test]
fn a_clients_document_reads_back_as_the_same_client() {
    let client = take(
        ClientDocument {
            post_logout_redirect_uris: vec!["https://app.example/".to_owned()],
            ..document(WEB, &["https://app.example/callback"])
        },
        PRODUCTION,
    )
    .unwrap();

    assert_eq!(take(client.document(), PRODUCTION).unwrap(), client);
}

#[test]
fn every_instance_describes_the_desktop_app_under_its_own_url() {
    let origin = InstanceOrigin::parse("https://idp.alice.com").unwrap();

    let desktop = desktop_client(&origin);

    assert_eq!(
        desktop.id.as_str(),
        "https://idp.alice.com/clients/desktop.json"
    );
    assert_eq!(desktop.kind, ClientKind::Native);
    assert!(desktop.allows("io.github.pina-i:/callback"));
    assert!(desktop.offline_access);
}

#[test]
fn a_client_lives_at_its_host_and_any_port_but_the_schemes() {
    for (raw, authority) in [
        ("https://app.example/oauth-client.json", "app.example"),
        (
            "https://app.example:8443/oauth-client.json",
            "app.example:8443",
        ),
        ("http://localhost:5173/oauth-client.json", "localhost:5173"),
    ] {
        assert_eq!(ClientId::parse(raw).unwrap().authority(), authority);
    }
}
