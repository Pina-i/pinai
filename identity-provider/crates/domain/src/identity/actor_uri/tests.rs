use super::*;

#[test]
fn an_actor_uri_is_an_http_url_with_a_host() {
    let uri = ActorUri::parse("https://IDP.Example/users/alice_x1y2z").unwrap();

    assert_eq!(uri.as_str(), "https://idp.example/users/alice_x1y2z");
}

#[test]
fn anything_but_a_plain_http_url_is_refused() {
    for raw in [
        "ftp://idp.example/users/alice_x1y2z",
        "mailto:alice@idp.example",
        "idp.example/users/alice_x1y2z",
        "https://idp.example/users/alice_x1y2z#main-key",
        "https://idp.example/users/alice_x1y2z?page=2",
        "http:///users/alice_x1y2z",
        "http://[::1]:8080/users/alice_x1y2z",
        "",
    ] {
        assert!(ActorUri::parse(raw).is_err(), "{raw:?} should be refused");
    }
}

#[test]
fn an_actor_uri_is_at_most_2_kib() {
    let of_length = |len: usize| {
        let prefix = "https://idp.example/users/";
        format!("{prefix}{}", "a".repeat(len - prefix.len()))
    };

    assert!(ActorUri::parse(&of_length(ActorUri::MAX_BYTES)).is_ok());
    assert!(ActorUri::parse(&of_length(ActorUri::MAX_BYTES + 1)).is_err());
    // Measured as stored: `é` is written `%C3%A9`.
    let encoded = format!("{}é", of_length(ActorUri::MAX_BYTES - 5));
    assert!(ActorUri::parse(&encoded).is_err());
}

#[test]
fn a_users_uri_gives_the_address_it_stands_for() {
    let address = |raw: &str| {
        ActorUri::parse(raw)
            .unwrap()
            .federated_address()
            .map(|a| a.to_string())
    };

    assert_eq!(
        address("https://idp.bob.test/users/bob_k2m9x").as_deref(),
        Some("bob_k2m9x@idp.bob.test")
    );
    assert_eq!(
        address("http://localhost:8081/users/bob_k2m9x").as_deref(),
        Some("bob_k2m9x@localhost:8081")
    );
    assert_eq!(address("https://social.example/@bob"), None);
    assert_eq!(address("https://idp.bob.test/users/bob/inbox"), None);
}
