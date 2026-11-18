use super::*;

#[test]
fn an_address_is_a_user_and_a_domain() {
    let address = FederatedAddress::parse("alice_x1y2z@idp.example").unwrap();

    assert_eq!(address.user(), "alice_x1y2z");
    assert_eq!(address.domain().as_str(), "idp.example");
    assert_eq!(address.to_string(), "alice_x1y2z@idp.example");
}

#[test]
fn a_leading_at_is_dropped_and_the_domain_lowercased_with_its_port() {
    let address = FederatedAddress::parse("@Bob_k2m9x@IDP.Example:8443").unwrap();

    assert_eq!(address.to_string(), "Bob_k2m9x@idp.example:8443");
}

#[test]
fn an_authoritys_host_drops_a_numeric_port() {
    for (authority, host) in [
        ("chat.example.org", "chat.example.org"),
        ("chat.example.org:8443", "chat.example.org"),
        ("localhost:18443", "localhost"),
        ("[::1]:8080", "[::1]"),
        ("[2001:db8::1]", "[2001:db8::1]"),
    ] {
        assert_eq!(host_of(authority), host, "{authority}");
    }
}

/// Only a port of digits is one: anything else is part of a host this rule can't read.
#[test]
fn an_authority_without_a_numeric_port_is_kept_whole() {
    for authority in [
        "chat.example.org:",
        "chat.example.org:https",
        "::1",
        "[::1",
        "[::1]:",
        "[::1]:https",
    ] {
        assert_eq!(host_of(authority), authority, "{authority}");
    }
}

#[test]
fn a_domains_host_is_its_authority_without_the_port() {
    assert_eq!(
        Domain::parse("IDP.Example:8443").unwrap().host(),
        "idp.example"
    );
    assert_eq!(Domain::parse("idp.example").unwrap().host(), "idp.example");
}

#[test]
fn a_malformed_address_is_refused() {
    for raw in [
        "alice",
        "alice@b@c",
        "@alice",
        "alice@",
        "@@idp.example",
        "ali ce@idp.example",
        "ali/ce@idp.example",
        "alice@idp.example/users",
        "alice@idp example",
        "alice@idp.example:port",
        "alice@idp.example:99999",
        "alice@:8080",
        "",
    ] {
        assert!(
            FederatedAddress::parse(raw).is_err(),
            "{raw:?} should be refused"
        );
    }
}

#[test]
fn a_domain_whose_labels_no_name_server_could_answer_is_refused() {
    let label_64 = "a".repeat(64);
    let host_254 = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(62));
    for raw in [
        "x@reef..chat",
        "x@a.-b",
        "x@a-.b",
        "x@-reef.chat",
        "x@reef.chat-",
        "x@reef.chat.",
        "x@.reef.chat",
        "x@reef..chat:8443",
        "x@reef.123",
        "x@999.1.1.1",
        "x@1.2.3",
        "x@010.0.0.1",
        &format!("x@{label_64}.chat"),
        &format!("x@{host_254}"),
    ] {
        assert!(
            FederatedAddress::parse(raw).is_err(),
            "{raw:?} should be refused"
        );
    }
}

#[test]
fn a_domain_of_valid_labels_is_kept_as_today() {
    let label_63 = "a".repeat(63);
    let host_253 = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61));
    for raw in [
        "x@localhost",
        "x@localhost:8080",
        "x@reef.chat",
        "x@my-reef.chat",
        "x@xn--hk-8ia.chat",
        "x@a.b",
        "x@127.0.0.1:8081",
        "x@10.0.0.5",
        "x@123.reef.chat",
        "x@reef.c0m",
        &format!("x@{label_63}.chat"),
        &format!("x@{host_253}"),
    ] {
        assert!(
            FederatedAddress::parse(raw).is_ok(),
            "{raw:?} should be accepted"
        );
    }
}

#[test]
fn a_port_is_digits_and_kept_without_its_leading_zeros() {
    for (raw, kept) in [
        ("x@reef.chat:0443", "x@reef.chat:443"),
        ("x@reef.chat:00008443", "x@reef.chat:8443"),
        ("x@localhost:08080", "x@localhost:8080"),
    ] {
        assert_eq!(FederatedAddress::parse(raw).unwrap().to_string(), kept);
    }
    for raw in [
        "x@reef.chat:+443",
        "x@reef.chat:-1",
        "x@reef.chat: 443",
        "x@reef.chat:0",
    ] {
        assert!(
            FederatedAddress::parse(raw).is_err(),
            "{raw:?} should be refused"
        );
    }
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn a_rendered_address_parses_back_to_itself(
            user in "[A-Za-z0-9_.]{1,20}",
            host in "([a-z0-9]{1,10}\\.){0,2}[a-z][a-z0-9]{0,9}",
            port in proptest::option::of(1u16..),
        ) {
            let domain = match port {
                Some(port) => format!("{host}:{port}"),
                None => host,
            };
            let address = FederatedAddress::parse(&format!("{user}@{domain}")).unwrap();
            prop_assert_eq!(FederatedAddress::parse(&address.to_string()).unwrap(), address);
        }

        #[test]
        fn parsing_an_address_never_panics(raw in "\\PC*") {
            let _ = FederatedAddress::parse(&raw);
        }
    }
}
