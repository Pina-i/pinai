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

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn a_rendered_address_parses_back_to_itself(
            user in "[A-Za-z0-9_.]{1,20}",
            host in "[a-z0-9]{1,10}(\\.[a-z0-9]{1,10}){0,2}",
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
