use super::*;
use crate::identity::{ActorUri, FederatedAddress, Handle};

fn uri(raw: &str) -> ActorUri {
    ActorUri::parse(raw).unwrap()
}

fn origin() -> InstanceOrigin {
    InstanceOrigin::parse("http://localhost:8080").unwrap()
}

#[test]
fn an_instance_owns_the_actor_uris_under_its_scheme_host_and_port() {
    assert!(origin().owns(&uri("http://LOCALHOST:8080/users/alice_x1y2z")));

    for foreign in [
        "http://localhost:8081/users/alice_x1y2z",
        "https://localhost:8080/users/alice_x1y2z",
        "http://idp.example/users/alice_x1y2z",
    ] {
        assert!(!origin().owns(&uri(foreign)), "{foreign} is not ours");
    }
}

#[test]
fn an_instance_names_its_accounts_by_uri_and_by_address() {
    let alice = Handle::parse("alice_x1y2z").unwrap();

    assert_eq!(
        origin().actor_uri(&alice).as_str(),
        "http://localhost:8080/users/alice_x1y2z"
    );
    assert_eq!(
        origin().address_of(&alice).to_string(),
        "alice_x1y2z@localhost:8080"
    );
}

#[test]
fn a_local_actor_uri_names_one_valid_handle() {
    assert_eq!(
        origin().local_handle(&uri("http://localhost:8080/users/alice_x1y2z")),
        Some(Handle::parse("alice_x1y2z").unwrap())
    );

    for other in [
        "http://localhost:8080/users/alice_x1y2z/inbox",
        "http://localhost:8080/users/",
        "http://localhost:8080/actor",
        "http://localhost:8080/users/Alice_dev",
        "http://idp.example/users/alice_x1y2z",
    ] {
        assert_eq!(origin().local_handle(&uri(other)), None, "{other}");
    }
}

fn address(raw: &str) -> FederatedAddress {
    FederatedAddress::parse(raw).unwrap()
}

#[test]
fn an_address_on_our_domain_is_local_and_any_other_is_remote() {
    assert_eq!(
        origin()
            .recipient(&address("alice_x1y2z@localhost:8080"))
            .unwrap(),
        Recipient::Local(Handle::parse("alice_x1y2z").unwrap())
    );
    assert_eq!(
        origin()
            .recipient(&address("alice_x1y2z@idp.example"))
            .unwrap(),
        Recipient::Remote(address("alice_x1y2z@idp.example"))
    );
}

#[test]
fn our_domain_in_another_case_is_still_ours() {
    assert_eq!(
        origin()
            .recipient(&address("alice_x1y2z@LocalHost:8080"))
            .unwrap(),
        Recipient::Local(Handle::parse("alice_x1y2z").unwrap())
    );
}

#[test]
fn an_address_on_our_domain_that_is_no_valid_handle_is_refused() {
    assert!(
        origin()
            .recipient(&address("Alice_dev@localhost:8080"))
            .is_err()
    );
}

#[test]
fn a_bare_name_is_one_of_our_accounts_and_a_full_address_is_resolved() {
    assert_eq!(
        origin().resolve("alice_x1y2z").unwrap(),
        Recipient::Local(Handle::parse("alice_x1y2z").unwrap())
    );
    assert_eq!(
        origin().resolve("@bob_k2m9x@idp.example").unwrap(),
        Recipient::Remote(address("bob_k2m9x@idp.example"))
    );
    assert!(origin().resolve("Alice_dev").is_err());
}

#[test]
fn a_remote_account_is_expected_at_the_conventional_uri_over_our_scheme() {
    let bob = FederatedAddress::parse("bob_k2m9x@idp.bob.test:8443").unwrap();

    assert_eq!(
        origin().conventional_uri(&bob).map(|uri| uri.to_string()),
        Some("http://idp.bob.test:8443/users/bob_k2m9x".to_owned())
    );
}

#[test]
fn an_instance_is_reached_at_its_scheme_and_domain() {
    assert_eq!(origin().base_url(), "http://localhost:8080");
    assert_eq!(
        InstanceOrigin::parse("https://IDP.Alice.test")
            .unwrap()
            .base_url(),
        "https://idp.alice.test"
    );
}
