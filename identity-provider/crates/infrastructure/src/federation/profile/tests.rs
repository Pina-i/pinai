use domain::identity::testing::account;

use super::*;

#[test]
fn an_update_carries_the_accounts_name_and_avatar_as_its_person() {
    let alice = Account {
        avatar_url: Some("http://s3.test/avatars/alice.png?v=1".to_owned()),
        ..account("alice")
    };

    let update = update_person(&alice);

    assert_eq!(update["type"], "Update");
    assert_eq!(update["actor"], alice.actor_uri.as_str());
    let person = &update["object"];
    assert_eq!(person["type"], "Person");
    assert_eq!(person["id"], alice.actor_uri.as_str());
    assert_eq!(person["preferredUsername"], alice.username.as_str());
    assert_eq!(person["name"], "alice");
    assert_eq!(
        person["icon"]["url"],
        "http://s3.test/avatars/alice.png?v=1"
    );
}

#[test]
fn an_update_without_a_name_or_avatar_carries_neither() {
    let alice = Account {
        display_name: None,
        ..account("alice")
    };

    let person = &update_person(&alice)["object"];

    assert!(person.get("name").is_none());
    assert!(person.get("icon").is_none());
}
