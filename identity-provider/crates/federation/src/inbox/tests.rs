use super::*;
use serde_json::json;

const KEY_ID: &str = "https://idp.bob.com/users/bob#main-key";
const BOB: &str = "https://idp.bob.com/users/bob";

#[test]
fn accepts_activity_signed_by_its_own_actor() {
    let body = json!({ "type": "Follow", "actor": BOB });
    assert!(verify_actor_binding(KEY_ID, &body).is_ok());
}

#[test]
fn accepts_actor_as_embedded_object() {
    let body = json!({ "type": "Follow", "actor": { "id": BOB } });
    assert!(verify_actor_binding(KEY_ID, &body).is_ok());
}

/// The forgery this binding exists to stop: a peer with a valid key of its
/// own signing an Accept on behalf of someone else, which would flip a
/// pending friendship to accepted without the real actor consenting.
#[test]
fn rejects_activity_claiming_a_different_actor() {
    let body = json!({ "type": "Accept", "actor": "https://idp.alice.com/users/alice" });
    assert!(verify_actor_binding(KEY_ID, &body).is_err());
}

#[test]
fn rejects_actor_that_only_prefixes_the_signer() {
    let body = json!({ "type": "Follow", "actor": "https://idp.bob.com/users/bobby" });
    assert!(verify_actor_binding(KEY_ID, &body).is_err());
}

#[test]
fn rejects_activity_with_no_actor() {
    assert!(verify_actor_binding(KEY_ID, &json!({ "type": "Follow" })).is_err());
}

#[test]
fn rejects_non_string_non_object_actor() {
    assert!(verify_actor_binding(KEY_ID, &json!({ "actor": 42 })).is_err());
}
