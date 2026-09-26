use super::*;

use serde_json::json;

#[test]
fn a_change_of_whole_sections_is_accepted() {
    assert!(validate_sections(
        &json!({ "appearance": { "family": "lagoon", "motif": "raranga" } })
    )
    .is_ok());
}

#[test]
fn a_change_that_is_not_an_object_of_sections_is_refused() {
    for body in [
        json!(["appearance"]),
        json!("lagoon"),
        json!({}),
        json!({ "appearance": "lagoon" }),
        json!({ "appearance": { "family": "sand" }, "motif": null }),
    ] {
        assert!(
            validate_sections(&body).is_err(),
            "{body} should be refused"
        );
    }
}
