use super::*;
use serde_json::json;

#[test]
fn a_change_of_whole_sections_is_accepted() {
    let change = json!({ "appearance": { "family": "lagoon", "motif": "raranga" } });

    let patch = SettingsPatch::parse(change.clone()).unwrap();

    assert_eq!(patch.as_value(), &change);
}

#[test]
fn a_change_that_is_not_an_object_of_sections_is_refused() {
    for change in [
        json!(["appearance"]),
        json!("lagoon"),
        json!({}),
        json!({ "appearance": "lagoon" }),
        json!({ "appearance": { "family": "sand" }, "motif": null }),
    ] {
        assert!(
            SettingsPatch::parse(change.clone()).is_err(),
            "{change} should be refused"
        );
    }
}
