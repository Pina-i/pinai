use super::*;

fn origin() -> InstanceOrigin {
    InstanceOrigin::parse("http://localhost:8080").unwrap()
}

fn text(name: Option<&str>, description: Option<&str>) -> IntroText {
    IntroText::parse(name, description).unwrap()
}

#[test]
fn a_text_is_kept_trimmed_and_a_blank_field_is_the_default() {
    let written = text(Some(" Aotearoa "), Some(" Design people. "));

    assert_eq!(written.name(), Some("Aotearoa"));
    assert_eq!(written.description(), Some("Design people."));
    for blank in [None, Some(""), Some("  ")] {
        let defaults = text(blank, blank);

        assert_eq!((defaults.name(), defaults.description()), (None, None));
    }
}

#[test]
fn a_name_holds_40_characters_and_a_description_90() {
    let refused = |name: &str, description: &str| {
        IntroText::parse(Some(name), Some(description))
            .err()
            .map(|e| e.to_string())
    };

    assert_eq!(refused(&"ō".repeat(40), &"ō".repeat(90)), None);
    assert_eq!(
        refused(&"ō".repeat(41), ""),
        Some("instance name: 40 characters at most".to_owned())
    );
    assert_eq!(
        refused("", &"ō".repeat(91)),
        Some("instance description: 90 characters at most".to_owned())
    );
}

#[test]
fn a_text_without_a_name_is_shown_under_the_instances_domain() {
    let shown = text(None, Some("Design people.")).shown(&origin());

    assert_eq!(shown.name(), "localhost:8080");
    assert_eq!(shown.description(), Some("Design people."));
    assert_eq!(
        text(Some("Aotearoa"), None).shown(&origin()).name(),
        "Aotearoa"
    );
}

#[test]
fn a_saved_text_is_in_force_whole_over_the_configured_one() {
    let configured = text(Some("Aotearoa"), Some("Design people."));
    let saved = text(Some("Kāinga"), None);

    assert_eq!(
        intro_in_force(Some(saved.clone()), configured.clone()),
        saved
    );
    assert_eq!(intro_in_force(None, configured.clone()), configured);
}

#[test]
fn a_setting_left_unset_is_never_overridden() {
    let saved = text(Some("Kāinga"), Some("Weavers."));

    assert!(overridden_settings(&saved, &text(None, None)).is_empty());
}

#[test]
fn a_setting_equal_to_the_saved_field_is_not_overridden() {
    let saved = text(Some("Aotearoa"), Some("Design people."));

    assert!(
        overridden_settings(&saved, &text(Some(" Aotearoa "), Some("Design people."))).is_empty()
    );
}

#[test]
fn a_setting_the_saved_text_replaces_with_something_else_is_overridden_alone() {
    let configured = text(Some("Aotearoa"), Some("Design people."));

    assert_eq!(
        overridden_settings(&text(Some("Kāinga"), Some("Design people.")), &configured),
        vec![IntroField::Name]
    );
    assert_eq!(
        overridden_settings(&text(Some("Aotearoa"), None), &configured),
        vec![IntroField::Description],
        "the default replaces it too"
    );
}

#[test]
fn each_field_names_its_variable_and_itself() {
    assert_eq!(
        (IntroField::Name.env_var(), IntroField::Name.noun()),
        ("INSTANCE_NAME", "name")
    );
    assert_eq!(
        (
            IntroField::Description.env_var(),
            IntroField::Description.noun()
        ),
        ("INSTANCE_DESCRIPTION", "description")
    );
}
