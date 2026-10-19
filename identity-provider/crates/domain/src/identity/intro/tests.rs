use super::*;

fn origin() -> InstanceOrigin {
    InstanceOrigin::parse("http://localhost:8080").unwrap()
}

#[test]
fn an_instance_is_introduced_by_its_name_and_description_trimmed() {
    let intro =
        InstanceIntro::new(&origin(), Some(" Aotearoa "), Some(" Design people. ")).unwrap();

    assert_eq!(intro.name(), "Aotearoa");
    assert_eq!(intro.description(), Some("Design people."));
}

#[test]
fn an_instance_without_a_name_goes_by_its_host() {
    for name in [None, Some(""), Some("   ")] {
        let intro = InstanceIntro::new(&origin(), name, Some(" ")).unwrap();

        assert_eq!(intro.name(), "localhost:8080");
        assert_eq!(intro.description(), None);
    }
}

#[test]
fn a_name_or_a_description_past_its_limit_is_refused() {
    let long_name = "ō".repeat(InstanceIntro::MAX_NAME + 1);
    let long_description = "ō".repeat(InstanceIntro::MAX_DESCRIPTION + 1);

    assert!(InstanceIntro::new(&origin(), Some(&long_name), None).is_err());
    assert!(InstanceIntro::new(&origin(), None, Some(&long_description)).is_err());
    assert!(
        InstanceIntro::new(&origin(), Some(&"ō".repeat(InstanceIntro::MAX_NAME)), None).is_ok(),
        "counted in characters"
    );
}
