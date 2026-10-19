use super::*;

#[test]
fn a_chosen_name_of_lowercase_letters_digits_underscores_and_dots_is_accepted() {
    let choice = UsernameChoice::parse("alice.b_2").unwrap();

    assert_eq!(choice.as_str(), "alice.b_2");
}

#[test]
fn a_chosen_name_outside_the_rules_is_refused() {
    let too_long = "a".repeat(33);
    for raw in [
        "a",
        too_long.as_str(),
        "Alice",
        "alice smith",
        "alice@home",
        "alice/x",
        "alice-b",
        ".alice",
        "alice.",
        "ali..ce",
        "",
    ] {
        assert!(
            UsernameChoice::parse(raw).is_err(),
            "{raw:?} should be refused"
        );
    }
}

#[test]
fn a_display_name_gives_its_ascii_lowercase_as_the_chosen_name() {
    for (name, derived) in [
        ("Hōkū", "hoku"),
        ("Ana Tane", "ana_tane"),
        ("  J. R. R. Tolkien!  ", "j_r_r_tolkien"),
        ("Ærøskøbing", "aeroskobing"),
        ("alice_b", "alice_b"),
        ("Mika2", "mika2"),
    ] {
        assert_eq!(
            UsernameChoice::derived_from(name).as_str(),
            derived,
            "{name:?}"
        );
    }
}

#[test]
fn a_display_name_derives_a_chosen_name_of_32_characters_at_most() {
    let derived = UsernameChoice::derived_from(&format!("{} b", "a".repeat(31)));

    assert_eq!(
        derived.as_str(),
        "a".repeat(31),
        "cut, without a trailing underscore"
    );
}

#[test]
fn a_display_name_with_too_little_ascii_in_it_derives_user() {
    for name in ["A", "!!", "", "  ."] {
        assert_eq!(
            UsernameChoice::derived_from(name).as_str(),
            "user",
            "{name:?}"
        );
    }
}

#[test]
fn any_display_name_derives_a_valid_chosen_name() {
    for name in ["李雷", "Ωmega", "🦄 unicorn", "a.b", "x__y", "-Ana-"] {
        let derived = UsernameChoice::derived_from(name);

        assert!(
            UsernameChoice::parse(derived.as_str()).is_ok(),
            "{name:?} gave {derived:?}"
        );
    }
}

#[test]
fn a_handle_is_the_chosen_name_an_underscore_and_the_suffix() {
    let choice = UsernameChoice::parse("alice").unwrap();
    let suffix = HandleSuffix::parse("x1y2z").unwrap();

    assert_eq!(Handle::compose(&choice, &suffix).as_str(), "alice_x1y2z");
}

#[test]
fn a_stored_handle_is_a_valid_chosen_name_and_suffix() {
    assert_eq!(
        Handle::parse("al_ice.b_x1y2z").unwrap().as_str(),
        "al_ice.b_x1y2z"
    );

    for raw in [
        "Alice_dev",
        "alice",
        "alice_x1y2",
        "alice_x1-2z",
        "_x1y2z",
        "a_x1y2z",
        "",
    ] {
        assert!(Handle::parse(raw).is_err(), "{raw:?} should be refused");
    }
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn a_composed_handle_parses_back_to_itself(
            choice in "[a-z0-9_]{1,15}(\\.[a-z0-9_]{1,15})?",
            suffix in "[a-z0-9]{5}",
        ) {
            prop_assume!(choice.len() >= 2);
            let handle = Handle::compose(
                &UsernameChoice::parse(&choice).unwrap(),
                &HandleSuffix::parse(&suffix).unwrap(),
            );
            prop_assert_eq!(Handle::parse(handle.as_str()).unwrap(), handle);
        }

        #[test]
        fn parsing_a_handle_never_panics(raw in "\\PC*") {
            let _ = Handle::parse(&raw);
        }
    }
}
