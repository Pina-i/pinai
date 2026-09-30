use super::*;

#[test]
fn a_display_name_is_kept_trimmed_up_to_fifty_characters() {
    assert_eq!(DisplayName::parse("  Aroha  ").unwrap().as_str(), "Aroha");
    let fifty = "é".repeat(50);
    assert_eq!(DisplayName::parse(&fifty).unwrap().as_str(), fifty);

    let blank = DisplayName::parse("   ").unwrap_err();
    let long = DisplayName::parse(&"é".repeat(51)).unwrap_err();

    assert_eq!(blank.reason, "display_name cannot be blank");
    assert_eq!(long.reason, "display_name must be ≤ 50 characters");
}

#[test]
fn pronouns_are_one_of_a_closed_set() {
    for pronouns in Pronouns::ALL {
        assert_eq!(Pronouns::parse(pronouns.as_str()).unwrap(), pronouns);
    }

    let refused = Pronouns::parse("they").unwrap_err();

    assert_eq!(
        refused.reason,
        "pronouns must be one of: he, she, non-binary"
    );
}

#[test]
fn a_bio_holds_at_most_190_characters() {
    assert!(Bio::parse(&"é".repeat(190)).is_ok());

    let refused = Bio::parse(&"é".repeat(191)).unwrap_err();

    assert_eq!(refused.reason, "bio must be ≤ 190 characters");
}

#[test]
fn an_edit_needs_a_name_and_clears_what_is_left_empty() {
    let edit = ProfileEdit::parse(Some("Aroha"), Some(" "), Some("")).unwrap();

    assert_eq!(edit.display_name.as_str(), "Aroha");
    assert_eq!(edit.pronouns, None);
    assert_eq!(edit.bio, None);
    assert_eq!(
        ProfileEdit::parse(Some("Aroha"), Some(" she "), Some(" kia ora ")).unwrap(),
        ProfileEdit {
            display_name: DisplayName::parse("Aroha").unwrap(),
            pronouns: Some(Pronouns::She),
            bio: Some(Bio::parse(" kia ora ").unwrap()),
        }
    );
    assert_eq!(
        ProfileEdit::parse(None, None, None).unwrap_err().reason,
        "display_name is required"
    );
}
