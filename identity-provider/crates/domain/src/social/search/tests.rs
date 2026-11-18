use super::*;

#[test]
fn a_query_is_kept_trimmed_from_two_characters() {
    assert_eq!(SearchQuery::parse(" al ").unwrap().as_str(), "al");
    assert_eq!(SearchQuery::parse("%_").unwrap().as_str(), "%_");
    for short in ["", " ", "a", " a "] {
        assert!(SearchQuery::parse(short).is_err(), "{short:?}");
    }
}

#[test]
fn combining_marks_do_not_count_toward_the_two_characters() {
    for folding_short in ["\u{301}\u{301}", "a\u{301}", "a\u{301}\u{304}"] {
        assert!(
            SearchQuery::parse(folding_short).is_err(),
            "{folding_short:?}"
        );
    }
    assert_eq!(
        SearchQuery::parse("o\u{304}k").unwrap().as_str(),
        "o\u{304}k"
    );
}

#[test]
fn a_query_with_a_control_character_is_refused() {
    for raw in ["a\0b", "ab\u{0}", "a\tb", "a\u{7f}b", "a\u{85}b"] {
        assert!(SearchQuery::parse(raw).is_err(), "{raw:?}");
    }
}

#[test]
fn a_query_holds_a_hundred_characters_at_most_marks_included() {
    assert!(SearchQuery::parse(&"a".repeat(100)).is_ok());
    assert!(SearchQuery::parse(&"a".repeat(101)).is_err());
    assert!(SearchQuery::parse(&format!("ab{}", "\u{301}".repeat(99))).is_err());
}
