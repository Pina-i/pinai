use super::*;

#[test]
fn a_query_is_kept_trimmed_from_two_characters() {
    assert_eq!(SearchQuery::parse(" al ").unwrap().as_str(), "al");
    assert_eq!(SearchQuery::parse("%_").unwrap().as_str(), "%_");
    for short in ["", " ", "a", " a "] {
        assert!(SearchQuery::parse(short).is_err(), "{short:?}");
    }
}
