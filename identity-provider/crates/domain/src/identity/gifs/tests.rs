use super::*;

#[test]
fn a_klipy_key_is_kept_trimmed() {
    assert_eq!(KlipyKey::parse(" Ab3-x_9 ").unwrap().as_str(), "Ab3-x_9");
}

#[test]
fn a_klipy_key_that_would_need_escaping_in_a_url_path_is_refused() {
    for raw in ["", "   ", "abc/def", "abc?x=1", "abc def", "clé", "a%2Fb"] {
        assert!(KlipyKey::parse(raw).is_err(), "{raw:?}");
    }
}

#[test]
fn a_klipy_key_longer_than_the_limit_is_refused() {
    assert!(KlipyKey::parse(&"a".repeat(KlipyKey::MAX_LEN)).is_ok());
    assert!(KlipyKey::parse(&"a".repeat(KlipyKey::MAX_LEN + 1)).is_err());
}
