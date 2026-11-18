use super::*;

#[test]
fn an_inbox_is_an_http_url_of_2_kib_at_most() {
    let of_length = |len: usize| {
        let prefix = "https://idp.example/inbox/";
        format!("{prefix}{}", "a".repeat(len - prefix.len()))
    };

    assert!(RemoteActor::parse_inbox(&of_length(ActorUri::MAX_BYTES)).is_ok());
    assert!(RemoteActor::parse_inbox(&of_length(ActorUri::MAX_BYTES + 1)).is_err());
    for raw in ["ftp://idp.example/inbox", "/users/bob/inbox", "inbox", ""] {
        assert!(
            RemoteActor::parse_inbox(raw).is_err(),
            "{raw:?} should be refused"
        );
    }
}

#[test]
fn an_account_has_joined_once_its_address_is_confirmed_or_it_was_admitted() {
    assert!(has_joined(true, false));
    assert!(has_joined(false, true));
    assert!(has_joined(true, true));
    assert!(!has_joined(false, false));
}
