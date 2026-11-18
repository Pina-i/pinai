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
