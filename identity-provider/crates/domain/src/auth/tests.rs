use super::*;

link_token!(SomeToken, "some link");

#[test]
fn a_token_is_256_bits_in_url_safe_base64_without_padding() {
    let token = SomeToken::from_bytes([0xfb; 32]);

    assert_eq!(token.as_str().len(), SomeToken::LEN);
    assert!(
        !token.as_str().contains(['+', '/', '=']),
        "{}",
        token.as_str()
    );
    assert_eq!(SomeToken::parse(token.as_str()).unwrap(), token);
}

#[test]
fn a_token_of_another_shape_names_no_link_and_the_refusal_says_which() {
    let token = SomeToken::from_bytes([7; 32]);
    for refused in [
        "",
        &token.as_str()[1..],
        &format!("{}A", token.as_str()),
        &format!("{}=", &token.as_str()[..42]),
        &token
            .as_str()
            .replace(|c: char| c.is_ascii_alphanumeric(), "+"),
        "<script>alert(1)</script>",
    ] {
        let error = SomeToken::parse(refused).expect_err(refused);

        assert_eq!(error.field, "some link", "{refused:?}");
    }
}

#[test]
fn a_token_never_shows_in_debug_output() {
    let token = SomeToken::from_bytes([42; 32]);

    let shown = format!("{token:?}");

    assert_eq!(shown, "SomeToken(..)");
    assert!(!shown.contains(token.as_str()));
    assert_eq!(
        format!("{:?}", InvitationToken::from_bytes([42; 32])),
        "InvitationToken(..)"
    );
    assert_eq!(
        format!("{:?}", ResetToken::from_bytes([42; 32])),
        "ResetToken(..)"
    );
}
