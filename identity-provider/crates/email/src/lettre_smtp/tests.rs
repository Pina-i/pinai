use super::*;

fn cfg() -> EmailConfig {
    EmailConfig {
        host: "mailpit".into(),
        port: 1025,
        username: String::new(),
        password: String::new(),
        from: "Pīna'i <no-reply@localhost>".into(),
        starttls: false,
        issuer_host: "localhost:8080".into(),
    }
}

#[test]
fn build_message_has_expected_subject_and_body() {
    let sender = LettreSmtpSender::from_config(cfg()).unwrap();
    let msg = sender
        .build_signup_message("alice@example.com", "Alice", "123456")
        .unwrap();
    let formatted = std::str::from_utf8(&msg.formatted()).unwrap().to_string();
    let headers = formatted
        .split("\r\n\r\n")
        .next()
        .expect("message has headers");
    // Subject is RFC2047-encoded by lettre because of the non-ASCII "ī",
    // so we just check for stable substrings. The display name lives in
    // the rendered body, not the To header — the To header carries the
    // email address only.
    assert!(headers.contains("Confirm"));
    assert!(headers.contains("123456"));
    assert!(headers.contains("alice@example.com"));
    assert!(formatted.contains("123456"));
    assert!(formatted.contains("Alice"));
}

#[test]
fn rejects_invalid_to_address() {
    let sender = LettreSmtpSender::from_config(cfg()).unwrap();
    let err = sender
        .build_signup_message("not-an-email", "Alice", "123456")
        .unwrap_err();
    assert!(matches!(err, EmailError::Address(_)));
}
