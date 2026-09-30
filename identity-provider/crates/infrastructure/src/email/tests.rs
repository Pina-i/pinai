use super::*;

fn mailer() -> SmtpSignupMailer {
    SmtpSignupMailer::new(SmtpSettings {
        host: "mailpit".into(),
        port: 1025,
        username: String::new(),
        password: String::new(),
        from: "Pīna'i <no-reply@localhost>".into(),
        starttls: false,
        issuer_host: "localhost:8080".into(),
    })
    .unwrap()
}

fn code() -> OtpCode {
    OtpCode::parse("123456").unwrap()
}

#[test]
fn a_signup_mail_carries_the_code_in_its_subject_and_body() {
    let message = mailer()
        .message("alice@example.com", "Alice", &code())
        .unwrap();

    let formatted = String::from_utf8(message.formatted()).unwrap();
    let headers = formatted.split("\r\n\r\n").next().unwrap();
    // The subject is RFC 2047-encoded for its "ī": only stable parts are checked.
    assert!(headers.contains("Confirm"), "{headers}");
    assert!(headers.contains("123456"), "{headers}");
    assert!(headers.contains("alice@example.com"), "{headers}");
    assert!(formatted.contains("Alice"));
}

#[test]
fn a_mail_to_something_else_than_an_address_is_refused() {
    assert!(mailer().message("not-an-email", "Alice", &code()).is_err());
}
