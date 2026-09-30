use super::*;

#[test]
fn an_address_is_one_at_between_two_parts_and_is_kept_lowercase() {
    assert_eq!(
        Email::parse("  Alice.Smith@Example.COM ").unwrap().as_str(),
        "alice.smith@example.com"
    );
    for refused in [
        "",
        "alice",
        "alice@",
        "@example.com",
        "a@b@example.com",
        "alice smith@example.com",
        "alice@exam\nple.com",
        &format!("{}@example.com", "a".repeat(250)),
    ] {
        assert!(Email::parse(refused).is_err(), "{refused:?}");
    }
}

#[test]
fn a_password_of_eight_is_the_least_registration_takes() {
    assert!(check_password("12345678").is_ok());
    assert!(matches!(
        check_password("1234567"),
        Err(AuthError::PasswordTooShort)
    ));
}
