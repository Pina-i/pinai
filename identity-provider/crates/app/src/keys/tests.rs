use super::*;

#[test]
fn every_byte_of_the_secret_counts() {
    let secret = "a".repeat(64);
    let mut changed = secret.clone().into_bytes();
    changed[40] = b'b';
    let changed = String::from_utf8(changed).unwrap();

    let (keys, other) = (
        SessionKeys::from_secret(&secret),
        SessionKeys::from_secret(&changed),
    );

    assert_ne!(keys.cookies.signing(), other.cookies.signing());
    assert_ne!(keys.attachment_links, other.attachment_links);
}

#[test]
fn sessions_and_attachment_links_have_keys_of_their_own() {
    let secret = "0123456789abcdef0123456789abcdef";

    let keys = SessionKeys::from_secret(secret);

    assert_ne!(keys.cookies.signing(), keys.attachment_links.as_slice());
    assert_ne!(keys.cookies.signing(), secret.as_bytes());
    assert_ne!(keys.attachment_links, secret.as_bytes());
}

#[test]
fn a_secret_makes_the_same_keys_every_time() {
    let secret = "0123456789abcdef0123456789abcdef";

    let (keys, again) = (
        SessionKeys::from_secret(secret),
        SessionKeys::from_secret(secret),
    );

    assert_eq!(keys.cookies.signing(), again.cookies.signing());
    assert_eq!(keys.attachment_links, again.attachment_links);
}

#[test]
fn a_short_development_secret_still_makes_keys() {
    let keys = SessionKeys::from_secret("dev");

    assert_eq!(keys.cookies.signing().len(), 32);
    assert!(!keys.attachment_links.is_empty());
}
