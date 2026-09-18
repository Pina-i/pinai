use super::*;

#[test]
fn generate_returns_requested_length_of_digits() {
    for _ in 0..50 {
        let otp = generate_numeric_otp(OTP_LEN);
        assert_eq!(otp.len(), OTP_LEN);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn hash_is_deterministic_for_same_input() {
    let pepper = b"super-secret-pepper-of-at-least-32-bytes!";
    assert_eq!(hash("123456", pepper), hash("123456", pepper));
    assert_ne!(hash("123456", pepper), hash("123457", pepper));
}

#[test]
fn hash_changes_with_pepper() {
    let h1 = hash("123456", b"pepper-a");
    let h2 = hash("123456", b"pepper-b");
    assert_ne!(h1, h2);
}

#[test]
fn verify_round_trips() {
    let pepper = b"pepper-pepper-pepper-pepper-pepper-pepper";
    let h = hash("987654", pepper);
    assert!(verify("987654", &h, pepper));
    assert!(!verify("987653", &h, pepper));
    assert!(!verify("", &h, pepper));
    assert!(!verify("987654", &h, b"different-pepper"));
}

#[test]
fn verify_rejects_length_mismatched_hash() {
    let pepper = b"pepper";
    let h = hash("123456", pepper);
    let truncated = &h[..h.len() - 1];
    assert!(!verify("123456", truncated, pepper));
}
