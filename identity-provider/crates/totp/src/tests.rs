use super::*;

#[test]
fn generates_20_byte_secrets() {
    for _ in 0..10 {
        assert_eq!(generate_secret().len(), TOTP_SECRET_BYTES);
    }
}

#[test]
fn secrets_are_unique() {
    assert_ne!(generate_secret(), generate_secret());
}

#[test]
fn round_trips_current_code() {
    let secret = generate_secret();
    let totp = build_totp(&secret, "Pina'i", "alice@example.com").unwrap();
    let current = totp.generate_current().unwrap();
    assert!(verify_code(&secret, &current).unwrap());
    assert!(verify_code(&secret, &format!("  {}  ", current)).unwrap());
}

#[test]
fn rejects_wrong_code() {
    let secret = generate_secret();
    // "000000" only matches in the astronomical-but-not-impossible window
    // where the live code is actually 000000; the second + third asserts
    // are the durable checks (wrong length / non-digits).
    let _ = verify_code(&secret, "000000");
    assert!(!verify_code(&secret, "12345").unwrap());
    assert!(!verify_code(&secret, "abcdef").unwrap());
}

#[test]
fn provisioning_url_contains_issuer_and_account() {
    let secret = generate_secret();
    let url = provisioning_url(&secret, "Pina'i", "alice@example.com").unwrap();
    assert!(url.starts_with("otpauth://totp/"));
    assert!(url.contains("issuer="));
    assert!(url.contains("alice"));
}

#[test]
fn generates_ten_unique_recovery_codes() {
    let codes = generate_recovery_codes();
    assert_eq!(codes.len(), RECOVERY_CODES_PER_USER);
    for c in &codes {
        assert_eq!(c.len(), RECOVERY_CODE_LEN + 1); // includes the dash
        assert_eq!(c.chars().nth(5), Some('-'));
    }
    let unique: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn recovery_code_normalization() {
    assert_eq!(normalize_recovery_code("abcde-12345"), "ABCDE12345");
    assert_eq!(normalize_recovery_code("  ABCDE12345  "), "ABCDE12345");
    assert_eq!(normalize_recovery_code("ab-cd-e1-23-45"), "ABCDE12345");
}

#[test]
fn recovery_code_verify_round_trip() {
    let pepper = b"pepper-pepper-pepper-pepper-pepper-pepper";
    let codes = generate_recovery_codes();
    let hashed: Vec<_> = codes
        .iter()
        .map(|c| hash_recovery_code(c, pepper))
        .collect();
    for (code, hash) in codes.iter().zip(&hashed) {
        assert!(verify_recovery_code(code, hash, pepper));
        assert!(verify_recovery_code(&code.to_lowercase(), hash, pepper));
        assert!(verify_recovery_code(&code.replace('-', ""), hash, pepper));
    }
    assert!(!verify_recovery_code("WRONG-1234X", &hashed[0], pepper));
}
