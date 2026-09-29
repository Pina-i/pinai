use super::*;

#[test]
fn an_empty_ciphertext_is_refused() {
    assert!(MlsCiphertext::parse(Vec::new()).is_err());
}

#[test]
fn any_other_bytes_are_kept_as_they_are() {
    let ciphertext = MlsCiphertext::parse(vec![0, 1, 2]).unwrap();

    assert_eq!(ciphertext.as_bytes(), &[0, 1, 2]);
}

#[test]
fn a_ciphertext_over_64_kib_is_refused_whatever_path_it_came_by() {
    assert!(MlsCiphertext::parse(vec![0; 64 * 1024]).is_ok());

    let refused = MlsCiphertext::parse(vec![0; 64 * 1024 + 1]).unwrap_err();

    assert_eq!(refused.reason, "exceeds 65536 bytes");
}
