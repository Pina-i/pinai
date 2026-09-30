use super::*;

#[test]
fn a_recovery_code_is_two_groups_of_five_readable_characters() {
    for _ in 0..50 {
        let code = recovery_code();
        let (first, second) = code.split_once('-').unwrap();

        assert_eq!((first.len(), second.len()), (5, 5), "{code}");
        assert!(
            format!("{first}{second}")
                .bytes()
                .all(|b| RECOVERY_ALPHABET.contains(&b)),
            "{code}"
        );
    }
}
