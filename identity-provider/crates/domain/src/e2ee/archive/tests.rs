use super::*;

#[test]
fn a_nonce_is_12_bytes_and_a_salt_16() {
    assert_eq!(ArchiveNonce::parse(&[1; 12]).unwrap().as_bytes(), &[1; 12]);
    assert_eq!(ArchiveSalt::parse(&[2; 16]).unwrap().as_bytes(), &[2; 16]);
    for len in [0, 11, 13] {
        assert!(
            ArchiveNonce::parse(&vec![1; len]).is_err(),
            "nonce of {len}"
        );
    }
    for len in [0, 15, 17, 32] {
        assert!(ArchiveSalt::parse(&vec![1; len]).is_err(), "salt of {len}");
    }
}

#[test]
fn an_upload_holds_one_to_fifty_entries() {
    assert_eq!(check_archive_batch(1), Ok(()));
    assert_eq!(check_archive_batch(50), Ok(()));
    assert_eq!(check_archive_batch(0), Err(BatchSize));
    assert_eq!(check_archive_batch(51), Err(BatchSize));
    assert_eq!(BatchSize.to_string(), "batch size must be 1..=50");
}

#[test]
fn a_page_is_a_hundred_entries_unless_asked_and_never_more_than_five_hundred() {
    assert_eq!(archive_page_size(None), 100);
    assert_eq!(archive_page_size(Some(20)), 20);
    assert_eq!(archive_page_size(Some(0)), 1);
    assert_eq!(archive_page_size(Some(-5)), 1);
    assert_eq!(archive_page_size(Some(10_000)), 500);
}
