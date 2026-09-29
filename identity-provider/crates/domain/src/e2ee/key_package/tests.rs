use super::*;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn policy() -> KeyPackagePolicy {
    KeyPackagePolicy {
        cap_per_device: 10,
        refill_threshold: 3,
        max_lifetime: Duration::days(30),
    }
}

fn expiring(at: OffsetDateTime) -> NewKeyPackage {
    NewKeyPackage {
        bytes: KeyPackageBytes::parse(vec![1, 2, 3]).unwrap(),
        expires_at: at,
    }
}

#[test]
fn a_key_package_is_never_empty() {
    assert_eq!(KeyPackageBytes::parse(vec![9]).unwrap().as_bytes(), &[9]);
    assert!(KeyPackageBytes::parse(Vec::new()).is_err());
}

#[test]
fn a_batch_of_future_packages_within_the_lifetime_is_accepted() {
    let batch = [
        expiring(now() + Duration::days(1)),
        expiring(now() + Duration::days(30)),
    ];

    assert_eq!(policy().check_batch(&batch, now()), Ok(()));
}

#[test]
fn a_batch_is_refused_empty_or_at_its_first_bad_expiry() {
    assert_eq!(
        policy().check_batch(&[], now()),
        Err(KeyPackageRefusal::NoPackages)
    );
    assert_eq!(
        policy().check_batch(
            &[
                expiring(now() + Duration::days(1)),
                expiring(now() + Duration::days(31)),
                expiring(now() - Duration::days(1)),
            ],
            now()
        ),
        Err(KeyPackageRefusal::LivesTooLong(1))
    );
    assert_eq!(
        policy().check_batch(&[expiring(now())], now()),
        Err(KeyPackageRefusal::Expired(0))
    );
}

#[test]
fn a_stash_holds_up_to_the_cap() {
    assert_eq!(policy().check_stash(4, 6), Ok(()));
    assert_eq!(
        policy().check_stash(4, 7),
        Err(KeyPackageRefusal::StashFull {
            available: 4,
            uploading: 7,
            cap: 10
        })
    );
}

#[test]
fn a_stash_needs_refilling_at_the_threshold() {
    assert!(policy().needs_refill(3));
    assert!(!policy().needs_refill(4));
}
