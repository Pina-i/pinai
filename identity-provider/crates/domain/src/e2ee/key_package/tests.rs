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

fn expiries(packages: &[NewKeyPackage]) -> Vec<OffsetDateTime> {
    packages.iter().map(|p| p.expires_at).collect()
}

#[test]
fn a_batch_within_the_lifetime_keeps_its_expiries() {
    let batch = vec![
        expiring(now() + Duration::days(1)),
        expiring(now() + Duration::days(30)),
    ];

    let admitted = policy().admit_batch(batch.clone(), now()).unwrap();

    assert_eq!(admitted, batch);
}

#[test]
fn an_expiry_past_the_lifetime_is_brought_back_to_it() {
    // A device whose clock runs ahead of ours asks for "30 days" and lands past them.
    let admitted = policy()
        .admit_batch(
            vec![
                expiring(now() + Duration::days(30) + Duration::seconds(5)),
                expiring(now() + Duration::days(400)),
            ],
            now(),
        )
        .unwrap();

    assert_eq!(expiries(&admitted), vec![now() + Duration::days(30); 2]);
}

#[test]
fn an_expiry_already_gone_gets_the_full_lifetime() {
    // A device whose clock runs a month behind ours.
    let admitted = policy()
        .admit_batch(
            vec![expiring(now()), expiring(now() - Duration::days(45))],
            now(),
        )
        .unwrap();

    assert_eq!(expiries(&admitted), vec![now() + Duration::days(30); 2]);
}

#[test]
fn a_batch_is_refused_only_when_empty() {
    assert_eq!(
        policy().admit_batch(Vec::new(), now()),
        Err(KeyPackageRefusal::NoPackages)
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
