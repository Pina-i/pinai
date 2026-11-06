use super::*;
use crate::e2ee::testing::{PlainEd25519Verifier, plain_signature};
use crate::e2ee::{
    ATTESTATION_LIFETIME, ApprovalPublicKey, Attestation, DeviceLabel, HistoryCheckValue,
    HistorySalt,
};

fn actor() -> ActorUri {
    ActorUri::parse("https://idp.alice.test/users/alice_xk9mp").unwrap()
}

fn key(byte: u8) -> DeviceRootKey {
    DeviceRootKey::parse(&[byte; 32]).unwrap()
}

fn device(owner: UserId, root: Option<u8>) -> Device {
    let at = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        paired_at: at,
        last_seen_at: at,
        revoked_at: None,
        attestation: root.map(|byte| Attestation {
            root_key: key(byte),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: at,
            expires_at: at + ATTESTATION_LIFETIME,
        }),
        hpke_key: None,
        history_generation: None,
    }
}

fn revoked(mut device: Device) -> Device {
    device.revoked_at = Some(device.paired_at);
    device
}

fn history_key(generation: i64, approval_key: u8) -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::parse(generation).unwrap(),
        salt: HistorySalt::parse(&[1; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[1; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[approval_key; 32]).unwrap(),
    }
}

/// `signer`'s signature over `approved`'s root key, as a client makes it.
fn signed_by(signer: &dyn crate::e2ee::Ed25519PublicKey, approved: &Device) -> Ed25519Signature {
    let root = &approved.attestation.as_ref().unwrap().root_key;
    plain_signature(signer, &approval_bytes(&actor(), approved.id, root))
}

fn by_device(
    signer: &Device,
    approved_id: DeviceId,
    approved: Option<&Device>,
    signature: Ed25519Signature,
) -> Result<CheckedApproval, KeyDirectoryError> {
    let facts = ApprovalFacts {
        actor: &actor(),
        signer,
        approved,
        current: None,
    };
    may_approve(
        approved_id,
        ApprovalBy::Device,
        signature,
        facts,
        &PlainEd25519Verifier,
    )
}

fn by_passphrase(
    signer: &Device,
    approved_id: DeviceId,
    generation: i64,
    current: Option<&HistoryKey>,
    signature: Ed25519Signature,
) -> Result<CheckedApproval, KeyDirectoryError> {
    let facts = ApprovalFacts {
        actor: &actor(),
        signer,
        approved: None,
        current,
    };
    let by = ApprovalBy::Passphrase(HistoryGeneration::parse(generation).unwrap());
    may_approve(approved_id, by, signature, facts, &PlainEd25519Verifier)
}

#[test]
fn an_approval_signs_the_device_and_the_root_key_it_binds_as_the_spec_writes_them() {
    let device =
        DeviceId::from(uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap());

    let bytes = approval_bytes(&actor(), device, &key(1));

    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "PINAI-DEVICE-APPROVAL-v1\n\
         https://idp.alice.test/users/alice_xk9mp\n\
         550e8400-e29b-41d4-a716-446655440000\n\
         AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
}

#[test]
fn the_calling_device_is_the_callers_own_and_unrevoked() {
    let alice = UserId::generate();
    let own = device(alice, Some(1));

    assert_eq!(calling_device(alice, Some(own.clone())).unwrap(), own);
    assert!(matches!(
        calling_device(alice, None),
        Err(KeyDirectoryError::DeviceNotFound)
    ));
    assert!(matches!(
        calling_device(UserId::generate(), Some(own.clone())),
        Err(KeyDirectoryError::DeviceNotFound)
    ));
    assert!(matches!(
        calling_device(alice, Some(revoked(own))),
        Err(KeyDirectoryError::DeviceRevoked)
    ));
}

#[test]
fn a_device_approves_another_device_of_the_account_over_its_root_key() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, Some(1)), device(alice, Some(2)));

    let checked = by_device(&laptop, phone.id, Some(&phone), signed_by(&key(1), &phone)).unwrap();

    assert_eq!(checked.device(), phone.id);
    assert_eq!(checked.root_key(), &key(2));
    assert_eq!(checked.approver(), Approver::Device(laptop.id));
    assert_eq!(checked.approver_key(), Some(&key(1)));
    assert_eq!(checked.signature(), &signed_by(&key(1), &phone));
}

#[test]
fn a_device_never_approves_itself_with_its_root_key() {
    let laptop = device(UserId::generate(), Some(1));

    let result = by_device(
        &laptop,
        laptop.id,
        Some(&laptop),
        signed_by(&key(1), &laptop),
    );

    assert!(matches!(result, Err(KeyDirectoryError::SelfApproval)));
}

#[test]
fn a_device_approves_only_an_unrevoked_device_of_the_account_with_a_root_key() {
    let alice = UserId::generate();
    let laptop = device(alice, Some(1));
    let anothers = device(UserId::generate(), Some(2));
    let gone = revoked(device(alice, Some(3)));
    let unattested = device(alice, None);

    let signature = signed_by(&key(1), &anothers);
    assert!(matches!(
        by_device(&laptop, anothers.id, Some(&anothers), signature.clone()),
        Err(KeyDirectoryError::DeviceNotFound)
    ));
    assert!(matches!(
        by_device(&laptop, DeviceId::generate(), None, signature.clone()),
        Err(KeyDirectoryError::DeviceNotFound)
    ));
    assert!(matches!(
        by_device(&laptop, gone.id, Some(&gone), signed_by(&key(1), &gone)),
        Err(KeyDirectoryError::DeviceRevoked)
    ));
    assert!(matches!(
        by_device(&laptop, unattested.id, Some(&unattested), signature),
        Err(KeyDirectoryError::NoRootKey)
    ));
}

#[test]
fn a_device_without_a_root_key_approves_nothing() {
    let alice = UserId::generate();
    let (unattested, phone) = (device(alice, None), device(alice, Some(2)));

    let result = by_device(
        &unattested,
        phone.id,
        Some(&phone),
        signed_by(&key(1), &phone),
    );

    assert!(matches!(result, Err(KeyDirectoryError::NoRootKey)));
}

#[test]
fn a_signature_not_by_the_approver_or_not_over_the_root_key_held_is_refused() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, Some(1)), device(alice, Some(2)));
    let rotated = device(alice, Some(9));
    let other_actor = ActorUri::parse("https://idp.bob.test/users/alice_xk9mp").unwrap();

    let by_another_key = signed_by(&key(5), &phone);
    let over_another_root_key = signed_by(&key(1), &rotated);
    let for_another_actor =
        plain_signature(&key(1), &approval_bytes(&other_actor, phone.id, &key(2)));
    let for_another_device =
        plain_signature(&key(1), &approval_bytes(&actor(), laptop.id, &key(2)));

    for signature in [
        by_another_key,
        over_another_root_key,
        for_another_actor,
        for_another_device,
    ] {
        assert!(matches!(
            by_device(&laptop, phone.id, Some(&phone), signature),
            Err(KeyDirectoryError::ApprovalUnsigned)
        ));
    }
}

#[test]
fn the_passphrase_approves_the_sessions_device_with_the_current_approval_key() {
    let laptop = device(UserId::generate(), Some(1));
    let current = history_key(2, 40);

    let checked = by_passphrase(
        &laptop,
        laptop.id,
        2,
        Some(&current),
        signed_by(&current.approval_public_key, &laptop),
    )
    .unwrap();

    assert_eq!(checked.device(), laptop.id);
    assert_eq!(checked.root_key(), &key(1));
    assert_eq!(
        checked.approver(),
        Approver::Passphrase(HistoryGeneration::parse(2).unwrap())
    );
    assert_eq!(checked.approver_key(), None);
}

#[test]
fn the_passphrase_approves_no_other_device_than_the_sessions() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, Some(1)), device(alice, Some(2)));
    let current = history_key(1, 40);

    let result = by_passphrase(
        &laptop,
        phone.id,
        1,
        Some(&current),
        signed_by(&current.approval_public_key, &phone),
    );

    assert!(matches!(
        result,
        Err(KeyDirectoryError::NotTheSessionsDevice)
    ));
}

#[test]
fn the_passphrase_approves_under_the_current_generation_only() {
    let laptop = device(UserId::generate(), Some(1));
    let current = history_key(2, 40);
    let signature = signed_by(&current.approval_public_key, &laptop);

    for (generation, current) in [(1, Some(&current)), (3, Some(&current)), (1, None)] {
        assert!(
            matches!(
                by_passphrase(&laptop, laptop.id, generation, current, signature.clone()),
                Err(KeyDirectoryError::StaleHistoryKey(_))
            ),
            "{generation}"
        );
    }
}

#[test]
fn the_passphrase_approval_takes_the_current_approval_keys_signature_over_a_root_key() {
    let laptop = device(UserId::generate(), Some(1));
    let unattested = device(laptop.owner, None);
    let current = history_key(1, 40);

    let by_another_key = by_passphrase(
        &laptop,
        laptop.id,
        1,
        Some(&current),
        signed_by(&key(41), &laptop),
    );
    let by_its_own_root_key = by_passphrase(
        &laptop,
        laptop.id,
        1,
        Some(&current),
        signed_by(&key(1), &laptop),
    );
    let without_a_root_key = by_passphrase(
        &unattested,
        unattested.id,
        1,
        Some(&current),
        signed_by(&current.approval_public_key, &laptop),
    );

    assert!(matches!(
        by_another_key,
        Err(KeyDirectoryError::ApprovalUnsigned)
    ));
    assert!(matches!(
        by_its_own_root_key,
        Err(KeyDirectoryError::ApprovalUnsigned)
    ));
    assert!(matches!(
        without_a_root_key,
        Err(KeyDirectoryError::NoRootKey)
    ));
}

fn generation(raw: i64) -> HistoryGeneration {
    HistoryGeneration::parse(raw).unwrap()
}

/// `approver`'s approval of `device`'s root key as it holds it now, as the directory lists it.
fn stored(device: &Device, approver: Approver) -> Approval {
    Approval {
        device: device.id,
        root_key: device.attestation.as_ref().unwrap().root_key.clone(),
        approver,
        signature: Ed25519Signature::parse("signature", &[9; 64]).unwrap(),
        created_at: device.paired_at,
    }
}

/// Who approved each approval of the chain, from the device on.
fn chain(
    device: &Device,
    generation: HistoryGeneration,
    devices: &[Device],
    approvals: &[Approval],
) -> Option<Vec<Approver>> {
    approval_chain(device, generation, devices, approvals).map(|links| {
        links
            .into_iter()
            .map(|approval| approval.approver)
            .collect()
    })
}

#[test]
fn a_device_the_passphrase_approved_is_approved_by_one_link() {
    let alice = UserId::generate();
    let laptop = device(alice, Some(1));
    let approvals = [stored(&laptop, Approver::Passphrase(generation(1)))];

    assert_eq!(
        chain(
            &laptop,
            generation(1),
            std::slice::from_ref(&laptop),
            &approvals
        ),
        Some(vec![Approver::Passphrase(generation(1))])
    );
}

#[test]
fn a_device_approved_by_one_the_passphrase_approved_is_approved_by_two_links() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, Some(1)), device(alice, Some(2)));
    let approvals = [
        stored(&phone, Approver::Device(laptop.id)),
        stored(&laptop, Approver::Passphrase(generation(1))),
    ];
    let devices = [laptop.clone(), phone.clone()];

    assert_eq!(
        chain(&phone, generation(1), &devices, &approvals),
        Some(vec![
            Approver::Device(laptop.id),
            Approver::Passphrase(generation(1))
        ])
    );
}

#[test]
fn the_passphrase_link_is_taken_first_when_a_device_carries_both() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, Some(1)), device(alice, Some(2)));
    let approvals = [
        stored(&phone, Approver::Device(laptop.id)),
        stored(&laptop, Approver::Passphrase(generation(1))),
        stored(&phone, Approver::Passphrase(generation(1))),
    ];

    assert_eq!(
        chain(&phone, generation(1), &[laptop, phone.clone()], &approvals),
        Some(vec![Approver::Passphrase(generation(1))])
    );
}

#[test]
fn three_links_are_one_too_many() {
    let alice = UserId::generate();
    let (laptop, phone, tablet) = (
        device(alice, Some(1)),
        device(alice, Some(2)),
        device(alice, Some(3)),
    );
    let approvals = [
        stored(&laptop, Approver::Passphrase(generation(1))),
        stored(&phone, Approver::Device(laptop.id)),
        stored(&tablet, Approver::Device(phone.id)),
    ];

    assert_eq!(
        chain(
            &tablet,
            generation(1),
            &[laptop, phone, tablet.clone()],
            &approvals
        ),
        None
    );
}

#[test]
fn a_revoked_approver_approves_nothing() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, Some(1)), device(alice, Some(2)));
    let approvals = [
        stored(&phone, Approver::Device(laptop.id)),
        stored(&laptop, Approver::Passphrase(generation(1))),
    ];

    assert_eq!(
        chain(
            &phone,
            generation(1),
            &[revoked(laptop), phone.clone()],
            &approvals
        ),
        None
    );
}

#[test]
fn an_approver_not_listed_or_another_accounts_approves_nothing() {
    let (alice, bob) = (UserId::generate(), UserId::generate());
    let (bobs, phone) = (device(bob, Some(1)), device(alice, Some(2)));
    let approvals = [
        stored(&phone, Approver::Device(bobs.id)),
        stored(&bobs, Approver::Passphrase(generation(1))),
    ];

    assert_eq!(
        chain(
            &phone,
            generation(1),
            std::slice::from_ref(&phone),
            &approvals
        ),
        None
    );
    assert_eq!(
        chain(&phone, generation(1), &[bobs, phone.clone()], &approvals),
        None
    );
}

#[test]
fn an_older_generations_approval_approves_under_none_after_it() {
    let alice = UserId::generate();
    let (laptop, phone, tablet) = (
        device(alice, Some(1)),
        device(alice, Some(2)),
        device(alice, Some(3)),
    );
    let approvals = [
        stored(&laptop, Approver::Passphrase(generation(1))),
        stored(&phone, Approver::Device(laptop.id)),
        stored(&tablet, Approver::Passphrase(generation(2))),
    ];
    let devices = [laptop.clone(), phone.clone(), tablet.clone()];

    assert_eq!(chain(&laptop, generation(2), &devices, &approvals), None);
    assert_eq!(chain(&phone, generation(2), &devices, &approvals), None);
    assert_eq!(chain(&tablet, generation(1), &devices, &approvals), None);
    assert!(chain(&tablet, generation(2), &devices, &approvals).is_some());
}

#[test]
fn an_approval_of_another_root_key_or_of_a_revoked_device_counts_for_nothing() {
    let alice = UserId::generate();
    let (laptop, phone) = (device(alice, Some(1)), device(alice, Some(2)));
    let laptops = stored(&laptop, Approver::Passphrase(generation(1)));
    let phones = stored(&phone, Approver::Device(laptop.id));
    let (laptop_rotated, phone_rotated) = (device(alice, Some(8)), device(alice, Some(9)));
    let laptop_rotated = Device {
        id: laptop.id,
        ..laptop_rotated
    };
    let phone_rotated = Device {
        id: phone.id,
        ..phone_rotated
    };
    let approvals = [laptops, phones];

    assert_eq!(
        chain(
            &laptop_rotated,
            generation(1),
            std::slice::from_ref(&laptop_rotated),
            &approvals
        ),
        None
    );
    assert_eq!(
        chain(
            &phone_rotated,
            generation(1),
            &[laptop.clone(), phone_rotated.clone()],
            &approvals
        ),
        None
    );
    assert_eq!(
        chain(
            &phone,
            generation(1),
            &[laptop_rotated, phone.clone()],
            &approvals
        ),
        None,
        "its approver's root key changed"
    );
    assert_eq!(
        chain(
            &revoked(laptop.clone()),
            generation(1),
            &[laptop],
            &approvals
        ),
        None
    );
}
