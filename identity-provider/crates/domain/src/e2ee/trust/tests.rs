use time::OffsetDateTime;

use super::*;
use crate::UserId;
use crate::e2ee::{
    ATTESTATION_LIFETIME, Approver, Attestation, DeviceLabel, DeviceRootKey, Ed25519Signature,
};

fn generation(raw: i64) -> HistoryGeneration {
    HistoryGeneration::parse(raw).unwrap()
}

fn device(owner: UserId, root: u8) -> Device {
    let at = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        paired_at: at,
        last_seen_at: at,
        revoked_at: None,
        attestation: Some(Attestation {
            root_key: DeviceRootKey::parse(&[root; 32]).unwrap(),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: at,
            expires_at: at + ATTESTATION_LIFETIME,
        }),
        hpke_key: None,
        history_generation: None,
    }
}

fn approval(device: &Device, approver: Approver) -> Approval {
    Approval {
        device: device.id,
        root_key: device.attestation.as_ref().unwrap().root_key.clone(),
        approver,
        signature: Ed25519Signature::parse("signature", &[9; 64]).unwrap(),
        created_at: device.paired_at,
    }
}

/// An account under generation 2: the laptop approved by its words, the phone by the laptop, the
/// tablet by generation 1's words only, and a new device nobody approved.
struct Account {
    laptop: Device,
    phone: Device,
    tablet: Device,
    fresh: Device,
    trust: DeviceTrust,
}

fn account() -> Account {
    let alice = UserId::generate();
    let (laptop, phone, tablet, fresh) = (
        device(alice, 1),
        device(alice, 2),
        device(alice, 3),
        device(alice, 4),
    );
    let approvals = vec![
        approval(&laptop, Approver::Passphrase(generation(2))),
        approval(&phone, Approver::Device(laptop.id)),
        approval(&tablet, Approver::Passphrase(generation(1))),
    ];
    Account {
        trust: DeviceTrust {
            devices: vec![laptop.clone(), phone.clone(), tablet.clone(), fresh.clone()],
            approvals,
            current: Some(generation(2)),
        },
        laptop,
        phone,
        tablet,
        fresh,
    }
}

#[test]
fn approved_is_the_stored_approvals_structure_under_the_current_generation() {
    let a = account();

    assert!(a.trust.is_approved(a.laptop.id));
    assert!(a.trust.is_approved(a.phone.id), "two links");
    assert!(
        !a.trust.is_approved(a.tablet.id),
        "an older generation's words"
    );
    assert!(!a.trust.is_approved(a.fresh.id));
    assert_eq!(
        a.trust.approved_under(generation(2)),
        vec![a.laptop.id, a.phone.id]
    );
    assert_eq!(a.trust.approved_under(generation(1)), vec![a.tablet.id]);
}

#[test]
fn with_no_history_key_no_device_is_approved() {
    let mut a = account();
    a.trust.current = None;

    assert!(!a.trust.is_approved(a.laptop.id));
}

#[test]
fn an_approved_device_revokes_any_device_of_the_account() {
    let a = account();

    for target in [&a.phone, &a.tablet, &a.fresh] {
        assert_eq!(
            may_revoke(target.id, Some(a.laptop.id), &a.trust),
            Ok(()),
            "{:?}",
            target.id
        );
    }
}

#[test]
fn a_device_not_approved_revokes_only_unapproved_devices_and_itself() {
    let a = account();

    assert_eq!(
        may_revoke(a.laptop.id, Some(a.fresh.id), &a.trust),
        Err(ApprovalRequired)
    );
    assert_eq!(
        may_revoke(a.phone.id, Some(a.tablet.id), &a.trust),
        Err(ApprovalRequired)
    );
    assert_eq!(may_revoke(a.tablet.id, Some(a.fresh.id), &a.trust), Ok(()));
    assert_eq!(may_revoke(a.fresh.id, Some(a.fresh.id), &a.trust), Ok(()));
}

#[test]
fn a_session_that_named_no_device_revokes_no_approved_device() {
    let a = account();

    assert_eq!(
        may_revoke(a.phone.id, None, &a.trust),
        Err(ApprovalRequired)
    );
    assert_eq!(may_revoke(a.fresh.id, None, &a.trust), Ok(()));
}

#[test]
fn an_approved_device_revokes_itself() {
    let a = account();

    assert_eq!(may_revoke(a.phone.id, Some(a.phone.id), &a.trust), Ok(()));
}

#[test]
fn an_account_with_no_history_key_keeps_the_rule_of_any_device_of_its_own() {
    let mut a = account();
    a.trust.current = None;

    assert_eq!(may_revoke(a.laptop.id, Some(a.fresh.id), &a.trust), Ok(()));
    assert_eq!(may_revoke(a.laptop.id, None, &a.trust), Ok(()));
}

#[test]
fn only_an_approved_device_turns_the_second_factor_on_once_the_account_has_a_key() {
    let a = account();
    let mut without_a_key = account();
    without_a_key.trust.current = None;

    assert_eq!(
        may_turn_on_second_factor(Some(a.phone.id), &a.trust),
        Ok(())
    );
    assert_eq!(
        may_turn_on_second_factor(Some(a.fresh.id), &a.trust),
        Err(ApprovalRequired)
    );
    assert_eq!(
        may_turn_on_second_factor(None, &a.trust),
        Err(ApprovalRequired)
    );
    assert_eq!(
        may_turn_on_second_factor(None, &without_a_key.trust),
        Ok(())
    );
}
