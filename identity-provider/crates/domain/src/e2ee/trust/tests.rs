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
fn an_approved_device_acts_beyond_the_password_once_the_account_has_a_key() {
    let a = account();

    for device in [&a.laptop, &a.phone] {
        assert_eq!(
            may_act_beyond_the_password(Some(device.id), &a.trust),
            Ok(()),
            "{:?}",
            device.id
        );
    }
}

#[test]
fn a_device_not_approved_or_a_session_naming_none_does_not_once_the_account_has_a_key() {
    let a = account();

    for named in [Some(a.fresh.id), Some(a.tablet.id), None] {
        assert_eq!(
            may_act_beyond_the_password(named, &a.trust),
            Err(ApprovalRequired),
            "{named:?}"
        );
    }
}

#[test]
fn a_revoked_device_no_longer_acts_beyond_the_password() {
    let mut a = account();
    let laptop = a
        .trust
        .devices
        .iter_mut()
        .find(|device| device.id == a.laptop.id)
        .unwrap();
    laptop.revoked_at = Some(laptop.paired_at);

    assert_eq!(
        may_act_beyond_the_password(Some(a.laptop.id), &a.trust),
        Err(ApprovalRequired)
    );
    assert_eq!(
        may_act_beyond_the_password(Some(a.phone.id), &a.trust),
        Err(ApprovalRequired),
        "approved through the laptop only"
    );
}

#[test]
fn an_account_with_no_history_key_lets_any_session_act_beyond_the_password() {
    let mut a = account();
    a.trust.current = None;

    for named in [Some(a.fresh.id), Some(a.laptop.id), None] {
        assert_eq!(
            may_act_beyond_the_password(named, &a.trust),
            Ok(()),
            "{named:?}"
        );
    }
}
