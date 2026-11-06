use super::*;
use crate::UserId;
use crate::e2ee::testing::{PlainEd25519Verifier, plain_signature};
use crate::e2ee::{ATTESTATION_LIFETIME, Approver, Attestation, DeviceLabel, HeldHpkeKey};

fn actor() -> ActorUri {
    ActorUri::parse("https://idp.alice.test/users/alice_xk9mp").unwrap()
}

fn generation(raw: i64) -> HistoryGeneration {
    HistoryGeneration::parse(raw).unwrap()
}

fn key(byte: u8) -> DeviceRootKey {
    DeviceRootKey::parse(&[byte; 32]).unwrap()
}

/// A device of `owner`'s, its root key and HPKE key made of `root`s, holding `holds`.
fn device(owner: UserId, root: u8, holds: Option<i64>) -> Device {
    let at = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        paired_at: at,
        last_seen_at: at,
        revoked_at: None,
        attestation: Some(Attestation {
            root_key: key(root),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: at,
            expires_at: at + ATTESTATION_LIFETIME,
        }),
        hpke_key: Some(HeldHpkeKey {
            key: HpkePublicKey::parse(&[root; 32]).unwrap(),
            signature: Ed25519Signature::parse("hpke_key_signature", &[7; 64]).unwrap(),
        }),
        history_generation: holds.map(generation),
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

/// The share's seal, signed by `root` as the sender's root key would sign it.
fn sealed(root: u8, sender: DeviceId, recipient: DeviceId, generation_signed: i64) -> SealedShare {
    let enc = ShareEnc::parse(&[4; 32]).unwrap();
    let ciphertext = ShareCiphertext::parse(vec![5; 100]).unwrap();
    let aad = share_aad(&actor(), sender, recipient, generation(generation_signed));
    SealedShare {
        signature: plain_signature(&key(root), &share_signed_bytes(&aad, &enc, &ciphertext)),
        enc,
        ciphertext,
    }
}

/// An account whose laptop holds generation 1, approved by the passphrase, and whose phone the
/// laptop approved.
#[derive(Clone)]
struct Account {
    owner: UserId,
    laptop: Device,
    phone: Device,
    devices: Vec<Device>,
    approvals: Vec<Approval>,
    current: Option<HistoryGeneration>,
}

fn account() -> Account {
    let owner = UserId::generate();
    let laptop = device(owner, 1, Some(1));
    let phone = device(owner, 2, None);
    Account {
        approvals: vec![
            approval(&laptop, Approver::Passphrase(generation(1))),
            approval(&phone, Approver::Device(laptop.id)),
        ],
        devices: vec![laptop.clone(), phone.clone()],
        owner,
        laptop,
        phone,
        current: Some(generation(1)),
    }
}

impl Account {
    /// The same account, `changed` in place of the device with its id.
    fn with(&self, changed: Device) -> Self {
        let mut account = self.clone();
        for held in &mut account.devices {
            if held.id == changed.id {
                *held = changed.clone();
            }
        }
        if account.laptop.id == changed.id {
            account.laptop = changed.clone();
        }
        if account.phone.id == changed.id {
            account.phone = changed;
        }
        account
    }

    fn adding(&self, device: Device) -> Self {
        let mut account = self.clone();
        account.devices.push(device);
        account
    }

    /// The laptop's share for `recipient` under `named`, signed over it.
    fn share_to(&self, recipient: DeviceId, named: i64) -> Result<CheckedShare, KeyDirectoryError> {
        let seal = sealed(1, self.laptop.id, recipient, named);
        self.share(&self.laptop, recipient, named, seal)
    }

    fn share_to_phone(&self) -> Result<CheckedShare, KeyDirectoryError> {
        self.share_to(self.phone.id, 1)
    }

    fn share(
        &self,
        sender: &Device,
        recipient: DeviceId,
        named: i64,
        sealed: SealedShare,
    ) -> Result<CheckedShare, KeyDirectoryError> {
        let facts = ShareFacts {
            actor: &actor(),
            sender,
            devices: &self.devices,
            approvals: &self.approvals,
            current: self.current,
        };
        may_share(
            recipient,
            generation(named),
            sealed,
            facts,
            &PlainEd25519Verifier,
        )
    }
}

#[test]
fn a_share_binds_its_account_devices_and_generation_as_the_spec_writes_them() {
    let sender =
        DeviceId::from(uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap());
    let recipient =
        DeviceId::from(uuid::Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap());
    let enc = ShareEnc::parse(&[1; 32]).unwrap();
    let ciphertext = ShareCiphertext::parse(b"sealed words".to_vec()).unwrap();

    let aad = share_aad(&actor(), sender, recipient, generation(12));
    let signed = share_signed_bytes(&aad, &enc, &ciphertext);

    assert_eq!(
        String::from_utf8(aad).unwrap(),
        "PINAI-HISTORY-SHARE-v1\n\
         https://idp.alice.test/users/alice_xk9mp\n\
         550e8400-e29b-41d4-a716-446655440000\n\
         6ba7b810-9dad-11d1-80b4-00c04fd430c8\n\
         12"
    );
    assert_eq!(
        String::from_utf8(signed).unwrap(),
        "PINAI-HISTORY-SHARE-v1\n\
         https://idp.alice.test/users/alice_xk9mp\n\
         550e8400-e29b-41d4-a716-446655440000\n\
         6ba7b810-9dad-11d1-80b4-00c04fd430c8\n\
         12\n\
         AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
         c2VhbGVkIHdvcmRz"
    );
}

#[test]
fn the_seal_is_32_bytes_and_its_ciphertext_a_kibibyte_at_most() {
    assert!(ShareEnc::parse(&[1; 31]).is_err());
    assert!(ShareEnc::parse(&[1; 33]).is_err());
    assert!(ShareCiphertext::parse(Vec::new()).is_err());
    assert!(ShareCiphertext::parse(vec![1; KEY_SHARE_CIPHERTEXT_MAX_BYTES + 1]).is_err());
    assert!(ShareCiphertext::parse(vec![1; KEY_SHARE_CIPHERTEXT_MAX_BYTES]).is_ok());
}

#[test]
fn a_holder_approved_by_the_passphrase_shares_with_a_device_it_approved() {
    let a = account();

    let checked = a.share_to_phone().unwrap();

    assert_eq!(
        (checked.sender(), checked.recipient(), checked.generation()),
        (a.laptop.id, a.phone.id, generation(1))
    );
    assert_eq!(
        (
            checked.sender_key(),
            checked.recipient_key(),
            checked.recipient_hpke_key()
        ),
        (&key(1), &key(2), &HpkePublicKey::parse(&[2; 32]).unwrap())
    );
    assert_eq!(checked.sealed(), &sealed(1, a.laptop.id, a.phone.id, 1));
    let relied_on: Vec<_> = checked
        .relied_on()
        .iter()
        .map(|approval| (approval.device, approval.approver))
        .collect();
    assert_eq!(
        relied_on,
        vec![
            (a.laptop.id, Approver::Passphrase(generation(1))),
            (a.phone.id, Approver::Device(a.laptop.id)),
        ]
    );
}

#[test]
fn only_a_device_that_approved_the_recipient_shares_with_it() {
    let a = account();
    let tablet = device(a.owner, 3, Some(1));
    let mut another_holder = a.adding(tablet.clone());
    another_holder
        .approvals
        .push(approval(&tablet, Approver::Passphrase(generation(1))));
    let mut of_an_old_root_key = another_holder.clone();
    of_an_old_root_key.approvals.push(Approval {
        approver: Approver::Device(tablet.id),
        root_key: key(9),
        ..approval(&a.phone, Approver::Device(tablet.id))
    });
    let mut approved_by_it = another_holder.clone();
    approved_by_it
        .approvals
        .push(approval(&a.phone, Approver::Device(tablet.id)));
    let from = |account: &Account| {
        account.share(&tablet, a.phone.id, 1, sealed(3, tablet.id, a.phone.id, 1))
    };

    assert!(matches!(
        from(&another_holder),
        Err(KeyDirectoryError::NotTheApprover)
    ));
    assert!(matches!(
        from(&of_an_old_root_key),
        Err(KeyDirectoryError::NotTheApprover)
    ));
    let checked = from(&approved_by_it).unwrap();
    assert!(
        checked
            .relied_on()
            .iter()
            .any(|approval| approval.device == a.phone.id
                && approval.approver == Approver::Device(tablet.id)),
        "the sender's approval of the recipient is held for the write"
    );
}

#[test]
fn a_device_shares_with_another_unrevoked_device_of_the_account() {
    let a = account();
    let bobs = device(UserId::generate(), 3, None);
    let revoked = Device {
        revoked_at: Some(a.phone.paired_at),
        ..a.phone.clone()
    };

    let itself = a.share_to(a.laptop.id, 1);
    let unknown = a.share_to(DeviceId::generate(), 1);
    let anothers = a.adding(bobs.clone()).share_to(bobs.id, 1);
    let to_revoked = a.with(revoked).share_to_phone();

    assert!(matches!(itself, Err(KeyDirectoryError::SelfShare)));
    assert!(matches!(unknown, Err(KeyDirectoryError::DeviceNotFound)));
    assert!(matches!(anothers, Err(KeyDirectoryError::DeviceNotFound)));
    assert!(matches!(to_revoked, Err(KeyDirectoryError::DeviceRevoked)));
}

#[test]
fn a_share_is_of_the_current_generation_only() {
    let none_set = Account {
        current: None,
        ..account()
    };
    let moved_on = Account {
        current: Some(generation(2)),
        ..account()
    };

    assert!(matches!(
        none_set.share_to_phone(),
        Err(KeyDirectoryError::StaleHistoryKey(_))
    ));
    assert!(matches!(
        moved_on.share_to_phone(),
        Err(KeyDirectoryError::StaleHistoryKey(_))
    ));
}

#[test]
fn the_sender_holds_the_generation_and_is_approved_under_it() {
    let a = account();
    let unattested = Device {
        attestation: None,
        hpke_key: None,
        ..a.laptop.clone()
    };
    let not_holding = Device {
        history_generation: None,
        ..a.laptop.clone()
    };
    let unapproved = Account {
        approvals: vec![approval(&a.phone, Approver::Device(a.laptop.id))],
        ..a.clone()
    };

    assert!(matches!(
        a.with(unattested).share_to_phone(),
        Err(KeyDirectoryError::NoRootKey)
    ));
    assert!(matches!(
        a.with(not_holding).share_to_phone(),
        Err(KeyDirectoryError::HistoryKeyNotHeld)
    ));
    assert!(matches!(
        unapproved.share_to_phone(),
        Err(KeyDirectoryError::SenderNotApproved)
    ));
}

#[test]
fn the_recipient_has_keys_is_approved_and_holds_nothing_yet() {
    let a = account();
    let unattested = Device {
        attestation: None,
        hpke_key: None,
        ..a.phone.clone()
    };
    let without_hpke = Device {
        hpke_key: None,
        ..a.phone.clone()
    };
    let holding = Device {
        history_generation: Some(generation(1)),
        ..a.phone.clone()
    };
    let unapproved = Account {
        approvals: vec![approval(&a.laptop, Approver::Passphrase(generation(1)))],
        ..a.clone()
    };

    assert!(matches!(
        a.with(unattested).share_to_phone(),
        Err(KeyDirectoryError::NoRootKey)
    ));
    assert!(matches!(
        a.with(without_hpke).share_to_phone(),
        Err(KeyDirectoryError::NoHpkeKey)
    ));
    assert!(matches!(
        unapproved.share_to_phone(),
        Err(KeyDirectoryError::RecipientNotApproved)
    ));
    assert!(matches!(
        a.with(holding).share_to_phone(),
        Err(KeyDirectoryError::HistoryKeyHeld)
    ));
}

#[test]
fn a_recipient_approved_through_a_revoked_device_or_under_an_older_generation_is_not() {
    let a = account();
    let tablet = device(a.owner, 3, Some(1));
    let tablets_approval = approval(&tablet, Approver::Passphrase(generation(1)));
    let mut through_a_revoked = a.adding(tablet.clone()).with(Device {
        revoked_at: Some(a.laptop.paired_at),
        ..a.laptop.clone()
    });
    through_a_revoked.approvals.push(tablets_approval);
    let next = Device {
        history_generation: Some(generation(2)),
        ..tablet.clone()
    };
    let mut moved_on = a.adding(next.clone());
    moved_on
        .approvals
        .push(approval(&next, Approver::Passphrase(generation(2))));
    moved_on.current = Some(generation(2));

    let refused_through_a_revoked =
        through_a_revoked.share(&tablet, a.phone.id, 1, sealed(3, tablet.id, a.phone.id, 1));
    let refused_under_an_older =
        moved_on.share(&next, a.phone.id, 2, sealed(3, next.id, a.phone.id, 2));

    assert!(matches!(
        refused_through_a_revoked,
        Err(KeyDirectoryError::RecipientNotApproved)
    ));
    assert!(matches!(
        refused_under_an_older,
        Err(KeyDirectoryError::RecipientNotApproved)
    ));
}

#[test]
fn the_share_is_signed_by_the_senders_root_key_over_its_recipient_and_generation() {
    let a = account();
    let tablet = device(a.owner, 3, None);
    let tampered = SealedShare {
        ciphertext: ShareCiphertext::parse(vec![6; 100]).unwrap(),
        ..sealed(1, a.laptop.id, a.phone.id, 1)
    };

    for seal in [
        sealed(9, a.laptop.id, a.phone.id, 1),
        sealed(1, a.laptop.id, tablet.id, 1),
        sealed(1, a.laptop.id, a.phone.id, 2),
        sealed(1, a.phone.id, a.phone.id, 1),
        tampered,
    ] {
        assert!(matches!(
            a.share(&a.laptop, a.phone.id, 1, seal),
            Err(KeyDirectoryError::ShareUnsigned)
        ));
    }
}
