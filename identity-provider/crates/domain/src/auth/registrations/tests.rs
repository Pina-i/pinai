use super::*;

#[test]
fn an_open_instance_lets_anyone_sign_up_invited_or_not() {
    for joining in [Joining::Uninvited, Joining::Invited] {
        assert!(Registrations::Open.admit(joining).is_ok(), "{joining:?}");
    }
}

#[test]
fn an_invite_only_instance_refuses_an_uninvited_sign_up() {
    assert!(matches!(
        Registrations::Invite.admit(Joining::Uninvited),
        Err(AuthError::InvitationRequired)
    ));
}

#[test]
fn an_invite_only_instance_lets_the_invited_sign_up() {
    assert!(Registrations::Invite.admit(Joining::Invited).is_ok());
}

#[test]
fn invitations_are_made_on_an_invite_only_instance_only() {
    assert!(Registrations::Invite.allow_invitations().is_ok());
    assert!(matches!(
        Registrations::Open.allow_invitations(),
        Err(AuthError::RegistrationsOpen)
    ));
}

#[test]
fn only_an_open_instance_says_its_registrations_are_open() {
    assert!(Registrations::Open.are_open());
    assert!(!Registrations::Invite.are_open());
}
