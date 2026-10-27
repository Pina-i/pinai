use super::AuthError;

/// Who may create an account on the instance, `REGISTRATIONS` — see
/// identity-provider/specs/auth.md § 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registrations {
    /// Anyone signs up, and confirms the address with a mailed code.
    Open,
    /// Only someone an admin invited signs up.
    Invite,
}

/// How someone comes to create an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joining {
    /// On their own: the register tab, `POST /register`.
    Uninvited,
    /// With an admin's invitation.
    Invited,
}

impl Registrations {
    pub fn are_open(self) -> bool {
        self == Self::Open
    }

    /// An uninvited sign-up only on an open instance. An invitation lets its person in whatever
    /// the setting: a link made while the instance was invite-only admits until it ends.
    pub fn admit(self, joining: Joining) -> Result<(), AuthError> {
        match (self, joining) {
            (Self::Open, _) => Ok(()),
            (Self::Invite, Joining::Invited) => Ok(()),
            (Self::Invite, Joining::Uninvited) => Err(AuthError::InvitationRequired),
        }
    }

    /// Invitations are made on an invite-only instance: on an open one, people sign up
    /// themselves.
    pub fn allow_invitations(self) -> Result<(), AuthError> {
        match self {
            Self::Invite => Ok(()),
            Self::Open => Err(AuthError::RegistrationsOpen),
        }
    }

    /// Someone who forgot their password asks for a reset link by mail on an open instance, which
    /// always has a relay; on an invite-only one, its admins give the links.
    pub fn allow_reset_by_mail(self) -> Result<(), AuthError> {
        match self {
            Self::Open => Ok(()),
            Self::Invite => Err(AuthError::NoResetByMail),
        }
    }
}

#[cfg(test)]
mod tests;
