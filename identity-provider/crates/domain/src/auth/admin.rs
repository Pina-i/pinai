use crate::profile::DisplayName;

use super::{AuthError, Email, check_password};

/// The name the instance's first admin account is created with.
pub fn admin_display_name() -> DisplayName {
    DisplayName::parse("Admin").expect("a name within the rules")
}

/// Who has the address the instance is told to make its admin's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressHolder {
    Nobody,
    Admin,
    NotAdmin,
}

/// What the store tells of the instance's admins as it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminFacts {
    /// Who has the address asked about; `Nobody` when none was.
    pub holder: AddressHolder,
    pub admin_exists: bool,
}

/// The password the admin account is created with, within the instance's rule.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminPassword(String);

impl AdminPassword {
    pub fn parse(raw: &str) -> Result<Self, AdminRefusal> {
        match check_password(raw) {
            Ok(()) => Ok(Self(raw.to_owned())),
            Err(AuthError::PasswordTooShort) => Err(AdminRefusal::PasswordTooShort),
            Err(other) => Err(AdminRefusal::PasswordRefused(other.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AdminPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminPassword(..)")
    }
}

/// The admin account to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAdmin {
    pub address: Email,
    pub password: AdminPassword,
}

/// What starting the instance does about its admin. `Create` holds the account to create, and
/// once it is created, what is told of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminBootstrap<Account> {
    /// No account has the address: the admin account is created with it and the password.
    Create(Account),
    /// The admin has the address already, and keeps its password: one it chose is never
    /// reverted. `password_unused` when a password is still configured.
    AlreadyAdmin { password_unused: bool },
    /// An account that is not an admin has the address, and is not made one: a typo must not
    /// make a stranger admin. `no_admin` when the instance has none at all.
    NotPromoted { no_admin: bool },
    /// No address is configured, and the instance has no admin.
    NoAdmin,
    /// No address is configured, and the instance has its admin.
    Settled,
    /// The admin account can't be created: the instance must not start.
    Refused(AdminRefusal),
}

impl<Account> AdminBootstrap<Account> {
    pub fn map_create<Told>(self, tell: impl FnOnce(Account) -> Told) -> AdminBootstrap<Told> {
        match self {
            Self::Create(account) => AdminBootstrap::Create(tell(account)),
            Self::AlreadyAdmin { password_unused } => {
                AdminBootstrap::AlreadyAdmin { password_unused }
            }
            Self::NotPromoted { no_admin } => AdminBootstrap::NotPromoted { no_admin },
            Self::NoAdmin => AdminBootstrap::NoAdmin,
            Self::Settled => AdminBootstrap::Settled,
            Self::Refused(refusal) => AdminBootstrap::Refused(refusal),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminRefusal {
    /// The configured address is not one: the rule it breaks.
    BadAddress(String),
    NoPassword,
    PasswordTooShort,
    /// The password breaks another of the instance's rules.
    PasswordRefused(String),
}

/// What starting does about the admin: `configured` is the admin's address, with who has it.
pub fn admin_bootstrap(
    admin_exists: bool,
    configured: Option<(Email, AddressHolder)>,
    password: Option<&str>,
) -> AdminBootstrap<NewAdmin> {
    let Some((address, holder)) = configured else {
        return if admin_exists {
            AdminBootstrap::Settled
        } else {
            AdminBootstrap::NoAdmin
        };
    };
    match holder {
        AddressHolder::Admin => AdminBootstrap::AlreadyAdmin {
            password_unused: password.is_some(),
        },
        AddressHolder::NotAdmin => AdminBootstrap::NotPromoted {
            no_admin: !admin_exists,
        },
        AddressHolder::Nobody => match password.map(AdminPassword::parse) {
            None => AdminBootstrap::Refused(AdminRefusal::NoPassword),
            Some(Err(refusal)) => AdminBootstrap::Refused(refusal),
            Some(Ok(password)) => AdminBootstrap::Create(NewAdmin { address, password }),
        },
    }
}

#[cfg(test)]
mod tests;
