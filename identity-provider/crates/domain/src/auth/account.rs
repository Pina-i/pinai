use crate::UserId;

/// A stored password hash, opaque here.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordHash(..)")
    }
}

/// An account as signing in sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInAccount {
    pub id: UserId,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: PasswordHash,
    pub email_verified: bool,
    /// Let in without confirming its address, someone having vouched for it.
    pub admitted: bool,
    /// An admin of the instance.
    pub admin: bool,
    pub totp_enabled: bool,
}

impl SignInAccount {
    /// Its address must be confirmed with a mailed code before it signs in.
    pub fn needs_code(&self) -> bool {
        !self.email_verified && !self.admitted
    }
}

#[cfg(test)]
mod tests;
