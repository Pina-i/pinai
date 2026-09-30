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
    pub totp_enabled: bool,
}
