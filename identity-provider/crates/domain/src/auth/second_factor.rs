use crate::UserId;
use crate::ValidationError;

use super::AuthorizationRequest;

/// Guesses per login ticket; then the password step must be cleared again.
pub const TICKET_ATTEMPTS: i32 = 5;
pub const RECOVERY_CODES: usize = 10;

/// An authenticator's shared secret: 160 bits (RFC 4226), kept by this instance and the app.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(Vec<u8>);

impl TotpSecret {
    pub const LEN: usize = 20;

    pub fn parse(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.len() != Self::LEN {
            return Err(ValidationError::new("totp secret", "20 bytes"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret(..)")
    }
}

/// A sign-in waiting for its second factor: who, answering which request, and how many guesses
/// it has had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub user: UserId,
    pub request: AuthorizationRequest,
    pub attempts: i32,
}

/// An attempt reserved on a ticket, before its code is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketAttempt {
    /// This attempt counted; `attempts` includes it.
    Open(Ticket),
    /// The ticket had its guesses.
    Exhausted,
    /// Spent, expired, or never opened.
    Gone,
}

/// What enrolling shows the user: the secret for manual entry, and the URL a QR code encodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub secret_base32: String,
    pub provisioning_url: String,
}
