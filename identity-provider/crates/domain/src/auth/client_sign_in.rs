use crate::UserId;

use super::{AuthorizationRequest, ClientId};

/// An app an account signed in to here with its password. A live session signs in again to
/// these only: a site that just sends the browser to `/authorize` gets the login page, never a
/// code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSignIn {
    pub user: UserId,
    pub client: ClientId,
    /// It asked to stay signed in on its device.
    pub offline_access: bool,
}

impl ClientSignIn {
    /// What a sign-in answering `request` leaves, once the password is through.
    pub fn of(user: UserId, request: &AuthorizationRequest) -> Self {
        Self {
            user,
            client: request.client.clone(),
            offline_access: request.asks_offline_access(),
        }
    }

    /// Whether a live session answers `request` without the password: the same app, asking to
    /// stay signed in only if this sign-in did.
    pub fn covers(&self, request: &AuthorizationRequest) -> bool {
        self.client == request.client && (self.offline_access || !request.asks_offline_access())
    }
}

#[cfg(test)]
mod tests;
