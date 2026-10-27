use std::sync::Arc;

use domain::TicketId;
use domain::auth::{
    AuthError, AuthorizationRequest, Client, Clients, InvitationToken, Invitations, LoginTickets,
    OpenInvitation, OpenReset, PasswordResets, ResetToken,
};
use time::OffsetDateTime;

/// What a sign-in page needs before it is shown: a request from a client it may go back to, so
/// that its cancel link never points anywhere else — or, on an invitation's pages, the
/// invitation, and on a reset link's page the link, while it is open.
pub struct ShowSignIn {
    clients: Arc<dyn Clients>,
    tickets: Arc<dyn LoginTickets>,
    invitations: Arc<dyn Invitations>,
    resets: Arc<dyn PasswordResets>,
}

impl ShowSignIn {
    pub fn new(
        clients: Arc<dyn Clients>,
        tickets: Arc<dyn LoginTickets>,
        invitations: Arc<dyn Invitations>,
        resets: Arc<dyn PasswordResets>,
    ) -> Self {
        Self {
            clients,
            tickets,
            invitations,
            resets,
        }
    }

    /// The invitation `token` names, while it is open.
    pub async fn invitation(
        &self,
        token: &InvitationToken,
        now: OffsetDateTime,
    ) -> Result<Option<OpenInvitation>, AuthError> {
        self.invitations.find_open(token, now).await
    }

    /// The reset link `token` names, while it is open.
    pub async fn password_reset(
        &self,
        token: &ResetToken,
        now: OffsetDateTime,
    ) -> Result<Option<OpenReset>, AuthError> {
        self.resets.find_open(token, now).await
    }

    /// The request's client, if it lists the request's redirect URI.
    pub async fn request(&self, request: &AuthorizationRequest) -> Result<Client, AuthError> {
        let client = self
            .clients
            .find(&request.client)
            .await?
            .ok_or(AuthError::UnknownClient)?;
        if !client.allows(&request.redirect_uri) {
            return Err(AuthError::UnregisteredRedirect);
        }
        Ok(client)
    }

    /// The request a second-factor ticket carries, while it is open. Checked when the ticket was
    /// opened.
    pub async fn ticket(
        &self,
        ticket: TicketId,
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationRequest>, AuthError> {
        Ok(self
            .tickets
            .find(ticket, now)
            .await?
            .map(|ticket| ticket.request))
    }
}

#[cfg(test)]
mod tests;
