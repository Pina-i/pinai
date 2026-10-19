use std::sync::Arc;

use domain::auth::{AuthError, ClientId, Clients};

/// `GET /logout`: the session ends, and the browser goes back where its client asked if the
/// client listed that place.
pub struct LogOut {
    clients: Arc<dyn Clients>,
}

impl LogOut {
    pub fn new(clients: Arc<dyn Clients>) -> Self {
        Self { clients }
    }

    /// Where to send the browser; `None` for this instance's root.
    pub async fn execute(
        &self,
        client: Option<&str>,
        return_to: Option<&str>,
    ) -> Result<Option<String>, AuthError> {
        let (Some(client), Some(uri)) = (client, return_to) else {
            return Ok(None);
        };
        let listed = match ClientId::parse(client) {
            Ok(id) => self
                .clients
                .find(&id)
                .await?
                .is_some_and(|client| client.may_return_to(uri)),
            Err(_) => false,
        };
        if !listed {
            tracing::warn!(client, uri, "post-logout redirect refused");
            return Ok(None);
        }
        Ok(Some(uri.to_owned()))
    }
}

#[cfg(test)]
mod tests;
