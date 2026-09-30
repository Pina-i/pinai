use std::sync::Arc;

use domain::auth::{AuthError, Clients, may_return_after_logout};

/// `GET /logout`: the session ends, and the browser goes back where it asked if it may.
pub struct LogOut {
    clients: Arc<dyn Clients>,
}

impl LogOut {
    pub fn new(clients: Arc<dyn Clients>) -> Self {
        Self { clients }
    }

    /// Where to send the browser; `None` for this instance's root.
    pub async fn execute(&self, return_to: Option<&str>) -> Result<Option<String>, AuthError> {
        let Some(uri) = return_to else {
            return Ok(None);
        };
        if !may_return_after_logout(uri, &self.clients.all().await?) {
            tracing::warn!(uri, "post-logout redirect refused");
            return Ok(None);
        }
        Ok(Some(uri.to_owned()))
    }
}

#[cfg(test)]
mod tests;
