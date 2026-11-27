//! Push notices handed to the relay each device named, in Expo's message format — the relay
//! protocol of identity-provider/specs/push.md, which a relay of our own takes too.

use anyhow::Context;
use domain::e2ee::{
    Delivery, PUSH_CHANNEL, PUSH_NOTICE_TTL, PushNotice, PushRegistration, PushRelays,
};
use federation_transport::UrlPolicy;
use federation_transport::http::{client, read_capped, screen_url};
use reqwest::header::ACCEPT;
use serde::Deserialize;
use serde_json::json;

/// Every relay asked through the federation's screened client: a relay's address is one a device
/// chose, so private space, redirects and slow answers are refused as a peer's are.
pub struct ExpoRelays {
    policy: UrlPolicy,
}

impl ExpoRelays {
    pub fn new(policy: UrlPolicy) -> Self {
        Self { policy }
    }
}

#[derive(Deserialize)]
struct Tickets {
    #[serde(default)]
    data: Vec<Ticket>,
}

#[derive(Deserialize)]
struct Ticket {
    status: String,
    details: Option<TicketDetails>,
}

/// Only the error's code is read: the relay's message names the token.
#[derive(Deserialize)]
struct TicketDetails {
    error: Option<String>,
}

#[async_trait::async_trait]
impl PushRelays for ExpoRelays {
    async fn send(&self, to: &PushRegistration, notice: PushNotice) -> anyhow::Result<Delivery> {
        let url = screen_url(to.relay.as_str(), self.policy).context("screen a relay's address")?;
        let messages = json!([{
            "to": to.token.as_str(),
            "title": notice.title(),
            "body": notice.body(),
            "tag": notice.tag(),
            "priority": "high",
            "ttl": PUSH_NOTICE_TTL.whole_seconds(),
            "channelId": PUSH_CHANNEL,
            "data": { "kind": notice.kind() },
        }]);
        let response = client(self.policy)
            .post(url)
            .header(ACCEPT, "application/json")
            .json(&messages)
            .send()
            .await
            .context("reach a relay")?;
        let status = response.status();
        // The answer's words may list the token: the status alone is told.
        anyhow::ensure!(status.is_success(), "a relay answered {status}");
        let body = read_capped(response)
            .await
            .context("read a relay's answer")?;
        let tickets: Tickets = serde_json::from_slice(&body).context("decode a relay's answer")?;
        let ticket = tickets
            .data
            .into_iter()
            .next()
            .context("a relay answered no ticket")?;
        if ticket.status == "ok" {
            return Ok(Delivery::Sent);
        }
        match ticket.details.and_then(|details| details.error).as_deref() {
            Some("DeviceNotRegistered") => Ok(Delivery::Gone),
            code => anyhow::bail!("a relay refused a notice: {}", code.unwrap_or("no code")),
        }
    }
}

#[cfg(test)]
mod tests;
