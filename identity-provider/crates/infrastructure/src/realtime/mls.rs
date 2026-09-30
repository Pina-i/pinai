use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use connections::Hub;
use domain::UserId;
use domain::e2ee::{Commit, MlsNotifier, Welcome};

use super::events::{MlsCommitPayload, MlsWelcomeReadyPayload, WsEvent};

/// Pushes commits and Welcome notices to an account's live sessions; a client that missed one
/// catches up through the log, or polls its Welcomes on login.
pub struct HubMlsNotifier {
    hub: Arc<Hub>,
}

impl HubMlsNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }
}

impl MlsNotifier for HubMlsNotifier {
    fn committed(&self, to: UserId, commit: &Commit) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::MlsCommit(MlsCommitPayload {
                conversation_id: commit.conversation.as_uuid(),
                epoch: commit.epoch.value(),
                proposer_actor_uri: commit.proposer.to_string(),
                commit_blob: B64.encode(commit.blob.as_bytes()),
                created_at: commit.created_at,
            }),
        );
    }

    fn welcome_ready(&self, to: UserId, welcome: &Welcome) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::MlsWelcomeReady(MlsWelcomeReadyPayload {
                conversation_id: welcome.conversation.as_uuid(),
                recipient_device_id: welcome.device.as_uuid(),
            }),
        );
    }
}
