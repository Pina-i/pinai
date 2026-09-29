use std::sync::Arc;

use std::collections::HashMap;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{Conversations, HistoryCursor, Message, Messages, MessagingError};
use domain::{ConversationId, UserId};

use super::shared::{member_account, sender_name};

pub struct HistoryEntry {
    pub message: Message,
    pub sender_display_name: Option<String>,
}

/// `GET /api/dm/{id}`: a page of a conversation, newest first. Reading the first page marks the
/// conversation read.
pub struct LoadHistory {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
}

impl LoadHistory {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            messages,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        conversation: ConversationId,
        before: Option<HistoryCursor>,
        limit: Option<i64>,
    ) -> Result<Vec<HistoryEntry>, MessagingError> {
        let reader =
            member_account(&*self.accounts, &*self.conversations, caller, conversation).await?;
        let limit = limit.unwrap_or(50).min(100);
        let page = self.messages.history(conversation, before, limit).await?;

        let mut names: HashMap<ActorUri, Option<String>> = HashMap::new();
        let mut entries = Vec::with_capacity(page.len());
        for message in page {
            let name = match names.get(&message.sender) {
                Some(name) => name.clone(),
                None => {
                    let name =
                        sender_name(&*self.accounts, &*self.remote_actors, &message.sender).await?;
                    names.insert(message.sender.clone(), name.clone());
                    name
                }
            };
            entries.push(HistoryEntry {
                message,
                sender_display_name: name,
            });
        }

        if before.is_none() {
            // Reading the page succeeded; a lost read marker only leaves a badge behind.
            if let Err(e) = self.conversations.mark_read(reader.id, conversation).await {
                tracing::warn!(%conversation, error = ?e, "failed to mark the conversation read");
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests;
