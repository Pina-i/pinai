use std::sync::Arc;

use std::collections::HashMap;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    Conversations, EventWindow, GroupEvents, HistoryCursor, Message, Messages, MessagingError,
    NamedEvent,
};
use domain::{ConversationId, UserId};
use time::OffsetDateTime;

use super::shared::{caller, name_event, sender_name};

pub struct HistoryEntry {
    pub message: Message,
    pub sender_display_name: Option<String>,
}

/// One item of a conversation's timeline.
pub enum TimelineEntry {
    Message(HistoryEntry),
    /// A change to the group, between its messages.
    Event(NamedEvent),
}

impl TimelineEntry {
    fn key(&self) -> (OffsetDateTime, u128) {
        match self {
            Self::Message(entry) => (
                entry.message.created_at,
                entry.message.id.as_uuid().as_u128(),
            ),
            Self::Event(named) => (named.event.at, named.event.id.as_uuid().as_u128()),
        }
    }
}

/// `GET /api/dm/{id}`: a page of a conversation, newest first — its messages, and with
/// `include_events` its group's changes between them, those the reader saw happen. Reading the
/// first page marks the conversation read. A member removed from a group still reads it up to
/// their removal, until they clear it.
pub struct LoadHistory {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
    events: Arc<dyn GroupEvents>,
}

impl LoadHistory {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
        events: Arc<dyn GroupEvents>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            messages,
            events,
        }
    }

    pub async fn execute(
        &self,
        reader: UserId,
        conversation: ConversationId,
        before: Option<HistoryCursor>,
        limit: Option<i64>,
        include_events: bool,
    ) -> Result<Vec<TimelineEntry>, MessagingError> {
        let reader = caller(&*self.accounts, reader).await?;
        let held = self.conversations.memberships(conversation).await?;
        let mine = held
            .iter()
            .find(|m| m.member.actor_uri == reader.actor_uri)
            .ok_or(MessagingError::ConversationNotFound)?;
        let departure = match mine.is_active() {
            true => None,
            false => {
                self.conversations
                    .departure(conversation, &reader.actor_uri)
                    .await?
            }
        };
        let window = EventWindow::for_reader(mine, departure.as_ref())
            .ok_or(MessagingError::ConversationNotFound)?;
        let limit = limit.unwrap_or(50).min(100);
        let page = self
            .messages
            .history(conversation, before, window.until, limit)
            .await?;

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
            entries.push(TimelineEntry::Message(HistoryEntry {
                message,
                sender_display_name: name,
            }));
        }
        if include_events {
            for event in self
                .events
                .page(conversation, before, window, limit)
                .await?
            {
                let named = name_event(&*self.accounts, &*self.remote_actors, event).await?;
                entries.push(TimelineEntry::Event(named));
            }
            // Each source is a page of its own: their newest `limit` together are the timeline's.
            entries.sort_by_key(|entry| std::cmp::Reverse(entry.key()));
            entries.truncate(usize::try_from(limit).unwrap_or(0));
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
