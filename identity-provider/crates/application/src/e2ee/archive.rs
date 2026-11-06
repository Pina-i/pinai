//! The history archive: what an account's devices decrypted, sealed again under a key derived
//! from a passphrase the server never sees, so a new device can restore past messages.

use std::sync::Arc;

use domain::UserId;
use domain::auth::Sessions;
use domain::e2ee::{
    ArchiveCursor, ArchiveEntry, ArchiveError, Archived, Cleared, DeviceApprovals, HistoryArchive,
    HistoryGeneration, HistoryKeys, NewArchiveEntry, StaleHistoryKey, archive_page_size,
    check_archive_batch, check_history_generation, may_act_beyond_the_password,
};
use domain::identity::{Accounts, Bearer};
use domain::messaging::Conversations;

use crate::auth::calling_trust;

/// `POST /api/history/messages`: archive a batch sealed under the account's current history key,
/// for conversations the account is or was in — leaving a group keeps the history one already
/// read.
pub struct ArchiveMessages {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    keys: Arc<dyn HistoryKeys>,
    archive: Arc<dyn HistoryArchive>,
}

impl ArchiveMessages {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        keys: Arc<dyn HistoryKeys>,
        archive: Arc<dyn HistoryArchive>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            keys,
            archive,
        }
    }

    /// How many entries were new.
    pub async fn execute(
        &self,
        owner: UserId,
        generation: HistoryGeneration,
        entries: Vec<NewArchiveEntry>,
    ) -> Result<usize, ArchiveError> {
        check_archive_batch(entries.len())?;
        let current = self
            .keys
            .current(owner)
            .await?
            .map(|held| held.key.generation);
        check_history_generation(generation, current)?;
        let account = self.accounts.find(owner).await?.ok_or_else(|| {
            ArchiveError::Unexpected(anyhow::anyhow!("the archiving account is gone"))
        })?;
        let mut named: Vec<_> = entries.iter().map(|e| e.conversation).collect();
        named.sort();
        named.dedup();
        let held = self
            .conversations
            .ever_held(&account.actor_uri, &named)
            .await?;
        if held.len() != named.len() {
            return Err(ArchiveError::NotAMember);
        }
        match self.archive.store(owner, generation, &entries).await? {
            Archived::Stored(new) => Ok(new),
            // A new generation was set since the key was read.
            Archived::Stale => Err(StaleHistoryKey.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePage {
    pub entries: Vec<ArchiveEntry>,
    /// After the page's last entry; `None` only for an empty page.
    pub next: Option<ArchiveCursor>,
}

/// `GET /api/history/messages`: the archive, newest first, a page at a time.
pub struct ReadArchive {
    archive: Arc<dyn HistoryArchive>,
}

impl ReadArchive {
    pub fn new(archive: Arc<dyn HistoryArchive>) -> Self {
        Self { archive }
    }

    pub async fn execute(
        &self,
        owner: UserId,
        after: Option<ArchiveCursor>,
        limit: Option<i64>,
    ) -> Result<ArchivePage, ArchiveError> {
        let entries = self
            .archive
            .page(owner, after, archive_page_size(limit))
            .await?;
        Ok(ArchivePage {
            next: entries.last().map(ArchiveEntry::cursor),
            entries,
        })
    }
}

/// `DELETE /api/history/messages`: Settings → Clear. The key stays, and every device goes on
/// saving under it. Once the account has a history key, only from an approved device: a device
/// added later restores from what this erases.
pub struct ClearArchive {
    sessions: Arc<dyn Sessions>,
    approvals: Arc<dyn DeviceApprovals>,
    archive: Arc<dyn HistoryArchive>,
}

impl ClearArchive {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        approvals: Arc<dyn DeviceApprovals>,
        archive: Arc<dyn HistoryArchive>,
    ) -> Self {
        Self {
            sessions,
            approvals,
            archive,
        }
    }

    /// How many entries went. The erase happens only under the generation decided on: one set
    /// since is `Stale`, its entries kept.
    pub async fn execute(&self, bearer: &Bearer) -> Result<usize, ArchiveError> {
        let (named, trust) = calling_trust(&*self.sessions, &*self.approvals, bearer).await?;
        may_act_beyond_the_password(named, &trust)?;
        // Nothing is archived without a history key.
        let Some(generation) = trust.current else {
            return Ok(0);
        };
        match self.archive.clear(bearer.user, generation).await? {
            Cleared::Erased(erased) => Ok(erased),
            Cleared::Stale => Err(StaleHistoryKey.into()),
        }
    }
}

#[cfg(test)]
mod tests;
