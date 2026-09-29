//! The history archive: what an account's devices decrypted, sealed again under a key derived
//! from a passphrase the server never sees, so a new device can restore past messages.

use std::sync::Arc;

use domain::UserId;
use domain::e2ee::{
    ArchiveCursor, ArchiveEntry, ArchiveError, ArchiveSalt, HistoryArchive, NewArchiveEntry,
    archive_page_size, check_archive_batch,
};
use domain::identity::Accounts;
use domain::messaging::Conversations;

/// `POST /api/history/messages`: archive a batch, for conversations the account is or was in —
/// leaving a group keeps the history one already read.
pub struct ArchiveMessages {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    archive: Arc<dyn HistoryArchive>,
}

impl ArchiveMessages {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        archive: Arc<dyn HistoryArchive>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            archive,
        }
    }

    /// How many entries were new.
    pub async fn execute(
        &self,
        owner: UserId,
        entries: Vec<NewArchiveEntry>,
    ) -> Result<usize, ArchiveError> {
        check_archive_batch(entries.len())?;
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
        Ok(self.archive.store(owner, &entries).await?)
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

/// `DELETE /api/history/messages`: Settings → Clear.
pub struct ClearArchive {
    archive: Arc<dyn HistoryArchive>,
}

impl ClearArchive {
    pub fn new(archive: Arc<dyn HistoryArchive>) -> Self {
        Self { archive }
    }

    /// How many entries went.
    pub async fn execute(&self, owner: UserId) -> Result<usize, ArchiveError> {
        Ok(self.archive.clear(owner).await?)
    }
}

/// `GET /api/history/salt`
pub struct LoadArchiveSalt {
    archive: Arc<dyn HistoryArchive>,
}

impl LoadArchiveSalt {
    pub fn new(archive: Arc<dyn HistoryArchive>) -> Self {
        Self { archive }
    }

    /// `NoSalt` until a device sets one.
    pub async fn execute(&self, owner: UserId) -> Result<ArchiveSalt, ArchiveError> {
        self.archive.salt(owner).await?.ok_or(ArchiveError::NoSalt)
    }
}

/// `POST /api/history/salt`: set once — a second device reads back the first one's.
pub struct SetArchiveSalt {
    archive: Arc<dyn HistoryArchive>,
}

impl SetArchiveSalt {
    pub fn new(archive: Arc<dyn HistoryArchive>) -> Self {
        Self { archive }
    }

    /// The salt now held.
    pub async fn execute(
        &self,
        owner: UserId,
        salt: ArchiveSalt,
    ) -> Result<ArchiveSalt, ArchiveError> {
        Ok(self.archive.set_salt_once(owner, &salt).await?)
    }
}

#[cfg(test)]
mod tests;
