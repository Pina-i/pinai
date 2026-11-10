use std::sync::Arc;

use domain::ConversationId;
use domain::auth::Sessions;
use domain::e2ee::{
    Append, Commit, CommitBlob, CommitKind, CommitLog, DeliveryError, DeviceApprovals, Epoch,
    GroupInfo, GroupInfoBlob, GroupInfos, MlsFederation, MlsNotifier, NewCommit, may_commit,
    may_commit_externally,
};
use domain::identity::{Accounts, Bearer};
use domain::messaging::Conversations;

use super::group_roster::roster_of;
use crate::auth::calling_trust;

/// `POST /api/mls/groups/{id}/commits`: a member's commit at the next epoch, with the GroupInfo of
/// the epoch it opens, then to every member — the proposer's own sessions too, so its other tabs
/// keep up. A group's travels to other instances with its roster. Only a commit a client makes —
/// a member's, or a device committing itself in, only from a session naming it, approved.
pub struct AppendCommit {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    commits: Arc<dyn CommitLog>,
    group_infos: Arc<dyn GroupInfos>,
    sessions: Arc<dyn Sessions>,
    approvals: Arc<dyn DeviceApprovals>,
    notifier: Arc<dyn MlsNotifier>,
    federation: Arc<dyn MlsFederation>,
}

impl AppendCommit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        commits: Arc<dyn CommitLog>,
        group_infos: Arc<dyn GroupInfos>,
        sessions: Arc<dyn Sessions>,
        approvals: Arc<dyn DeviceApprovals>,
        notifier: Arc<dyn MlsNotifier>,
        federation: Arc<dyn MlsFederation>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            commits,
            group_infos,
            sessions,
            approvals,
            notifier,
            federation,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        conversation: ConversationId,
        epoch: Epoch,
        blob: CommitBlob,
        group_info: GroupInfoBlob,
    ) -> Result<Commit, DeliveryError> {
        let kind = blob.kind().ok_or(DeliveryError::NotACommit)?;
        let account = self.accounts.find(bearer.user).await?.ok_or_else(|| {
            DeliveryError::Unexpected(anyhow::anyhow!("the proposer's account is gone"))
        })?;
        // A conversation exists before its MLS group: a DM from the friendship, a group from
        // its creation.
        let members = self.conversations.members(conversation).await?;
        if members.is_empty() {
            return Err(DeliveryError::ConversationNotFound);
        }
        if !may_commit(&members, &account.actor_uri) {
            return Err(DeliveryError::NotAMember);
        }
        if kind == CommitKind::External {
            let (named, trust) = calling_trust(&*self.sessions, &*self.approvals, bearer).await?;
            may_commit_externally(named, &trust)?;
        }
        let latest = self.commits.latest(conversation).await?;
        if !epoch.follows(latest) {
            return Err(match self.commits.at(conversation, epoch).await? {
                Some(winner) => DeliveryError::EpochTaken(Box::new(winner)),
                None => DeliveryError::EpochNotNext(Epoch::after(latest)),
            });
        }
        let commit = match self
            .commits
            .append(&NewCommit {
                conversation,
                epoch,
                blob,
                proposer: account.actor_uri.clone(),
            })
            .await?
        {
            Append::Stored(commit) => commit,
            Append::Taken(winner) => return Err(DeliveryError::EpochTaken(Box::new(winner))),
        };
        // Only a stored commit's: one that lost its epoch belongs to another history.
        let group_info = GroupInfo {
            epoch: commit.epoch,
            blob: group_info,
        };
        self.group_infos.keep(conversation, &group_info).await?;
        let mut remote = Vec::new();
        for member in &members {
            if let Some(local) = self.accounts.find_by_uri(&member.actor_uri).await? {
                self.notifier.committed(local.id, &commit);
            } else {
                remote.push(member.actor_uri.clone());
            }
        }
        if !remote.is_empty() {
            let roster = roster_of(&*self.conversations, conversation).await?;
            self.federation.send_commit(
                &account.actor_uri,
                &remote,
                &commit,
                &group_info.blob,
                roster.as_ref(),
            );
        }
        Ok(commit)
    }
}
