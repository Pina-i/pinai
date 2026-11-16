mod approval;
mod archive;
mod attachments;
mod auth;
mod delivery;
mod dm;
mod group_events;
mod identity;
mod key_directory;
mod key_share;
mod messaging;
mod presence;
mod profile;
mod reach;
mod settings;
mod social;
mod start_over;

pub use approval::{PgApprovalRequests, PgDeviceApprovals};

use anyhow::Context;
use domain::UserId;

/// Locks the account until the transaction ends: what takes it is decided one at a time.
async fn lock_account(c: &mut sqlx::PgConnection, user: UserId) -> anyhow::Result<()> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE")
        .bind(user.as_uuid())
        .execute(c)
        .await
        .context("lock an account")?;
    Ok(())
}
pub use archive::{PgHistoryArchive, PgHistoryKeys};
pub use attachments::PgAttachments;
pub use auth::{
    PgAuthorizationCodes, PgClientSignIns, PgInstanceMembers, PgInvitations, PgLoginTickets,
    PgPasswordResets, PgRefreshTokens, PgSecondFactors, PgSessions, PgSignInAccounts, PgSignUps,
    PgSignupCodes,
};
pub use delivery::{PgCommitLog, PgGroupInfos, PgWelcomes};
pub use group_events::PgGroupEvents;
pub use identity::{PgAccounts, PgSavedIntro};
pub use key_directory::{PgDevices, PgKeyPackages};
pub use key_share::PgKeyShares;
pub use messaging::{PgConversations, PgMessages};
pub use presence::PgPresenceAudience;
pub use profile::{PgPeerProfiles, PgProfileAudience, PgProfileCards, PgProfiles};
pub use reach::{PgContactPolicies, PgReachability};
pub use settings::PgSettingsStore;
pub use social::PgSocialGraph;
pub use start_over::PgStartOverRequests;
