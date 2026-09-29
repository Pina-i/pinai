use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::social::SocialError;

/// How the other end of a friendship is named to the account's clients: a local account by its
/// own username and display name; a remote one by the address its URI stands for, and the display
/// name this instance cached.
pub(crate) async fn name_of(
    accounts: &dyn Accounts,
    remote_actors: &dyn RemoteActors,
    uri: &ActorUri,
) -> Result<(String, Option<String>), SocialError> {
    if let Some(account) = accounts.find_by_uri(uri).await? {
        return Ok((account.username, account.display_name));
    }
    let display_name = remote_actors.find(uri).await?.and_then(|r| r.display_name);
    let username = uri
        .federated_address()
        .map(|address| address.user().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    Ok((username, display_name))
}
