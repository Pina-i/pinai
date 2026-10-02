//! A group's changes from another instance — `Add`, `Remove`, `Leave`, and `Update` of a `Group`'s
//! name or a `Membership`'s role; see identity-provider/specs/03-direct-messages.md § 10, Group
//! changes. Whether to take one is the use case's to say.

use domain::ConversationId;
use domain::identity::{Account, ActorUri};
use domain::messaging::{GroupChange, GroupChangeKind, GroupName};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{ApiError, AppState};

/// `by` is the activity's actor, bound to its signer by the inbox.
pub(super) async fn change(
    state: &AppState,
    activity: &Value,
    recipient: &Account,
    by: ActorUri,
) -> Result<(), ApiError> {
    let change = parse(activity, by)?;
    state
        .receive_group_change
        .execute(recipient.id, change)
        .await?;
    Ok(())
}

fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn parse(activity: &Value, by: ActorUri) -> Result<GroupChange, ApiError> {
    let group = text(activity.get("context"))
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .map(ConversationId::from)
        .ok_or_else(|| ApiError::bad_request("a group change names its group in `context`"))?;
    let at = text(activity.get("published"))
        .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
        .ok_or_else(|| ApiError::bad_request("a group change carries its stamp in `published`"))?;
    let object = activity.get("object");
    let field = |name: &str| object.and_then(|o| o.get(name));
    let actor = |value: Option<&Value>| {
        text(value)
            .and_then(|uri| ActorUri::parse(uri).ok())
            .ok_or_else(|| ApiError::bad_request("a group change names its member by actor URI"))
    };
    let kind = match (text(activity.get("type")), text(field("type"))) {
        (Some("Add"), _) => GroupChangeKind::Added(actor(object)?),
        (Some("Remove"), _) => GroupChangeKind::Removed(actor(object)?),
        (Some("Leave"), _) => GroupChangeKind::Left,
        (Some("Update"), Some("Group")) => GroupChangeKind::Renamed(
            GroupName::parse(text(field("name")).unwrap_or(""))
                .map_err(|e| ApiError::bad_request(format!("Group name {}", e.reason)))?,
        ),
        (Some("Update"), Some("Membership")) => GroupChangeKind::RoleChanged(
            actor(field("member"))?,
            text(field("role"))
                .and_then(|role| role.parse().ok())
                .ok_or_else(|| ApiError::bad_request("a role is admin or member"))?,
        ),
        _ => return Err(ApiError::bad_request("not a group change")),
    };
    Ok(GroupChange {
        group,
        by,
        at,
        kind,
    })
}
