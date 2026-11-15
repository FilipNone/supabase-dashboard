//! Reading the audit log: an organization's events for its owners and
//! admins, and an account's own events for that account.
//!
//! Events name who did what to which target, when, and whether it was
//! allowed. They never hold passwords, keys, tokens, or managed project
//! data, so every field can be shown to whoever may read the event.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// How many events a page lists, newest first.
pub const AUDIT_PAGE: u16 = 50;

/// Most members offered in an organization log's member filter.
pub const AUDIT_MEMBER_CHOICES: u16 = 200;

/// Whether the action was carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEntryOutcome {
    Success,
    /// Refused because the actor's role or session did not allow it.
    Denied,
    /// Allowed, but it did not complete.
    Failure,
}

impl AuditEntryOutcome {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "success" => Some(Self::Success),
            "denied" => Some(Self::Denied),
            "failure" => Some(Self::Failure),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Success => "Succeeded",
            Self::Denied => "Denied",
            Self::Failure => "Failed",
        }
    }
}

/// The account that acted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditActor {
    /// For filtering by member. An identifier, not a credential.
    pub account_id: Uuid,
    pub display_name: String,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The event's ID, for paging.
    pub id: Uuid,
    pub at: OffsetDateTime,
    /// `None` for events without an actor, such as a failed sign-in or a
    /// background job, and for accounts that no longer exist.
    pub actor: Option<AuditActor>,
    /// Dotted name such as `project.rename`; see [`action_label`].
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: AuditEntryOutcome,
}

/// One page of a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogPage {
    /// Newest first, at most [`AUDIT_PAGE`].
    pub entries: Vec<AuditEntry>,
    /// The `id` of the last entry, when older entries follow; pass it back
    /// to read the next page.
    pub older: Option<Uuid>,
    /// For an organization's log: the accounts with events in it, by name,
    /// at most [`AUDIT_MEMBER_CHOICES`]. Empty for an account's own log.
    pub members: Vec<AuditActor>,
    /// More accounts have events than `members` lists.
    pub more_members: bool,
}

/// A short description of an action for the log's tables. Unknown names,
/// such as ones a newer release writes, are shown as they are.
pub fn action_label(action: &str) -> &str {
    match action {
        "account.bootstrap_owner" => "Created the first owner",
        "account.create_from_invitation" => "Created an account from an invitation",
        "account.oidc_link" => "Linked a single sign-on identity",
        "account.oidc_unlink" => "Unlinked a single sign-on identity",
        "account.password_change" => "Changed the password",
        "account.password_reset" => "Reset the password",
        "account.update_profile" => "Updated the profile",
        "admin.account_disable" => "Disabled an account",
        "admin.account_enable" => "Enabled an account",
        "admin.account_list" => "Listed accounts",
        "admin.resource_list" => "Listed organizations and projects",
        "api_token.create" => "Created an API token",
        "api_token.revoke" => "Revoked an API token",
        "audit.read" => "Read the audit log",
        "credentials.reseal" => "Moved stored credentials to a new key",
        "dokploy.connect" => "Connected Dokploy",
        "dokploy.disconnect" => "Disconnected Dokploy",
        "dokploy.environment_create" => "Created a Dokploy environment",
        "dokploy.key_replace" => "Replaced the Dokploy key",
        "dokploy.placement_clear" => "Forgot the dashboard's Dokploy service",
        "dokploy.placement_confirm" => "Confirmed the dashboard's Dokploy service",
        "dokploy.target_allow" => "Allowed a Dokploy target",
        "dokploy.target_remove" => "Removed a Dokploy target",
        "dokploy.view" => "Viewed the Dokploy connection",
        "organization.create" => "Created the organization",
        "organization.invitation_accept" => "Accepted an invitation",
        "organization.invitation_create" => "Invited a member",
        "organization.invitation_revoke" => "Revoked an invitation",
        "organization.leave" => "Left the organization",
        "organization.member_remove" => "Removed a member",
        "organization.member_role_change" => "Changed a member's role",
        "organization.rename" => "Renamed the organization",
        "project.adopt" => "Adopted a stack from Dokploy",
        "project.adopt_keys" => "Copied an adopted stack's keys",
        "project.authorities.remove" => "Removed the project's certificate authorities",
        "project.authorities.replace" => "Replaced the project's certificate authorities",
        "project.change_url" => "Changed the project's API URL",
        "project.credential.remove" => "Removed a stored key",
        "project.credential.replace" => "Replaced a stored key",
        "project.provision" => "Started creating a stack",
        "project.provisioned" => "Registered a created stack",
        "project.register" => "Registered a project",
        "project.rename" => "Renamed a project",
        "project.unregister" => "Unregistered a project",
        "session.revoke" => "Signed out a session",
        "session.revoke_others" => "Signed out other sessions",
        "session.sign_in" => "Sign-in",
        "session.sign_in_oidc" => "Sign-in with single sign-on",
        "session.sign_out" => "Signed out",
        "stack.configure" => "Changed stack settings",
        "stack.destroy" => "Destroyed a stack and its data",
        "stack.redeploy" => "Redeployed a stack",
        "stack.remove" => "Removed a stack from Dokploy",
        "stack.start" => "Started a stack",
        "stack.stop" => "Stopped a stack",
        "stack.variables_accept" => "Accepted variables edited in Dokploy",
        "studio.open" => "Opened Studio",
        "studio_access.export" => "Exported the Studio access log",
        "studio_access.read" => "Read the Studio access log",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_round_trip_their_stored_names() {
        for outcome in [
            AuditEntryOutcome::Success,
            AuditEntryOutcome::Denied,
            AuditEntryOutcome::Failure,
        ] {
            let name = serde_json::to_value(outcome).unwrap();
            assert_eq!(
                AuditEntryOutcome::from_name(name.as_str().unwrap()),
                Some(outcome)
            );
        }
        assert_eq!(AuditEntryOutcome::from_name("ok"), None);
    }

    #[test]
    fn unknown_actions_are_shown_as_written() {
        assert_eq!(action_label("project.rename"), "Renamed a project");
        assert_eq!(action_label("future.thing"), "future.thing");
    }
}
