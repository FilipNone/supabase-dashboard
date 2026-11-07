//! Invitations to join a dashboard organization.
//!
//! An invitation names an email address and a role. Whoever holds its code
//! can see which organization sent it and accept it, but only as the account
//! with that email address, or by creating that account. Codes are single
//! use, expire, and can be withdrawn.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    account::{DisplayName, Email},
    authz::{MembershipError, OrgRole, Permission},
    organization::OrganizationName,
};

/// How long an invitation stays usable after it is created.
pub const INVITATION_LIFETIME: time::Duration = time::Duration::days(7);

/// Upper bound on open invitations per organization. Keeps the list and
/// the number of live codes bounded.
pub const MAX_OPEN_INVITATIONS_PER_ORGANIZATION: usize = 100;

/// Whether `actor_role` may invite someone as `invited_role`. The same rules
/// apply as for changing a member's role: managing members is required, and
/// only an owner can hand out the owner role.
pub fn check_invitation(actor_role: OrgRole, invited_role: OrgRole) -> Result<(), MembershipError> {
    if !actor_role.allows(Permission::MembersManage) {
        return Err(MembershipError::NotPermitted);
    }
    if invited_role == OrgRole::Owner && actor_role != OrgRole::Owner {
        return Err(MembershipError::OwnerRoleRequiresOwner);
    }
    Ok(())
}

/// An open invitation as shown to the organization's members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationSummary {
    pub id: Uuid,
    pub email: Email,
    pub role: OrgRole,
    /// `None` when the inviting account has since been deleted.
    pub invited_by: Option<DisplayName>,
    pub expires_at: OffsetDateTime,
}

/// What the holder of an invitation code is shown before accepting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationPreview {
    pub organization_name: OrganizationName,
    pub email: Email,
    pub role: OrgRole,
    pub expires_at: OffsetDateTime,
    /// Whether a dashboard account already uses the invited email. If so,
    /// the invitee signs in to accept; otherwise they create the account.
    pub account_exists: bool,
}

/// The secret part of an invitation link. It is shown once, to the operator
/// who created the invitation, and is never logged or stored in plain form.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InvitationCode(String);

impl InvitationCode {
    pub const fn new(code: String) -> Self {
        Self(code)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InvitationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvitationCode([REDACTED])")
    }
}

/// A newly created invitation and its code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedInvitation {
    pub invitation: InvitationSummary,
    pub code: InvitationCode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_rules_match_role_changes() {
        for actor in OrgRole::ALL {
            for invited in OrgRole::ALL {
                let allowed = check_invitation(actor, invited).is_ok();
                let expected = actor.allows(Permission::MembersManage)
                    && (invited != OrgRole::Owner || actor == OrgRole::Owner);
                assert_eq!(allowed, expected, "{actor:?} inviting {invited:?}");
            }
        }
        assert_eq!(
            check_invitation(OrgRole::Admin, OrgRole::Owner),
            Err(MembershipError::OwnerRoleRequiresOwner)
        );
        assert_eq!(
            check_invitation(OrgRole::Developer, OrgRole::Viewer),
            Err(MembershipError::NotPermitted)
        );
    }

    #[test]
    fn code_debug_is_redacted() {
        let code = InvitationCode::new("ab".repeat(32));
        assert!(!format!("{code:?}").contains("abab"));
    }
}
