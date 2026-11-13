//! Organization roles and the permissions they grant.
//!
//! This is the single source of truth for dashboard authorization rules.
//! Application services call it on every operation; hiding a UI control is
//! never a substitute.
//!
//! Matches below are written without wildcards on purpose: adding a
//! `Permission` or `OrgRole` variant fails to compile until every role has
//! an explicit decision for it.

use serde::{Deserialize, Serialize};

/// A member's role within one dashboard organization. Roles are ordered from
/// most to least privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    Owner,
    Admin,
    Developer,
    Viewer,
}

impl OrgRole {
    pub const ALL: [Self; 4] = [Self::Owner, Self::Admin, Self::Developer, Self::Viewer];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Owner => "Owner",
            Self::Admin => "Administrator",
            Self::Developer => "Developer",
            Self::Viewer => "Read-only",
        }
    }

    /// Stable machine name, used in storage and in serialized form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Developer => "developer",
            Self::Viewer => "viewer",
        }
    }

    /// Inverse of [`Self::as_str`].
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == name)
    }

    /// Whether this role grants `permission`.
    pub const fn allows(self, permission: Permission) -> bool {
        use Permission as P;
        match self {
            Self::Owner => true,
            Self::Admin => match permission {
                P::OrgDelete | P::StackDestroy => false,
                P::OrgRead
                | P::OrgUpdate
                | P::MembersRead
                | P::MembersManage
                | P::AuditRead
                | P::ProjectRead
                | P::ProjectRegister
                | P::ProjectUpdate
                | P::ProjectCredentialsReplace
                | P::ProjectUnregister
                | P::StackOperate
                | P::StackRemove
                | P::StudioOpen => true,
            },
            Self::Developer => match permission {
                P::OrgRead | P::MembersRead | P::ProjectRead | P::StudioOpen => true,
                P::OrgUpdate
                | P::OrgDelete
                | P::MembersManage
                | P::AuditRead
                | P::ProjectRegister
                | P::ProjectUpdate
                | P::ProjectCredentialsReplace
                | P::ProjectUnregister
                | P::StackOperate
                | P::StackRemove
                | P::StackDestroy => false,
            },
            Self::Viewer => match permission {
                P::OrgRead | P::MembersRead | P::ProjectRead => true,
                // Studio has no roles of its own: whoever opens it can run
                // any SQL as the database owner, so read-only members cannot.
                P::StudioOpen
                | P::OrgUpdate
                | P::OrgDelete
                | P::MembersManage
                | P::AuditRead
                | P::ProjectRegister
                | P::ProjectUpdate
                | P::ProjectCredentialsReplace
                | P::ProjectUnregister
                | P::StackOperate
                | P::StackRemove
                | P::StackDestroy => false,
            },
        }
    }
}

/// An action on an organization or one of its projects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    OrgRead,
    OrgUpdate,
    OrgDelete,
    MembersRead,
    /// Invite, remove, and change roles, subject to [`check_membership_change`].
    MembersManage,
    AuditRead,
    ProjectRead,
    /// Register an existing self-hosted stack with the organization.
    ProjectRegister,
    ProjectUpdate,
    /// Replace stored credentials without reading the old values.
    ProjectCredentialsReplace,
    /// Remove the registry entry only; never deletes the stack or its data.
    ProjectUnregister,
    /// Stop, start, or redeploy the Dokploy service of a stack the
    /// dashboard provisioned. Never removes the service or its data.
    StackOperate,
    /// Delete a provisioned stack's Dokploy service, keeping its data
    /// volumes on the server. The project stays registered.
    StackRemove,
    /// Delete a provisioned stack's Dokploy service together with its data
    /// volumes: the database, the stored files, and Studio's snippets.
    /// This cannot be undone, so only owners may.
    StackDestroy,
    /// Open the project's Supabase Studio through the dashboard. Studio has
    /// no roles, so this grants full database access and shows the stack's
    /// API keys and JWT secret.
    StudioOpen,
}

impl Permission {
    pub const ALL: [Self; 15] = [
        Self::OrgRead,
        Self::OrgUpdate,
        Self::OrgDelete,
        Self::MembersRead,
        Self::MembersManage,
        Self::AuditRead,
        Self::ProjectRead,
        Self::ProjectRegister,
        Self::ProjectUpdate,
        Self::ProjectCredentialsReplace,
        Self::ProjectUnregister,
        Self::StackOperate,
        Self::StackRemove,
        Self::StackDestroy,
        Self::StudioOpen,
    ];
}

/// Why a membership change was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    #[error("your role cannot manage members")]
    NotPermitted,
    #[error("only an owner can grant, change, or remove the owner role")]
    OwnerRoleRequiresOwner,
    #[error("an organization must keep at least one owner")]
    LastOwner,
}

/// A requested change to one member: a new role, or removal (`None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipChange {
    pub actor_role: OrgRole,
    pub target_current_role: OrgRole,
    pub target_new_role: Option<OrgRole>,
    /// Owners in the organization before the change, including the target.
    pub owner_count: usize,
}

/// Validates a role change or removal, including a member removing
/// themselves. The caller must load `owner_count` in the same transaction
/// that applies the change, so two concurrent demotions cannot both pass.
pub fn check_membership_change(change: MembershipChange) -> Result<(), MembershipError> {
    let MembershipChange {
        actor_role,
        target_current_role,
        target_new_role,
        owner_count,
    } = change;

    if !actor_role.allows(Permission::MembersManage) {
        return Err(MembershipError::NotPermitted);
    }
    let touches_owner =
        target_current_role == OrgRole::Owner || target_new_role == Some(OrgRole::Owner);
    if touches_owner && actor_role != OrgRole::Owner {
        return Err(MembershipError::OwnerRoleRequiresOwner);
    }
    let loses_owner =
        target_current_role == OrgRole::Owner && target_new_role != Some(OrgRole::Owner);
    if loses_owner && owner_count <= 1 {
        return Err(MembershipError::LastOwner);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use OrgRole::*;
    use Permission as P;

    /// The full expected matrix, written out so a change to `allows` has to
    /// be mirrored here deliberately.
    fn expected(role: OrgRole) -> &'static [Permission] {
        match role {
            Owner => &Permission::ALL,
            Admin => &[
                P::OrgRead,
                P::OrgUpdate,
                P::MembersRead,
                P::MembersManage,
                P::AuditRead,
                P::ProjectRead,
                P::ProjectRegister,
                P::ProjectUpdate,
                P::ProjectCredentialsReplace,
                P::ProjectUnregister,
                P::StackOperate,
                P::StackRemove,
                P::StudioOpen,
            ],
            Developer => &[P::OrgRead, P::MembersRead, P::ProjectRead, P::StudioOpen],
            Viewer => &[P::OrgRead, P::MembersRead, P::ProjectRead],
        }
    }

    #[test]
    fn role_matrix_matches_expectation_exactly() {
        for role in OrgRole::ALL {
            for permission in Permission::ALL {
                assert_eq!(
                    role.allows(permission),
                    expected(role).contains(&permission),
                    "{role:?} / {permission:?}"
                );
            }
        }
    }

    #[test]
    fn role_names_round_trip_and_match_serde() {
        for role in OrgRole::ALL {
            assert_eq!(OrgRole::from_name(role.as_str()), Some(role));
            assert_eq!(
                serde_json::to_string(&role).unwrap(),
                format!("\"{}\"", role.as_str())
            );
        }
        assert_eq!(OrgRole::from_name("Owner"), None);
    }

    #[test]
    fn roles_are_strictly_nested() {
        // Each role's grants are a subset of the next more privileged role's.
        for pair in OrgRole::ALL.windows(2) {
            let (higher, lower) = (pair[0], pair[1]);
            for permission in Permission::ALL {
                if lower.allows(permission) {
                    assert!(higher.allows(permission), "{higher:?} lacks {permission:?}");
                }
            }
        }
    }

    fn change(
        actor: OrgRole,
        from: OrgRole,
        to: Option<OrgRole>,
        owners: usize,
    ) -> MembershipChange {
        MembershipChange {
            actor_role: actor,
            target_current_role: from,
            target_new_role: to,
            owner_count: owners,
        }
    }

    #[test]
    fn developers_and_viewers_cannot_manage_members() {
        for actor in [Developer, Viewer] {
            assert_eq!(
                check_membership_change(change(actor, Viewer, None, 1)),
                Err(MembershipError::NotPermitted)
            );
        }
    }

    #[test]
    fn admins_cannot_touch_owners() {
        assert_eq!(
            check_membership_change(change(Admin, Developer, Some(Owner), 1)),
            Err(MembershipError::OwnerRoleRequiresOwner)
        );
        assert_eq!(
            check_membership_change(change(Admin, Owner, None, 3)),
            Err(MembershipError::OwnerRoleRequiresOwner)
        );
        assert_eq!(
            check_membership_change(change(Admin, Owner, Some(Admin), 3)),
            Err(MembershipError::OwnerRoleRequiresOwner)
        );
        assert!(check_membership_change(change(Admin, Developer, Some(Admin), 1)).is_ok());
        assert!(check_membership_change(change(Admin, Viewer, None, 1)).is_ok());
    }

    #[test]
    fn last_owner_cannot_be_removed_or_demoted() {
        for to in [None, Some(Admin), Some(Developer), Some(Viewer)] {
            assert_eq!(
                check_membership_change(change(Owner, Owner, to, 1)),
                Err(MembershipError::LastOwner),
                "{to:?}"
            );
            assert!(check_membership_change(change(Owner, Owner, to, 2)).is_ok());
        }
    }

    #[test]
    fn owners_can_promote_to_owner() {
        assert!(check_membership_change(change(Owner, Viewer, Some(Owner), 1)).is_ok());
        assert!(check_membership_change(change(Owner, Owner, Some(Owner), 1)).is_ok());
    }

    #[test]
    fn zero_owner_count_is_treated_as_last_owner() {
        // Inconsistent input must fail closed.
        assert_eq!(
            check_membership_change(change(Owner, Owner, None, 0)),
            Err(MembershipError::LastOwner)
        );
    }
}
