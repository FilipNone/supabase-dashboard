//! Organization use cases. Every method takes the signed-in operator and
//! checks their membership and role on the server before reading or
//! writing anything.
//!
//! An organization the operator does not belong to is reported as
//! [`OrganizationError::NotFound`], exactly like one that does not exist,
//! so organization IDs cannot be probed.

use supabase_dashboard_domain::{
    authz::{MembershipChange, MembershipError, OrgRole, Permission, check_membership_change},
    organization::{
        MAX_MEMBERS_PER_ORGANIZATION, MAX_ORGANIZATIONS_PER_ACCOUNT, MemberSummary,
        OrganizationInputError, OrganizationName, OrganizationSummary,
    },
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::{AuditEvent, AuditOutcome},
    organizations::{CreateOrganizationOutcome, Membership, MembershipChangeOutcome},
};
use uuid::Uuid;

use crate::auth::{CurrentSession, RequestContext};

#[derive(Debug, thiserror::Error)]
pub enum OrganizationError {
    /// The organization does not exist or the operator is not a member.
    #[error("organization not found")]
    NotFound,
    /// The operator is a member, but their role does not grant this.
    #[error("your role in this organization does not allow this action")]
    Forbidden,
    #[error("that account is not a member of this organization")]
    MemberNotFound,
    #[error("you already belong to the maximum of {MAX_ORGANIZATIONS_PER_ACCOUNT} organizations")]
    LimitReached,
    #[error(transparent)]
    Input(#[from] OrganizationInputError),
    #[error(transparent)]
    Membership(#[from] MembershipError),
    /// Internal failure. The message is for server logs only.
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

pub struct OrganizationService {
    db: Database,
}

impl OrganizationService {
    pub const fn new(db: Database) -> Self {
        Self { db }
    }

    /// Organizations the operator belongs to, by name.
    pub async fn list(
        &self,
        current: &CurrentSession,
    ) -> Result<Vec<OrganizationSummary>, OrganizationError> {
        let memberships = self
            .db
            .list_account_organizations(current.account.id, MAX_ORGANIZATIONS_PER_ACCOUNT)
            .await?;
        Ok(memberships.into_iter().map(summary).collect())
    }

    pub async fn get(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<OrganizationSummary, OrganizationError> {
        let membership = self
            .authorize(current, organization_id, Permission::OrgRead)
            .await?;
        Ok(summary(membership))
    }

    /// Creates an organization with the operator as its only owner. Any
    /// signed-in operator may do this; accounts themselves are only created
    /// by bootstrap or invitation.
    pub async fn create(
        &self,
        current: &CurrentSession,
        name: &str,
        ctx: RequestContext<'_>,
    ) -> Result<OrganizationSummary, OrganizationError> {
        let name = OrganizationName::parse(name)?;
        let id = Uuid::now_v7();
        let outcome = self
            .db
            .create_organization(
                id,
                &name,
                current.account.id,
                MAX_ORGANIZATIONS_PER_ACCOUNT,
                &event(
                    current,
                    "organization.create",
                    ("organization", id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        match outcome {
            CreateOrganizationOutcome::Created => Ok(OrganizationSummary {
                id,
                name,
                role: OrgRole::Owner,
            }),
            CreateOrganizationOutcome::LimitReached => Err(OrganizationError::LimitReached),
        }
    }

    pub async fn rename(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        name: &str,
        ctx: RequestContext<'_>,
    ) -> Result<OrganizationSummary, OrganizationError> {
        let name = OrganizationName::parse(name)?;
        let target = ("organization", organization_id.to_string());
        let membership = match self
            .authorize(current, organization_id, Permission::OrgUpdate)
            .await
        {
            Err(OrganizationError::Forbidden) => {
                self.deny(current, "organization.rename", target, ctx).await;
                return Err(OrganizationError::Forbidden);
            }
            other => other?,
        };
        let renamed = self
            .db
            .rename_organization(
                organization_id,
                &name,
                &event(
                    current,
                    "organization.rename",
                    target,
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        if !renamed {
            return Err(OrganizationError::NotFound);
        }
        Ok(OrganizationSummary {
            id: organization_id,
            name,
            role: membership.role,
        })
    }

    pub async fn members(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<Vec<MemberSummary>, OrganizationError> {
        self.authorize(current, organization_id, Permission::MembersRead)
            .await?;
        let members = self
            .db
            .list_members(organization_id, MAX_MEMBERS_PER_ORGANIZATION)
            .await?;
        Ok(members
            .into_iter()
            .map(|member| MemberSummary {
                is_you: member.account_id == current.account.id,
                account_id: member.account_id,
                email: member.email,
                display_name: member.display_name,
                role: member.role,
            })
            .collect())
    }

    /// Gives a member a new role. Only owners grant, change, or remove the
    /// owner role, and the last owner cannot be demoted.
    pub async fn change_role(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        account_id: Uuid,
        role: OrgRole,
        ctx: RequestContext<'_>,
    ) -> Result<(), OrganizationError> {
        self.change(
            current,
            organization_id,
            account_id,
            Some(role),
            "organization.member_role_change",
            ctx,
        )
        .await
    }

    /// Removes a member. Removing yourself is leaving, which every member
    /// may do unless they are the last owner.
    pub async fn remove_member(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        account_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<(), OrganizationError> {
        let action = if account_id == current.account.id {
            "organization.leave"
        } else {
            "organization.member_remove"
        };
        self.change(current, organization_id, account_id, None, action, ctx)
            .await
    }

    async fn change(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        account_id: Uuid,
        new_role: Option<OrgRole>,
        action: &'static str,
        ctx: RequestContext<'_>,
    ) -> Result<(), OrganizationError> {
        let leaving = new_role.is_none() && account_id == current.account.id;
        let target = (
            "organization_member",
            format!("{organization_id}:{account_id}"),
        );
        let outcome = self
            .db
            .change_membership(
                organization_id,
                current.account.id,
                account_id,
                new_role,
                |snapshot| {
                    if leaving {
                        // Leaving needs no management permission, only
                        // that someone else still owns the organization.
                        if snapshot.target_role == OrgRole::Owner && snapshot.owner_count <= 1 {
                            return Err(MembershipError::LastOwner);
                        }
                        return Ok(());
                    }
                    check_membership_change(MembershipChange {
                        actor_role: snapshot.actor_role,
                        target_current_role: snapshot.target_role,
                        target_new_role: new_role,
                        owner_count: snapshot.owner_count,
                    })
                },
                &event(current, action, target.clone(), AuditOutcome::Success, ctx),
            )
            .await?;
        match outcome {
            MembershipChangeOutcome::Applied => Ok(()),
            MembershipChangeOutcome::ActorNotMember => Err(OrganizationError::NotFound),
            MembershipChangeOutcome::TargetNotMember => Err(OrganizationError::MemberNotFound),
            MembershipChangeOutcome::Refused(refusal) => {
                self.deny(current, action, target, ctx).await;
                Err(match refusal {
                    MembershipError::NotPermitted => OrganizationError::Forbidden,
                    other => OrganizationError::Membership(other),
                })
            }
        }
    }

    /// Loads the operator's membership and checks one permission.
    async fn authorize(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        permission: Permission,
    ) -> Result<Membership, OrganizationError> {
        let membership = self
            .db
            .find_membership(organization_id, current.account.id)
            .await?
            .ok_or(OrganizationError::NotFound)?;
        if membership.role.allows(permission) {
            Ok(membership)
        } else {
            Err(OrganizationError::Forbidden)
        }
    }

    /// Records a refused mutation. Best effort: a failure is logged and the
    /// caller still gets the refusal.
    async fn deny(
        &self,
        current: &CurrentSession,
        action: &'static str,
        target: (&'static str, String),
        ctx: RequestContext<'_>,
    ) {
        let event = event(current, action, target, AuditOutcome::Denied, ctx);
        if let Err(err) = self.db.record_audit_event(&event).await {
            tracing::error!(error = %err, action, "could not record audit event");
        }
    }
}

fn summary(membership: Membership) -> OrganizationSummary {
    OrganizationSummary {
        id: membership.organization.id,
        name: membership.organization.name,
        role: membership.role,
    }
}

fn event<'a>(
    current: &CurrentSession,
    action: &'static str,
    (target_type, target_id): (&'static str, String),
    outcome: AuditOutcome,
    ctx: RequestContext<'a>,
) -> AuditEvent<'a> {
    AuditEvent {
        actor_account_id: Some(current.account.id),
        action,
        target_type: Some(target_type),
        target_id: Some(target_id),
        outcome,
        request_id: ctx.request_id,
    }
}
