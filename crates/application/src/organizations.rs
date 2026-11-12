//! Organization use cases. Every method takes the signed-in operator and
//! checks their membership and role on the server before reading or
//! writing anything.
//!
//! An organization the operator does not belong to is reported as
//! [`OrganizationError::NotFound`], exactly like one that does not exist,
//! so organization IDs cannot be probed.

use supabase_dashboard_domain::{
    account::{AccountInputError, Email},
    authz::{MembershipChange, MembershipError, OrgRole, Permission, check_membership_change},
    invitation::{
        INVITATION_LIFETIME, InvitationCode, InvitationSummary, IssuedInvitation,
        MAX_OPEN_INVITATIONS_PER_ORGANIZATION, check_invitation,
    },
    organization::{
        MAX_MEMBERS_PER_ORGANIZATION, MAX_ORGANIZATIONS_PER_ACCOUNT, MemberSummary,
        OrganizationInputError, OrganizationName, OrganizationSummary,
    },
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::{AuditEvent, AuditOutcome},
    invitations::{AcceptOutcome, InvitationChangeOutcome, NewInvitation},
    organizations::{CreateOrganizationOutcome, Membership, MembershipChangeOutcome},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    token::{InvitationToken, RandomnessError},
};

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
    #[error("that person is already a member of this organization")]
    AlreadyMember,
    #[error(
        "this organization already has {MAX_OPEN_INVITATIONS_PER_ORGANIZATION} open invitations; \
         withdraw some before sending more"
    )]
    TooManyInvitations,
    #[error("that invitation is no longer open")]
    InvitationNotFound,
    /// Unknown, used, withdrawn, or expired code. Not distinguished.
    #[error("this invitation is not valid: it may have expired, been used, or been withdrawn")]
    InvitationInvalid,
    #[error(
        "this invitation was sent to a different email address; \
         sign in with that address to accept it"
    )]
    InvitationEmailMismatch,
    #[error(transparent)]
    Input(#[from] OrganizationInputError),
    #[error(transparent)]
    AccountInput(#[from] AccountInputError),
    #[error(transparent)]
    Membership(#[from] MembershipError),
    /// Internal failure. The message is for server logs only.
    #[error(transparent)]
    Internal(#[from] PersistenceError),
    #[error(transparent)]
    Randomness(#[from] RandomnessError),
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
            CreateOrganizationOutcome::LimitReached => {
                let target = ("account", current.account.id.to_string());
                self.record(
                    current,
                    "organization.create",
                    target,
                    AuditOutcome::Failure,
                    ctx,
                )
                .await;
                Err(OrganizationError::LimitReached)
            }
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

    /// Invites `email` to join as `role`. Inviting an address that already
    /// has an open invitation replaces it with a new code. The code is
    /// returned once and only its hash is stored.
    pub async fn invite(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        email: &str,
        role: OrgRole,
        ctx: RequestContext<'_>,
    ) -> Result<IssuedInvitation, OrganizationError> {
        let email = Email::parse(email)?;
        let token = InvitationToken::generate()?;
        let id = Uuid::now_v7();
        // Whole seconds, so the returned value matches what the database
        // stores (microsecond precision).
        let expires_at = OffsetDateTime::now_utc()
            .checked_add(INVITATION_LIFETIME)
            .and_then(|at| at.replace_nanosecond(0).ok())
            .ok_or(OrganizationError::InvitationInvalid)?;
        let action = "organization.invitation_create";
        let target = ("organization_invitation", id.to_string());
        let outcome = self
            .db
            .create_invitation(
                &NewInvitation {
                    id,
                    organization_id,
                    email: &email,
                    role,
                    token_hash: token.hash(),
                    invited_by: current.account.id,
                    expires_at,
                },
                |snapshot| {
                    check_invitation(snapshot.actor_role, role)?;
                    if snapshot.already_member {
                        return Err(OrganizationError::AlreadyMember);
                    }
                    if snapshot.open_invitations >= MAX_OPEN_INVITATIONS_PER_ORGANIZATION {
                        return Err(OrganizationError::TooManyInvitations);
                    }
                    Ok(())
                },
                &event(current, action, target.clone(), AuditOutcome::Success, ctx),
            )
            .await?;
        match outcome {
            InvitationChangeOutcome::Applied => Ok(IssuedInvitation {
                invitation: InvitationSummary {
                    id,
                    email,
                    role,
                    invited_by: Some(current.account.display_name.clone()),
                    expires_at,
                },
                code: InvitationCode::new(token.expose_code().to_owned()),
            }),
            InvitationChangeOutcome::ActorNotMember
            | InvitationChangeOutcome::InvitationNotFound => Err(OrganizationError::NotFound),
            InvitationChangeOutcome::Refused(refusal) => {
                Err(self.refused(current, action, target, ctx, refusal).await)
            }
        }
    }

    /// Open invitations, visible to anyone who can see the member list.
    pub async fn invitations(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<Vec<InvitationSummary>, OrganizationError> {
        self.authorize(current, organization_id, Permission::MembersRead)
            .await?;
        let invitations = self
            .db
            .list_open_invitations(organization_id, MAX_OPEN_INVITATIONS_PER_ORGANIZATION)
            .await?;
        Ok(invitations
            .into_iter()
            .map(|record| InvitationSummary {
                id: record.id,
                email: record.email,
                role: record.role,
                invited_by: record.invited_by,
                expires_at: record.expires_at,
            })
            .collect())
    }

    /// Withdraws an open invitation. The same rules apply as for creating
    /// it, so only an owner can withdraw an invitation to the owner role.
    pub async fn revoke_invitation(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        invitation_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<(), OrganizationError> {
        let action = "organization.invitation_revoke";
        let target = ("organization_invitation", invitation_id.to_string());
        let outcome = self
            .db
            .revoke_invitation(
                organization_id,
                invitation_id,
                current.account.id,
                |actor_role, invited_role| {
                    check_invitation(actor_role, invited_role).map_err(OrganizationError::from)
                },
                &event(current, action, target.clone(), AuditOutcome::Success, ctx),
            )
            .await?;
        match outcome {
            InvitationChangeOutcome::Applied => Ok(()),
            InvitationChangeOutcome::ActorNotMember => Err(OrganizationError::NotFound),
            InvitationChangeOutcome::InvitationNotFound => {
                Err(OrganizationError::InvitationNotFound)
            }
            InvitationChangeOutcome::Refused(refusal) => {
                Err(self.refused(current, action, target, ctx, refusal).await)
            }
        }
    }

    /// Accepts an invitation as the signed-in operator, whose email must be
    /// the invited one. Returns the organization joined. Accepting when
    /// already a member succeeds without using the invitation.
    pub async fn accept_invitation(
        &self,
        current: &CurrentSession,
        code: &str,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, OrganizationError> {
        let action = "organization.invitation_accept";
        let Some(token) = InvitationToken::parse(code) else {
            return Err(self.unknown_invitation(current, action, ctx).await);
        };
        let Some(invitation) = self.db.find_open_invitation_by_token(token.hash()).await? else {
            return Err(self.unknown_invitation(current, action, ctx).await);
        };
        let target = ("organization_invitation", invitation.id.to_string());
        let outcome = self
            .db
            .accept_invitation(
                invitation.id,
                token.hash(),
                current.account.id,
                MAX_ORGANIZATIONS_PER_ACCOUNT,
                &event(current, action, target.clone(), AuditOutcome::Success, ctx),
            )
            .await?;
        match outcome {
            AcceptOutcome::Joined { organization_id }
            | AcceptOutcome::AlreadyMember { organization_id } => Ok(organization_id),
            AcceptOutcome::Invalid => {
                self.deny(current, action, target, ctx).await;
                Err(OrganizationError::InvitationInvalid)
            }
            AcceptOutcome::LimitReached => {
                self.record(current, action, target, AuditOutcome::Failure, ctx)
                    .await;
                Err(OrganizationError::LimitReached)
            }
            AcceptOutcome::EmailMismatch => {
                self.deny(current, action, target, ctx).await;
                Err(OrganizationError::InvitationEmailMismatch)
            }
        }
    }

    /// Audits a refusal from a decision callback and maps it for the caller.
    async fn refused(
        &self,
        current: &CurrentSession,
        action: &'static str,
        target: (&'static str, String),
        ctx: RequestContext<'_>,
        refusal: OrganizationError,
    ) -> OrganizationError {
        self.deny(current, action, target, ctx).await;
        match refusal {
            OrganizationError::Membership(MembershipError::NotPermitted) => {
                OrganizationError::Forbidden
            }
            other => other,
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
        self.record(current, action, target, AuditOutcome::Denied, ctx)
            .await;
    }

    /// Records a code that matches no open invitation. There is no
    /// invitation to name, and the code is not kept.
    async fn unknown_invitation(
        &self,
        current: &CurrentSession,
        action: &'static str,
        ctx: RequestContext<'_>,
    ) -> OrganizationError {
        let mut event = event(
            current,
            action,
            ("organization_invitation", String::new()),
            AuditOutcome::Denied,
            ctx,
        );
        event.target_id = None;
        if let Err(err) = self.db.record_audit_event(&event).await {
            tracing::error!(error = %err, action, "could not record audit event");
        }
        OrganizationError::InvitationInvalid
    }

    /// Records a refusal. Best effort: a failed write is logged.
    async fn record(
        &self,
        current: &CurrentSession,
        action: &'static str,
        target: (&'static str, String),
        outcome: AuditOutcome,
        ctx: RequestContext<'_>,
    ) {
        let event = event(current, action, target, outcome, ctx);
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

pub(crate) fn event<'a>(
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
