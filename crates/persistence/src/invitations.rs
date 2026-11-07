//! Invitations to join an organization.
//!
//! Only the SHA-256 of an invitation code is stored. Queries here never
//! decide who may invite whom; the application layer passes a decision
//! callback that runs inside the transaction, after the organization row is
//! locked.

use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    organization::OrganizationName,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    accounts::NewAccount,
    audit::{AuditEvent, insert_audit_event},
    organizations::{parse_role, query_err},
};

/// SQL condition for invitations that can still be used. A macro so it can
/// be spliced into static query strings with `concat!`.
macro_rules! open {
    () => {
        "accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()"
    };
}

pub struct NewInvitation<'a> {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: &'a Email,
    pub role: OrgRole,
    pub token_hash: &'a [u8; 32],
    pub invited_by: Uuid,
    pub expires_at: OffsetDateTime,
}

/// State read under the organization lock, handed to the decision callback
/// before an invitation is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvitationSnapshot {
    pub actor_role: OrgRole,
    /// An account with the invited email is already a member.
    pub already_member: bool,
    /// Open invitations to other addresses. An open invitation to the same
    /// address is replaced, so it is not counted.
    pub open_invitations: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InvitationChangeOutcome<E> {
    Applied,
    /// The organization does not exist or the actor is not a member.
    ActorNotMember,
    /// No open invitation with that ID in this organization.
    InvitationNotFound,
    Refused(E),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationRecord {
    pub id: Uuid,
    pub email: Email,
    pub role: OrgRole,
    pub invited_by: Option<DisplayName>,
    pub expires_at: OffsetDateTime,
}

/// An open invitation found by its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationByToken {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub organization_name: OrganizationName,
    pub email: Email,
    pub role: OrgRole,
    pub expires_at: OffsetDateTime,
    pub account_exists: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    Joined {
        organization_id: Uuid,
    },
    /// Unknown, used, withdrawn, or expired code, or a disabled account.
    Invalid,
    /// The signed-in account's email differs from the invited one.
    EmailMismatch,
    AlreadyMember {
        organization_id: Uuid,
    },
    /// The account already belongs to the maximum number of organizations.
    LimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptNewAccountOutcome {
    Joined {
        organization_id: Uuid,
    },
    Invalid,
    EmailMismatch,
    /// An account with the invited email exists; the invitee signs in instead.
    AccountExists,
}

#[derive(sqlx::FromRow)]
struct LockedInvitation {
    organization_id: Uuid,
    email: String,
    role: String,
}

/// Locks an open invitation, checking both its ID and its code hash.
async fn lock_open_invitation(
    tx: &mut sqlx::PgConnection,
    invitation_id: Uuid,
    token_hash: &[u8; 32],
) -> Result<Option<LockedInvitation>, PersistenceError> {
    sqlx::query_as(concat!(
        "SELECT organization_id, email, role FROM organization_invitations \
         WHERE id = $1 AND token_hash = $2 AND ",
        open!(),
        " FOR UPDATE"
    ))
    .bind(invitation_id)
    .bind(token_hash.as_slice())
    .fetch_optional(tx)
    .await
    .map_err(query_err)
}

async fn mark_accepted(
    tx: &mut sqlx::PgConnection,
    invitation_id: Uuid,
    account_id: Uuid,
) -> Result<(), PersistenceError> {
    sqlx::query(
        "UPDATE organization_invitations SET accepted_at = now(), accepted_by = $2 WHERE id = $1",
    )
    .bind(invitation_id)
    .bind(account_id)
    .execute(tx)
    .await
    .map_err(query_err)?;
    Ok(())
}

async fn insert_member(
    tx: &mut sqlx::PgConnection,
    organization_id: Uuid,
    account_id: Uuid,
    role: OrgRole,
) -> Result<(), PersistenceError> {
    sqlx::query(
        "INSERT INTO organization_members (organization_id, account_id, role) VALUES ($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(account_id)
    .bind(role.as_str())
    .execute(tx)
    .await
    .map_err(query_err)?;
    Ok(())
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}

impl Database {
    /// Creates an invitation, replacing any open invitation to the same
    /// address in the organization, if `decide` allows it.
    pub async fn create_invitation<E>(
        &self,
        new: &NewInvitation<'_>,
        decide: impl FnOnce(InvitationSnapshot) -> Result<(), E>,
        audit: &AuditEvent<'_>,
    ) -> Result<InvitationChangeOutcome<E>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let locked = sqlx::query("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(new.organization_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_err)?;
        if locked.is_none() {
            return Ok(InvitationChangeOutcome::ActorNotMember);
        }
        let Some(actor_role) = sqlx::query_scalar::<_, String>(
            "SELECT role FROM organization_members WHERE organization_id = $1 AND account_id = $2",
        )
        .bind(new.organization_id)
        .bind(new.invited_by)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?
        else {
            return Ok(InvitationChangeOutcome::ActorNotMember);
        };
        let already_member: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM organization_members m \
                 JOIN accounts a ON a.id = m.account_id \
                 WHERE m.organization_id = $1 AND a.email = $2)",
        )
        .bind(new.organization_id)
        .bind(new.email.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(query_err)?;
        let open: i64 = sqlx::query_scalar(concat!(
            "SELECT count(*) FROM organization_invitations \
             WHERE organization_id = $1 AND email <> $2 AND ",
            open!()
        ))
        .bind(new.organization_id)
        .bind(new.email.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(query_err)?;

        let snapshot = InvitationSnapshot {
            actor_role: parse_role(&actor_role)?,
            already_member,
            // A count that does not fit fails closed in the rules.
            open_invitations: usize::try_from(open).unwrap_or(usize::MAX),
        };
        if let Err(refusal) = decide(snapshot) {
            return Ok(InvitationChangeOutcome::Refused(refusal));
        }

        // Includes expired invitations, which still hold the unique slot.
        sqlx::query(
            "UPDATE organization_invitations SET revoked_at = now() \
             WHERE organization_id = $1 AND email = $2 \
               AND accepted_at IS NULL AND revoked_at IS NULL",
        )
        .bind(new.organization_id)
        .bind(new.email.as_str())
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        sqlx::query(
            "INSERT INTO organization_invitations \
                 (id, organization_id, email, role, token_hash, invited_by, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(new.id)
        .bind(new.organization_id)
        .bind(new.email.as_str())
        .bind(new.role.as_str())
        .bind(new.token_hash.as_slice())
        .bind(new.invited_by)
        .bind(new.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(InvitationChangeOutcome::Applied)
    }

    /// Open, unexpired invitations of one organization, newest first.
    pub async fn list_open_invitations(
        &self,
        organization_id: Uuid,
        limit: usize,
    ) -> Result<Vec<InvitationRecord>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            email: String,
            role: String,
            invited_by: Option<String>,
            expires_at: OffsetDateTime,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT i.id, i.email, i.role, a.display_name AS invited_by, i.expires_at \
             FROM organization_invitations i LEFT JOIN accounts a ON a.id = i.invited_by \
             WHERE i.organization_id = $1 AND i.accepted_at IS NULL \
               AND i.revoked_at IS NULL AND i.expires_at > now() \
             ORDER BY i.created_at DESC, i.id \
             LIMIT $2",
        )
        .bind(organization_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter()
            .map(|row| {
                Ok(InvitationRecord {
                    id: row.id,
                    email: Email::parse(&row.email).map_err(|_| {
                        PersistenceError::InvalidRow("organization_invitations.email")
                    })?,
                    role: parse_role(&row.role)?,
                    invited_by: row
                        .invited_by
                        .map(|name| {
                            DisplayName::parse(&name)
                                .map_err(|_| PersistenceError::InvalidRow("accounts.display_name"))
                        })
                        .transpose()?,
                    expires_at: row.expires_at,
                })
            })
            .collect()
    }

    /// Withdraws an open invitation if `decide` allows it. `decide` gets the
    /// actor's role and the invited role.
    pub async fn revoke_invitation<E>(
        &self,
        organization_id: Uuid,
        invitation_id: Uuid,
        actor_id: Uuid,
        decide: impl FnOnce(OrgRole, OrgRole) -> Result<(), E>,
        audit: &AuditEvent<'_>,
    ) -> Result<InvitationChangeOutcome<E>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let locked = sqlx::query("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(organization_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_err)?;
        if locked.is_none() {
            return Ok(InvitationChangeOutcome::ActorNotMember);
        }
        let Some(actor_role) = sqlx::query_scalar::<_, String>(
            "SELECT role FROM organization_members WHERE organization_id = $1 AND account_id = $2",
        )
        .bind(organization_id)
        .bind(actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?
        else {
            return Ok(InvitationChangeOutcome::ActorNotMember);
        };
        let Some(invited_role) = sqlx::query_scalar::<_, String>(concat!(
            "SELECT role FROM organization_invitations \
             WHERE id = $1 AND organization_id = $2 AND ",
            open!(),
            " FOR UPDATE"
        ))
        .bind(invitation_id)
        .bind(organization_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?
        else {
            return Ok(InvitationChangeOutcome::InvitationNotFound);
        };
        if let Err(refusal) = decide(parse_role(&actor_role)?, parse_role(&invited_role)?) {
            return Ok(InvitationChangeOutcome::Refused(refusal));
        }
        sqlx::query("UPDATE organization_invitations SET revoked_at = now() WHERE id = $1")
            .bind(invitation_id)
            .execute(&mut *tx)
            .await
            .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(InvitationChangeOutcome::Applied)
    }

    /// Finds an open, unexpired invitation by the hash of its code.
    pub async fn find_open_invitation_by_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<InvitationByToken>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            organization_id: Uuid,
            organization_name: String,
            email: String,
            role: String,
            expires_at: OffsetDateTime,
            account_exists: bool,
        }
        let row: Option<Row> = sqlx::query_as(
            "SELECT i.id, i.organization_id, o.name AS organization_name, i.email, i.role, \
                    i.expires_at, \
                    EXISTS (SELECT 1 FROM accounts a WHERE a.email = i.email) AS account_exists \
             FROM organization_invitations i JOIN organizations o ON o.id = i.organization_id \
             WHERE i.token_hash = $1 AND i.accepted_at IS NULL \
               AND i.revoked_at IS NULL AND i.expires_at > now()",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        row.map(|row| {
            Ok(InvitationByToken {
                id: row.id,
                organization_id: row.organization_id,
                organization_name: OrganizationName::parse(&row.organization_name)
                    .map_err(|_| PersistenceError::InvalidRow("organizations.name"))?,
                email: Email::parse(&row.email)
                    .map_err(|_| PersistenceError::InvalidRow("organization_invitations.email"))?,
                role: parse_role(&row.role)?,
                expires_at: row.expires_at,
                account_exists: row.account_exists,
            })
        })
        .transpose()
    }

    /// Adds an existing account to the organization and closes the
    /// invitation. The code is checked again under a row lock, so two
    /// concurrent attempts cannot both use it.
    pub async fn accept_invitation(
        &self,
        invitation_id: Uuid,
        token_hash: &[u8; 32],
        account_id: Uuid,
        max_memberships: usize,
        audit: &AuditEvent<'_>,
    ) -> Result<AcceptOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let Some(invitation) = lock_open_invitation(&mut tx, invitation_id, token_hash).await?
        else {
            return Ok(AcceptOutcome::Invalid);
        };
        // Locks the account the same way organization creation does, so the
        // membership limit holds under concurrency.
        let account: Option<(String, bool)> = sqlx::query_as(
            "SELECT email, disabled_at IS NOT NULL FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?;
        let Some((email, disabled)) = account else {
            return Ok(AcceptOutcome::Invalid);
        };
        if disabled {
            return Ok(AcceptOutcome::Invalid);
        }
        if email != invitation.email {
            return Ok(AcceptOutcome::EmailMismatch);
        }
        let organization_id = invitation.organization_id;
        let already_member: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM organization_members \
                 WHERE organization_id = $1 AND account_id = $2)",
        )
        .bind(organization_id)
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(query_err)?;
        if already_member {
            return Ok(AcceptOutcome::AlreadyMember { organization_id });
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM organization_members WHERE account_id = $1")
                .bind(account_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(query_err)?;
        if usize::try_from(count).map_or(true, |count| count >= max_memberships) {
            return Ok(AcceptOutcome::LimitReached);
        }
        insert_member(
            &mut tx,
            organization_id,
            account_id,
            parse_role(&invitation.role)?,
        )
        .await?;
        mark_accepted(&mut tx, invitation_id, account_id).await?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(AcceptOutcome::Joined { organization_id })
    }

    /// Creates an account for the invited email, adds it to the
    /// organization, and closes the invitation, all in one transaction.
    /// The account is never an installation administrator, whatever
    /// `account.is_installation_admin` says.
    pub async fn accept_invitation_with_new_account(
        &self,
        invitation_id: Uuid,
        token_hash: &[u8; 32],
        account: &NewAccount<'_>,
        audit: &[AuditEvent<'_>],
    ) -> Result<AcceptNewAccountOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let Some(invitation) = lock_open_invitation(&mut tx, invitation_id, token_hash).await?
        else {
            return Ok(AcceptNewAccountOutcome::Invalid);
        };
        if account.email.as_str() != invitation.email {
            return Ok(AcceptNewAccountOutcome::EmailMismatch);
        }
        let inserted = sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash, is_installation_admin) \
             VALUES ($1, $2, $3, $4, FALSE)",
        )
        .bind(account.id)
        .bind(account.email.as_str())
        .bind(account.display_name.as_str())
        .bind(account.password_hash)
        .execute(&mut *tx)
        .await;
        match inserted {
            Ok(_) => {}
            Err(err) if is_unique_violation(&err) => {
                return Ok(AcceptNewAccountOutcome::AccountExists);
            }
            Err(err) => return Err(query_err(err)),
        }
        let organization_id = invitation.organization_id;
        insert_member(
            &mut tx,
            organization_id,
            account.id,
            parse_role(&invitation.role)?,
        )
        .await?;
        mark_accepted(&mut tx, invitation_id, account.id).await?;
        for event in audit {
            insert_audit_event(&mut *tx, event).await?;
        }
        tx.commit().await.map_err(query_err)?;
        Ok(AcceptNewAccountOutcome::Joined { organization_id })
    }
}
