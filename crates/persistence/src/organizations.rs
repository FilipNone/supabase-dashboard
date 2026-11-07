//! Organizations and their members.
//!
//! Queries here never decide who may do what; the application layer does.
//! Membership changes take a decision callback that runs inside the
//! transaction, after the organization row is locked, so rules such as
//! "keep at least one owner" see a consistent member list.

use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    organization::OrganizationName,
};
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationRecord {
    pub id: Uuid,
    pub name: OrganizationName,
}

/// An account's membership in one organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub organization: OrganizationRecord,
    pub role: OrgRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRecord {
    pub account_id: Uuid,
    pub email: Email,
    pub display_name: DisplayName,
    pub role: OrgRole,
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOrganizationOutcome {
    Created,
    /// The owner already belongs to the maximum number of organizations.
    LimitReached,
}

/// Roles read under the organization lock, handed to the decision callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipSnapshot {
    pub actor_role: OrgRole,
    pub target_role: OrgRole,
    pub owner_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MembershipChangeOutcome<E> {
    Applied,
    /// The organization does not exist or the actor is not a member. Both
    /// are reported the same way so organization IDs cannot be probed.
    ActorNotMember,
    TargetNotMember,
    /// The decision callback refused the change; nothing was written.
    Refused(E),
}

#[derive(sqlx::FromRow)]
struct MembershipRow {
    id: Uuid,
    name: String,
    role: String,
}

impl TryFrom<MembershipRow> for Membership {
    type Error = PersistenceError;
    fn try_from(row: MembershipRow) -> Result<Self, Self::Error> {
        Ok(Self {
            organization: OrganizationRecord {
                id: row.id,
                name: OrganizationName::parse(&row.name)
                    .map_err(|_| PersistenceError::InvalidRow("organizations.name"))?,
            },
            role: parse_role(&row.role)?,
        })
    }
}

pub(crate) fn parse_role(role: &str) -> Result<OrgRole, PersistenceError> {
    OrgRole::from_name(role).ok_or(PersistenceError::InvalidRow("organization_members.role"))
}

pub(crate) fn query_err(err: sqlx::Error) -> PersistenceError {
    PersistenceError::Query(err)
}

impl Database {
    /// Creates an organization with `owner_id` as its only owner, unless the
    /// owner already belongs to `max_memberships` organizations.
    pub async fn create_organization(
        &self,
        id: Uuid,
        name: &OrganizationName,
        owner_id: Uuid,
        max_memberships: usize,
        audit: &AuditEvent<'_>,
    ) -> Result<CreateOrganizationOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        // Serializes concurrent creations by the same account so the limit
        // holds. The account row exists because the caller is signed in.
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(owner_id)
            .execute(&mut *tx)
            .await
            .map_err(query_err)?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM organization_members WHERE account_id = $1")
                .bind(owner_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(query_err)?;
        if usize::try_from(count).map_or(true, |count| count >= max_memberships) {
            return Ok(CreateOrganizationOutcome::LimitReached);
        }
        sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, $2)")
            .bind(id)
            .bind(name.as_str())
            .execute(&mut *tx)
            .await
            .map_err(query_err)?;
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             VALUES ($1, $2, $3)",
        )
        .bind(id)
        .bind(owner_id)
        .bind(OrgRole::Owner.as_str())
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(CreateOrganizationOutcome::Created)
    }

    /// Organizations the account belongs to, by name, at most `limit`.
    pub async fn list_account_organizations(
        &self,
        account_id: Uuid,
        limit: usize,
    ) -> Result<Vec<Membership>, PersistenceError> {
        let rows: Vec<MembershipRow> = sqlx::query_as(
            "SELECT o.id, o.name, m.role \
             FROM organization_members m JOIN organizations o ON o.id = m.organization_id \
             WHERE m.account_id = $1 \
             ORDER BY lower(o.name), o.id \
             LIMIT $2",
        )
        .bind(account_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter().map(Membership::try_from).collect()
    }

    /// The account's membership in one organization, or `None` when the
    /// organization does not exist or the account is not a member.
    pub async fn find_membership(
        &self,
        organization_id: Uuid,
        account_id: Uuid,
    ) -> Result<Option<Membership>, PersistenceError> {
        let row: Option<MembershipRow> = sqlx::query_as(
            "SELECT o.id, o.name, m.role \
             FROM organization_members m JOIN organizations o ON o.id = m.organization_id \
             WHERE m.organization_id = $1 AND m.account_id = $2",
        )
        .bind(organization_id)
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        row.map(Membership::try_from).transpose()
    }

    /// Renames an organization. Returns `false` when it does not exist.
    pub async fn rename_organization(
        &self,
        organization_id: Uuid,
        name: &OrganizationName,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let updated =
            sqlx::query("UPDATE organizations SET name = $2, updated_at = now() WHERE id = $1")
                .bind(organization_id)
                .bind(name.as_str())
                .execute(&mut *tx)
                .await
                .map_err(query_err)?
                .rows_affected();
        if updated == 0 {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }

    /// Members of one organization: owners first, then by name. At most
    /// `limit` rows.
    pub async fn list_members(
        &self,
        organization_id: Uuid,
        limit: usize,
    ) -> Result<Vec<MemberRecord>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            account_id: Uuid,
            email: String,
            display_name: String,
            role: String,
            disabled: bool,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT a.id AS account_id, a.email, a.display_name, m.role, \
                    a.disabled_at IS NOT NULL AS disabled \
             FROM organization_members m JOIN accounts a ON a.id = m.account_id \
             WHERE m.organization_id = $1 \
             ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 \
                                  WHEN 'developer' THEN 2 ELSE 3 END, \
                      lower(a.display_name), a.id \
             LIMIT $2",
        )
        .bind(organization_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter()
            .map(|row| {
                Ok(MemberRecord {
                    account_id: row.account_id,
                    email: Email::parse(&row.email)
                        .map_err(|_| PersistenceError::InvalidRow("accounts.email"))?,
                    display_name: DisplayName::parse(&row.display_name)
                        .map_err(|_| PersistenceError::InvalidRow("accounts.display_name"))?,
                    role: parse_role(&row.role)?,
                    disabled: row.disabled,
                })
            })
            .collect()
    }

    /// Changes `target_id`'s role to `new_role`, or removes the member when
    /// `new_role` is `None`. `actor_id` may equal `target_id` (leaving).
    ///
    /// The organization row is locked first, so concurrent changes to the
    /// same organization run one after another and `decide` always sees the
    /// current owner count. The audit event is written in the same
    /// transaction, only when the change is applied.
    pub async fn change_membership<E>(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        target_id: Uuid,
        new_role: Option<OrgRole>,
        decide: impl FnOnce(MembershipSnapshot) -> Result<(), E>,
        audit: &AuditEvent<'_>,
    ) -> Result<MembershipChangeOutcome<E>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let locked = sqlx::query("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(organization_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_err)?;
        if locked.is_none() {
            return Ok(MembershipChangeOutcome::ActorNotMember);
        }
        let role_of = |account_id: Uuid| {
            sqlx::query_scalar::<_, String>(
                "SELECT role FROM organization_members \
                 WHERE organization_id = $1 AND account_id = $2",
            )
            .bind(organization_id)
            .bind(account_id)
        };
        let Some(actor_role) = role_of(actor_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_err)?
        else {
            return Ok(MembershipChangeOutcome::ActorNotMember);
        };
        let Some(target_role) = role_of(target_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_err)?
        else {
            return Ok(MembershipChangeOutcome::TargetNotMember);
        };
        let owner_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_members \
             WHERE organization_id = $1 AND role = 'owner'",
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(query_err)?;

        let snapshot = MembershipSnapshot {
            actor_role: parse_role(&actor_role)?,
            target_role: parse_role(&target_role)?,
            // A negative count cannot happen; zero fails closed in the rules.
            owner_count: usize::try_from(owner_count).unwrap_or(0),
        };
        if let Err(refusal) = decide(snapshot) {
            return Ok(MembershipChangeOutcome::Refused(refusal));
        }

        let query = match new_role {
            Some(role) => sqlx::query(
                "UPDATE organization_members SET role = $3 \
                 WHERE organization_id = $1 AND account_id = $2",
            )
            .bind(organization_id)
            .bind(target_id)
            .bind(role.as_str()),
            None => sqlx::query(
                "DELETE FROM organization_members \
                 WHERE organization_id = $1 AND account_id = $2",
            )
            .bind(organization_id)
            .bind(target_id),
        };
        query.execute(&mut *tx).await.map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(MembershipChangeOutcome::Applied)
    }
}
