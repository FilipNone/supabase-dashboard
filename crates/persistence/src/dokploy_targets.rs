//! The Dokploy targets each dashboard organization may use for new stacks.
//!
//! Checking that Dokploy shows the environment and server to the stored
//! key, and that the caller is an installation administrator, happens in
//! the application layer. Every change is written in one transaction with
//! its audit event.

use supabase_dashboard_domain::account::DisplayName;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    dokploy::display_name,
    organizations::query_err,
};

/// Most rows read in one listing.
const MAX_ROWS: i64 = 10_000;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredStackTarget {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: String,
    pub project_name: String,
    pub environment_id: String,
    pub environment_name: String,
    pub server_id: Option<String>,
    pub server_name: Option<String>,
    pub added_at: OffsetDateTime,
    pub added_by_name: Option<String>,
}

impl StoredStackTarget {
    /// Who added the target; `None` once that account has been deleted.
    pub fn added_by(&self) -> Result<Option<DisplayName>, PersistenceError> {
        display_name(self.added_by_name.clone())
    }
}

/// An organization's ID and name, for the administrator page.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredOrganizationName {
    pub id: Uuid,
    pub name: String,
}

pub struct NewStackTarget<'a> {
    /// The connection the IDs belong to. Nothing is written when another
    /// URL is connected by then.
    pub url: &'a str,
    pub organization_id: Uuid,
    pub project_id: &'a str,
    pub project_name: &'a str,
    pub environment_id: &'a str,
    pub environment_name: &'a str,
    /// `None` for Dokploy's own server.
    pub server: Option<(&'a str, &'a str)>,
    pub added_by: Uuid,
    /// Most targets the organization may have.
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowOutcome {
    Added(Uuid),
    AlreadyAllowed,
    LimitReached,
    NotConnected,
    NoOrganization,
}

/// The columns of [`StoredStackTarget`], as a macro so queries can extend
/// it with `concat!` and stay static strings.
macro_rules! select_targets {
    () => {
        "SELECT t.id, t.organization_id, t.project_id, t.project_name, \
            t.environment_id, t.environment_name, t.server_id, t.server_name, t.added_at, \
            a.display_name AS added_by_name \
     FROM dokploy_stack_targets t \
     LEFT JOIN accounts a ON a.id = t.added_by"
    };
}

impl Database {
    /// Every organization's targets, oldest first within an organization.
    pub async fn list_dokploy_stack_targets(
        &self,
    ) -> Result<Vec<StoredStackTarget>, PersistenceError> {
        sqlx::query_as(concat!(
            select_targets!(),
            " ORDER BY t.organization_id, t.added_at, t.id LIMIT $1"
        ))
        .bind(MAX_ROWS)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)
    }

    /// One organization's targets, oldest first.
    pub async fn list_organization_stack_targets(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<StoredStackTarget>, PersistenceError> {
        sqlx::query_as(concat!(
            select_targets!(),
            " WHERE t.organization_id = $1 ORDER BY t.added_at, t.id LIMIT $2"
        ))
        .bind(organization_id)
        .bind(MAX_ROWS)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)
    }

    /// Organizations by name, at most `limit`.
    pub async fn list_organization_names(
        &self,
        limit: i64,
    ) -> Result<Vec<StoredOrganizationName>, PersistenceError> {
        sqlx::query_as("SELECT id, name FROM organizations ORDER BY lower(name), id LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(query_err)
    }

    /// Allows `target` and records `audit` with it. Nothing is written, and
    /// nothing audited, unless the outcome is [`AllowOutcome::Added`].
    pub async fn allow_dokploy_stack_target(
        &self,
        target: &NewStackTarget<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<AllowOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        // Locks the connection row, so a concurrent removal waits and then
        // removes this target with it.
        let connected: Option<bool> = sqlx::query_scalar(
            "SELECT singleton FROM dokploy_connection WHERE url = $1 FOR UPDATE",
        )
        .bind(target.url)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?;
        if connected.is_none() {
            return Ok(AllowOutcome::NotConnected);
        }
        // Locks the organization, so two requests cannot both pass the
        // limit, and a deleted organization gets no rows.
        let organization: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(target.organization_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(query_err)?;
        if organization.is_none() {
            return Ok(AllowOutcome::NoOrganization);
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM dokploy_stack_targets WHERE organization_id = $1",
        )
        .bind(target.organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(query_err)?;
        let id = Uuid::now_v7();
        let inserted = sqlx::query(
            "INSERT INTO dokploy_stack_targets \
                 (id, organization_id, project_id, project_name, environment_id, \
                  environment_name, server_id, server_name, added_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(target.organization_id)
        .bind(target.project_id)
        .bind(target.project_name)
        .bind(target.environment_id)
        .bind(target.environment_name)
        .bind(target.server.map(|(id, _)| id))
        .bind(target.server.map(|(_, name)| name))
        .bind(target.added_by)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?
        .rows_affected();
        if inserted == 0 {
            return Ok(AllowOutcome::AlreadyAllowed);
        }
        // Counted before the insert, so a duplicate is reported as such
        // even at the limit.
        if usize::try_from(count).map_or(true, |count| count >= target.limit) {
            return Ok(AllowOutcome::LimitReached);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(AllowOutcome::Added(id))
    }

    /// Removes target `id` from `organization_id` and records `audit`.
    /// Returns the removed row, or `None`, writing nothing, when the
    /// organization has no such target.
    pub async fn remove_dokploy_stack_target(
        &self,
        organization_id: Uuid,
        id: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<(String, Option<String>)>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let removed: Option<(String, Option<String>)> = sqlx::query_as(
            "DELETE FROM dokploy_stack_targets WHERE organization_id = $1 AND id = $2 \
             RETURNING environment_id, server_id",
        )
        .bind(organization_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?;
        if removed.is_none() {
            return Ok(None);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(removed)
    }
}
