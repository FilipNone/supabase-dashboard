//! Project registry entries.
//!
//! As elsewhere in this crate, queries never decide who may do what. The
//! application layer checks the operator's role first. Lookups by project
//! join the operator's membership so that a project in another
//! organization reads exactly like one that does not exist.

use supabase_dashboard_domain::{
    authz::OrgRole,
    project::{ProjectName, ProjectUrl},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    organizations::{parse_role, query_err},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: ProjectName,
    pub api_url: ProjectUrl,
    pub created_at: OffsetDateTime,
}

/// A project together with the operator's role in its organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectAccess {
    pub project: ProjectRecord,
    pub role: OrgRole,
}

#[derive(Debug, Clone)]
pub struct NewProject<'a> {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: &'a ProjectName,
    pub api_url: &'a ProjectUrl,
    pub created_by: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateProjectOutcome {
    Created,
    /// The organization disappeared before the insert.
    OrganizationNotFound,
    /// The organization already has the maximum number of projects.
    LimitReached,
}

#[derive(sqlx::FromRow)]
struct ProjectRow {
    id: Uuid,
    organization_id: Uuid,
    name: String,
    api_url: String,
    created_at: OffsetDateTime,
}

impl TryFrom<ProjectRow> for ProjectRecord {
    type Error = PersistenceError;
    fn try_from(row: ProjectRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            name: ProjectName::parse(&row.name)
                .map_err(|_| PersistenceError::InvalidRow("projects.name"))?,
            api_url: ProjectUrl::parse(&row.api_url)
                .map_err(|_| PersistenceError::InvalidRow("projects.api_url"))?,
            created_at: row.created_at,
        })
    }
}

impl Database {
    /// Registers a project, unless the organization already has
    /// `max_projects`. The organization row is locked so concurrent
    /// registrations cannot exceed the limit.
    pub async fn create_project(
        &self,
        project: &NewProject<'_>,
        max_projects: usize,
        audit: &AuditEvent<'_>,
    ) -> Result<CreateProjectOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let exists: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(project.organization_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(query_err)?;
        if exists.is_none() {
            return Ok(CreateProjectOutcome::OrganizationNotFound);
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM projects WHERE organization_id = $1")
                .bind(project.organization_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(query_err)?;
        if usize::try_from(count).map_or(true, |count| count >= max_projects) {
            return Ok(CreateProjectOutcome::LimitReached);
        }
        sqlx::query(
            "INSERT INTO projects (id, organization_id, name, api_url, created_by) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(project.id)
        .bind(project.organization_id)
        .bind(project.name.as_str())
        .bind(project.api_url.as_str())
        .bind(project.created_by)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(CreateProjectOutcome::Created)
    }

    /// Projects of one organization by name, at most `limit`.
    pub async fn list_projects(
        &self,
        organization_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ProjectRecord>, PersistenceError> {
        let rows: Vec<ProjectRow> = sqlx::query_as(
            "SELECT id, organization_id, name, api_url, created_at FROM projects \
             WHERE organization_id = $1 \
             ORDER BY lower(name), id \
             LIMIT $2",
        )
        .bind(organization_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter().map(ProjectRecord::try_from).collect()
    }

    /// The project and the account's role in its organization, or `None`
    /// when the project does not exist or the account is not a member.
    pub async fn find_project_access(
        &self,
        project_id: Uuid,
        account_id: Uuid,
    ) -> Result<Option<ProjectAccess>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            #[sqlx(flatten)]
            project: ProjectRow,
            role: String,
        }
        let row: Option<Row> = sqlx::query_as(
            "SELECT p.id, p.organization_id, p.name, p.api_url, p.created_at, m.role \
             FROM projects p \
             JOIN organization_members m ON m.organization_id = p.organization_id \
             WHERE p.id = $1 AND m.account_id = $2",
        )
        .bind(project_id)
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        row.map(|row| {
            Ok(ProjectAccess {
                project: row.project.try_into()?,
                role: parse_role(&row.role)?,
            })
        })
        .transpose()
    }

    /// Renames a project. Returns `false` when it does not exist.
    pub async fn rename_project(
        &self,
        project_id: Uuid,
        name: &ProjectName,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let updated =
            sqlx::query("UPDATE projects SET name = $2, updated_at = now() WHERE id = $1")
                .bind(project_id)
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

    /// Removes a project's registry entry. The stack itself is not touched.
    /// Returns `false` when the entry does not exist.
    pub async fn delete_project(
        &self,
        project_id: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let deleted = sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(query_err)?
            .rows_affected();
        if deleted == 0 {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }
}
