//! Projects the dashboard provisioned: the registry entry, its keys, and
//! the Dokploy service behind it, written together by the provisioning
//! job.

use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    connections::NewCredential,
    organizations::query_err,
    projects::NewProject,
};

/// The Dokploy compose service a provisioned project runs as.
#[derive(Debug, Clone, Copy)]
pub struct NewDokployService<'a> {
    pub compose_id: &'a str,
    pub app_name: &'a str,
    pub environment_id: &'a str,
    pub server_id: Option<&'a str>,
    pub job_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterProvisionedOutcome {
    Created,
    /// The job registered it before; nothing was written.
    AlreadyRegistered,
    OrganizationNotFound,
    LimitReached,
}

impl Database {
    /// Registers a provisioned project with its keys and its Dokploy
    /// service in one transaction, unless the organization already has
    /// `max_projects`. A job that runs this again after an interruption
    /// finds its own row and writes nothing.
    pub async fn register_provisioned_project(
        &self,
        project: &NewProject<'_>,
        service: &NewDokployService<'_>,
        credentials: &[NewCredential<'_>],
        max_projects: usize,
        audit: &AuditEvent<'_>,
    ) -> Result<RegisterProvisionedOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let exists: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(project.organization_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(query_err)?;
        if exists.is_none() {
            return Ok(RegisterProvisionedOutcome::OrganizationNotFound);
        }
        let registered: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM project_dokploy_services WHERE job_id = $1")
                .bind(service.job_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(query_err)?;
        if registered.is_some() {
            return Ok(RegisterProvisionedOutcome::AlreadyRegistered);
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM projects WHERE organization_id = $1")
                .bind(project.organization_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(query_err)?;
        if usize::try_from(count).map_or(true, |count| count >= max_projects) {
            return Ok(RegisterProvisionedOutcome::LimitReached);
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
        sqlx::query(
            "INSERT INTO project_dokploy_services \
             (project_id, compose_id, app_name, environment_id, server_id, job_id) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(project.id)
        .bind(service.compose_id)
        .bind(service.app_name)
        .bind(service.environment_id)
        .bind(service.server_id)
        .bind(service.job_id)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        for credential in credentials {
            sqlx::query(
                "INSERT INTO project_credentials \
                 (project_id, kind, key_id, nonce, ciphertext, updated_by, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, now())",
            )
            .bind(credential.project_id)
            .bind(credential.kind.as_str())
            .bind(credential.key_id)
            .bind(credential.nonce)
            .bind(credential.ciphertext)
            .bind(credential.updated_by)
            .execute(&mut *tx)
            .await
            .map_err(query_err)?;
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(RegisterProvisionedOutcome::Created)
    }

    /// Whether the account exists and is not disabled.
    pub async fn account_is_active(&self, account_id: Uuid) -> Result<bool, PersistenceError> {
        let active: Option<bool> =
            sqlx::query_scalar("SELECT disabled_at IS NULL FROM accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(query_err)?;
        Ok(active == Some(true))
    }

    /// How many projects the organization has.
    pub async fn count_projects(&self, organization_id: Uuid) -> Result<i64, PersistenceError> {
        sqlx::query_scalar("SELECT count(*) FROM projects WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&self.pool)
            .await
            .map_err(query_err)
    }
}
