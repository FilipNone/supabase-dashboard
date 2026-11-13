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
    /// The sealed record of the variables the job wrote.
    pub env_record: Option<&'a SealedEnvRecord>,
}

/// A project's sealed variable record as stored.
#[derive(Clone, sqlx::FromRow)]
pub struct SealedEnvRecord {
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// Ciphertext is not secret without the key, but keep it out of logs.
impl std::fmt::Debug for SealedEnvRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedEnvRecord")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// The recorded Dokploy service of a provisioned project, as it was when
/// the job created it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StoredDokployService {
    pub compose_id: String,
    pub app_name: String,
    pub environment_id: String,
    pub server_id: Option<String>,
    pub job_id: Uuid,
    pub created_at: time::OffsetDateTime,
    /// Set once the dashboard removed the service from Dokploy.
    pub removed_at: Option<time::OffsetDateTime>,
    /// The removal deleted the data volumes too.
    pub volumes_deleted: bool,
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
        if let Some(record) = service.env_record {
            sqlx::query(
                "INSERT INTO project_dokploy_env_records (project_id, key_id, nonce, ciphertext) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(project.id)
            .bind(&record.key_id)
            .bind(&record.nonce)
            .bind(&record.ciphertext)
            .execute(&mut *tx)
            .await
            .map_err(query_err)?;
        }
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

    /// The projects these jobs registered, as (job, project) pairs.
    pub async fn provisioned_projects(
        &self,
        job_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, Uuid)>, PersistenceError> {
        sqlx::query_as(
            "SELECT job_id, project_id FROM project_dokploy_services WHERE job_id = ANY($1)",
        )
        .bind(job_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)
    }

    /// The Dokploy service recorded for a project, or `None` for a project
    /// the dashboard did not provision.
    pub async fn find_project_dokploy_service(
        &self,
        project_id: Uuid,
    ) -> Result<Option<StoredDokployService>, PersistenceError> {
        sqlx::query_as(
            "SELECT compose_id, app_name, environment_id, server_id, job_id, created_at, \
             removed_at, volumes_deleted \
             FROM project_dokploy_services WHERE project_id = $1",
        )
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)
    }

    /// The project's sealed variable record, if it has one.
    pub async fn find_env_record(
        &self,
        project_id: Uuid,
    ) -> Result<Option<SealedEnvRecord>, PersistenceError> {
        sqlx::query_as(
            "SELECT key_id, nonce, ciphertext FROM project_dokploy_env_records \
             WHERE project_id = $1",
        )
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)
    }

    /// Replaces the project's variable record when it still holds the
    /// value read with `old_nonce`, or stores it when `old_nonce` is `None`
    /// and the project has none. Returns `false` when the record changed
    /// meanwhile or the project has no Dokploy service.
    pub async fn replace_env_record(
        &self,
        project_id: Uuid,
        old_nonce: Option<&[u8]>,
        record: &SealedEnvRecord,
    ) -> Result<bool, PersistenceError> {
        let updated = match old_nonce {
            Some(old_nonce) => {
                sqlx::query(
                    "UPDATE project_dokploy_env_records \
                 SET key_id = $3, nonce = $4, ciphertext = $5, updated_at = now() \
                 WHERE project_id = $1 AND nonce = $2",
                )
                .bind(project_id)
                .bind(old_nonce)
                .bind(&record.key_id)
                .bind(&record.nonce)
                .bind(&record.ciphertext)
                .execute(&self.pool)
                .await
            }
            None => sqlx::query(
                "INSERT INTO project_dokploy_env_records (project_id, key_id, nonce, ciphertext) \
                 SELECT $1, $2, $3, $4 FROM project_dokploy_services WHERE project_id = $1 \
                 ON CONFLICT (project_id) DO NOTHING",
            )
            .bind(project_id)
            .bind(&record.key_id)
            .bind(&record.nonce)
            .bind(&record.ciphertext)
            .execute(&self.pool)
            .await,
        }
        .map_err(query_err)?
        .rows_affected();
        Ok(updated == 1)
    }

    /// Up to `limit` variable records not sealed under `key_id`, by
    /// project, starting after `after`.
    pub async fn env_records_not_under(
        &self,
        key_id: &str,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<(Uuid, SealedEnvRecord)>, PersistenceError> {
        let rows: Vec<(Uuid, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT project_id, key_id, nonce, ciphertext FROM project_dokploy_env_records \
             WHERE key_id <> $1 AND ($2::uuid IS NULL OR project_id > $2) \
             ORDER BY project_id LIMIT $3",
        )
        .bind(key_id)
        .bind(after)
        .bind(limit.clamp(1, 500))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|(project_id, key_id, nonce, ciphertext)| {
                (
                    project_id,
                    SealedEnvRecord {
                        key_id,
                        nonce,
                        ciphertext,
                    },
                )
            })
            .collect())
    }

    /// Records that the dashboard removed the project's service
    /// `compose_id` from Dokploy. Recording it again keeps the first time
    /// and never clears `volumes_deleted`. Returns `false` when the project
    /// no longer has that service.
    pub async fn mark_dokploy_service_removed(
        &self,
        project_id: Uuid,
        compose_id: &str,
        volumes_deleted: bool,
    ) -> Result<bool, PersistenceError> {
        let updated = sqlx::query(
            "UPDATE project_dokploy_services \
             SET removed_at = COALESCE(removed_at, now()), \
                 volumes_deleted = volumes_deleted OR $3 \
             WHERE project_id = $1 AND compose_id = $2",
        )
        .bind(project_id)
        .bind(compose_id)
        .bind(volumes_deleted)
        .execute(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(updated.rows_affected() == 1)
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
