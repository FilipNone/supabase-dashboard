//! Durable background jobs. See the `jobs` migration for the model.
//!
//! Every write after the claim names the worker's lease: a worker whose
//! lease ran out, and whose job another worker has since claimed, changes
//! nothing. The caller checks the returned `bool` and stops when it is
//! `false`.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    organizations::query_err,
};

/// Most rows read in one listing.
const MAX_ROWS: i64 = 500;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredJob {
    pub id: Uuid,
    pub kind: String,
    pub organization_id: Uuid,
    pub state: String,
    pub step: String,
    /// The `data` column as JSON text.
    pub data: String,
    pub interruptions: i32,
    pub run_after: OffsetDateTime,
    pub lease_until: Option<OffsetDateTime>,
    pub message: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

/// A job's sealed secrets as stored.
#[derive(Clone, sqlx::FromRow)]
pub struct SealedJobSecrets {
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// Ciphertext is not secret without the encryption key, but there is no
// reason to print it either.
impl std::fmt::Debug for SealedJobSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedJobSecrets")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

pub struct NewJob<'a> {
    pub id: Uuid,
    pub kind: &'a str,
    pub organization_id: Uuid,
    pub step: &'a str,
    /// JSON object text.
    pub data: &'a str,
    pub secrets: Option<&'a SealedJobSecrets>,
    pub created_by: Uuid,
}

/// What a worker does with its job after a step.
pub enum JobUpdate<'a> {
    /// Saves progress and keeps the lease for `lease_seconds` more.
    Continue {
        step: &'a str,
        data: &'a str,
        lease_seconds: f64,
    },
    /// Releases the job until `run_after`, for example to poll again.
    /// `interrupted` counts it as an interruption, for a step that took too
    /// long.
    Wait {
        step: &'a str,
        data: &'a str,
        run_after: OffsetDateTime,
        message: Option<&'a str>,
        interrupted: bool,
    },
    Succeed {
        data: &'a str,
        message: Option<&'a str>,
    },
    Fail {
        data: &'a str,
        message: &'a str,
    },
}

/// The columns of [`StoredJob`], as a macro so queries stay static strings.
macro_rules! job_columns {
    () => {
        "id, kind, organization_id, state, step, data::text AS data, interruptions, \
         run_after, lease_until, message, created_by, created_at, updated_at, finished_at"
    };
}

impl Database {
    /// Queues a job, with its sealed secrets, and records `audit` with it.
    pub async fn insert_job(
        &self,
        job: &NewJob<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<(), PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        sqlx::query(
            "INSERT INTO jobs (id, kind, organization_id, state, step, data, created_by) \
             VALUES ($1, $2, $3, 'queued', $4, $5::jsonb, $6)",
        )
        .bind(job.id)
        .bind(job.kind)
        .bind(job.organization_id)
        .bind(job.step)
        .bind(job.data)
        .bind(job.created_by)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        if let Some(secrets) = job.secrets {
            sqlx::query(
                "INSERT INTO job_secrets (job_id, key_id, nonce, ciphertext) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(job.id)
            .bind(&secrets.key_id)
            .bind(&secrets.nonce)
            .bind(&secrets.ciphertext)
            .execute(&mut *tx)
            .await
            .map_err(query_err)?;
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)
    }

    /// Queues a stop, start, or redeploy job for `project_id` with its
    /// audit event, unless the project already has one unfinished. Returns
    /// `false`, writing nothing, in that case.
    pub async fn insert_stack_action_job(
        &self,
        job: &NewJob<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        match self.insert_job(job, audit).await {
            Ok(()) => Ok(true),
            Err(PersistenceError::Query(sqlx::Error::Database(err)))
                if err.is_unique_violation() =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    /// The newest stop, start, or redeploy job of a project.
    pub async fn latest_stack_action_job(
        &self,
        project_id: Uuid,
    ) -> Result<Option<StoredJob>, PersistenceError> {
        sqlx::query_as(concat!(
            "SELECT ",
            job_columns!(),
            " FROM jobs WHERE kind = 'stack_action' AND data ->> 'project_id' = $1 \
             ORDER BY created_at DESC, id DESC LIMIT 1"
        ))
        .bind(project_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)
    }

    /// Claims the next due job for `owner`: a queued job whose `run_after`
    /// has passed, or a running job whose lease ran out, which counts as an
    /// interruption.
    pub async fn claim_job(
        &self,
        owner: Uuid,
        lease_seconds: f64,
    ) -> Result<Option<StoredJob>, PersistenceError> {
        sqlx::query_as(concat!(
            "UPDATE jobs SET state = 'running', lease_owner = $1, \
                 lease_until = now() + make_interval(secs => $2), \
                 interruptions = interruptions + (state = 'running')::int, updated_at = now() \
             WHERE id = ( \
                 SELECT id FROM jobs \
                 WHERE (state = 'queued' AND run_after <= now()) \
                    OR (state = 'running' AND lease_until < now()) \
                 ORDER BY run_after, id \
                 LIMIT 1 \
                 FOR UPDATE SKIP LOCKED) \
             RETURNING ",
            job_columns!()
        ))
        .bind(owner)
        .bind(lease_seconds)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)
    }

    /// Applies `update` to job `id` if `owner` still holds its lease.
    /// Finishing a job successfully also deletes its secrets.
    pub async fn update_job(
        &self,
        id: Uuid,
        owner: Uuid,
        update: &JobUpdate<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let query = match update {
            JobUpdate::Continue {
                step,
                data,
                lease_seconds,
            } => sqlx::query(
                "UPDATE jobs SET step = $3, data = $4::jsonb, message = NULL, \
                     lease_until = now() + make_interval(secs => $5), updated_at = now() \
                 WHERE id = $1 AND lease_owner = $2 AND state = 'running'",
            )
            .bind(id)
            .bind(owner)
            .bind(*step)
            .bind(*data)
            .bind(*lease_seconds),
            JobUpdate::Wait {
                step,
                data,
                run_after,
                message,
                interrupted,
            } => sqlx::query(
                "UPDATE jobs SET state = 'queued', step = $3, data = $4::jsonb, \
                     run_after = $5, message = $6, lease_owner = NULL, lease_until = NULL, \
                     interruptions = interruptions + $7::int, updated_at = now() \
                 WHERE id = $1 AND lease_owner = $2 AND state = 'running'",
            )
            .bind(id)
            .bind(owner)
            .bind(*step)
            .bind(*data)
            .bind(*run_after)
            .bind(*message)
            .bind(i32::from(*interrupted)),
            JobUpdate::Succeed { data, message } => sqlx::query(
                "UPDATE jobs SET state = 'succeeded', data = $3::jsonb, message = $4, \
                     lease_owner = NULL, lease_until = NULL, updated_at = now(), \
                     finished_at = now() \
                 WHERE id = $1 AND lease_owner = $2 AND state = 'running'",
            )
            .bind(id)
            .bind(owner)
            .bind(*data)
            .bind(*message),
            JobUpdate::Fail { data, message } => sqlx::query(
                "UPDATE jobs SET state = 'failed', data = $3::jsonb, message = $4, \
                     lease_owner = NULL, lease_until = NULL, updated_at = now(), \
                     finished_at = now() \
                 WHERE id = $1 AND lease_owner = $2 AND state = 'running'",
            )
            .bind(id)
            .bind(owner)
            .bind(*data)
            .bind(*message),
        };
        let held = query
            .execute(&mut *tx)
            .await
            .map_err(query_err)?
            .rows_affected()
            == 1;
        if held && matches!(update, JobUpdate::Succeed { .. }) {
            sqlx::query("DELETE FROM job_secrets WHERE job_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(query_err)?;
        }
        tx.commit().await.map_err(query_err)?;
        Ok(held)
    }

    /// Up to `limit` jobs whose secrets are not sealed under `key_id`, in
    /// job order, starting after `after`.
    pub async fn job_secrets_not_under(
        &self,
        key_id: &str,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<(Uuid, SealedJobSecrets)>, PersistenceError> {
        let rows: Vec<(Uuid, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT job_id, key_id, nonce, ciphertext FROM job_secrets \
             WHERE key_id <> $1 AND ($2::uuid IS NULL OR job_id > $2) \
             ORDER BY job_id LIMIT $3",
        )
        .bind(key_id)
        .bind(after)
        .bind(limit.clamp(1, MAX_ROWS))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|(job_id, key_id, nonce, ciphertext)| {
                (
                    job_id,
                    SealedJobSecrets {
                        key_id,
                        nonce,
                        ciphertext,
                    },
                )
            })
            .collect())
    }

    /// Replaces a job's sealed secrets with the same value sealed under
    /// another key. Returns `false` when they are gone or changed since
    /// they were read (their nonce differs).
    pub async fn reseal_job_secrets(
        &self,
        job_id: Uuid,
        old_nonce: &[u8],
        sealed: &SealedJobSecrets,
    ) -> Result<bool, PersistenceError> {
        let updated = sqlx::query(
            "UPDATE job_secrets SET key_id = $3, nonce = $4, ciphertext = $5 \
             WHERE job_id = $1 AND nonce = $2",
        )
        .bind(job_id)
        .bind(old_nonce)
        .bind(&sealed.key_id)
        .bind(&sealed.nonce)
        .bind(&sealed.ciphertext)
        .execute(&self.pool)
        .await
        .map_err(query_err)?
        .rows_affected();
        Ok(updated == 1)
    }

    pub async fn job_secrets(
        &self,
        id: Uuid,
    ) -> Result<Option<SealedJobSecrets>, PersistenceError> {
        sqlx::query_as("SELECT key_id, nonce, ciphertext FROM job_secrets WHERE job_id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(query_err)
    }

    pub async fn get_job(&self, id: Uuid) -> Result<Option<StoredJob>, PersistenceError> {
        sqlx::query_as(concat!(
            "SELECT ",
            job_columns!(),
            " FROM jobs WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)
    }

    /// An organization's jobs, newest first, at most `limit` (capped).
    pub async fn list_organization_jobs(
        &self,
        organization_id: Uuid,
        limit: i64,
    ) -> Result<Vec<StoredJob>, PersistenceError> {
        sqlx::query_as(concat!(
            "SELECT ",
            job_columns!(),
            " FROM jobs WHERE organization_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
        ))
        .bind(organization_id)
        .bind(limit.clamp(1, MAX_ROWS))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)
    }
}
