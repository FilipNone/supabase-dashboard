//! Encrypted API keys and the service checks of each project: the latest
//! one, and a bounded history.
//!
//! This module stores ciphertext it cannot read. Encryption and decryption
//! happen in the application layer, which also decides who may call these
//! queries.

use supabase_dashboard_domain::connection::{CredentialKind, HealthReport, ServiceCheck};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    organizations::query_err,
};

/// How many past checks to keep for each project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryRetention {
    pub max_age_days: u16,
    /// At least one: the check just saved is always kept.
    pub max_entries: u16,
}

/// A project's kept checks as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHealthHistory {
    /// Newest first.
    pub recent: Vec<HealthReport>,
    pub total: i64,
    pub with_failures: i64,
    pub since: Option<OffsetDateTime>,
    /// Kept checks counted per UTC hour, oldest first: the hour's start,
    /// all checks, and checks with a failing service. Hours without a
    /// check are left out.
    pub hours: Vec<(OffsetDateTime, i64, i64)>,
    /// The database's clock when the history was read.
    pub read_at: OffsetDateTime,
}

/// One encrypted key as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredCredential {
    pub kind: CredentialKind,
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub updated_at: OffsetDateTime,
}

// Ciphertext is not secret without the key, but there is no reason to print
// it either.
impl std::fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCredential")
            .field("kind", &self.kind)
            .field("key_id", &self.key_id)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

pub struct NewCredential<'a> {
    pub project_id: Uuid,
    pub kind: CredentialKind,
    pub key_id: &'a str,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub updated_by: Uuid,
}

#[derive(sqlx::FromRow)]
struct CredentialRow {
    kind: String,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    updated_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct ProjectCredentialRow {
    project_id: Uuid,
    #[sqlx(flatten)]
    row: CredentialRow,
}

impl Database {
    /// Every stored key of a project.
    pub async fn list_credentials(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<StoredCredential>, PersistenceError> {
        let rows: Vec<CredentialRow> = sqlx::query_as(
            "SELECT kind, key_id, nonce, ciphertext, updated_at FROM project_credentials \
             WHERE project_id = $1 ORDER BY kind",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter()
            .map(|row| {
                Ok(StoredCredential {
                    kind: CredentialKind::parse(&row.kind)
                        .ok_or(PersistenceError::InvalidRow("project_credentials.kind"))?,
                    key_id: row.key_id,
                    nonce: row.nonce,
                    ciphertext: row.ciphertext,
                    updated_at: row.updated_at,
                })
            })
            .collect()
    }

    /// Stores or replaces one key. Returns `false` when the project no
    /// longer exists.
    pub async fn upsert_credential(
        &self,
        credential: &NewCredential<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        // Lock the project so a concurrent unregister cannot leave the new
        // row behind or fail on the foreign key halfway through.
        let exists: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM projects WHERE id = $1 FOR UPDATE")
                .bind(credential.project_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(query_err)?;
        if exists.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO project_credentials \
             (project_id, kind, key_id, nonce, ciphertext, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, now()) \
             ON CONFLICT (project_id, kind) DO UPDATE SET \
             key_id = EXCLUDED.key_id, nonce = EXCLUDED.nonce, \
             ciphertext = EXCLUDED.ciphertext, updated_by = EXCLUDED.updated_by, \
             updated_at = now()",
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
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }

    /// The project's stored certificate bundle and when it was saved.
    pub async fn find_project_authorities(
        &self,
        project_id: Uuid,
    ) -> Result<Option<(String, OffsetDateTime)>, PersistenceError> {
        sqlx::query_as("SELECT pem, updated_at FROM project_authorities WHERE project_id = $1")
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(query_err)
    }

    /// Stores or replaces the project's certificate bundle and records
    /// `audit` with it. Returns when it was saved, or `None` when the
    /// project no longer exists.
    pub async fn upsert_project_authorities(
        &self,
        project_id: Uuid,
        pem: &str,
        updated_by: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<OffsetDateTime>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let exists: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM projects WHERE id = $1 FOR UPDATE")
                .bind(project_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(query_err)?;
        if exists.is_none() {
            return Ok(None);
        }
        let updated_at: OffsetDateTime = sqlx::query_scalar(
            "INSERT INTO project_authorities (project_id, pem, updated_by, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (project_id) DO UPDATE SET \
             pem = EXCLUDED.pem, updated_by = EXCLUDED.updated_by, updated_at = now() \
             RETURNING updated_at",
        )
        .bind(project_id)
        .bind(pem)
        .bind(updated_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(Some(updated_at))
    }

    /// Deletes the project's certificate bundle. Returns `false` when none
    /// was stored.
    pub async fn delete_project_authorities(
        &self,
        project_id: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let deleted = sqlx::query("DELETE FROM project_authorities WHERE project_id = $1")
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

    /// Deletes one key. Returns `false` when none was stored.
    pub async fn delete_credential(
        &self,
        project_id: Uuid,
        kind: CredentialKind,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let deleted =
            sqlx::query("DELETE FROM project_credentials WHERE project_id = $1 AND kind = $2")
                .bind(project_id)
                .bind(kind.as_str())
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

    /// How many stored keys each encryption key ID holds: project keys and
    /// the Dokploy API key.
    pub async fn count_credentials_by_key(&self) -> Result<Vec<(String, i64)>, PersistenceError> {
        sqlx::query_as(
            "SELECT key_id, count(*) FROM ( \
                 SELECT key_id FROM project_credentials \
                 UNION ALL SELECT key_id FROM dokploy_connection \
             ) stored GROUP BY key_id ORDER BY key_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)
    }

    /// Up to `limit` stored keys that are not sealed under `key_id`, in
    /// project and kind order, starting after `after`. Paging by position
    /// lets a caller skip rows it cannot reseal without seeing them again.
    pub async fn list_credentials_not_under(
        &self,
        key_id: &str,
        after: Option<(Uuid, CredentialKind)>,
        limit: i64,
    ) -> Result<Vec<(Uuid, StoredCredential)>, PersistenceError> {
        let (after_project, after_kind) = match after {
            Some((project, kind)) => (Some(project), Some(kind.as_str())),
            None => (None, None),
        };
        let rows: Vec<ProjectCredentialRow> = sqlx::query_as(
            "SELECT project_id, kind, key_id, nonce, ciphertext, updated_at \
             FROM project_credentials \
             WHERE key_id <> $1 AND ($2::uuid IS NULL OR (project_id, kind) > ($2, $3)) \
             ORDER BY project_id, kind LIMIT $4",
        )
        .bind(key_id)
        .bind(after_project)
        .bind(after_kind)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter()
            .map(|ProjectCredentialRow { project_id, row }| {
                Ok((
                    project_id,
                    StoredCredential {
                        kind: CredentialKind::parse(&row.kind)
                            .ok_or(PersistenceError::InvalidRow("project_credentials.kind"))?,
                        key_id: row.key_id,
                        nonce: row.nonce,
                        ciphertext: row.ciphertext,
                        updated_at: row.updated_at,
                    },
                ))
            })
            .collect()
    }

    /// Replaces a stored key's ciphertext with the same value sealed under
    /// another key. Only applies while the row still holds `old_nonce`, so
    /// a key replaced in the meantime is left alone. Who set the key and
    /// when stay as they were. Returns whether the row was changed.
    pub async fn reseal_credential(
        &self,
        project_id: Uuid,
        kind: CredentialKind,
        old_nonce: &[u8],
        key_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<bool, PersistenceError> {
        let updated = sqlx::query(
            "UPDATE project_credentials SET key_id = $4, nonce = $5, ciphertext = $6 \
             WHERE project_id = $1 AND kind = $2 AND nonce = $3",
        )
        .bind(project_id)
        .bind(kind.as_str())
        .bind(old_nonce)
        .bind(key_id)
        .bind(nonce)
        .bind(ciphertext)
        .execute(&self.pool)
        .await
        .map_err(query_err)?
        .rows_affected();
        Ok(updated == 1)
    }

    /// The latest check of a project, if one was saved.
    pub async fn find_health_report(
        &self,
        project_id: Uuid,
    ) -> Result<Option<HealthReport>, PersistenceError> {
        let row: Option<(OffsetDateTime, String)> = sqlx::query_as(
            "SELECT checked_at, checks::text FROM project_health_reports WHERE project_id = $1",
        )
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        row.map(|(checked_at, checks)| {
            let checks: Vec<ServiceCheck> = serde_json::from_str(&checks)
                .map_err(|_| PersistenceError::InvalidRow("project_health_reports.checks"))?;
            Ok(HealthReport { checked_at, checks })
        })
        .transpose()
    }

    /// The saved checks of an organization's projects, at most `limit` of
    /// them. Projects never checked have no entry.
    pub async fn list_health_reports(
        &self,
        organization_id: Uuid,
        limit: usize,
    ) -> Result<Vec<(Uuid, HealthReport)>, PersistenceError> {
        let rows: Vec<(Uuid, OffsetDateTime, String)> = sqlx::query_as(
            "SELECT h.project_id, h.checked_at, h.checks::text \
             FROM project_health_reports h JOIN projects p ON p.id = h.project_id \
             WHERE p.organization_id = $1 \
             ORDER BY h.project_id \
             LIMIT $2",
        )
        .bind(organization_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter()
            .map(|(project_id, checked_at, checks)| {
                let checks: Vec<ServiceCheck> = serde_json::from_str(&checks)
                    .map_err(|_| PersistenceError::InvalidRow("project_health_reports.checks"))?;
                Ok((project_id, HealthReport { checked_at, checks }))
            })
            .collect()
    }

    /// Saves a check as the project's latest and adds it to its history,
    /// then deletes history entries beyond `retention`. Does nothing when
    /// the project was unregistered while the check ran.
    pub async fn save_health_report(
        &self,
        project_id: Uuid,
        report: &HealthReport,
        retention: HistoryRetention,
    ) -> Result<(), PersistenceError> {
        let checks = serde_json::to_string(&report.checks)
            .map_err(|_| PersistenceError::InvalidRow("project_health_reports.checks"))?;
        let failing = !report.failing().is_empty();
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        sqlx::query(
            "INSERT INTO project_health_reports (project_id, checked_at, checks) \
             SELECT id, $2, $3::jsonb FROM projects WHERE id = $1 \
             ON CONFLICT (project_id) DO UPDATE SET \
             checked_at = EXCLUDED.checked_at, checks = EXCLUDED.checks",
        )
        .bind(project_id)
        .bind(report.checked_at)
        .bind(&checks)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        sqlx::query(
            "INSERT INTO project_health_history (project_id, checked_at, failing, checks) \
             SELECT id, $2, $3, $4::jsonb FROM projects WHERE id = $1 \
             ON CONFLICT (project_id, checked_at) DO NOTHING",
        )
        .bind(project_id)
        .bind(report.checked_at)
        .bind(failing)
        .bind(&checks)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        sqlx::query(
            "DELETE FROM project_health_history \
             WHERE project_id = $1 AND checked_at < now() - make_interval(days => $2)",
        )
        .bind(project_id)
        .bind(i32::from(retention.max_age_days))
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        // With fewer entries than the cap the subquery is NULL and nothing
        // is deleted.
        sqlx::query(
            "DELETE FROM project_health_history \
             WHERE project_id = $1 AND checked_at < ( \
                 SELECT checked_at FROM project_health_history WHERE project_id = $1 \
                 ORDER BY checked_at DESC OFFSET $2 LIMIT 1)",
        )
        .bind(project_id)
        .bind(i64::from(retention.max_entries.max(1)) - 1)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        tx.commit().await.map_err(query_err)
    }

    /// The project's kept checks within `retention`: counts over all of
    /// them and the newest `limit` in full. Entries past their age are left
    /// out even before the next save deletes them.
    pub async fn health_history(
        &self,
        project_id: Uuid,
        retention: HistoryRetention,
        limit: u16,
    ) -> Result<StoredHealthHistory, PersistenceError> {
        let (total, with_failures, since, read_at): (
            i64,
            i64,
            Option<OffsetDateTime>,
            OffsetDateTime,
        ) = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE failing), min(checked_at), now() \
             FROM project_health_history \
             WHERE project_id = $1 AND checked_at >= now() - make_interval(days => $2)",
        )
        .bind(project_id)
        .bind(i32::from(retention.max_age_days))
        .fetch_one(&self.pool)
        .await
        .map_err(query_err)?;
        let rows: Vec<(OffsetDateTime, String)> = sqlx::query_as(
            "SELECT checked_at, checks::text FROM project_health_history \
             WHERE project_id = $1 AND checked_at >= now() - make_interval(days => $2) \
             ORDER BY checked_at DESC LIMIT $3",
        )
        .bind(project_id)
        .bind(i32::from(retention.max_age_days))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        // At most 24 rows per kept day, so the result stays small.
        let hours: Vec<(OffsetDateTime, i64, i64)> = sqlx::query_as(
            "SELECT date_trunc('hour', checked_at, 'UTC') AS hour, count(*), \
                    count(*) FILTER (WHERE failing) \
             FROM project_health_history \
             WHERE project_id = $1 AND checked_at >= now() - make_interval(days => $2) \
             GROUP BY hour ORDER BY hour",
        )
        .bind(project_id)
        .bind(i32::from(retention.max_age_days))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        let recent = rows
            .into_iter()
            .map(|(checked_at, checks)| {
                let checks: Vec<ServiceCheck> = serde_json::from_str(&checks)
                    .map_err(|_| PersistenceError::InvalidRow("project_health_history.checks"))?;
                Ok(HealthReport { checked_at, checks })
            })
            .collect::<Result<_, PersistenceError>>()?;
        Ok(StoredHealthHistory {
            recent,
            total,
            with_failures,
            since,
            hours,
            read_at,
        })
    }

    /// When the project was last checked, used for the check cooldown.
    pub async fn last_health_check(
        &self,
        project_id: Uuid,
    ) -> Result<Option<OffsetDateTime>, PersistenceError> {
        sqlx::query_scalar("SELECT checked_at FROM project_health_reports WHERE project_id = $1")
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(query_err)
    }
}
