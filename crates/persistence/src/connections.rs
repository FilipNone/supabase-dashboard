//! Encrypted API keys and the latest service check of each project.
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

    /// Replaces the saved check of a project. Does nothing when the project
    /// was unregistered while the check ran.
    pub async fn save_health_report(
        &self,
        project_id: Uuid,
        report: &HealthReport,
    ) -> Result<(), PersistenceError> {
        let checks = serde_json::to_string(&report.checks)
            .map_err(|_| PersistenceError::InvalidRow("project_health_reports.checks"))?;
        sqlx::query(
            "INSERT INTO project_health_reports (project_id, checked_at, checks) \
             SELECT id, $2, $3::jsonb FROM projects WHERE id = $1 \
             ON CONFLICT (project_id) DO UPDATE SET \
             checked_at = EXCLUDED.checked_at, checks = EXCLUDED.checks",
        )
        .bind(project_id)
        .bind(report.checked_at)
        .bind(checks)
        .execute(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(())
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
