//! The installation's Dokploy connection: its URL, the encrypted API key,
//! the version Dokploy reported, and who connected it.
//!
//! This module stores ciphertext it cannot read. Encryption, the call to
//! Dokploy that must succeed before anything is written, and the check that
//! the caller is an installation administrator happen in the application
//! layer. Every change is written in one transaction with its audit event.

use supabase_dashboard_domain::account::DisplayName;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    organizations::query_err,
};

/// The encrypted key as stored. `nonce` also identifies the stored value
/// when it is resealed, so a key replaced meanwhile is not overwritten.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedDokployKey {
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// Ciphertext is not secret without the encryption key, but there is no
// reason to print it either.
impl std::fmt::Debug for SealedDokployKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedDokployKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// The stored connection as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDokployConnection {
    /// As the application stored it after parsing; parsed again by the
    /// caller.
    pub url: String,
    pub key: SealedDokployKey,
    pub version: String,
    pub verified_at: OffsetDateTime,
    pub connected_at: OffsetDateTime,
    pub connected_by: Option<DisplayName>,
    pub key_replaced_at: Option<OffsetDateTime>,
    pub key_replaced_by: Option<DisplayName>,
    /// The deployment supplies this connection; administrators cannot
    /// replace or remove it.
    pub from_deployment: bool,
    /// The server connected it from the deployment's configuration.
    pub connected_by_deployment: bool,
    /// The server last replaced the key from the deployment's
    /// configuration.
    pub key_replaced_by_deployment: bool,
}

pub struct NewDokployConnection<'a> {
    pub url: &'a str,
    pub key_id: &'a str,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub version: &'a str,
    /// `None` when the deployment supplies the connection.
    pub connected_by: Option<Uuid>,
}

pub struct ReplacedDokployKey<'a> {
    /// The URL the replacement was checked against. Nothing is written
    /// when the stored connection points elsewhere by now.
    pub url: &'a str,
    pub key_id: &'a str,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub version: &'a str,
    /// `None` when the deployment supplies the key. An administrator's
    /// replacement writes nothing while the deployment supplies the
    /// connection.
    pub replaced_by: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct ConnectionRow {
    url: String,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    version: String,
    verified_at: OffsetDateTime,
    connected_at: OffsetDateTime,
    connected_by_name: Option<String>,
    key_replaced_at: Option<OffsetDateTime>,
    key_replaced_by_name: Option<String>,
    from_deployment: bool,
    connected_by_deployment: bool,
    key_replaced_by_deployment: bool,
}

pub(crate) fn display_name(raw: Option<String>) -> Result<Option<DisplayName>, PersistenceError> {
    raw.map(|name| {
        DisplayName::parse(&name).map_err(|_| PersistenceError::InvalidRow("accounts.display_name"))
    })
    .transpose()
}

impl Database {
    /// The stored Dokploy connection, if there is one.
    pub async fn find_dokploy_connection(
        &self,
    ) -> Result<Option<StoredDokployConnection>, PersistenceError> {
        let row: Option<ConnectionRow> = sqlx::query_as(
            "SELECT d.url, d.key_id, d.nonce, d.ciphertext, d.version, d.verified_at, \
                    d.connected_at, c.display_name AS connected_by_name, \
                    d.key_replaced_at, r.display_name AS key_replaced_by_name, \
                    d.from_deployment, d.connected_by_deployment, \
                    d.key_replaced_by_deployment \
             FROM dokploy_connection d \
             LEFT JOIN accounts c ON c.id = d.connected_by \
             LEFT JOIN accounts r ON r.id = d.key_replaced_by",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        row.map(|row| {
            Ok(StoredDokployConnection {
                connected_by: display_name(row.connected_by_name)?,
                key_replaced_by: display_name(row.key_replaced_by_name)?,
                url: row.url,
                key: SealedDokployKey {
                    key_id: row.key_id,
                    nonce: row.nonce,
                    ciphertext: row.ciphertext,
                },
                version: row.version,
                verified_at: row.verified_at,
                connected_at: row.connected_at,
                key_replaced_at: row.key_replaced_at,
                from_deployment: row.from_deployment,
                connected_by_deployment: row.connected_by_deployment,
                key_replaced_by_deployment: row.key_replaced_by_deployment,
            })
        })
        .transpose()
    }

    /// Stores the connection and records `audit` with it. Returns `false`,
    /// writing nothing, when a connection is already stored.
    pub async fn insert_dokploy_connection(
        &self,
        connection: &NewDokployConnection<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let inserted = sqlx::query(
            "INSERT INTO dokploy_connection \
                 (url, key_id, nonce, ciphertext, version, connected_by, \
                  from_deployment, connected_by_deployment) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
             ON CONFLICT (singleton) DO NOTHING",
        )
        .bind(connection.url)
        .bind(connection.key_id)
        .bind(connection.nonce)
        .bind(connection.ciphertext)
        .bind(connection.version)
        .bind(connection.connected_by)
        .bind(connection.connected_by.is_none())
        .execute(&mut *tx)
        .await
        .map_err(query_err)?
        .rows_affected();
        if inserted == 0 {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }

    /// Replaces the stored key and the version found with it, and records
    /// `audit`. Returns `false`, writing nothing, when no connection to
    /// `replacement.url` is stored.
    pub async fn replace_dokploy_key(
        &self,
        replacement: &ReplacedDokployKey<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let updated = sqlx::query(
            "UPDATE dokploy_connection SET key_id = $2, nonce = $3, ciphertext = $4, \
                 version = $5, verified_at = now(), key_replaced_by = $6, \
                 key_replaced_at = now(), key_replaced_by_deployment = $7, \
                 from_deployment = $7 \
             WHERE url = $1 AND (NOT from_deployment OR $7)",
        )
        .bind(replacement.url)
        .bind(replacement.key_id)
        .bind(replacement.nonce)
        .bind(replacement.ciphertext)
        .bind(replacement.version)
        .bind(replacement.replaced_by)
        .bind(replacement.replaced_by.is_none())
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

    /// Deletes the stored connection and records `audit`. Returns the URL
    /// it pointed to, or `None`, writing nothing, when none was stored or
    /// the deployment supplies it.
    pub async fn delete_dokploy_connection(
        &self,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<String>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let url: Option<String> = sqlx::query_scalar(
            "DELETE FROM dokploy_connection WHERE NOT from_deployment RETURNING url",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?;
        if url.is_none() {
            return Ok(None);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(url)
    }

    /// Replaces the stored connection, which pointed to `old_url`, with one
    /// the deployment supplies, and records `audit`. The dashboard's
    /// placement in Dokploy goes with the old connection. Returns `false`,
    /// writing nothing, when the stored connection is no longer the one the
    /// deployment supplied for `old_url`.
    pub async fn replace_deployment_dokploy_connection(
        &self,
        old_url: &str,
        connection: &NewDokployConnection<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let deleted =
            sqlx::query("DELETE FROM dokploy_connection WHERE url = $1 AND from_deployment")
                .bind(old_url)
                .execute(&mut *tx)
                .await
                .map_err(query_err)?
                .rows_affected();
        if deleted == 0 {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO dokploy_connection \
                 (url, key_id, nonce, ciphertext, version, connected_by, \
                  from_deployment, connected_by_deployment) \
             VALUES ($1, $2, $3, $4, $5, NULL, TRUE, TRUE)",
        )
        .bind(connection.url)
        .bind(connection.key_id)
        .bind(connection.nonce)
        .bind(connection.ciphertext)
        .bind(connection.version)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }

    /// Marks the stored connection to `url` as supplied by the deployment,
    /// or no longer supplied. Returns `false` when no connection to `url`
    /// is stored.
    pub async fn set_dokploy_from_deployment(
        &self,
        url: &str,
        from_deployment: bool,
    ) -> Result<bool, PersistenceError> {
        let updated =
            sqlx::query("UPDATE dokploy_connection SET from_deployment = $2 WHERE url = $1")
                .bind(url)
                .bind(from_deployment)
                .execute(&self.pool)
                .await
                .map_err(query_err)?
                .rows_affected();
        Ok(updated > 0)
    }

    /// The stored Dokploy key with its URL, when it is not sealed under
    /// `key_id`.
    pub async fn find_dokploy_key_not_under(
        &self,
        key_id: &str,
    ) -> Result<Option<(String, SealedDokployKey)>, PersistenceError> {
        let row: Option<(String, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT url, key_id, nonce, ciphertext FROM dokploy_connection WHERE key_id <> $1",
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(row.map(|(url, key_id, nonce, ciphertext)| {
            (
                url,
                SealedDokployKey {
                    key_id,
                    nonce,
                    ciphertext,
                },
            )
        }))
    }

    /// Replaces the stored Dokploy key's ciphertext with the same value
    /// sealed under another key. Who connected or replaced it and when stay
    /// as they are. Returns `false` when the stored key is no longer the
    /// one read (its nonce changed) or points to another URL.
    pub async fn reseal_dokploy_key(
        &self,
        url: &str,
        old_nonce: &[u8],
        key_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<bool, PersistenceError> {
        let updated = sqlx::query(
            "UPDATE dokploy_connection SET key_id = $3, nonce = $4, ciphertext = $5 \
             WHERE url = $1 AND nonce = $2",
        )
        .bind(url)
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
}

/// The confirmed Dokploy placement as stored. The application parses the
/// IDs and kind again.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StoredDokployPlacement {
    pub service_kind: String,
    pub service_id: String,
    pub service_name: String,
    pub project_id: String,
    pub project_name: String,
    pub environment_id: String,
    pub environment_name: String,
    pub confirmed_at: OffsetDateTime,
    #[sqlx(rename = "confirmed_by_name")]
    pub confirmed_by_raw: Option<String>,
}

impl StoredDokployPlacement {
    /// Who confirmed it, `None` once that account has been deleted.
    pub fn confirmed_by(&self) -> Result<Option<DisplayName>, PersistenceError> {
        display_name(self.confirmed_by_raw.clone())
    }
}

pub struct NewDokployPlacement<'a> {
    /// The connection the placement was read through. Nothing is written
    /// when the stored connection points elsewhere by now.
    pub url: &'a str,
    pub service_kind: &'a str,
    pub service_id: &'a str,
    pub service_name: &'a str,
    pub project_id: &'a str,
    pub project_name: &'a str,
    pub environment_id: &'a str,
    pub environment_name: &'a str,
    pub confirmed_by: Uuid,
}

impl Database {
    /// The confirmed placement, if there is one.
    pub async fn find_dokploy_placement(
        &self,
    ) -> Result<Option<StoredDokployPlacement>, PersistenceError> {
        sqlx::query_as(
            "SELECT p.service_kind, p.service_id, p.service_name, p.project_id, \
                    p.project_name, p.environment_id, p.environment_name, p.confirmed_at, \
                    a.display_name AS confirmed_by_name \
             FROM dokploy_placement p \
             LEFT JOIN accounts a ON a.id = p.confirmed_by",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)
    }

    /// Stores `placement` in place of any confirmed before, and records
    /// `audit`. Returns `false`, writing nothing, when no connection to
    /// `placement.url` is stored.
    pub async fn confirm_dokploy_placement(
        &self,
        placement: &NewDokployPlacement<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        // Locks the connection row, so a concurrent removal waits and then
        // removes this placement with it.
        let connected: Option<bool> = sqlx::query_scalar(
            "SELECT singleton FROM dokploy_connection WHERE url = $1 FOR UPDATE",
        )
        .bind(placement.url)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?;
        if connected.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO dokploy_placement \
                 (service_kind, service_id, service_name, project_id, project_name, \
                  environment_id, environment_name, confirmed_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (singleton) DO UPDATE SET \
                 service_kind = EXCLUDED.service_kind, service_id = EXCLUDED.service_id, \
                 service_name = EXCLUDED.service_name, project_id = EXCLUDED.project_id, \
                 project_name = EXCLUDED.project_name, \
                 environment_id = EXCLUDED.environment_id, \
                 environment_name = EXCLUDED.environment_name, \
                 confirmed_by = EXCLUDED.confirmed_by, confirmed_at = now()",
        )
        .bind(placement.service_kind)
        .bind(placement.service_id)
        .bind(placement.service_name)
        .bind(placement.project_id)
        .bind(placement.project_name)
        .bind(placement.environment_id)
        .bind(placement.environment_name)
        .bind(placement.confirmed_by)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }

    /// Deletes the confirmed placement and records `audit`. Returns
    /// `false`, writing nothing, when none was confirmed.
    pub async fn clear_dokploy_placement(
        &self,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let removed = sqlx::query("DELETE FROM dokploy_placement")
            .execute(&mut *tx)
            .await
            .map_err(query_err)?
            .rows_affected();
        if removed == 0 {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }
}
