//! Handoff codes and Studio sessions (docs/adr/0002-studio-access.md).
//!
//! The application decides who may open Studio. These queries make the
//! rest hold in the database: a code works once and briefly, and a Studio
//! session is only valid while its dashboard session, the account, the
//! membership, and the project's Studio login all still exist.

use std::time::Duration;

use supabase_dashboard_domain::{authz::OrgRole, connection::CredentialKind, project::ProjectUrl};
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    connections::StoredCredential,
    organizations::{parse_role, query_err},
};

/// What a request on a Studio host needs, read in one query.
#[derive(Debug)]
pub struct StudioGrant {
    pub account_id: Uuid,
    pub role: OrgRole,
    pub api_url: ProjectUrl,
    pub login: StoredCredential,
    /// The project's own certificate bundle, if one is stored.
    pub authorities: Option<String>,
}

impl Database {
    /// Stores a handoff code, valid for `ttl`, and records `audit` with it.
    /// Expired codes of the same dashboard session are removed first.
    pub async fn create_studio_handoff(
        &self,
        code_hash: &[u8; 32],
        session_id: Uuid,
        project_id: Uuid,
        return_path: &str,
        ttl: Duration,
        audit: &AuditEvent<'_>,
    ) -> Result<(), PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        sqlx::query("DELETE FROM studio_handoffs WHERE session_id = $1 AND expires_at <= now()")
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(query_err)?;
        sqlx::query(
            "INSERT INTO studio_handoffs (code_hash, session_id, project_id, return_path, expires_at) \
             VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
        )
        .bind(code_hash.as_slice())
        .bind(session_id)
        .bind(project_id)
        .bind(return_path)
        .bind(ttl.as_secs_f64())
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(())
    }

    /// Uses up a handoff code for `project_id` and starts a Studio session
    /// with `token_hash`. The session ends after `lifetime` or with its
    /// dashboard session, whichever comes first. Returns the path to land
    /// on, or `None` when the code is unknown, used, expired, or for
    /// another project.
    pub async fn redeem_studio_handoff(
        &self,
        code_hash: &[u8; 32],
        project_id: Uuid,
        token_hash: &[u8; 32],
        lifetime: Duration,
    ) -> Result<Option<String>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let redeemed: Option<(Uuid, String)> = sqlx::query_as(
            "DELETE FROM studio_handoffs WHERE code_hash = $1 \
             RETURNING session_id, return_path, project_id = $2 AND expires_at > now() AS usable",
        )
        .bind(code_hash.as_slice())
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_err)?
        .and_then(|(session_id, path, usable): (Uuid, String, bool)| {
            usable.then_some((session_id, path))
        });
        let Some((session_id, return_path)) = redeemed else {
            // A wrong or stale code is still used up.
            tx.commit().await.map_err(query_err)?;
            return Ok(None);
        };
        let inserted = sqlx::query(
            "INSERT INTO studio_sessions (token_hash, session_id, project_id, expires_at) \
             SELECT $1, s.id, $3, LEAST(s.expires_at, now() + make_interval(secs => $4)) \
             FROM sessions s WHERE s.id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()",
        )
        .bind(token_hash.as_slice())
        .bind(session_id)
        .bind(project_id)
        .bind(lifetime.as_secs_f64())
        .execute(&mut *tx)
        .await
        .map_err(query_err)?
        .rows_affected();
        tx.commit().await.map_err(query_err)?;
        Ok((inserted == 1).then_some(return_path))
    }

    /// Everything a Studio request needs, if the Studio session is valid
    /// for this project right now: its dashboard session is live and not
    /// idle for longer than `idle_timeout`, the account is enabled, the
    /// account is still a member, and the project has a Studio login. A
    /// valid request also counts as activity on the dashboard session,
    /// refreshed at most once a minute. The caller checks the role.
    pub async fn find_studio_grant(
        &self,
        token_hash: &[u8; 32],
        project_id: Uuid,
        idle_timeout: Duration,
    ) -> Result<Option<StudioGrant>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            session_id: Uuid,
            account_id: Uuid,
            role: String,
            api_url: String,
            key_id: String,
            nonce: Vec<u8>,
            ciphertext: Vec<u8>,
            updated_at: time::OffsetDateTime,
            pem: Option<String>,
        }
        let row: Option<Row> = sqlx::query_as(
            "SELECT s.id AS session_id, a.id AS account_id, m.role, p.api_url, \
                    c.key_id, c.nonce, c.ciphertext, c.updated_at, pa.pem \
             FROM studio_sessions ss \
             JOIN sessions s ON s.id = ss.session_id \
             JOIN accounts a ON a.id = s.account_id \
             JOIN projects p ON p.id = ss.project_id \
             JOIN organization_members m \
               ON m.organization_id = p.organization_id AND m.account_id = a.id \
             JOIN project_credentials c ON c.project_id = p.id AND c.kind = $3 \
             LEFT JOIN project_authorities pa ON pa.project_id = p.id \
             WHERE ss.token_hash = $1 AND ss.project_id = $2 AND ss.expires_at > now() \
               AND s.revoked_at IS NULL AND s.expires_at > now() \
               AND s.last_seen_at > now() - make_interval(secs => $4) \
               AND a.disabled_at IS NULL",
        )
        .bind(token_hash.as_slice())
        .bind(project_id)
        .bind(CredentialKind::StudioLogin.as_str())
        .bind(idle_timeout.as_secs_f64())
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        sqlx::query(
            "UPDATE sessions SET last_seen_at = now() \
             WHERE id = $1 AND last_seen_at < now() - interval '1 minute'",
        )
        .bind(row.session_id)
        .execute(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(Some(StudioGrant {
            account_id: row.account_id,
            role: parse_role(&row.role)?,
            api_url: ProjectUrl::parse(&row.api_url)
                .map_err(|_| PersistenceError::InvalidRow("projects.api_url"))?,
            login: StoredCredential {
                kind: CredentialKind::StudioLogin,
                key_id: row.key_id,
                nonce: row.nonce,
                ciphertext: row.ciphertext,
                updated_at: row.updated_at,
            },
            authorities: row.pem,
        }))
    }
}
