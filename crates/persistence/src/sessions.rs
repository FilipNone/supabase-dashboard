//! Browser sessions. Only a SHA-256 hash of each session token is stored.

use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Database, PersistenceError, accounts::AccountRecord, accounts::AccountRow};

/// Upper bound on sessions returned for one account.
pub const SESSION_LIST_LIMIT: i64 = 100;

pub struct NewSession<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub token_hash: &'a [u8; 32],
    pub expires_at: OffsetDateTime,
    pub user_agent: Option<&'a str>,
}

/// A valid session and the account it belongs to.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_id: Uuid,
    pub account: AccountRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SessionInfo {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub user_agent: Option<String>,
}

impl Database {
    pub async fn create_session(&self, new: &NewSession<'_>) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO sessions (id, account_id, token_hash, expires_at, user_agent) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(new.id)
        .bind(new.account_id)
        .bind(new.token_hash.as_slice())
        .bind(new.expires_at)
        .bind(new.user_agent)
        .execute(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        Ok(())
    }

    /// Looks up a session that is not revoked, not past its absolute expiry,
    /// not idle for longer than `idle_timeout`, and whose account is enabled.
    /// Refreshes `last_seen_at` at most once a minute.
    pub async fn find_active_session(
        &self,
        token_hash: &[u8; 32],
        idle_timeout: Duration,
    ) -> Result<Option<ActiveSession>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            session_id: Uuid,
            #[sqlx(flatten)]
            account: AccountRow,
        }
        let row: Option<Row> = sqlx::query_as(
            "WITH valid AS ( \
                 SELECT s.id FROM sessions s JOIN accounts a ON a.id = s.account_id \
                 WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() \
                   AND s.last_seen_at > now() - make_interval(secs => $2) \
                   AND a.disabled_at IS NULL \
             ), touched AS ( \
                 UPDATE sessions SET last_seen_at = now() \
                 WHERE id IN (SELECT id FROM valid) AND last_seen_at < now() - interval '1 minute' \
             ) \
             SELECT s.id AS session_id, a.id, a.email, a.display_name, a.is_installation_admin, \
                    FALSE AS disabled \
             FROM valid v JOIN sessions s ON s.id = v.id JOIN accounts a ON a.id = s.account_id",
        )
        .bind(token_hash.as_slice())
        .bind(idle_timeout.as_secs_f64())
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        row.map(|row| {
            Ok(ActiveSession {
                session_id: row.session_id,
                account: row.account.try_into()?,
            })
        })
        .transpose()
    }

    /// Revokes the session with this token hash. Returns its ID and account
    /// when a live session was revoked.
    pub async fn revoke_session_by_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<(Uuid, Uuid)>, PersistenceError> {
        sqlx::query_as(
            "UPDATE sessions SET revoked_at = now() \
             WHERE token_hash = $1 AND revoked_at IS NULL RETURNING id, account_id",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)
    }

    /// Revokes one session, but only if it belongs to `account_id`.
    pub async fn revoke_account_session(
        &self,
        account_id: Uuid,
        session_id: Uuid,
    ) -> Result<bool, PersistenceError> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = now() \
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(account_id)
        .execute(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        Ok(result.rows_affected() == 1)
    }

    /// Revokes every live session of an account except `keep`.
    pub async fn revoke_other_sessions(
        &self,
        account_id: Uuid,
        keep: Option<Uuid>,
    ) -> Result<u64, PersistenceError> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = now() \
             WHERE account_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)",
        )
        .bind(account_id)
        .bind(keep)
        .execute(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        Ok(result.rows_affected())
    }

    /// Live sessions of one account, newest first, at most
    /// [`SESSION_LIST_LIMIT`].
    pub async fn list_live_sessions(
        &self,
        account_id: Uuid,
        idle_timeout: Duration,
    ) -> Result<Vec<SessionInfo>, PersistenceError> {
        sqlx::query_as(
            "SELECT id, created_at, last_seen_at, expires_at, user_agent FROM sessions \
             WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > now() \
               AND last_seen_at > now() - make_interval(secs => $2) \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(account_id)
        .bind(idle_timeout.as_secs_f64())
        .bind(SESSION_LIST_LIMIT)
        .fetch_all(&self.pool)
        .await
        .map_err(PersistenceError::Query)
    }

    /// Deletes sessions that can no longer be used. Returns the count.
    pub async fn delete_dead_sessions(
        &self,
        idle_timeout: Duration,
    ) -> Result<u64, PersistenceError> {
        let result = sqlx::query(
            "DELETE FROM sessions WHERE revoked_at IS NOT NULL OR expires_at <= now() \
               OR last_seen_at <= now() - make_interval(secs => $1)",
        )
        .bind(idle_timeout.as_secs_f64())
        .execute(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        Ok(result.rows_affected())
    }
}
