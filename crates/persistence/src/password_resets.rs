//! Password reset links sent by email.
//!
//! Only the SHA-256 of a reset code is stored. A link is open while it is
//! unused, not replaced by a newer request, unexpired, its account is
//! enabled, and the account's password has not changed since the request.

use supabase_dashboard_domain::account::Email;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    accounts::replace_password,
    audit::{AuditEvent, insert_audit_event},
};

/// SQL condition for requests that can still be used, on `r` joined with
/// its account `a`. A macro so it can be spliced into static queries.
macro_rules! open_request {
    () => {
        "r.used_at IS NULL AND r.revoked_at IS NULL AND r.expires_at > now() \
         AND a.disabled_at IS NULL AND r.created_at > a.password_changed_at"
    };
}

pub struct NewPasswordReset<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub token_hash: &'a [u8; 32],
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateResetOutcome {
    /// Saved; earlier open requests for the account no longer work.
    Created,
    /// The account already made `limit` requests in the window.
    TooMany,
    /// The account does not exist or is disabled.
    NoAccount,
}

/// An open request found by its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPasswordReset {
    pub id: Uuid,
    pub account_id: Uuid,
    pub email: Email,
    pub expires_at: OffsetDateTime,
}

impl Database {
    /// Saves a reset request unless the account made `limit` or more in the
    /// last `window_secs` seconds, replacing the account's open requests.
    /// The account row is locked, so concurrent requests count each other.
    pub async fn create_password_reset(
        &self,
        new: &NewPasswordReset<'_>,
        limit: u32,
        window_secs: u32,
    ) -> Result<CreateResetOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT disabled_at IS NULL FROM accounts WHERE id = $1 FOR UPDATE")
                .bind(new.account_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(PersistenceError::Query)?;
        if enabled != Some(true) {
            return Ok(CreateResetOutcome::NoAccount);
        }
        // Old requests are only kept long enough to count against the
        // limit; they go when the account asks again.
        sqlx::query(
            "DELETE FROM password_reset_requests \
             WHERE account_id = $1 AND created_at < now() - interval '1 day'",
        )
        .bind(new.account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let recent: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM password_reset_requests \
             WHERE account_id = $1 AND created_at > now() - make_interval(secs => $2)",
        )
        .bind(new.account_id)
        .bind(f64::from(window_secs))
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        if recent >= i64::from(limit) {
            return Ok(CreateResetOutcome::TooMany);
        }
        sqlx::query(
            "UPDATE password_reset_requests SET revoked_at = now() \
             WHERE account_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
        )
        .bind(new.account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        sqlx::query(
            "INSERT INTO password_reset_requests (id, account_id, token_hash, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(new.id)
        .bind(new.account_id)
        .bind(new.token_hash.as_slice())
        .bind(new.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(CreateResetOutcome::Created)
    }

    /// The open request with this code hash, if any.
    pub async fn find_open_password_reset(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<OpenPasswordReset>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            account_id: Uuid,
            email: String,
            expires_at: OffsetDateTime,
        }
        let row: Option<Row> = sqlx::query_as(concat!(
            "SELECT r.id, r.account_id, a.email, r.expires_at \
             FROM password_reset_requests r JOIN accounts a ON a.id = r.account_id \
             WHERE r.token_hash = $1 AND ",
            open_request!()
        ))
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        row.map(|row| {
            Ok(OpenPasswordReset {
                id: row.id,
                account_id: row.account_id,
                email: Email::parse(&row.email)
                    .map_err(|_| PersistenceError::InvalidRow("accounts.email"))?,
                expires_at: row.expires_at,
            })
        })
        .transpose()
    }

    /// Uses an open request: sets the account's password, signs out its
    /// sessions, revokes its API tokens, and records `audit` (whose target
    /// is filled in with the account), all in one transaction. Returns the
    /// account and the number of sessions signed out, or `None` when the
    /// code is not open, so a code works once even when used twice at the
    /// same time.
    pub async fn complete_password_reset(
        &self,
        token_hash: &[u8; 32],
        new_hash: &str,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<(Uuid, u64)>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let found: Option<(Uuid, Uuid)> = sqlx::query_as(concat!(
            "SELECT r.id, r.account_id \
             FROM password_reset_requests r JOIN accounts a ON a.id = r.account_id \
             WHERE r.token_hash = $1 AND ",
            open_request!(),
            " FOR UPDATE OF r, a"
        ))
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let Some((request_id, account_id)) = found else {
            return Ok(None);
        };
        sqlx::query("UPDATE password_reset_requests SET used_at = now() WHERE id = $1")
            .bind(request_id)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?;
        let Some(revoked) = replace_password(&mut tx, account_id, new_hash).await? else {
            return Ok(None);
        };
        let target = account_id.to_string();
        let event = AuditEvent {
            actor_account_id: Some(account_id),
            target_type: Some("account"),
            target_id: Some(target),
            ..audit.clone()
        };
        insert_audit_event(&mut *tx, &event).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(Some((account_id, revoked)))
    }
}
