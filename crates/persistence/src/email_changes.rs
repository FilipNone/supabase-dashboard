//! Sign-in email changes confirmed by a link sent to the new address.
//!
//! Only the SHA-256 of a confirmation code is stored. A request is open
//! while it is unused, not replaced, unexpired, its account is enabled,
//! still has the address the request was made from, and has not changed
//! its password since the request.

use supabase_dashboard_domain::account::Email;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
};

/// SQL condition for requests that can still be used, on `r` joined with
/// its account `a`. A macro so it can be spliced into static queries.
macro_rules! open_request {
    () => {
        "r.used_at IS NULL AND r.revoked_at IS NULL AND r.expires_at > now() \
         AND a.disabled_at IS NULL AND a.email = r.old_email \
         AND r.created_at > a.password_changed_at"
    };
}

/// PostgreSQL's code for a unique violation.
const UNIQUE_VIOLATION: &str = "23505";

pub struct NewEmailChange<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    /// The account's sign-in email as the requester saw it; the request is
    /// refused if it no longer matches.
    pub old_email: &'a Email,
    pub new_email: &'a Email,
    pub token_hash: &'a [u8; 32],
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateEmailChangeOutcome {
    /// Saved; earlier open requests for the account no longer work.
    Created,
    /// Another account uses the new address.
    Taken,
    /// The account does not exist, is disabled, or its email changed.
    NoAccount,
}

/// An open request found by its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenEmailChange {
    pub id: Uuid,
    pub account_id: Uuid,
    pub old_email: Email,
    pub new_email: Email,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteEmailChangeOutcome {
    /// The account now signs in with `new_email`.
    Changed {
        account_id: Uuid,
        old_email: Email,
        new_email: Email,
    },
    /// The code is not open.
    NotOpen,
    /// Another account took the new address after the request was made.
    /// Carries the account the request was for.
    Taken { account_id: Uuid },
}

fn parse_email(raw: &str, column: &'static str) -> Result<Email, PersistenceError> {
    Email::parse(raw).map_err(|_| PersistenceError::InvalidRow(column))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| code == UNIQUE_VIOLATION)
}

impl Database {
    /// Saves an email change request, replacing the account's open ones,
    /// and records `audit` in the same transaction. The account row is
    /// locked, so a concurrent request or confirmation waits for this one.
    pub async fn create_email_change(
        &self,
        new: &NewEmailChange<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<CreateEmailChangeOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let current: Option<bool> = sqlx::query_scalar(
            "SELECT disabled_at IS NULL AND email = $2 FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(new.account_id)
        .bind(new.old_email.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        if current != Some(true) {
            return Ok(CreateEmailChangeOutcome::NoAccount);
        }
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE email = $1 AND id <> $2)",
        )
        .bind(new.new_email.as_str())
        .bind(new.account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        if taken {
            return Ok(CreateEmailChangeOutcome::Taken);
        }
        // Finished requests are kept for a day, then go when the account
        // asks again.
        sqlx::query(
            "DELETE FROM email_change_requests \
             WHERE account_id = $1 AND created_at < now() - interval '1 day'",
        )
        .bind(new.account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        sqlx::query(
            "UPDATE email_change_requests SET revoked_at = now() \
             WHERE account_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
        )
        .bind(new.account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        sqlx::query(
            "INSERT INTO email_change_requests \
             (id, account_id, old_email, new_email, token_hash, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(new.id)
        .bind(new.account_id)
        .bind(new.old_email.as_str())
        .bind(new.new_email.as_str())
        .bind(new.token_hash.as_slice())
        .bind(new.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(CreateEmailChangeOutcome::Created)
    }

    /// The open request with this code hash, if any.
    pub async fn find_open_email_change(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<OpenEmailChange>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            account_id: Uuid,
            old_email: String,
            new_email: String,
            expires_at: OffsetDateTime,
        }
        let row: Option<Row> = sqlx::query_as(concat!(
            "SELECT r.id, r.account_id, r.old_email, r.new_email, r.expires_at \
             FROM email_change_requests r JOIN accounts a ON a.id = r.account_id \
             WHERE r.token_hash = $1 AND ",
            open_request!()
        ))
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        row.map(|row| {
            Ok(OpenEmailChange {
                id: row.id,
                account_id: row.account_id,
                old_email: parse_email(&row.old_email, "email_change_requests.old_email")?,
                new_email: parse_email(&row.new_email, "email_change_requests.new_email")?,
                expires_at: row.expires_at,
            })
        })
        .transpose()
    }

    /// Uses an open request: sets the account's sign-in email, marks the
    /// request used, withdraws the account's other email change requests
    /// and its open password reset links (they went to the old address),
    /// and records `audit` with the account as actor and target, in one
    /// transaction. A code works once even when used twice at the same
    /// time. Sessions and API tokens stay valid: they belong to the
    /// account, not to its address.
    pub async fn complete_email_change(
        &self,
        token_hash: &[u8; 32],
        audit: &AuditEvent<'_>,
    ) -> Result<CompleteEmailChangeOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let found: Option<(Uuid, Uuid, String, String)> = sqlx::query_as(concat!(
            "SELECT r.id, r.account_id, r.old_email, r.new_email \
             FROM email_change_requests r JOIN accounts a ON a.id = r.account_id \
             WHERE r.token_hash = $1 AND ",
            open_request!(),
            " FOR UPDATE OF r, a"
        ))
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let Some((request_id, account_id, old_email, new_email)) = found else {
            return Ok(CompleteEmailChangeOutcome::NotOpen);
        };
        let old_email = parse_email(&old_email, "email_change_requests.old_email")?;
        let new_email = parse_email(&new_email, "email_change_requests.new_email")?;
        let changed =
            sqlx::query("UPDATE accounts SET email = $2, updated_at = now() WHERE id = $1")
                .bind(account_id)
                .bind(new_email.as_str())
                .execute(&mut *tx)
                .await;
        match changed {
            Ok(_) => {}
            // Another account took the address since the request; the
            // unique index is the final word. The transaction is rolled
            // back when dropped.
            Err(err) if is_unique_violation(&err) => {
                return Ok(CompleteEmailChangeOutcome::Taken { account_id });
            }
            Err(err) => return Err(PersistenceError::Query(err)),
        }
        sqlx::query("UPDATE email_change_requests SET used_at = now() WHERE id = $1")
            .bind(request_id)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?;
        sqlx::query(
            "UPDATE email_change_requests SET revoked_at = now() \
             WHERE account_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
        )
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        sqlx::query(
            "UPDATE password_reset_requests SET revoked_at = now() \
             WHERE account_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
        )
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let target = account_id.to_string();
        let event = AuditEvent {
            actor_account_id: Some(account_id),
            target_type: Some("account"),
            target_id: Some(target),
            ..audit.clone()
        };
        insert_audit_event(&mut *tx, &event).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(CompleteEmailChangeOutcome::Changed {
            account_id,
            old_email,
            new_email,
        })
    }
}
