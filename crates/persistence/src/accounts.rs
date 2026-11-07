//! Operator accounts.

use supabase_dashboard_domain::account::{DisplayName, Email};
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
};

/// Lock key that serializes first-owner creation across concurrent callers.
const BOOTSTRAP_LOCK_KEY: i64 = 0x5344_0001;

/// Lock key that serializes disabling accounts, so two administrators
/// cannot disable each other at the same time and leave none.
const ADMIN_LOCK_KEY: i64 = 0x5344_0002;

/// Upper bound on accounts returned to the administrator view.
pub const ACCOUNT_LIST_LIMIT: i64 = 500;

/// An account as listed for installation administrators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountListing {
    pub account: AccountRecord,
    pub created_at: time::OffsetDateTime,
    pub organization_count: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetDisabledOutcome {
    /// Changed; carries the number of sessions revoked.
    Changed {
        revoked_sessions: u64,
    },
    /// Already in the requested state; nothing was written.
    Unchanged,
    NotFound,
    /// Disabling would leave no enabled installation administrator.
    LastAdmin,
}

/// An account as the application sees it. The password hash is kept out of
/// this type so it cannot be passed to a view by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    pub id: Uuid,
    pub email: Email,
    pub display_name: DisplayName,
    pub is_installation_admin: bool,
    pub disabled: bool,
}

/// An account together with its stored password hash, used only to verify
/// a sign-in attempt.
pub struct AccountCredentials {
    pub account: AccountRecord,
    pub password_hash: String,
}

pub struct NewAccount<'a> {
    pub id: Uuid,
    pub email: &'a Email,
    pub display_name: &'a DisplayName,
    pub password_hash: &'a str,
    pub is_installation_admin: bool,
}

#[derive(sqlx::FromRow)]
pub(crate) struct AccountRow {
    pub(crate) id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) is_installation_admin: bool,
    pub(crate) disabled: bool,
}

impl TryFrom<AccountRow> for AccountRecord {
    type Error = PersistenceError;
    fn try_from(row: AccountRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            email: Email::parse(&row.email)
                .map_err(|_| PersistenceError::InvalidRow("accounts.email"))?,
            display_name: DisplayName::parse(&row.display_name)
                .map_err(|_| PersistenceError::InvalidRow("accounts.display_name"))?,
            is_installation_admin: row.is_installation_admin,
            disabled: row.disabled,
        })
    }
}

impl Database {
    /// Creates the first account if, and only if, no account exists yet.
    /// Returns `Ok(false)` without writing anything when accounts already
    /// exist. Records an audit event in the same transaction.
    pub async fn create_first_account(
        &self,
        new: &NewAccount<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(BOOTSTRAP_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts)")
            .fetch_one(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?;
        if exists {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash, is_installation_admin) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(new.id)
        .bind(new.email.as_str())
        .bind(new.display_name.as_str())
        .bind(new.password_hash)
        .bind(new.is_installation_admin)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(true)
    }

    pub async fn account_count(&self) -> Result<i64, PersistenceError> {
        sqlx::query_scalar("SELECT count(*) FROM accounts")
            .fetch_one(&self.pool)
            .await
            .map_err(PersistenceError::Query)
    }

    pub async fn find_credentials_by_email(
        &self,
        email: &Email,
    ) -> Result<Option<AccountCredentials>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            #[sqlx(flatten)]
            account: AccountRow,
            password_hash: String,
        }
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, email, display_name, is_installation_admin, \
                    disabled_at IS NOT NULL AS disabled, password_hash \
             FROM accounts WHERE email = $1",
        )
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        row.map(|row| {
            Ok(AccountCredentials {
                account: row.account.try_into()?,
                password_hash: row.password_hash,
            })
        })
        .transpose()
    }

    /// Renames an account and records `audit` in the same transaction.
    /// Returns `false` when the account does not exist.
    pub async fn update_display_name(
        &self,
        account_id: Uuid,
        display_name: &DisplayName,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let updated =
            sqlx::query("UPDATE accounts SET display_name = $2, updated_at = now() WHERE id = $1")
                .bind(account_id)
                .bind(display_name.as_str())
                .execute(&mut *tx)
                .await
                .map_err(PersistenceError::Query)?
                .rows_affected()
                == 1;
        if updated {
            insert_audit_event(&mut *tx, audit).await?;
        }
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(updated)
    }

    /// The stored password hash of an enabled account.
    pub async fn find_password_hash(
        &self,
        account_id: Uuid,
    ) -> Result<Option<String>, PersistenceError> {
        sqlx::query_scalar(
            "SELECT password_hash FROM accounts WHERE id = $1 AND disabled_at IS NULL",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)
    }

    /// Replaces a password hash, but only if it is still `expected_hash`,
    /// so a change verified against an older password cannot overwrite a
    /// newer one. In the same transaction it revokes every other session of
    /// the account except `keep_session` and records `audit`. Returns the
    /// number of sessions revoked, or `None` when nothing was changed.
    pub async fn change_password(
        &self,
        account_id: Uuid,
        expected_hash: &str,
        new_hash: &str,
        keep_session: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<u64>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let updated = sqlx::query(
            "UPDATE accounts SET password_hash = $3, updated_at = now(), password_changed_at = now() \
             WHERE id = $1 AND password_hash = $2 AND disabled_at IS NULL",
        )
        .bind(account_id)
        .bind(expected_hash)
        .bind(new_hash)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(None);
        }
        let revoked = sqlx::query(
            "UPDATE sessions SET revoked_at = now() \
             WHERE account_id = $1 AND revoked_at IS NULL AND id <> $2",
        )
        .bind(account_id)
        .bind(keep_session)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?
        .rows_affected();
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(Some(revoked))
    }

    /// Sets a new password hash without checking the old one, revokes every
    /// session of the account, and records `audit`, in one transaction.
    /// For out-of-band recovery by someone with server access. Returns the
    /// number of sessions revoked, or `None` when the account does not
    /// exist.
    pub async fn reset_password(
        &self,
        account_id: Uuid,
        new_hash: &str,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<u64>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let updated =
            sqlx::query("UPDATE accounts SET password_hash = $2, updated_at = now(), password_changed_at = now() WHERE id = $1")
                .bind(account_id)
                .bind(new_hash)
                .execute(&mut *tx)
                .await
                .map_err(PersistenceError::Query)?
                .rows_affected()
                == 1;
        if !updated {
            return Ok(None);
        }
        let revoked = sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL",
        )
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?
        .rows_affected();
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(Some(revoked))
    }

    /// All accounts, oldest first, at most [`ACCOUNT_LIST_LIMIT`].
    pub async fn list_accounts(&self) -> Result<Vec<AccountListing>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            #[sqlx(flatten)]
            account: AccountRow,
            created_at: time::OffsetDateTime,
            organization_count: i64,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT a.id, a.email, a.display_name, a.is_installation_admin, \
                    a.disabled_at IS NOT NULL AS disabled, a.created_at, \
                    (SELECT count(*) FROM organization_members m WHERE m.account_id = a.id) \
                        AS organization_count \
             FROM accounts a ORDER BY a.created_at, a.id LIMIT $1",
        )
        .bind(ACCOUNT_LIST_LIMIT)
        .fetch_all(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        rows.into_iter()
            .map(|row| {
                Ok(AccountListing {
                    account: row.account.try_into()?,
                    created_at: row.created_at,
                    organization_count: row.organization_count,
                })
            })
            .collect()
    }

    /// Disables or re-enables an account. Disabling revokes all of its
    /// sessions and is refused when it would leave no enabled installation
    /// administrator. `audit` is recorded only when something changed.
    pub async fn set_account_disabled(
        &self,
        account_id: Uuid,
        disabled: bool,
        audit: &AuditEvent<'_>,
    ) -> Result<SetDisabledOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(ADMIN_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?;
        let current: Option<(bool, bool)> = sqlx::query_as(
            "SELECT is_installation_admin, disabled_at IS NOT NULL FROM accounts \
             WHERE id = $1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let Some((is_admin, is_disabled)) = current else {
            return Ok(SetDisabledOutcome::NotFound);
        };
        if is_disabled == disabled {
            return Ok(SetDisabledOutcome::Unchanged);
        }
        if disabled && is_admin {
            let other_admins: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM accounts \
                 WHERE is_installation_admin AND disabled_at IS NULL AND id <> $1",
            )
            .bind(account_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?;
            if other_admins == 0 {
                return Ok(SetDisabledOutcome::LastAdmin);
            }
        }
        sqlx::query(
            "UPDATE accounts SET disabled_at = CASE WHEN $2 THEN now() END, updated_at = now() \
             WHERE id = $1",
        )
        .bind(account_id)
        .bind(disabled)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let revoked_sessions = if disabled {
            sqlx::query(
                "UPDATE sessions SET revoked_at = now() \
                 WHERE account_id = $1 AND revoked_at IS NULL",
            )
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?
            .rows_affected()
        } else {
            0
        };
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(SetDisabledOutcome::Changed { revoked_sessions })
    }
}
