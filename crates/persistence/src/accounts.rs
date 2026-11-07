//! Operator accounts.

use supabase_dashboard_domain::account::{DisplayName, Email};
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
};

/// Lock key that serializes first-owner creation across concurrent callers.
const BOOTSTRAP_LOCK_KEY: i64 = 0x5344_0001;

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
}
