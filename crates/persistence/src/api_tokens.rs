//! Dashboard API tokens. Only a SHA-256 hash of each token is stored.

use supabase_dashboard_domain::api_token::{
    API_TOKEN_KEEP_DAYS, ApiTokenName, ApiTokenScope, ApiTokenState, ApiTokenSummary,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    accounts::{AccountRecord, AccountRow},
    audit::{AuditEvent, insert_audit_event},
};

pub struct NewApiToken<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: &'a ApiTokenName,
    pub token_hash: &'a [u8; 32],
    pub display_prefix: &'a str,
    pub scopes: &'a [ApiTokenScope],
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateApiTokenOutcome {
    Created,
    /// The account already holds `limit` working tokens.
    LimitReached,
    /// The account was disabled or deleted meanwhile.
    AccountUnavailable,
}

/// A working token and the enabled account it acts as.
#[derive(Debug, Clone)]
pub struct ActiveApiToken {
    pub token_id: Uuid,
    pub scopes: Vec<ApiTokenScope>,
    pub account: AccountRecord,
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    id: Uuid,
    name: String,
    display_prefix: String,
    scopes: Vec<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

impl TryFrom<SummaryRow> for ApiTokenSummary {
    type Error = PersistenceError;

    fn try_from(row: SummaryRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            name: ApiTokenName::parse(&row.name)
                .map_err(|_| PersistenceError::InvalidRow("api_tokens.name"))?,
            display_prefix: row.display_prefix,
            scopes: stored_scopes(&row.scopes)?,
            created_at: row.created_at,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
            state: ApiTokenState::at(row.revoked_at, row.expires_at, OffsetDateTime::now_utc()),
        })
    }
}

fn stored_scopes(values: &[String]) -> Result<Vec<ApiTokenScope>, PersistenceError> {
    values
        .iter()
        .map(|value| {
            ApiTokenScope::parse(value).ok_or(PersistenceError::InvalidRow("api_tokens.scopes"))
        })
        .collect()
}

impl Database {
    /// Stores a new token unless the account already holds `limit` working
    /// ones, and records `audit` in the same transaction. Also deletes the
    /// account's tokens revoked or expired more than
    /// [`API_TOKEN_KEEP_DAYS`] days ago, so the list stays short.
    pub async fn create_api_token(
        &self,
        new: &NewApiToken<'_>,
        limit: usize,
        audit: &AuditEvent<'_>,
    ) -> Result<CreateApiTokenOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        // Locking the account row serializes concurrent creations, so two
        // requests cannot both pass the limit.
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT disabled_at IS NULL FROM accounts WHERE id = $1 FOR UPDATE")
                .bind(new.account_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(PersistenceError::Query)?;
        if enabled != Some(true) {
            return Ok(CreateApiTokenOutcome::AccountUnavailable);
        }
        sqlx::query(
            "DELETE FROM api_tokens WHERE account_id = $1 \
               AND LEAST(COALESCE(revoked_at, expires_at), expires_at) \
                   < now() - make_interval(days => $2)",
        )
        .bind(new.account_id)
        .bind(i32::from(API_TOKEN_KEEP_DAYS))
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM api_tokens \
             WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(new.account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        if usize::try_from(active).unwrap_or(usize::MAX) >= limit {
            return Ok(CreateApiTokenOutcome::LimitReached);
        }
        let scopes: Vec<&str> = new.scopes.iter().map(|scope| scope.as_str()).collect();
        sqlx::query(
            "INSERT INTO api_tokens \
                 (id, account_id, name, token_hash, display_prefix, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(new.id)
        .bind(new.account_id)
        .bind(new.name.as_str())
        .bind(new.token_hash.as_slice())
        .bind(new.display_prefix)
        .bind(&scopes)
        .bind(new.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(CreateApiTokenOutcome::Created)
    }

    /// The account's tokens, newest first, at most `limit`.
    pub async fn list_api_tokens(
        &self,
        account_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ApiTokenSummary>, PersistenceError> {
        let rows: Vec<SummaryRow> = sqlx::query_as(
            "SELECT id, name, display_prefix, scopes, created_at, expires_at, last_used_at, \
                    revoked_at \
             FROM api_tokens WHERE account_id = $1 \
             ORDER BY created_at DESC, id DESC LIMIT $2",
        )
        .bind(account_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Revokes one of the account's unrevoked tokens and records `audit` in
    /// the same transaction. Returns `false`, writing nothing, when the
    /// account has no such unrevoked token.
    pub async fn revoke_api_token(
        &self,
        account_id: Uuid,
        token_id: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let revoked = sqlx::query(
            "UPDATE api_tokens SET revoked_at = now() \
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
        )
        .bind(token_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(true)
    }

    /// Looks up a token that is not revoked or expired and whose account is
    /// enabled. Refreshes `last_used_at` at most once a minute.
    pub async fn find_active_api_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<ActiveApiToken>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            token_id: Uuid,
            scopes: Vec<String>,
            #[sqlx(flatten)]
            account: AccountRow,
        }
        let row: Option<Row> = sqlx::query_as(
            "WITH valid AS ( \
                 SELECT t.id FROM api_tokens t JOIN accounts a ON a.id = t.account_id \
                 WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now() \
                   AND a.disabled_at IS NULL \
             ), touched AS ( \
                 UPDATE api_tokens SET last_used_at = now() \
                 WHERE id IN (SELECT id FROM valid) \
                   AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute') \
             ) \
             SELECT t.id AS token_id, t.scopes, a.id, a.email, a.display_name, \
                    a.is_installation_admin, FALSE AS disabled \
             FROM valid v JOIN api_tokens t ON t.id = v.id JOIN accounts a ON a.id = t.account_id",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        row.map(|row| {
            Ok(ActiveApiToken {
                token_id: row.token_id,
                scopes: stored_scopes(&row.scopes)?,
                account: row.account.try_into()?,
            })
        })
        .transpose()
    }
}
