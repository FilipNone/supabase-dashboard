//! Identities at the deployment's OpenID Connect provider, linked to
//! dashboard accounts.
//!
//! An identity is the pair (issuer, subject). Each one belongs to at most
//! one account, and an account has at most one identity per issuer.
//! Nothing here looks accounts up by email.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    accounts::{AccountRecord, AccountRow},
    audit::{AuditEvent, insert_audit_event},
};

/// Most identities listed for one account. An account has at most one per
/// issuer, so this is only reached after many provider changes.
pub const OIDC_IDENTITY_LIST_LIMIT: i64 = 50;

pub struct NewOidcIdentity<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub label: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOidcOutcome {
    Linked,
    /// This account already has exactly this identity.
    AlreadyLinked,
    /// Another account has this identity.
    LinkedToOther,
    /// This account already has another identity at the same issuer.
    IssuerTaken,
    /// The account does not exist or is disabled.
    NoAccount,
}

/// The account an identity signs in to.
#[derive(Debug, Clone)]
pub struct OidcAccount {
    pub identity_id: Uuid,
    pub account: AccountRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OidcIdentityRecord {
    pub id: Uuid,
    pub issuer: String,
    pub label: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

impl Database {
    /// The account `(issuer, subject)` is linked to, disabled or not.
    pub async fn find_oidc_account(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<OidcAccount>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            identity_id: Uuid,
            #[sqlx(flatten)]
            account: AccountRow,
        }
        let row: Option<Row> = sqlx::query_as(
            "SELECT i.id AS identity_id, a.id, a.email, a.display_name, \
                    a.is_installation_admin, a.disabled_at IS NOT NULL AS disabled \
             FROM oidc_identities i JOIN accounts a ON a.id = i.account_id \
             WHERE i.issuer = $1 AND i.subject = $2",
        )
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        row.map(|row| {
            Ok(OidcAccount {
                identity_id: row.identity_id,
                account: row.account.try_into()?,
            })
        })
        .transpose()
    }

    /// Notes that an identity was just used to sign in.
    pub async fn touch_oidc_identity(&self, identity_id: Uuid) -> Result<(), PersistenceError> {
        sqlx::query("UPDATE oidc_identities SET last_used_at = now() WHERE id = $1")
            .bind(identity_id)
            .execute(&self.pool)
            .await
            .map_err(PersistenceError::Query)?;
        Ok(())
    }

    /// Links an identity to an enabled account and records `audit` with it.
    /// The account row is locked, so a concurrent link or unlink for the
    /// same account waits; the unique indexes settle a race between two
    /// accounts for the same identity.
    pub async fn link_oidc_identity(
        &self,
        new: &NewOidcIdentity<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<LinkOidcOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT disabled_at IS NULL FROM accounts WHERE id = $1 FOR UPDATE")
                .bind(new.account_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(PersistenceError::Query)?;
        if enabled != Some(true) {
            return Ok(LinkOidcOutcome::NoAccount);
        }
        let owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT account_id FROM oidc_identities WHERE issuer = $1 AND subject = $2",
        )
        .bind(new.issuer)
        .bind(new.subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        match owner {
            Some(owner) if owner == new.account_id => return Ok(LinkOidcOutcome::AlreadyLinked),
            Some(_) => return Ok(LinkOidcOutcome::LinkedToOther),
            None => {}
        }
        let issuer_taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM oidc_identities WHERE account_id = $1 AND issuer = $2)",
        )
        .bind(new.account_id)
        .bind(new.issuer)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        if issuer_taken {
            return Ok(LinkOidcOutcome::IssuerTaken);
        }
        let inserted = sqlx::query(
            "INSERT INTO oidc_identities (id, account_id, issuer, subject, label) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(new.id)
        .bind(new.account_id)
        .bind(new.issuer)
        .bind(new.subject)
        .bind(new.label)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?
        .rows_affected();
        if inserted == 0 {
            // Another account linked the identity meanwhile.
            return Ok(LinkOidcOutcome::LinkedToOther);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(LinkOidcOutcome::Linked)
    }

    /// The account's identities, oldest first.
    pub async fn list_oidc_identities(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<OidcIdentityRecord>, PersistenceError> {
        sqlx::query_as(
            "SELECT id, issuer, label, created_at, last_used_at FROM oidc_identities \
             WHERE account_id = $1 ORDER BY created_at, id LIMIT $2",
        )
        .bind(account_id)
        .bind(OIDC_IDENTITY_LIST_LIMIT)
        .fetch_all(&self.pool)
        .await
        .map_err(PersistenceError::Query)
    }

    /// The identities of each of `account_ids`, oldest first, at most
    /// [`OIDC_IDENTITY_LIST_LIMIT`] per account, for the administrator's
    /// account list.
    pub async fn list_oidc_identities_of(
        &self,
        account_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, OidcIdentityRecord)>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            account_id: Uuid,
            #[sqlx(flatten)]
            record: OidcIdentityRecord,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT account_id, id, issuer, label, created_at, last_used_at FROM ( \
                 SELECT *, row_number() OVER (PARTITION BY account_id ORDER BY created_at, id) AS n \
                 FROM oidc_identities WHERE account_id = ANY($1) \
             ) ranked WHERE n <= $2 ORDER BY account_id, created_at, id",
        )
        .bind(account_ids)
        .bind(OIDC_IDENTITY_LIST_LIMIT)
        .fetch_all(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        Ok(rows
            .into_iter()
            .map(|row| (row.account_id, row.record))
            .collect())
    }

    /// Removes one of the account's identities, revokes the account's
    /// sessions that were signed in with it, and records `audit`, in one
    /// transaction. Returns how many sessions were revoked, or `None` when
    /// the account has no identity with that ID.
    pub async fn unlink_oidc_identity_and_sessions(
        &self,
        account_id: Uuid,
        identity_id: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<u64>, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let removed: Option<(String, String)> = sqlx::query_as(
            "DELETE FROM oidc_identities WHERE id = $1 AND account_id = $2 \
             RETURNING issuer, subject",
        )
        .bind(identity_id)
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?;
        let Some((issuer, subject)) = removed else {
            return Ok(None);
        };
        let revoked = sqlx::query(
            "UPDATE sessions SET revoked_at = now() \
             WHERE account_id = $1 AND oidc_issuer = $2 AND oidc_subject = $3 \
               AND revoked_at IS NULL",
        )
        .bind(account_id)
        .bind(&issuer)
        .bind(&subject)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Query)?
        .rows_affected();
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(Some(revoked))
    }

    /// Removes one of the account's identities and records `audit` with it.
    /// Returns `false` when the account has no identity with that ID.
    pub async fn unlink_oidc_identity(
        &self,
        account_id: Uuid,
        identity_id: Uuid,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Query)?;
        let removed = sqlx::query("DELETE FROM oidc_identities WHERE id = $1 AND account_id = $2")
            .bind(identity_id)
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Query)?
            .rows_affected();
        if removed == 0 {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(PersistenceError::Query)?;
        Ok(true)
    }
}
