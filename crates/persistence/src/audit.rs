//! Security audit log. Events name the actor, action, target, and outcome.
//! They never carry passwords, tokens, credentials, or managed project data.

use uuid::Uuid;

use crate::{Database, PersistenceError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Denied,
    Failure,
}

impl AuditOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEvent<'a> {
    pub actor_account_id: Option<Uuid>,
    /// Dotted lowercase name such as `session.sign_in`.
    pub action: &'static str,
    pub target_type: Option<&'static str>,
    pub target_id: Option<String>,
    pub outcome: AuditOutcome,
    pub request_id: Option<&'a str>,
}

pub(crate) async fn insert_audit_event<'e, E>(
    executor: E,
    event: &AuditEvent<'_>,
) -> Result<(), PersistenceError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO audit_events \
             (id, actor_account_id, action, target_type, target_id, outcome, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(event.actor_account_id)
    .bind(event.action)
    .bind(event.target_type)
    .bind(event.target_id.as_deref())
    .bind(event.outcome.as_str())
    // Request IDs may come from the client, so cap their length.
    .bind(event.request_id.map(|id| truncate(id, 128)))
    .execute(executor)
    .await
    .map_err(PersistenceError::Query)?;
    Ok(())
}

fn truncate(value: &str, max_chars: usize) -> &str {
    match value.char_indices().nth(max_chars) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

impl Database {
    pub async fn record_audit_event(&self, event: &AuditEvent<'_>) -> Result<(), PersistenceError> {
        insert_audit_event(&self.pool, event).await
    }

    /// Number of audit events with this action. Used by tests and the
    /// administrator view.
    pub async fn count_audit_events(&self, action: &str) -> Result<i64, PersistenceError> {
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1")
            .bind(action)
            .fetch_one(&self.pool)
            .await
            .map_err(PersistenceError::Query)
    }
}
