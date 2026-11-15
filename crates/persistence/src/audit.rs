//! Security audit log. Events name the actor, action, target, and outcome.
//! They never carry passwords, tokens, credentials, or managed project data.

use supabase_dashboard_domain::audit::{AuditActor, AuditEntry, AuditEntryOutcome};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Database, PersistenceError};

/// Which events to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditScope {
    /// Events that belong to the organization, by anyone.
    Organization(Uuid),
    /// Events the account did, and events about the account by others or
    /// by no one, such as an administrator disabling it or a failed sign-in.
    Account(Uuid),
}

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
    /// The organization the event belongs to. When `None`, it is taken
    /// from the target if the target names an organization, a member, a
    /// project, an invitation, or a job that still exists. Name it when the
    /// target is deleted in the same transaction, such as an unregistered
    /// project.
    pub organization_id: Option<Uuid>,
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
             (id, actor_account_id, action, target_type, target_id, outcome, request_id, \
              organization_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, \
                 COALESCE($8, audit_target_organization($4, $5)))",
    )
    .bind(Uuid::now_v7())
    .bind(event.actor_account_id)
    .bind(event.action)
    .bind(event.target_type)
    .bind(event.target_id.as_deref())
    .bind(event.outcome.as_str())
    // Request IDs may come from the client, so cap their length.
    .bind(event.request_id.map(|id| truncate(id, 128)))
    .bind(event.organization_id)
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

/// Whether event `e` is in the scope given as `$1` (an organization) or
/// `$2` (an account), exactly one of them set. The cursor's event is
/// checked with it too, so a cursor from another scope matches nothing.
macro_rules! audit_scope_condition {
    () => {
        "(($1::uuid IS NOT NULL AND e.organization_id = $1) \
          OR ($2::uuid IS NOT NULL AND (e.actor_account_id = $2 \
              OR (e.target_type = 'account' AND e.target_id = $2::text))))"
    };
}

impl Database {
    pub async fn record_audit_event(&self, event: &AuditEvent<'_>) -> Result<(), PersistenceError> {
        insert_audit_event(&self.pool, event).await
    }

    /// The newest `limit` events in `scope`, only those `actor` did when
    /// given, starting after the event `before` when given. Events are
    /// ordered by time and then ID, so a page boundary between events with
    /// the same time neither repeats nor skips one. A `before` that is not
    /// in `scope` gives an empty page.
    pub async fn list_audit_events(
        &self,
        scope: AuditScope,
        actor: Option<Uuid>,
        before: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<AuditEntry>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            occurred_at: OffsetDateTime,
            account_id: Option<Uuid>,
            display_name: Option<String>,
            email: Option<String>,
            action: String,
            target_type: Option<String>,
            target_id: Option<String>,
            outcome: String,
        }
        let (organization, account) = match scope {
            AuditScope::Organization(id) => (Some(id), None),
            AuditScope::Account(id) => (None, Some(id)),
        };
        let rows: Vec<Row> = sqlx::query_as(concat!(
            "SELECT e.id, e.occurred_at, a.id AS account_id, a.display_name, a.email, \
                    e.action, e.target_type, e.target_id, e.outcome \
             FROM audit_events e LEFT JOIN accounts a ON a.id = e.actor_account_id \
             WHERE ",
            audit_scope_condition!(),
            " AND ($3::uuid IS NULL OR e.actor_account_id = $3) \
               AND ($4::uuid IS NULL OR (e.occurred_at, e.id) < ( \
                   SELECT e.occurred_at, e.id FROM audit_events e WHERE e.id = $4 AND ",
            audit_scope_condition!(),
            ")) ORDER BY e.occurred_at DESC, e.id DESC LIMIT $5",
        ))
        .bind(organization)
        .bind(account)
        .bind(actor)
        .bind(before)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        rows.into_iter()
            .map(|row| {
                Ok(AuditEntry {
                    id: row.id,
                    at: row.occurred_at,
                    actor: match (row.account_id, row.display_name, row.email) {
                        (Some(account_id), Some(display_name), Some(email)) => Some(AuditActor {
                            account_id,
                            display_name,
                            email,
                        }),
                        _ => None,
                    },
                    action: row.action,
                    target_type: row.target_type,
                    target_id: row.target_id,
                    outcome: AuditEntryOutcome::from_name(&row.outcome)
                        .ok_or(PersistenceError::InvalidRow("audit_events.outcome"))?,
                })
            })
            .collect()
    }

    /// The accounts that did something in the organization, ordered by
    /// name, at most `limit`. Deleted accounts are not listed.
    pub async fn list_audit_actors(
        &self,
        organization_id: Uuid,
        limit: u16,
    ) -> Result<Vec<AuditActor>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            display_name: String,
            email: String,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT a.id, a.display_name, a.email FROM accounts a \
             WHERE EXISTS ( \
                 SELECT 1 FROM audit_events e \
                 WHERE e.organization_id = $1 AND e.actor_account_id = a.id) \
             ORDER BY lower(a.display_name), a.email, a.id LIMIT $2",
        )
        .bind(organization_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(PersistenceError::Query)?;
        Ok(rows
            .into_iter()
            .map(|row| AuditActor {
                account_id: row.id,
                display_name: row.display_name,
                email: row.email,
            })
            .collect())
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
