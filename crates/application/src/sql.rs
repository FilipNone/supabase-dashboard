//! Running SQL from a project's SQL editor.
//!
//! SQL runs through the stack's postgres-meta with the stored service role
//! key, as the database user postgres-meta is configured with. That is a
//! privileged action, so only roles with [`Permission::SqlExecute`] may do
//! it; read-only members get no SQL at all, since arbitrary SQL cannot be
//! shown to be read-only by looking at it.
//!
//! Each member can have one run per project at a time. A run is tagged
//! with its own `application_name`, which is how a cancel request finds
//! the database backend running it. Runs live in this process's memory,
//! so a cancel must reach the server process that started the run.
//!
//! Every run that reaches the stack is audited with its outcome. The SQL
//! text and any rows or error messages are never written to the audit log
//! or to server logs.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use secrecy::SecretString;
use supabase_dashboard_domain::{
    authz::Permission,
    connection::CredentialKind,
    project::ProjectUrl,
    schema::MetaUnavailable,
    sql::{SqlFailure, SqlOutcome, SqlResult, SqlText},
};
use supabase_dashboard_persistence::{
    Database, PersistenceError, audit::AuditOutcome, projects::ProjectAccess,
};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    connections::open_key,
    organizations::event,
    secrets::CredentialCipher,
};

/// SQL runs at once from this process, across all projects. Each one holds
/// a database connection on its stack for up to the statement timeout.
const MAX_CONCURRENT_RUNS: usize = 8;

pub type SqlFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs SQL on a stack. Implementations apply the outbound network policy,
/// never follow redirects, bound time and response size, and have the
/// database stop the statement after
/// [`supabase_dashboard_domain::sql::SQL_STATEMENT_TIMEOUT_SECS`].
pub trait SqlRunner: Send + Sync {
    /// Runs `sql` on a connection whose `application_name` is
    /// [`supabase_dashboard_domain::sql::sql_application_name`] of
    /// `run_id`. A statement stopped by the database, for any reason, is
    /// [`SqlFailure::Timeout`]; the service tells a cancel apart. The
    /// result's `elapsed_ms` is set by the service.
    fn run<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        sql: &'a SqlText,
        run_id: Uuid,
    ) -> SqlFuture<'a, SqlOutcome>;

    /// Asks the database to cancel what the connection tagged for `run_id`
    /// is running. Gives the number of backends signalled, which is zero
    /// when the run has already finished.
    fn cancel<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        run_id: Uuid,
    ) -> SqlFuture<'a, Result<u32, MetaUnavailable>>;
}

#[derive(Debug, thiserror::Error)]
pub enum SqlError {
    #[error("project not found")]
    NotFound,
    #[error("your role in this organization does not allow this action")]
    Forbidden,
    /// The run limiter was shut down; only possible while the server
    /// stops.
    #[error("the dashboard is shutting down")]
    Unavailable,
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunOwner {
    account_id: Uuid,
    project_id: Uuid,
}

#[derive(Debug)]
struct ActiveRun {
    owner: RunOwner,
    cancel_requested: bool,
}

type Registry = Arc<Mutex<HashMap<Uuid, ActiveRun>>>;

/// Removes a run from the registry when its request ends, including when
/// the request is dropped because the browser went away.
struct Registration {
    registry: Registry,
    run_id: Uuid,
}

impl Drop for Registration {
    fn drop(&mut self) {
        lock(&self.registry).remove(&self.run_id);
    }
}

fn lock(registry: &Registry) -> std::sync::MutexGuard<'_, HashMap<Uuid, ActiveRun>> {
    // The map is only ever inserted into and removed from, so it is
    // consistent even if a holder panicked.
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct SqlService {
    db: Database,
    cipher: Option<CredentialCipher>,
    runner: Arc<dyn SqlRunner>,
    permits: Arc<Semaphore>,
    active: Registry,
}

impl SqlService {
    pub fn new(db: Database, cipher: Option<CredentialCipher>, runner: Arc<dyn SqlRunner>) -> Self {
        Self {
            db,
            cipher,
            runner,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RUNS)),
            active: Arc::default(),
        }
    }

    /// Runs `sql` on the project's database. Dashboard errors are the outer
    /// `Result`; what the stack said is the [`SqlOutcome`].
    pub async fn run(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        sql: &SqlText,
        ctx: RequestContext<'_>,
    ) -> Result<SqlOutcome, SqlError> {
        let access = self.access(current, project_id, ctx).await?;
        let key = match self.service_key(&access).await? {
            Ok(key) => key,
            Err(reason) => return Ok(Err(SqlFailure::Unavailable { reason })),
        };
        let owner = RunOwner {
            account_id: current.account.id,
            project_id,
        };
        let Some(registration) = self.register(owner) else {
            return Ok(Err(SqlFailure::Busy));
        };
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| SqlError::Unavailable)?;
        let started = Instant::now();
        let outcome = self
            .runner
            .run(&access.project.api_url, &key, sql, registration.run_id)
            .await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let cancelled = lock(&self.active)
            .get(&registration.run_id)
            .is_some_and(|run| run.cancel_requested);
        drop(registration);
        let outcome = match outcome {
            Ok(result) => Ok(SqlResult {
                elapsed_ms,
                ..result
            }),
            Err(SqlFailure::Timeout) if cancelled => Err(SqlFailure::Cancelled),
            Err(failure) => Err(failure),
        };
        let audit_outcome = if outcome.is_ok() {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure
        };
        self.audit(current, project_id, audit_outcome, ctx).await;
        Ok(outcome)
    }

    /// Cancels the caller's running SQL on this project, if any. Gives the
    /// number of database backends signalled; zero means nothing was
    /// running any more.
    pub async fn cancel(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<Result<u32, MetaUnavailable>, SqlError> {
        let access = self.access(current, project_id, ctx).await?;
        let owner = RunOwner {
            account_id: current.account.id,
            project_id,
        };
        let run_ids: Vec<Uuid> = lock(&self.active)
            .iter_mut()
            .filter(|(_, run)| run.owner == owner)
            .map(|(id, run)| {
                run.cancel_requested = true;
                *id
            })
            .collect();
        if run_ids.is_empty() {
            return Ok(Ok(0));
        }
        let key = match self.service_key(&access).await? {
            Ok(key) => key,
            Err(reason) => return Ok(Err(reason)),
        };
        // No run permit: a cancel must not wait behind the runs it stops.
        let mut signalled = 0u32;
        for run_id in run_ids {
            match self
                .runner
                .cancel(&access.project.api_url, &key, run_id)
                .await
            {
                Ok(count) => signalled = signalled.saturating_add(count),
                Err(state) => return Ok(Err(state)),
            }
        }
        Ok(Ok(signalled))
    }

    fn register(&self, owner: RunOwner) -> Option<Registration> {
        let mut active = lock(&self.active);
        if active.values().any(|run| run.owner == owner) {
            return None;
        }
        let run_id = Uuid::new_v4();
        active.insert(
            run_id,
            ActiveRun {
                owner,
                cancel_requested: false,
            },
        );
        Some(Registration {
            registry: Arc::clone(&self.active),
            run_id,
        })
    }

    async fn service_key(
        &self,
        access: &ProjectAccess,
    ) -> Result<Result<SecretString, MetaUnavailable>, SqlError> {
        let stored = self.db.list_credentials(access.project.id).await?;
        Ok(open_key(
            self.cipher.as_ref(),
            access.project.id,
            &[CredentialKind::ServiceRoleKey],
            &stored,
        )
        .map_err(|reason| MetaUnavailable::NoKey { reason }))
    }

    /// The project if the caller may run SQL on it. A member without the
    /// permission is refused, and the refusal is audited; a non-member gets
    /// the same answer as for a project that does not exist.
    async fn access(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<ProjectAccess, SqlError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(SqlError::NotFound)?;
        if access.role.allows(Permission::SqlExecute) {
            Ok(access)
        } else {
            self.audit(current, project_id, AuditOutcome::Denied, ctx)
                .await;
            Err(SqlError::Forbidden)
        }
    }

    /// Best effort: a failure is logged and the caller still gets its
    /// answer.
    async fn audit(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        outcome: AuditOutcome,
        ctx: RequestContext<'_>,
    ) {
        let action = "sql.execute";
        let event = event(
            current,
            action,
            ("project", project_id.to_string()),
            outcome,
            ctx,
        );
        if let Err(err) = self.db.record_audit_event(&event).await {
            tracing::error!(error = %err, action, "could not record audit event");
        }
    }
}
