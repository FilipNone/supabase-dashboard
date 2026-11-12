//! The optional Studio access log ([`supabase_dashboard_domain::studio_access`]).
//!
//! The Studio host hands each forwarded request to a
//! [`StudioAccessRecorder`], which queues it and returns at once; a
//! background task writes the queue in batches. When the queue is full, or
//! a write fails, entries are dropped and a warning is logged: the log is a
//! record for owners and admins, not a gate in front of Studio, so it never
//! slows down or refuses a request.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use supabase_dashboard_domain::{
    authz::Permission,
    studio_access::{
        NewStudioAccess, STUDIO_ACCESS_MAX_RETENTION_DAYS, STUDIO_ACCESS_MEMBER_CHOICES,
        STUDIO_ACCESS_PAGE, StudioAccessLog,
    },
};
use supabase_dashboard_persistence::{Database, PersistenceError};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::auth::CurrentSession;

/// Requests waiting to be written. Beyond this, new entries are dropped.
pub const QUEUE_CAPACITY: usize = 4096;
/// Most entries written in one statement.
pub const WRITE_BATCH: usize = 256;
/// Most entries deleted in one statement when pruning.
const PRUNE_BATCH: u32 = 10_000;
/// Most prune statements in one pass; the next pass continues.
const PRUNE_ROUNDS: u32 = 100;

#[derive(Debug, thiserror::Error)]
pub enum StudioAccessError {
    /// The project does not exist or the caller is not a member.
    #[error("project not found")]
    NotFound,
    #[error("your role in this organization does not allow reading the Studio access log")]
    Forbidden,
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

/// Reading and pruning the log.
pub struct StudioAccessService {
    db: Database,
    retention_days: Option<u16>,
}

impl StudioAccessService {
    /// `retention_days` of `None` means the installation does not record
    /// Studio requests. Values above
    /// [`STUDIO_ACCESS_MAX_RETENTION_DAYS`] are lowered to it.
    pub fn new(db: Database, retention_days: Option<u16>) -> Self {
        Self {
            db,
            retention_days: retention_days
                .filter(|days| *days > 0)
                .map(|days| days.min(STUDIO_ACCESS_MAX_RETENTION_DAYS)),
        }
    }

    pub fn retention_days(&self) -> Option<u16> {
        self.retention_days
    }

    /// One page of a project's entries, newest first, for its owners and
    /// admins: the newest ones, or those older than the entry with id
    /// `before`. With `member`, only that account's entries.
    pub async fn read(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        member: Option<Uuid>,
        before: Option<i64>,
    ) -> Result<StudioAccessLog, StudioAccessError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(StudioAccessError::NotFound)?;
        if !access.role.allows(Permission::AuditRead) {
            return Err(StudioAccessError::Forbidden);
        }
        let Some(retention_days) = self.retention_days else {
            return Ok(StudioAccessLog::Off);
        };
        // One more than a page tells whether an older page exists.
        let mut entries = self
            .db
            .list_studio_access(
                project_id,
                retention_days,
                member,
                before,
                STUDIO_ACCESS_PAGE.saturating_add(1),
            )
            .await?;
        let older = if entries.len() > usize::from(STUDIO_ACCESS_PAGE) {
            entries.truncate(usize::from(STUDIO_ACCESS_PAGE));
            entries.last().map(|entry| entry.id)
        } else {
            None
        };
        let mut members = self
            .db
            .list_studio_access_members(
                project_id,
                retention_days,
                STUDIO_ACCESS_MEMBER_CHOICES.saturating_add(1),
            )
            .await?;
        let more_members = members.len() > usize::from(STUDIO_ACCESS_MEMBER_CHOICES);
        members.truncate(usize::from(STUDIO_ACCESS_MEMBER_CHOICES));
        Ok(StudioAccessLog::On {
            retention_days,
            entries,
            older,
            members,
            more_members,
        })
    }

    /// Deletes entries past the retention period. With the log turned off,
    /// deletes every entry left from when it was on. Returns how many were
    /// deleted.
    pub async fn prune(&self) -> Result<u64, StudioAccessError> {
        let days = self.retention_days.unwrap_or(0);
        let mut deleted = 0;
        for _ in 0..PRUNE_ROUNDS {
            let round = self.db.prune_studio_access(days, PRUNE_BATCH).await?;
            deleted += round;
            if round < u64::from(PRUNE_BATCH) {
                break;
            }
        }
        Ok(deleted)
    }
}

/// Queues entries for the background writer.
pub struct StudioAccessRecorder {
    queue: mpsc::Sender<NewStudioAccess>,
    dropped: AtomicU64,
}

impl StudioAccessRecorder {
    /// Starts the writer on the current Tokio runtime. It stops once the
    /// recorder is dropped and the queue is written.
    pub fn start(db: Database) -> Arc<Self> {
        let (queue, entries) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(write_entries(db, entries));
        Arc::new(Self {
            queue,
            dropped: AtomicU64::new(0),
        })
    }

    /// Queues one entry without waiting. A full queue drops it.
    pub fn record(&self, entry: NewStudioAccess) {
        if self.queue.try_send(entry).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // Once per power of two, so a long overload does not flood the
            // server's own log.
            if dropped.is_power_of_two() {
                tracing::warn!(
                    dropped,
                    "Studio access log queue is full; entries were dropped"
                );
            }
        }
    }

    /// Entries dropped because the queue was full, since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

async fn write_entries(db: Database, mut entries: mpsc::Receiver<NewStudioAccess>) {
    let mut batch = Vec::with_capacity(WRITE_BATCH);
    while entries.recv_many(&mut batch, WRITE_BATCH).await > 0 {
        if let Err(err) = db.insert_studio_access(&batch).await {
            tracing::warn!(error = %err, count = batch.len(), "could not record Studio access entries");
        }
        batch.clear();
    }
}
