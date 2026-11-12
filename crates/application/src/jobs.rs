//! Runs durable background jobs one step at a time.
//!
//! A [`JobRunner`] claims a due job, asks the job kind's [`JobHandler`] to
//! run its current step, and saves the outcome before the next step. When
//! the dashboard stops partway, the job's lease runs out and the next
//! runner claims it again at the last saved step. Every step must therefore
//! be safe to run again: one that changes something outside the dashboard
//! reads the current state first (for example, looks a service up by name
//! before creating it), and an action that cannot be repeated safely is
//! never retried blindly.
//!
//! Steps that take longer than the step timeout are abandoned and counted
//! as interruptions, like a lost lease. A job interrupted more than
//! [`RunnerSettings::max_interruptions`] times fails.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use serde_json::Value;
use supabase_dashboard_domain::job::{JobKind, is_step_name};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    jobs::{JobUpdate, StoredJob},
};
use time::OffsetDateTime;
use uuid::Uuid;

/// The most a job message may hold, as the database checks.
const MAX_MESSAGE_CHARS: usize = 1000;

#[derive(Debug, Clone)]
pub struct RunnerSettings {
    /// How long a claim lasts without being renewed. Longer than
    /// `step_timeout`, so a step never outlives its lease.
    pub lease: Duration,
    pub step_timeout: Duration,
    /// How long a step that took too long waits before it runs again.
    pub retry_after_timeout: Duration,
    pub max_interruptions: i32,
    /// Steps run in one claim before the job is released for others.
    pub max_steps_per_claim: usize,
    /// How long an idle runner waits before looking for due jobs again.
    pub idle_poll: Duration,
}

impl Default for RunnerSettings {
    fn default() -> Self {
        Self {
            lease: Duration::from_secs(180),
            step_timeout: Duration::from_secs(120),
            retry_after_timeout: Duration::from_secs(30),
            max_interruptions: 5,
            max_steps_per_claim: 50,
            idle_poll: Duration::from_secs(5),
        }
    }
}

/// A job as its handler sees it.
#[derive(Debug, Clone)]
pub struct ClaimedJob {
    pub id: Uuid,
    pub kind: JobKind,
    pub organization_id: Uuid,
    pub step: String,
    pub data: Value,
    pub interruptions: i32,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

/// What a step decided.
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    /// Saves `data` and runs `step` next, right away.
    Next { step: &'static str, data: Value },
    /// Saves `data` and runs `step` after `after`, for example to poll.
    Wait {
        step: &'static str,
        data: Value,
        after: Duration,
        message: Option<String>,
    },
    Succeed {
        data: Value,
        message: Option<String>,
    },
    /// The job stops. `message` says why and what to do, for the operator.
    Fail { data: Value, message: String },
}

pub type StepFuture<'a> = Pin<Box<dyn Future<Output = StepOutcome> + Send + 'a>>;

pub trait JobHandler: Send + Sync {
    fn kind(&self) -> JobKind;

    /// Runs `job.step`. See the module documentation: the step must be safe
    /// to run again after an interruption.
    fn run_step<'a>(&'a self, job: &'a ClaimedJob) -> StepFuture<'a>;
}

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

/// What [`JobRunner::run_due`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunResult {
    /// No job was due.
    Idle,
    /// The job was saved as waiting, finished, or released after the step
    /// limit.
    Ran(Uuid),
    /// Another runner took the job over, because this runner's lease ran
    /// out. Nothing more was saved.
    LeaseLost(Uuid),
}

pub struct JobRunner {
    db: Database,
    handlers: Vec<Arc<dyn JobHandler>>,
    owner: Uuid,
    settings: RunnerSettings,
}

impl JobRunner {
    pub fn new(db: Database, handlers: Vec<Arc<dyn JobHandler>>, settings: RunnerSettings) -> Self {
        Self {
            db,
            handlers,
            owner: Uuid::now_v7(),
            settings,
        }
    }

    /// Runs due jobs until `shutdown` resolves. Database errors are logged
    /// and retried after the idle interval.
    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let idle = match self.run_due().await {
                Ok(RunResult::Idle) => true,
                Ok(_) => false,
                Err(err) => {
                    tracing::warn!(error = %err, "job runner could not reach the database");
                    true
                }
            };
            if idle {
                tokio::select! {
                    () = &mut shutdown => return,
                    () = tokio::time::sleep(self.settings.idle_poll) => {}
                }
            }
        }
    }

    /// Claims one due job and runs its steps until it waits, finishes, or
    /// reaches the step limit.
    pub async fn run_due(&self) -> Result<RunResult, JobError> {
        let lease = self.settings.lease.as_secs_f64();
        let Some(stored) = self.db.claim_job(self.owner, lease).await? else {
            return Ok(RunResult::Idle);
        };
        let id = stored.id;
        let data_text = stored.data.clone();
        let mut job = match claimed(stored) {
            Ok(job) => job,
            Err(message) => {
                return self
                    .save(
                        id,
                        &JobUpdate::Fail {
                            data: &data_text,
                            message: &message,
                        },
                    )
                    .await;
            }
        };
        if job.interruptions > self.settings.max_interruptions {
            let message = format!(
                "The job was interrupted {} times at step {}, so it stopped. Check what the step had done before starting again.",
                job.interruptions, job.step
            );
            return self.fail(&job, message).await;
        }
        let Some(handler) = self.handlers.iter().find(|h| h.kind() == job.kind).cloned() else {
            let message = format!("This server cannot run {} jobs.", job.kind);
            return self.fail(&job, message).await;
        };

        for _ in 0..self.settings.max_steps_per_claim {
            let outcome = match tokio::time::timeout(
                self.settings.step_timeout,
                handler.run_step(&job),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(_) => {
                    tracing::warn!(job_id = %job.id, step = %job.step, "job step took too long");
                    let data = job.data.to_string();
                    let message = format!(
                        "Step {} took longer than {} seconds; it will run again.",
                        job.step,
                        self.settings.step_timeout.as_secs()
                    );
                    return self
                        .save(
                            job.id,
                            &JobUpdate::Wait {
                                step: &job.step,
                                data: &data,
                                run_after: after(self.settings.retry_after_timeout),
                                message: Some(&message),
                                interrupted: true,
                            },
                        )
                        .await;
                }
            };
            match outcome {
                StepOutcome::Next { step, data } => {
                    if !is_step_name(step) {
                        return self
                            .fail(&job, format!("Unknown next step {step:?}."))
                            .await;
                    }
                    let text = data.to_string();
                    let update = JobUpdate::Continue {
                        step,
                        data: &text,
                        lease_seconds: lease,
                    };
                    if self.save(job.id, &update).await? != RunResult::Ran(job.id) {
                        return Ok(RunResult::LeaseLost(job.id));
                    }
                    job.step = step.to_owned();
                    job.data = data;
                }
                StepOutcome::Wait {
                    step,
                    data,
                    after: delay,
                    message,
                } => {
                    if !is_step_name(step) {
                        return self
                            .fail(&job, format!("Unknown next step {step:?}."))
                            .await;
                    }
                    let text = data.to_string();
                    let message = message.map(|m| clip(&m));
                    return self
                        .save(
                            job.id,
                            &JobUpdate::Wait {
                                step,
                                data: &text,
                                run_after: after(delay),
                                message: message.as_deref(),
                                interrupted: false,
                            },
                        )
                        .await;
                }
                StepOutcome::Succeed { data, message } => {
                    tracing::info!(job_id = %job.id, kind = %job.kind, "job succeeded");
                    let text = data.to_string();
                    let message = message.map(|m| clip(&m));
                    return self
                        .save(
                            job.id,
                            &JobUpdate::Succeed {
                                data: &text,
                                message: message.as_deref(),
                            },
                        )
                        .await;
                }
                StepOutcome::Fail { data, message } => {
                    job.data = data;
                    return self.fail(&job, message).await;
                }
            }
        }
        // Let other jobs run; this one is due again right away.
        let data = job.data.to_string();
        self.save(
            job.id,
            &JobUpdate::Wait {
                step: &job.step,
                data: &data,
                run_after: OffsetDateTime::now_utc(),
                message: None,
                interrupted: false,
            },
        )
        .await
    }

    async fn fail(&self, job: &ClaimedJob, message: String) -> Result<RunResult, JobError> {
        tracing::warn!(job_id = %job.id, kind = %job.kind, step = %job.step, "job failed");
        let data = job.data.to_string();
        let message = clip(&message);
        self.save(
            job.id,
            &JobUpdate::Fail {
                data: &data,
                message: &message,
            },
        )
        .await
    }

    async fn save(&self, id: Uuid, update: &JobUpdate<'_>) -> Result<RunResult, JobError> {
        if self.db.update_job(id, self.owner, update).await? {
            Ok(RunResult::Ran(id))
        } else {
            tracing::warn!(job_id = %id, "job lease lost to another runner");
            Ok(RunResult::LeaseLost(id))
        }
    }
}

fn claimed(stored: StoredJob) -> Result<ClaimedJob, String> {
    let kind = JobKind::parse(&stored.kind).ok_or_else(|| "Unknown job kind.".to_owned())?;
    let data: Value =
        serde_json::from_str(&stored.data).map_err(|_| "The job's saved data is unreadable.")?;
    Ok(ClaimedJob {
        id: stored.id,
        kind,
        organization_id: stored.organization_id,
        step: stored.step,
        data,
        interruptions: stored.interruptions,
        created_by: stored.created_by,
        created_at: stored.created_at,
    })
}

fn after(delay: Duration) -> OffsetDateTime {
    let delay = time::Duration::try_from(delay).unwrap_or(time::Duration::DAY);
    OffsetDateTime::now_utc().saturating_add(delay)
}

fn clip(message: &str) -> String {
    message.chars().take(MAX_MESSAGE_CHARS).collect()
}
