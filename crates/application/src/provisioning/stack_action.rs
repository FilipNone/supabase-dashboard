//! Stopping, starting, and redeploying a provisioned stack's Dokploy
//! service, as a durable job.
//!
//! [`ProvisioningService::queue_action`] checks the operator's role and
//! that the dashboard provisioned the project, and queues one job. A
//! project has at most one unfinished action; the database refuses a
//! second. [`StackActionHandler`] then runs:
//!
//! 1. `check`: the operator who asked may still operate the stack, and the
//!    project still has the Dokploy service it had when the job was
//!    queued.
//! 2. `act`: reads the service, then stops or starts it, or queues a
//!    redeployment titled after the job. Stop and start are safe to repeat
//!    when Dokploy does not answer. A redeployment is never asked for
//!    twice: the job records the request before sending it and afterwards
//!    only looks for its title.
//! 3. `wait`: for a redeployment, polls it until it finishes.
//!
//! Removing and destroying run instead:
//!
//! 2. `act`: the service exists; the job records that it asks before it
//!    asks.
//! 3. `remove`: reads the service again and, while Dokploy still has it,
//!    sends `compose.delete`, with the volumes only for destroy. A delete
//!    is never sent without reading the service first.
//! 4. `confirm_removed`: waits until Dokploy no longer lists the service,
//!    then records the removal on the project.
//!
//! No action unregisters the project; that stays a separate operation.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use supabase_dashboard_domain::{
    dokploy::{DokployError, DokployUrl},
    dokploy_compose::{DASHBOARD_DEPLOYMENT_TITLE_PREFIX, DeploymentStatus},
    dokploy_placement::DokployId,
    job::{JobKind, JobState},
    provisioning::{StackAction, StackActionSummary},
};
use supabase_dashboard_persistence::{
    Database,
    audit::AuditOutcome,
    jobs::{NewJob, StoredJob},
};
use uuid::Uuid;

use std::sync::Arc;

use super::{
    ComposeApi, ProvisionError, ProvisionTimings, ProvisioningService, Stop, Then, internal,
};
use crate::{
    auth::{CurrentSession, RequestContext},
    dokploy::{DokployService, is_transient},
    jobs::{ClaimedJob, JobHandler, StepFuture, StepOutcome},
    organizations::event,
};

/// The job's saved state. Holds no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActionData {
    project_id: Uuid,
    action: StackAction,
    /// The service the project had when the job was queued.
    compose_id: String,
    /// Unix time the redeployment was requested, once it was.
    #[serde(default)]
    requested_at: Option<i64>,
    #[serde(default)]
    transient_errors: u32,
    /// Dokploy answered the delete request.
    #[serde(default)]
    delete_answered: bool,
}

/// How the operator confirmed an action.
#[derive(Clone, Copy)]
enum Confirmation<'a> {
    /// A confirmation checkbox, needed to stop.
    Given(bool),
    /// The project's name as typed, needed to remove or destroy.
    TypedName(&'a str),
}

fn redeploy_title(job_id: Uuid) -> String {
    format!("{DASHBOARD_DEPLOYMENT_TITLE_PREFIX}redeploy {job_id}")
}

impl ProvisioningService {
    /// Queues `action` on the Dokploy service of a project the dashboard
    /// provisioned, and returns the job's ID. Stopping takes the stack
    /// offline, so it needs `confirmed`. Removing and destroying go through
    /// [`Self::queue_removal`].
    pub async fn queue_action(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        action: StackAction,
        confirmed: bool,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, ProvisionError> {
        self.queue(
            current,
            project_id,
            action,
            Confirmation::Given(confirmed),
            ctx,
        )
        .await
    }

    /// Queues removing the project's service from Dokploy, with its data
    /// volumes for [`StackAction::Destroy`]. `typed_name` must be the
    /// project's name.
    pub async fn queue_removal(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        action: StackAction,
        typed_name: &str,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, ProvisionError> {
        self.queue(
            current,
            project_id,
            action,
            Confirmation::TypedName(typed_name),
            ctx,
        )
        .await
    }

    async fn queue(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        action: StackAction,
        confirmation: Confirmation<'_>,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, ProvisionError> {
        let audit = action.audit_action();
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(ProvisionError::NotFound)?;
        if !access.role.allows(action.permission()) {
            let denied = event(
                current,
                audit,
                ("project", project_id.to_string()),
                AuditOutcome::Denied,
                ctx,
            );
            if let Err(err) = self.db.record_audit_event(&denied).await {
                tracing::error!(error = %err, action = audit, "could not record audit event");
            }
            return Err(ProvisionError::Forbidden);
        }
        let stored = self
            .db
            .find_project_dokploy_service(project_id)
            .await?
            .ok_or(ProvisionError::NotProvisioned)?;
        if stored.removed_at.is_some() {
            return Err(ProvisionError::AlreadyRemoved);
        }
        match (action, confirmation) {
            (StackAction::Remove | StackAction::Destroy, Confirmation::TypedName(typed))
                if typed.trim() == access.project.name.as_str() => {}
            (StackAction::Remove | StackAction::Destroy, _) => {
                return Err(ProvisionError::NameMismatch);
            }
            (StackAction::Stop, Confirmation::Given(false)) => {
                return Err(ProvisionError::NotConfirmed);
            }
            _ => {}
        }
        let job_id = Uuid::now_v7();
        let data = serde_json::to_string(&ActionData {
            project_id,
            action,
            compose_id: stored.compose_id,
            requested_at: None,
            transient_errors: 0,
            delete_answered: false,
        })
        .map_err(|err| ProvisionError::Internal(err.to_string()))?;
        let queued = self
            .db
            .insert_stack_action_job(
                &NewJob {
                    id: job_id,
                    kind: JobKind::StackAction.as_str(),
                    organization_id: access.project.organization_id,
                    step: "check",
                    data: &data,
                    secrets: None,
                    created_by: current.account.id,
                },
                &event(
                    current,
                    audit,
                    ("project", project_id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        if queued {
            Ok(job_id)
        } else {
            let refused = event(
                current,
                audit,
                ("project", project_id.to_string()),
                AuditOutcome::Failure,
                ctx,
            );
            if let Err(err) = self.db.record_audit_event(&refused).await {
                tracing::error!(error = %err, action = audit, "could not record audit event");
            }
            Err(ProvisionError::Busy)
        }
    }

    /// The newest action asked for on `project_id`. The caller has
    /// checked that the operator may read the project.
    pub(super) async fn last_action(
        &self,
        project_id: Uuid,
    ) -> Result<Option<StackActionSummary>, ProvisionError> {
        Ok(self
            .db
            .latest_stack_action_job(project_id)
            .await?
            .and_then(action_summary))
    }
}

fn action_summary(job: StoredJob) -> Option<StackActionSummary> {
    let data: ActionData = serde_json::from_str(&job.data).ok()?;
    Some(StackActionSummary {
        id: job.id,
        action: data.action,
        state: JobState::parse(&job.state)?,
        message: job.message,
        created_at: job.created_at,
        finished_at: job.finished_at,
    })
}

/// Runs stop, start, and redeploy jobs.
pub struct StackActionHandler {
    db: Database,
    dokploy: Arc<DokployService>,
    compose: Arc<dyn ComposeApi>,
    timings: ProvisionTimings,
}

impl StackActionHandler {
    pub fn new(db: Database, dokploy: Arc<DokployService>, compose: Arc<dyn ComposeApi>) -> Self {
        Self {
            db,
            dokploy,
            compose,
            timings: ProvisionTimings::default(),
        }
    }

    #[must_use]
    pub fn with_timings(mut self, timings: ProvisionTimings) -> Self {
        self.timings = timings;
        self
    }
}

impl JobHandler for StackActionHandler {
    fn kind(&self) -> JobKind {
        JobKind::StackAction
    }

    fn run_step<'a>(&'a self, job: &'a ClaimedJob) -> StepFuture<'a> {
        Box::pin(async move {
            let mut data: ActionData = match serde_json::from_value(job.data.clone()) {
                Ok(data) => data,
                Err(_) => {
                    return StepOutcome::Fail {
                        data: job.data.clone(),
                        message: "The job's saved state could not be read.".to_owned(),
                    };
                }
            };
            let result = ActionStep { handler: self, job }.run(&mut data).await;
            if result.is_ok() {
                data.transient_errors = 0;
            }
            let value =
                |data: &ActionData| serde_json::to_value(data).unwrap_or_else(|_| job.data.clone());
            match result {
                Ok(Then::Next(step)) => StepOutcome::Next {
                    step,
                    data: value(&data),
                },
                Ok(Then::Wait(step, after, message)) => StepOutcome::Wait {
                    step,
                    data: value(&data),
                    after,
                    message,
                },
                Ok(Then::Succeed(message)) => StepOutcome::Succeed {
                    data: value(&data),
                    message: Some(message),
                },
                Err(Stop::Fail(message)) => StepOutcome::Fail {
                    data: value(&data),
                    message,
                },
                Err(Stop::Unanswered(err)) => {
                    data.transient_errors = data.transient_errors.saturating_add(1);
                    let max = self.timings.max_transient_errors;
                    if data.transient_errors > max {
                        StepOutcome::Fail {
                            data: value(&data),
                            message: format!(
                                "Dokploy did not answer {max} times in a row: {err}. Check the service in Dokploy."
                            ),
                        }
                    } else {
                        StepOutcome::Wait {
                            step: action_step_name(&job.step),
                            data: value(&data),
                            after: self.timings.transient_retry,
                            message: Some(format!("Dokploy did not answer ({err}); trying again.")),
                        }
                    }
                }
            }
        })
    }
}

fn action_step_name(step: &str) -> &'static str {
    match step {
        "act" => "act",
        "wait" => "wait",
        "remove" => "remove",
        "confirm_removed" => "confirm_removed",
        _ => "check",
    }
}

struct ActionStep<'a> {
    handler: &'a StackActionHandler,
    job: &'a ClaimedJob,
}

impl ActionStep<'_> {
    async fn run(&self, data: &mut ActionData) -> Result<Then, Stop> {
        match self.job.step.as_str() {
            "check" => self.check(data).await,
            "act" => self.act(data).await,
            "wait" => self.wait(data).await,
            "remove" => self.remove(data).await,
            "confirm_removed" => self.confirm_removed(data).await,
            other => Err(Stop::Fail(format!("Unknown step {other}."))),
        }
    }

    /// The operator may still operate the stack, and the project still
    /// has the service the job was queued for.
    async fn check(&self, data: &ActionData) -> Result<Then, Stop> {
        let Some(account) = self.job.created_by else {
            return Err(Stop::Fail(
                "The account that asked for this no longer exists.".to_owned(),
            ));
        };
        let db = &self.handler.db;
        let active = db
            .account_is_active(account)
            .await
            .map_err(|err| internal("check the operator's account", err))?;
        let access = db
            .find_project_access(data.project_id, account)
            .await
            .map_err(|err| internal("check the operator's role", err))?;
        match access {
            Some(access)
                if active
                    && access.project.organization_id == self.job.organization_id
                    && access.role.allows(data.action.permission()) => {}
            _ => {
                return Err(Stop::Fail(
                    "The account that asked for this may no longer operate this project's stack."
                        .to_owned(),
                ));
            }
        }
        let stored = db
            .find_project_dokploy_service(data.project_id)
            .await
            .map_err(|err| internal("read the project's Dokploy service", err))?;
        match stored {
            Some(stored) if stored.compose_id == data.compose_id => {
                if stored.removed_at.is_some() {
                    return Err(Stop::Fail(
                        "The dashboard already removed this service from Dokploy.".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(Stop::Fail(
                    "The project no longer has the Dokploy service this was asked for.".to_owned(),
                ));
            }
        }
        Ok(Then::Next("act"))
    }

    async fn dokploy(&self) -> Result<(DokployUrl, SecretString), Stop> {
        match self.handler.dokploy.credentials().await {
            Ok(Some(credentials)) => Ok((credentials.url, credentials.key)),
            Ok(None) => Err(Stop::Fail("Dokploy is no longer connected.".to_owned())),
            Err(err) => Err(internal("read the Dokploy connection", err)),
        }
    }

    fn compose_id(data: &ActionData) -> Result<DokployId, Stop> {
        DokployId::parse(&data.compose_id)
            .map_err(|_| Stop::Fail("The job's Dokploy service ID is not valid.".to_owned()))
    }

    async fn act(&self, data: &mut ActionData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let api = &self.handler.compose;
        if api.compose_details(&url, &key, &compose).await?.is_none() {
            return Err(Stop::Fail(
                "Dokploy no longer has this service, so nothing was changed. It was deleted in Dokploy, or the dashboard's key can no longer see it."
                    .to_owned(),
            ));
        }
        match data.action {
            StackAction::Remove | StackAction::Destroy => {
                // Saved before anything is sent: from here on, a service
                // that is gone counts as removed by this job.
                data.requested_at = Some(time::OffsetDateTime::now_utc().unix_timestamp());
                Ok(Then::Next("remove"))
            }
            StackAction::Stop => {
                api.stop_compose(&url, &key, &compose).await?;
                Ok(Then::Succeed(
                    "Stopped. The containers are down; the volumes and data are kept.".to_owned(),
                ))
            }
            StackAction::Start => {
                api.start_compose(&url, &key, &compose).await?;
                Ok(Then::Succeed(
                    "Started. The health check shows when the services answer.".to_owned(),
                ))
            }
            StackAction::Redeploy => self.redeploy(data, &url, &key, &compose).await,
        }
    }

    async fn redeploy(
        &self,
        data: &mut ActionData,
        url: &DokployUrl,
        key: &SecretString,
        compose: &DokployId,
    ) -> Result<Then, Stop> {
        let api = &self.handler.compose;
        let title = redeploy_title(self.job.id);
        let deployments = api.deployments(url, key, compose).await?;
        let started = deployments
            .iter()
            .any(|d| d.title.as_deref() == Some(title.as_str()));
        if !started && data.requested_at.is_none() {
            // Recorded first: if the answer is lost, the job waits for the
            // title instead of asking again.
            data.requested_at = Some(time::OffsetDateTime::now_utc().unix_timestamp());
            if let Err(err) = api.redeploy_compose(url, key, compose, &title).await {
                if !is_transient(&err) {
                    return Err(err.into());
                }
                tracing::warn!(error = %err, job = %self.job.id, "redeployment request unanswered");
            }
        }
        Ok(Then::Wait(
            "wait",
            self.handler.timings.deploy_poll,
            Some("Redeploying the stack.".to_owned()),
        ))
    }

    /// Sends the delete while Dokploy still has the service. Runs again
    /// only after an interruption, and reads the service first each time.
    async fn remove(&self, data: &mut ActionData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let api = &self.handler.compose;
        if api.compose_details(&url, &key, &compose).await?.is_none() {
            return self.removed(data).await;
        }
        let volumes = data.action == StackAction::Destroy;
        match api.delete_compose(&url, &key, &compose, volumes).await {
            Ok(()) => {
                data.delete_answered = true;
                Ok(Then::Next("confirm_removed"))
            }
            // Already gone: confirmed by the next read.
            Err(DokployError::Http(404)) => Ok(Then::Next("confirm_removed")),
            Err(err) if is_transient(&err) => {
                tracing::warn!(error = %err, job = %self.job.id, "delete request unanswered");
                Ok(Then::Wait(
                    "confirm_removed",
                    self.handler.timings.deploy_poll,
                    Some("Waiting for Dokploy to remove the service.".to_owned()),
                ))
            }
            Err(err) => Err(Stop::Fail(format!(
                "Dokploy refused to remove the service: {err}. Part of it may already be gone; check it in Dokploy. The dashboard did not ask again."
            ))),
        }
    }

    /// Waits until Dokploy no longer lists the service. Never asks again.
    async fn confirm_removed(&self, data: &mut ActionData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        if self
            .handler
            .compose
            .compose_details(&url, &key, &compose)
            .await?
            .is_none()
        {
            return self.removed(data).await;
        }
        let elapsed = data.requested_at.map_or(0, |at| {
            time::OffsetDateTime::now_utc().unix_timestamp() - at
        });
        let deadline =
            i64::try_from(self.handler.timings.deploy_deadline.as_secs()).unwrap_or(i64::MAX);
        if elapsed > deadline {
            return Err(Stop::Fail(
                "Dokploy still lists the service long after it was asked to remove it. Check it in Dokploy; the dashboard did not ask again."
                    .to_owned(),
            ));
        }
        Ok(Then::Wait(
            "confirm_removed",
            self.handler.timings.deploy_poll,
            Some("Waiting for Dokploy to remove the service.".to_owned()),
        ))
    }

    /// Records the removal on the project and ends the job.
    async fn removed(&self, data: &ActionData) -> Result<Then, Stop> {
        let destroy = data.action == StackAction::Destroy;
        let recorded = self
            .handler
            .db
            .mark_dokploy_service_removed(data.project_id, &data.compose_id, destroy)
            .await
            .map_err(|err| internal("record the removal", err))?;
        let unregister = if recorded {
            " The project stays registered until it is unregistered under Settings."
        } else {
            " The project was unregistered meanwhile."
        };
        let what = match (destroy, data.delete_answered) {
            (true, true) => "Destroyed: Dokploy deleted the service and its data volumes.",
            (true, false) => {
                "Dokploy no longer lists the service. Its answer to the request to delete it with its data volumes was lost; check the server for volumes whose names start with the service's name."
            }
            (false, true) => "Removed from Dokploy. The data volumes stay on the server.",
            (false, false) => {
                "Dokploy no longer lists the service. The request kept the data volumes on the server."
            }
        };
        Ok(Then::Succeed(format!("{what}{unregister}")))
    }

    async fn wait(&self, data: &ActionData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let title = redeploy_title(self.job.id);
        let deployments = self
            .handler
            .compose
            .deployments(&url, &key, &compose)
            .await?;
        let status = deployments
            .iter()
            .find(|d| d.title.as_deref() == Some(title.as_str()))
            .map(|d| d.status);
        let elapsed = data.requested_at.map_or(0, |at| {
            time::OffsetDateTime::now_utc().unix_timestamp() - at
        });
        let deadline =
            i64::try_from(self.handler.timings.deploy_deadline.as_secs()).unwrap_or(i64::MAX);
        let poll = self.handler.timings.deploy_poll;
        match status {
            Some(DeploymentStatus::Done) => Ok(Then::Succeed("Redeployed.".to_owned())),
            Some(DeploymentStatus::Error) => Err(Stop::Fail(
                "The redeployment failed. Its log in Dokploy says why.".to_owned(),
            )),
            Some(DeploymentStatus::Cancelled) => Err(Stop::Fail(
                "The redeployment was cancelled in Dokploy.".to_owned(),
            )),
            _ if elapsed > deadline => Err(Stop::Fail(if status.is_none() {
                "Dokploy did not start the redeployment in time. Check the service in Dokploy before asking again.".to_owned()
            } else {
                "The redeployment ran longer than the job waits. Check it in Dokploy.".to_owned()
            })),
            None => Ok(Then::Wait(
                "wait",
                poll,
                Some("Waiting for Dokploy to start the redeployment.".to_owned()),
            )),
            Some(DeploymentStatus::Running) => Ok(Then::Wait(
                "wait",
                poll,
                Some("Redeploying the stack.".to_owned()),
            )),
        }
    }
}
