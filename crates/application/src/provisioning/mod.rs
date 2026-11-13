//! Provisioning a new Supabase stack through Dokploy, as a durable job.
//!
//! [`ProvisioningService::start`] checks the operator's role, the name,
//! the host, and the target, generates the stack's secrets, and queues a
//! job with the secrets sealed apart from its data. [`ProvisionStackHandler`]
//! then runs these steps, each safe to run again:
//!
//! 1. `check`: the operator who asked may still register projects in the
//!    organization, and the organization may still use the target.
//! 2. `create_service`: finds the compose service by its job-derived name,
//!    or creates it.
//! 3. `configure`: sets the pinned compose file and the variables.
//! 4. `mounts`: writes the files the compose file mounts.
//! 5. `domain`: routes the host to the gateway.
//! 6. `deploy`: starts a deployment titled after the job, unless one with
//!    that title exists.
//! 7. `wait_deploy`: polls the deployment until it finishes.
//! 8. `register`: checks the role again, then registers the project with
//!    its keys, the Studio login, and its Dokploy service in one
//!    transaction.
//! 9. `health`: checks Auth through the public URL for a few minutes.
//!
//! Creating a service, a mount, or a domain, and starting a deployment,
//! are never sent twice blindly: each step looks for what an earlier,
//! interrupted run may have made. A deployment request whose answer was
//! lost is never sent again; the job waits for its title to appear and
//! fails with instructions if it does not. A failed job leaves what it
//! made in Dokploy and says so.

use std::{sync::Arc, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use supabase_dashboard_domain::{
    authz::Permission,
    connection::{CredentialKind, ServiceStatus, StackService, check_studio_login},
    dokploy::{DokployError, DokployUrl},
    dokploy_compose::{
        ComposeDetails, DASHBOARD_DEPLOYMENT_TITLE_PREFIX, DeploymentStatus, NewCompose,
        NewComposeDomain, check_stack_host, compose_name_for_job, is_dashboard_deployment,
    },
    dokploy_placement::DokployId,
    dokploy_target::{DefaultTarget, StackTarget},
    job::JobKind,
    job::JobState,
    project::{MAX_PROJECTS_PER_ORGANIZATION, ProjectInputError, ProjectName, ProjectUrl},
    provisioning::{
        ProvisionJobSummary, ProvisionStep, ProvisionTargets, StackDeployment, StackDeploymentRun,
        StackDeploymentView, StackLocation, TargetChoice,
    },
    stack_settings::EnvFile,
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::{AuditEvent, AuditOutcome},
    connections::NewCredential,
    jobs::{NewJob, SealedJobSecrets, StoredJob},
    projects::NewProject,
    provisioning::{NewDokployService, RegisterProvisionedOutcome, StoredDokployService},
};
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    connections::StackProbe,
    dokploy::{DokployService, DokployServiceError, EffectiveTargets, is_transient},
    jobs::{ClaimedJob, JobHandler, StepFuture, StepOutcome},
    organizations::event,
    secrets::{CipherError, CredentialCipher, Sealed},
    stack_secrets::{STUDIO_USERNAME, StackSecrets},
    stack_template::{COMPOSE_FILE, GATEWAY_PORT, GATEWAY_SERVICE, STACK_FILES, stack_env},
};

mod env_record;
mod port;
mod stack_action;
mod stack_config;

pub use port::{ComposeApi, ComposeConfig, DokployFuture};
pub use stack_action::StackActionHandler;

/// How long the job waits at each point. The defaults suit a real
/// Dokploy; tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionTimings {
    /// How often a running deployment is polled.
    pub deploy_poll: Duration,
    /// How long a deployment may run, or take to appear, before the job
    /// stops waiting.
    pub deploy_deadline: Duration,
    /// How long the job waits after Dokploy did not answer.
    pub transient_retry: Duration,
    /// Unanswered calls in a row before the job fails.
    pub max_transient_errors: u32,
    /// Health checks through the public URL, and the time between them.
    pub health_attempts: u32,
    pub health_poll: Duration,
}

impl Default for ProvisionTimings {
    fn default() -> Self {
        Self {
            deploy_poll: Duration::from_secs(5),
            deploy_deadline: Duration::from_secs(30 * 60),
            transient_retry: Duration::from_secs(30),
            max_transient_errors: 10,
            health_attempts: 30,
            health_poll: Duration::from_secs(10),
        }
    }
}

/// What the operator chose for a new stack.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionRequest<'a> {
    pub name: &'a str,
    /// A target's form value (see [`StackTarget::value`]).
    pub target: &'a str,
    /// The host name the stack is reached at. Its DNS must point at the
    /// Dokploy server.
    pub host: &'a str,
    /// Serve the stack over HTTPS with a Let's Encrypt certificate.
    /// Plain HTTP must be confirmed.
    pub https: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("you do not have permission to create projects in this organization")]
    Forbidden,
    #[error("organization not found")]
    NotFound,
    #[error(transparent)]
    Input(#[from] ProjectInputError),
    #[error("enter a host name such as shop.example.com")]
    InvalidHost,
    #[error("this organization may not create stacks there; ask an installation administrator")]
    TargetNotAllowed,
    #[error("Dokploy is not connected; ask an installation administrator to connect it")]
    NotConnected,
    #[error("the server has no credential key, so it cannot keep a new stack's secrets")]
    NoCipher,
    #[error("this organization already has the maximum number of projects")]
    LimitReached,
    #[error("the dashboard did not create this project's stack, so it cannot operate it")]
    NotProvisioned,
    #[error("an earlier action on this stack is still running; wait for it to finish")]
    Busy,
    #[error("the dashboard already removed this stack's service from Dokploy")]
    AlreadyRemoved,
    #[error("type the project's name exactly to confirm")]
    NameMismatch,
    #[error("confirm that the stack stops answering until it is started again")]
    NotConfirmed,
    #[error(transparent)]
    Setting(#[from] supabase_dashboard_domain::stack_settings::SettingError),
    /// A submitted setting the stack cannot take; the message names it.
    #[error("{0}")]
    SettingUnavailable(String),
    #[error("nothing to change: every setting already has that value")]
    NoChanges,
    #[error("the stack's settings changed since the preview; review the changes again")]
    PreviewOutdated,
    #[error("no variable was changed in Dokploy since the dashboard last wrote or accepted them")]
    NoEdits,
    #[error(
        "the stack's variables changed in Dokploy since this page read them; check the list again"
    )]
    EditsOutdated,
    #[error("Dokploy no longer has this stack's service")]
    ServiceMissing,
    /// Dokploy did not answer or refused; the message says which.
    #[error("{0}")]
    DokployUnavailable(String),
    /// Internal failure. The message is for server logs only.
    #[error("{0}")]
    Internal(String),
}

impl From<PersistenceError> for ProvisionError {
    fn from(err: PersistenceError) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<CipherError> for ProvisionError {
    fn from(err: CipherError) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<DokployServiceError> for ProvisionError {
    fn from(err: DokployServiceError) -> Self {
        match err {
            DokployServiceError::NotConnected => Self::NotConnected,
            other => Self::Internal(other.to_string()),
        }
    }
}

/// The job's saved state. Everything here is shown to nobody but the
/// server, and holds no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobData {
    project_id: Uuid,
    name: String,
    environment_id: String,
    server_id: Option<String>,
    host: String,
    https: bool,
    compose_name: String,
    #[serde(default)]
    compose_id: Option<String>,
    #[serde(default)]
    app_name: Option<String>,
    /// Unix time the deployment was requested, once it was.
    #[serde(default)]
    deploy_requested_at: Option<i64>,
    #[serde(default)]
    transient_errors: u32,
    #[serde(default)]
    health_attempts: u32,
}

impl JobData {
    fn public_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}", self.host)
    }

    fn deploy_title(job_id: Uuid) -> String {
        format!("{DASHBOARD_DEPLOYMENT_TITLE_PREFIX}provision {job_id}")
    }
}

/// Queues stacks for provisioning.
pub struct ProvisioningService {
    db: Database,
    cipher: Option<CredentialCipher>,
    dokploy: Arc<DokployService>,
    /// Reads provisioned stacks' services. `None` until the server wires
    /// the Dokploy client in.
    compose: Option<Arc<dyn ComposeApi>>,
}

impl ProvisioningService {
    pub fn new(
        db: Database,
        cipher: Option<CredentialCipher>,
        dokploy: Arc<DokployService>,
    ) -> Self {
        Self {
            db,
            cipher,
            dokploy,
            compose: None,
        }
    }

    /// Lets the service read provisioned stacks' services from Dokploy.
    #[must_use]
    pub fn with_compose(mut self, compose: Arc<dyn ComposeApi>) -> Self {
        self.compose = Some(compose);
        self
    }

    /// Queues a new stack in `organization_id` and returns the job's ID.
    /// Owners and admins only, as for registering a project.
    pub async fn start(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        request: ProvisionRequest<'_>,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, ProvisionError> {
        let action = "project.provision";
        let membership = self
            .db
            .find_membership(organization_id, current.account.id)
            .await?
            .ok_or(ProvisionError::NotFound)?;
        if !membership.role.allows(Permission::ProjectRegister) {
            let denied = event(
                current,
                action,
                ("organization", organization_id.to_string()),
                AuditOutcome::Denied,
                ctx,
            );
            if let Err(err) = self.db.record_audit_event(&denied).await {
                tracing::error!(error = %err, action, "could not record audit event");
            }
            return Err(ProvisionError::Forbidden);
        }
        let name = ProjectName::parse(request.name)?;
        let host = check_stack_host(request.host).ok_or(ProvisionError::InvalidHost)?;
        let cipher = self.cipher.as_ref().ok_or(ProvisionError::NoCipher)?;
        let target =
            StackTarget::parse_value(request.target).ok_or(ProvisionError::TargetNotAllowed)?;
        let targets = self.dokploy.organization_targets(organization_id).await?;
        if !target_allowed(&targets, &target) {
            return Err(ProvisionError::TargetNotAllowed);
        }
        let count = self.db.count_projects(organization_id).await?;
        if usize::try_from(count).map_or(true, |count| count >= MAX_PROJECTS_PER_ORGANIZATION) {
            return Err(ProvisionError::LimitReached);
        }

        let job_id = Uuid::now_v7();
        let secrets =
            StackSecrets::generate().map_err(|err| ProvisionError::Internal(err.to_string()))?;
        let sealed = cipher.seal_job_secrets(job_id, &secrets.to_json())?;
        let data = JobData {
            project_id: Uuid::now_v7(),
            name: name.as_str().to_owned(),
            environment_id: target.environment_id.as_str().to_owned(),
            server_id: target.server_id.as_ref().map(|id| id.as_str().to_owned()),
            host,
            https: request.https,
            compose_name: compose_name_for_job(job_id),
            compose_id: None,
            app_name: None,
            deploy_requested_at: None,
            transient_errors: 0,
            health_attempts: 0,
        };
        let data = serde_json::to_string(&data)
            .map_err(|err| ProvisionError::Internal(err.to_string()))?;
        self.db
            .insert_job(
                &NewJob {
                    id: job_id,
                    kind: JobKind::ProvisionStack.as_str(),
                    organization_id,
                    step: "check",
                    data: &data,
                    secrets: Some(&SealedJobSecrets {
                        key_id: sealed.key_id,
                        nonce: sealed.nonce,
                        ciphertext: sealed.ciphertext,
                    }),
                    created_by: current.account.id,
                },
                &event(
                    current,
                    action,
                    ("job", job_id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        Ok(job_id)
    }
}

/// Most provisioning jobs listed for an organization.
const MAX_LISTED_JOBS: i64 = 20;

impl ProvisioningService {
    /// The targets the operator may choose for a new stack in
    /// `organization_id`. Owners and admins only.
    pub async fn targets(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<ProvisionTargets, ProvisionError> {
        self.require(current, organization_id, Permission::ProjectRegister)
            .await?;
        let targets = match self.dokploy.organization_targets(organization_id).await {
            Ok(targets) => targets,
            Err(DokployServiceError::NotConnected) => return Ok(ProvisionTargets::NotConnected),
            Err(err) => return Err(err.into()),
        };
        Ok(match targets {
            EffectiveTargets::Allowed(allowed) => ProvisionTargets::Choices(
                allowed
                    .iter()
                    .map(|(target, names)| TargetChoice {
                        value: target.value(),
                        label: names.label(),
                    })
                    .collect(),
            ),
            EffectiveTargets::Default(DefaultTarget::Placement { target, names }) => {
                ProvisionTargets::Choices(vec![TargetChoice {
                    value: target.value(),
                    label: names.label(),
                }])
            }
            EffectiveTargets::Default(DefaultTarget::NoPlacement) => ProvisionTargets::NoTarget,
            EffectiveTargets::Default(DefaultTarget::Unavailable(reason)) => {
                tracing::warn!(%reason, "the default stack target could not be read");
                ProvisionTargets::Unavailable
            }
        })
    }

    /// A provisioning job, for members of its organization.
    pub async fn job(
        &self,
        current: &CurrentSession,
        job_id: Uuid,
    ) -> Result<ProvisionJobSummary, ProvisionError> {
        let job = self
            .db
            .get_job(job_id)
            .await?
            .filter(|job| job.kind == JobKind::ProvisionStack.as_str())
            .ok_or(ProvisionError::NotFound)?;
        self.require(current, job.organization_id, Permission::ProjectRead)
            .await?;
        let project = self
            .db
            .provisioned_projects(&[job.id])
            .await?
            .first()
            .map(|(_, project)| *project);
        summary(job, project).ok_or_else(|| ProvisionError::Internal("unreadable job".to_owned()))
    }

    /// The organization's latest provisioning jobs, newest first.
    pub async fn jobs(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<Vec<ProvisionJobSummary>, ProvisionError> {
        self.require(current, organization_id, Permission::ProjectRead)
            .await?;
        let jobs: Vec<StoredJob> = self
            .db
            .list_organization_jobs(organization_id, MAX_LISTED_JOBS)
            .await?
            .into_iter()
            .filter(|job| job.kind == JobKind::ProvisionStack.as_str())
            .collect();
        let ids: Vec<Uuid> = jobs.iter().map(|job| job.id).collect();
        let projects = self.db.provisioned_projects(&ids).await?;
        Ok(jobs
            .into_iter()
            .filter_map(|job| {
                let project = projects
                    .iter()
                    .find(|(id, _)| *id == job.id)
                    .map(|(_, project)| *project);
                summary(job, project)
            })
            .collect())
    }

    /// The Dokploy service behind a project the dashboard provisioned, as
    /// Dokploy reports it now, for members of the project's organization.
    /// Where the service is and the link to it are for owners and admins,
    /// who choose where stacks go. Dokploy is asked on every call, so
    /// redeploys, moves, and deletions made in Dokploy show up; a failed
    /// call is reported in the answer, not as an error.
    pub async fn deployment(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<StackDeploymentView, ProvisionError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(ProvisionError::NotFound)?;
        if !access.role.allows(Permission::ProjectRead) {
            return Err(ProvisionError::Forbidden);
        }
        let manager = access.role.allows(Permission::ProjectRegister);
        let Some(stored) = self.db.find_project_dokploy_service(project_id).await? else {
            return Ok(StackDeploymentView::NotProvisioned);
        };
        let last_action = self.last_action(project_id).await?;
        if let Some(removed_at) = stored.removed_at {
            return Ok(StackDeploymentView::Removed {
                removed_at,
                volumes_deleted: stored.volumes_deleted,
                app_name: manager.then(|| stored.app_name.clone()),
                last_action,
            });
        }
        let credentials = match self.dokploy.credentials().await {
            Ok(Some(credentials)) => credentials,
            Ok(None) | Err(DokployServiceError::NotConnected) => {
                return Ok(StackDeploymentView::NotConnected);
            }
            Err(err) => return Err(err.into()),
        };
        let Some(compose) = self.compose.as_ref() else {
            return Ok(StackDeploymentView::Unavailable {
                reason: "This server does not read Dokploy services.".to_owned(),
                last_action,
            });
        };
        let compose_id = DokployId::parse(&stored.compose_id)
            .map_err(|_| ProvisionError::Internal("unreadable Dokploy service ID".to_owned()))?;
        let details = match compose
            .compose_details(&credentials.url, &credentials.key, &compose_id)
            .await
        {
            Ok(Some(details)) => details,
            Ok(None) => {
                return Ok(StackDeploymentView::Missing {
                    compose_name: manager.then(|| compose_name_for_job(stored.job_id)),
                    last_action,
                });
            }
            Err(err) => {
                return Ok(StackDeploymentView::Unavailable {
                    reason: err.to_string(),
                    last_action,
                });
            }
        };
        let mut found = stack_deployment(&stored, details, manager.then_some(&credentials.url));
        found.can_operate = access.role.allows(Permission::StackOperate);
        found.can_remove = access.role.allows(Permission::StackRemove);
        found.can_destroy = access.role.allows(Permission::StackDestroy);
        found.last_action = last_action;
        Ok(StackDeploymentView::Found(Box::new(found)))
    }

    /// The operator's membership allows `permission`. A non-member gets
    /// [`ProvisionError::NotFound`].
    async fn require(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        permission: Permission,
    ) -> Result<(), ProvisionError> {
        let membership = self
            .db
            .find_membership(organization_id, current.account.id)
            .await?
            .ok_or(ProvisionError::NotFound)?;
        if membership.role.allows(permission) {
            Ok(())
        } else {
            Err(ProvisionError::Forbidden)
        }
    }
}

/// What members see of a stored job. `None` when its data is unreadable.
fn summary(job: StoredJob, project_id: Option<Uuid>) -> Option<ProvisionJobSummary> {
    let data: JobData = serde_json::from_str(&job.data).ok()?;
    Some(ProvisionJobSummary {
        id: job.id,
        organization_id: job.organization_id,
        name: data.name,
        host: data.host,
        https: data.https,
        state: JobState::parse(&job.state)?,
        step: ProvisionStep::parse(&job.step),
        message: job.message,
        project_id,
        created_at: job.created_at,
        updated_at: job.updated_at,
        finished_at: job.finished_at,
    })
}

/// Most deployments listed for a provisioned project.
const MAX_LISTED_DEPLOYMENTS: usize = 5;

/// What members see of a service Dokploy reported. `dokploy_url` is set
/// for owners and admins, who also see where the service is.
fn stack_deployment(
    stored: &StoredDokployService,
    details: ComposeDetails,
    dokploy_url: Option<&DokployUrl>,
) -> StackDeployment {
    let moved = details.environment_id.as_str() != stored.environment_id
        || details.server_id.as_ref().map(DokployId::as_str) != stored.server_id.as_deref();
    let location = dokploy_url.map(|url| StackLocation {
        dokploy_link: (!url.is_internal_name()).then(|| {
            url.compose_page(
                &details.project_id,
                &details.environment_id,
                &details.compose_id,
            )
        }),
        project_name: details.project_name.clone(),
        environment_name: details.environment_name.clone(),
        server_name: details.server_name.clone(),
        compose_id: details.compose_id.as_str().to_owned(),
        app_name: details.app_name.clone(),
    });
    let more_deployments = details.deployments.len() > MAX_LISTED_DEPLOYMENTS;
    let deployments = details
        .deployments
        .into_iter()
        .take(MAX_LISTED_DEPLOYMENTS)
        .map(|run| StackDeploymentRun {
            from_dashboard: is_dashboard_deployment(run.title.as_deref()),
            title: run.title,
            status: run.status,
            created_at: run.created_at,
            finished_at: run.finished_at,
        })
        .collect();
    StackDeployment {
        name: details.name,
        status: details.status,
        moved,
        location,
        deployments,
        more_deployments,
        can_operate: false,
        can_remove: false,
        can_destroy: false,
        last_action: None,
    }
}

fn target_allowed(targets: &EffectiveTargets, target: &StackTarget) -> bool {
    match targets {
        EffectiveTargets::Allowed(allowed) => allowed.iter().any(|(t, _)| t == target),
        EffectiveTargets::Default(DefaultTarget::Placement { target: t, .. }) => t == target,
        EffectiveTargets::Default(_) => false,
    }
}

/// Runs provisioning jobs.
pub struct ProvisionStackHandler {
    db: Database,
    cipher: Option<CredentialCipher>,
    dokploy: Arc<DokployService>,
    compose: Arc<dyn ComposeApi>,
    probe: Arc<dyn StackProbe>,
    timings: ProvisionTimings,
}

impl ProvisionStackHandler {
    pub fn new(
        db: Database,
        cipher: Option<CredentialCipher>,
        dokploy: Arc<DokployService>,
        compose: Arc<dyn ComposeApi>,
        probe: Arc<dyn StackProbe>,
    ) -> Self {
        Self {
            db,
            cipher,
            dokploy,
            compose,
            probe,
            timings: ProvisionTimings::default(),
        }
    }

    #[must_use]
    pub fn with_timings(mut self, timings: ProvisionTimings) -> Self {
        self.timings = timings;
        self
    }
}

impl JobHandler for ProvisionStackHandler {
    fn kind(&self) -> JobKind {
        JobKind::ProvisionStack
    }

    fn run_step<'a>(&'a self, job: &'a ClaimedJob) -> StepFuture<'a> {
        Box::pin(async move {
            let mut data: JobData = match serde_json::from_value(job.data.clone()) {
                Ok(data) => data,
                Err(_) => {
                    return StepOutcome::Fail {
                        data: job.data.clone(),
                        message: "The job's saved state could not be read.".to_owned(),
                    };
                }
            };
            let result = Step { handler: self, job }.run(&mut data).await;
            let value = serde_json::to_value(&data).unwrap_or_else(|_| job.data.clone());
            match result {
                Ok(Then::Next(step)) => StepOutcome::Next { step, data: value },
                Ok(Then::Wait(step, after, message)) => StepOutcome::Wait {
                    step,
                    data: value,
                    after,
                    message,
                },
                Ok(Then::Succeed(message)) => StepOutcome::Succeed {
                    data: value,
                    message: Some(message),
                },
                Err(Stop::Fail(message)) => StepOutcome::Fail {
                    data: value,
                    message,
                },
                Err(Stop::Unanswered(err)) => {
                    data.transient_errors = data.transient_errors.saturating_add(1);
                    let value = serde_json::to_value(&data).unwrap_or_else(|_| job.data.clone());
                    let max = self.timings.max_transient_errors;
                    if data.transient_errors > max {
                        StepOutcome::Fail {
                            data: value,
                            message: format!(
                                "Dokploy did not answer {max} times in a row at step {}: {err}. What the job made so far stays in Dokploy.",
                                job.step
                            ),
                        }
                    } else {
                        StepOutcome::Wait {
                            step: step_name(&job.step),
                            data: value,
                            after: self.timings.transient_retry,
                            message: Some(format!("Dokploy did not answer ({err}); trying again.")),
                        }
                    }
                }
            }
        })
    }
}

/// The saved step name, as `&'static str` for [`StepOutcome`].
fn step_name(step: &str) -> &'static str {
    ProvisionStep::parse(step).map_or("check", ProvisionStep::as_str)
}

enum Then {
    Next(&'static str),
    Wait(&'static str, Duration, Option<String>),
    Succeed(String),
}

enum Stop {
    Fail(String),
    /// Dokploy did not answer, or answered with an error of its own. The
    /// step runs again later.
    Unanswered(DokployError),
}

impl From<DokployError> for Stop {
    fn from(err: DokployError) -> Self {
        if is_transient(&err) {
            Self::Unanswered(err)
        } else if matches!(err, DokployError::KeyRejected) {
            Self::Fail(
                "Dokploy refused the dashboard's key, or the key may not use the chosen server. \
                 What the job made so far stays in Dokploy."
                    .to_owned(),
            )
        } else {
            Self::Fail(format!(
                "Dokploy refused a request: {err}. What the job made so far stays in Dokploy."
            ))
        }
    }
}

fn internal(context: &str, err: impl std::fmt::Display) -> Stop {
    tracing::error!(error = %err, context, "provisioning step failed");
    Stop::Fail(format!(
        "The dashboard could not {context}. See the server log."
    ))
}

struct Step<'a> {
    handler: &'a ProvisionStackHandler,
    job: &'a ClaimedJob,
}

impl Step<'_> {
    async fn run(&self, data: &mut JobData) -> Result<Then, Stop> {
        let then = match self.job.step.as_str() {
            "check" => self.check(data).await?,
            "create_service" => self.create_service(data).await?,
            "configure" => self.configure(data).await?,
            "mounts" => self.mounts(data).await?,
            "domain" => self.domain(data).await?,
            "deploy" => self.deploy(data).await?,
            "wait_deploy" => self.wait_deploy(data).await?,
            "register" => self.register(data).await?,
            "health" => self.health(data).await?,
            other => return Err(Stop::Fail(format!("Unknown step {other}."))),
        };
        // A step that went through clears the run of unanswered calls.
        data.transient_errors = 0;
        Ok(then)
    }

    fn handler(&self) -> &ProvisionStackHandler {
        self.handler
    }

    /// The operator who queued the job may still register projects in
    /// the organization.
    async fn authorize(&self) -> Result<(), Stop> {
        let Some(account) = self.job.created_by else {
            return Err(Stop::Fail(
                "The account that asked for this stack no longer exists.".to_owned(),
            ));
        };
        let db = &self.handler().db;
        let active = db
            .account_is_active(account)
            .await
            .map_err(|err| internal("check the operator's account", err))?;
        let membership = db
            .find_membership(self.job.organization_id, account)
            .await
            .map_err(|err| internal("check the operator's role", err))?;
        match membership {
            Some(m) if active && m.role.allows(Permission::ProjectRegister) => Ok(()),
            _ => Err(Stop::Fail(
                "The account that asked for this stack may no longer create projects in this organization."
                    .to_owned(),
            )),
        }
    }

    async fn dokploy(&self) -> Result<(DokployUrl, SecretString), Stop> {
        match self.handler().dokploy.credentials().await {
            Ok(Some(credentials)) => Ok((credentials.url, credentials.key)),
            Ok(None) => Err(Stop::Fail(
                "Dokploy is no longer connected. What the job made so far stays in Dokploy."
                    .to_owned(),
            )),
            Err(err) => Err(internal("read the Dokploy connection", err)),
        }
    }

    async fn secrets(&self) -> Result<StackSecrets, Stop> {
        let cipher = self.handler().cipher.as_ref().ok_or_else(|| {
            Stop::Fail("The server has no credential key to open the stack's secrets.".to_owned())
        })?;
        let sealed = self
            .handler()
            .db
            .job_secrets(self.job.id)
            .await
            .map_err(|err| internal("read the stack's secrets", err))?
            .ok_or_else(|| Stop::Fail("The stack's secrets are gone.".to_owned()))?;
        let json = cipher
            .open_job_secrets(
                self.job.id,
                &Sealed {
                    key_id: sealed.key_id,
                    nonce: sealed.nonce,
                    ciphertext: sealed.ciphertext,
                },
            )
            .map_err(|err| internal("open the stack's secrets", err))?;
        StackSecrets::from_json(&json)
            .ok_or_else(|| internal("read the stack's secrets", "malformed"))
    }

    fn compose_id(data: &JobData) -> Result<DokployId, Stop> {
        data.compose_id
            .as_deref()
            .and_then(|id| DokployId::parse(id).ok())
            .ok_or_else(|| Stop::Fail("The job lost its Dokploy service ID.".to_owned()))
    }

    fn environment_id(data: &JobData) -> Result<DokployId, Stop> {
        DokployId::parse(&data.environment_id)
            .map_err(|_| Stop::Fail("The job's environment ID is not valid.".to_owned()))
    }

    async fn check(&self, data: &mut JobData) -> Result<Then, Stop> {
        self.authorize().await?;
        let targets = self
            .handler()
            .dokploy
            .organization_targets(self.job.organization_id)
            .await
            .map_err(|err| match err {
                DokployServiceError::NotConnected => {
                    Stop::Fail("Dokploy is no longer connected.".to_owned())
                }
                other => internal("read the organization's targets", other),
            })?;
        let target = StackTarget {
            environment_id: Self::environment_id(data)?,
            server_id: match data.server_id.as_deref() {
                Some(id) => Some(
                    DokployId::parse(id)
                        .map_err(|_| Stop::Fail("The job's server ID is not valid.".to_owned()))?,
                ),
                None => None,
            },
        };
        if !target_allowed(&targets, &target) {
            return Err(Stop::Fail(
                "This organization may no longer create stacks in the chosen environment."
                    .to_owned(),
            ));
        }
        Ok(Then::Next("create_service"))
    }

    async fn create_service(&self, data: &mut JobData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let environment = Self::environment_id(data)?;
        let api = &self.handler().compose;
        let found = api
            .find_compose(&url, &key, &environment, &data.compose_name)
            .await?;
        let service = match found.as_slice() {
            [service] => service.clone(),
            [] => {
                let server =
                    match data.server_id.as_deref() {
                        Some(id) => Some(DokployId::parse(id).map_err(|_| {
                            Stop::Fail("The job's server ID is not valid.".to_owned())
                        })?),
                        None => None,
                    };
                // Points back to the dashboard project the stack will be
                // registered as, whose ID is fixed when the job is queued.
                let description = format!(
                    "Supabase stack {}, project {} in supabase-dashboard",
                    data.name, data.project_id
                );
                api.create_compose(
                    &url,
                    &key,
                    &NewCompose {
                        environment_id: &environment,
                        server_id: server.as_ref(),
                        name: &data.compose_name,
                        description: &description,
                        compose_file: COMPOSE_FILE,
                    },
                )
                .await?
            }
            _ => {
                return Err(Stop::Fail(format!(
                    "Dokploy has more than one service named {}; remove the extra ones and start again.",
                    data.compose_name
                )));
            }
        };
        data.compose_id = Some(service.compose_id.as_str().to_owned());
        data.app_name = Some(service.app_name);
        Ok(Then::Next("configure"))
    }

    async fn configure(&self, data: &mut JobData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let secrets = self.secrets().await?;
        let env = stack_env(&secrets, &data.public_url())
            .map_err(|err| internal("build the stack's variables", err))?;
        self.handler()
            .compose
            .configure_compose(&url, &key, &compose, COMPOSE_FILE, &env)
            .await?;
        Ok(Then::Next("mounts"))
    }

    async fn mounts(&self, data: &mut JobData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let api = &self.handler().compose;
        let existing = api.file_mounts(&url, &key, &compose).await?;
        for file in STACK_FILES {
            let matching: Vec<_> = existing
                .iter()
                .filter(|mount| mount.file_path == file.path)
                .collect();
            match matching.as_slice() {
                [] => {
                    api.create_file_mount(&url, &key, &compose, file.path, file.content)
                        .await?;
                }
                [mount] if mount.content != file.content => {
                    api.update_file_mount(&url, &key, &mount.mount_id, file.content)
                        .await?;
                }
                [_] => {}
                _ => {
                    return Err(Stop::Fail(format!(
                        "The Dokploy service has more than one file mount at {}; remove the extra ones and start again.",
                        file.path
                    )));
                }
            }
        }
        Ok(Then::Next("domain"))
    }

    async fn domain(&self, data: &mut JobData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let api = &self.handler().compose;
        let domains = api.compose_domains(&url, &key, &compose).await?;
        if !domains.iter().any(|d| d.host == data.host) {
            api.create_compose_domain(
                &url,
                &key,
                &compose,
                &NewComposeDomain {
                    host: &data.host,
                    service_name: GATEWAY_SERVICE,
                    port: GATEWAY_PORT,
                    https: data.https,
                },
            )
            .await?;
        }
        Ok(Then::Next("deploy"))
    }

    async fn deploy(&self, data: &mut JobData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let api = &self.handler().compose;
        let title = JobData::deploy_title(self.job.id);
        let deployments = api.deployments(&url, &key, &compose).await?;
        let started = deployments
            .iter()
            .any(|d| d.title.as_deref() == Some(title.as_str()));
        if !started && data.deploy_requested_at.is_none() {
            // Recorded first: if the answer is lost, the job waits for the
            // title instead of asking again.
            data.deploy_requested_at = Some(time::OffsetDateTime::now_utc().unix_timestamp());
            if let Err(err) = api.deploy_compose(&url, &key, &compose, &title).await {
                if !is_transient(&err) {
                    return Err(err.into());
                }
                tracing::warn!(error = %err, job = %self.job.id, "deployment request unanswered");
            }
        }
        Ok(Then::Wait(
            "wait_deploy",
            self.handler.timings.deploy_poll,
            Some("Deploying the stack.".to_owned()),
        ))
    }

    async fn wait_deploy(&self, data: &mut JobData) -> Result<Then, Stop> {
        let (url, key) = self.dokploy().await?;
        let compose = Self::compose_id(data)?;
        let title = JobData::deploy_title(self.job.id);
        let deployments = self
            .handler()
            .compose
            .deployments(&url, &key, &compose)
            .await?;
        let status = deployments
            .iter()
            .find(|d| d.title.as_deref() == Some(title.as_str()))
            .map(|d| d.status);
        let elapsed = data.deploy_requested_at.map_or(0, |at| {
            time::OffsetDateTime::now_utc().unix_timestamp() - at
        });
        let deadline =
            i64::try_from(self.handler.timings.deploy_deadline.as_secs()).unwrap_or(i64::MAX);
        match status {
            Some(DeploymentStatus::Done) => Ok(Then::Next("register")),
            Some(DeploymentStatus::Error) => Err(Stop::Fail(
                "The deployment failed. Its log in Dokploy says why; the service stays in Dokploy."
                    .to_owned(),
            )),
            Some(DeploymentStatus::Cancelled) => Err(Stop::Fail(
                "The deployment was cancelled in Dokploy; the service stays there.".to_owned(),
            )),
            _ if elapsed > deadline => Err(Stop::Fail(if status.is_none() {
                "Dokploy did not start the deployment in time. Deploy the service from Dokploy, then register the project.".to_owned()
            } else {
                "The deployment ran longer than the job waits. Check it in Dokploy.".to_owned()
            })),
            None => Ok(Then::Wait(
                "wait_deploy",
                self.handler.timings.deploy_poll,
                Some("Waiting for Dokploy to start the deployment.".to_owned()),
            )),
            Some(DeploymentStatus::Running) => Ok(Then::Wait(
                "wait_deploy",
                self.handler.timings.deploy_poll,
                Some("Deploying the stack.".to_owned()),
            )),
        }
    }

    async fn register(&self, data: &mut JobData) -> Result<Then, Stop> {
        self.authorize().await?;
        let handler = self.handler();
        let cipher = handler.cipher.as_ref().ok_or_else(|| {
            Stop::Fail("The server has no credential key to store the stack's keys.".to_owned())
        })?;
        let secrets = self.secrets().await?;
        let account = self.job.created_by.ok_or_else(|| {
            Stop::Fail("The account that asked for this stack no longer exists.".to_owned())
        })?;
        let name = ProjectName::parse(&data.name)
            .map_err(|_| Stop::Fail("The project name is no longer valid.".to_owned()))?;
        let api_url = ProjectUrl::parse(&data.public_url())
            .map_err(|_| Stop::Fail("The stack's URL is not valid.".to_owned()))?;
        let login = check_studio_login(STUDIO_USERNAME, secrets.studio_password.expose_secret())
            .map_err(|err| internal("check the Studio login", err))?;
        let project_id = data.project_id;
        // What the configure step wrote, to tell edits made in Dokploy.
        let written = stack_env(&secrets, &data.public_url())
            .map_err(|err| internal("build the stack's variables", err))?;
        let env_record = env_record::EnvRecord::of(&EnvFile::parse(written.expose_secret()))
            .seal(cipher, project_id)
            .map_err(|err| internal("encrypt the stack's variable record", err))?;
        let values = [
            (CredentialKind::AnonKey, secrets.anon_key),
            (CredentialKind::ServiceRoleKey, secrets.service_role_key),
            (CredentialKind::StudioLogin, SecretString::from(login)),
        ];
        let sealed = values
            .iter()
            .map(|(kind, value)| Ok((*kind, cipher.seal(project_id, *kind, value)?)))
            .collect::<Result<Vec<_>, CipherError>>()
            .map_err(|err| internal("encrypt the stack's keys", err))?;
        let credentials: Vec<NewCredential<'_>> = sealed
            .iter()
            .map(|(kind, sealed)| NewCredential {
                project_id,
                kind: *kind,
                key_id: &sealed.key_id,
                nonce: &sealed.nonce,
                ciphertext: &sealed.ciphertext,
                updated_by: account,
            })
            .collect();
        let compose_id = data
            .compose_id
            .clone()
            .ok_or_else(|| Stop::Fail("The job lost its Dokploy service ID.".to_owned()))?;
        let app_name = data.app_name.clone().unwrap_or_default();
        let outcome = handler
            .db
            .register_provisioned_project(
                &NewProject {
                    id: project_id,
                    organization_id: self.job.organization_id,
                    name: &name,
                    api_url: &api_url,
                    created_by: account,
                },
                &NewDokployService {
                    compose_id: &compose_id,
                    app_name: &app_name,
                    environment_id: &data.environment_id,
                    server_id: data.server_id.as_deref(),
                    job_id: self.job.id,
                    env_record: Some(&env_record),
                },
                &credentials,
                MAX_PROJECTS_PER_ORGANIZATION,
                &AuditEvent {
                    actor_account_id: Some(account),
                    action: "project.provisioned",
                    target_type: Some("project"),
                    target_id: Some(project_id.to_string()),
                    outcome: AuditOutcome::Success,
                    request_id: None,
                },
            )
            .await
            .map_err(|err| internal("register the project", err))?;
        match outcome {
            RegisterProvisionedOutcome::Created | RegisterProvisionedOutcome::AlreadyRegistered => {
                Ok(Then::Next("health"))
            }
            RegisterProvisionedOutcome::OrganizationNotFound => Err(Stop::Fail(
                "The organization was deleted. The stack stays in Dokploy.".to_owned(),
            )),
            RegisterProvisionedOutcome::LimitReached => Err(Stop::Fail(
                "The organization reached its project limit. The stack stays in Dokploy; register it once there is room."
                    .to_owned(),
            )),
        }
    }

    async fn health(&self, data: &mut JobData) -> Result<Then, Stop> {
        let secrets = self.secrets().await?;
        let api_url = ProjectUrl::parse(&data.public_url())
            .map_err(|_| Stop::Fail("The stack's URL is not valid.".to_owned()))?;
        let check = self
            .handler()
            .probe
            .check(&api_url, StackService::Auth, &secrets.anon_key, None)
            .await;
        if check.status == ServiceStatus::Healthy {
            return Ok(Then::Succeed(
                "The stack is running and registered.".to_owned(),
            ));
        }
        data.health_attempts = data.health_attempts.saturating_add(1);
        if data.health_attempts >= self.handler.timings.health_attempts {
            return Ok(Then::Succeed(format!(
                "The stack is deployed and registered, but {} did not answer yet. Check that its DNS points at the Dokploy server, then run a health check from the project.",
                api_url.as_str()
            )));
        }
        Ok(Then::Wait(
            "health",
            self.handler.timings.health_poll,
            Some(format!("Waiting for {} to answer.", api_url.as_str())),
        ))
    }
}
