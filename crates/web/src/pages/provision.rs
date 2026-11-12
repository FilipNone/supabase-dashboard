//! Creating a new stack through Dokploy, and following its progress.
//!
//! The form only queues a job; the server checks the role, the name, the
//! host, and the target again, and the job runs on the server. The job
//! page reloads the job every few seconds until it finishes.

use std::time::Duration;

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use leptos_router::hooks::use_navigate;
use supabase_dashboard_domain::{
    authz::Permission,
    dokploy_compose::STACK_HOST_MAX_LEN,
    job::JobState,
    project::PROJECT_NAME_MAX_CHARS,
    provisioning::{ProvisionJobSummary, ProvisionStep, ProvisionTargets, TargetChoice},
};
use uuid::Uuid;

use crate::{
    components::{
        layout::Refresh,
        page::{PageHeader, StatePanel, StateTone},
    },
    error::AppError,
    pages::{
        account::utc_minutes,
        project::{action_error, org_path, param_uuid, project_path},
    },
    server_fns::{
        StartProvisioning, get_organization, get_provision_job, get_provision_targets,
        list_provision_jobs,
    },
};

/// How often an unfinished job is reloaded.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The page that creates a stack in an organization.
pub fn new_stack_path(organization_id: Uuid) -> String {
    format!("/dashboard/new/{organization_id}/stack")
}

/// The progress page of a provisioning job.
pub fn provision_job_path(organization_id: Uuid, job_id: Uuid) -> String {
    format!("/dashboard/org/{organization_id}/provisioning/{job_id}")
}

/// `/dashboard/new/:org_id/stack`: create a new stack through Dokploy.
#[component]
pub fn NewStackPage() -> impl IntoView {
    let org_id = param_uuid("org_id");
    let org = Resource::new(
        move || org_id.get(),
        |id| async move {
            match id {
                Some(id) => get_organization(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    let targets = Resource::new(
        move || org_id.get(),
        |id| async move {
            match id {
                Some(id) => get_provision_targets(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    let start = ServerAction::<StartProvisioning>::new();
    let navigate = use_navigate();
    Effect::new(move |_| {
        if let (Some(Ok(job_id)), Some(org)) = (start.value().get(), org_id.get_untracked()) {
            navigate(&provision_job_path(org, job_id), Default::default());
        }
    });

    view! {
        <Title text="Create a new stack"/>
        <PageHeader
            title="Create a new stack"
            description="Deploy a new self-hosted Supabase stack through Dokploy. The dashboard generates its passwords and keys, deploys the stack, and registers it as a project in this organization."
        />
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading organization…"</p> }>
            {move || {
                org.get().map(|result| match result {
                    Ok(org) if !org.role.allows(Permission::ProjectRegister) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="You cannot create stacks here".to_string()
                            detail=format!(
                                "Only owners and administrators of {} can create stacks.",
                                org.name.as_str()
                            )
                        />
                        <p><a href=org_path(org.id)>"Back to the organization"</a></p>
                    }
                    .into_any(),
                    Ok(org) => {
                        let id = org.id;
                        let heading = format!("New stack in {}", org.name.as_str());
                        view! {
                            <section class="panel" aria-labelledby="new-stack-title">
                                <h2 class="section-title" id="new-stack-title">{heading}</h2>
                                {move || targets.get().map(|result| match result {
                                    Ok(ProvisionTargets::Choices(choices)) if !choices.is_empty() => {
                                        view! { <NewStackForm organization_id=id choices start/> }.into_any()
                                    }
                                    Ok(other) => no_targets(&other).into_any(),
                                    Err(err) => view! {
                                        <StatePanel
                                            tone=StateTone::Error
                                            title="Could not load where stacks can go".to_string()
                                            detail=err.to_string()
                                        />
                                    }
                                    .into_any(),
                                })}
                            </section>
                            <p><a href=org_path(id)>"Back to the organization"</a></p>
                        }
                        .into_any()
                    }
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Organization unavailable".to_string()
                            detail=err.to_string()
                        />
                        <p><a href="/dashboard/organizations">"Back to organizations"</a></p>
                    }
                    .into_any(),
                })
            }}
        </Transition>
    }
}

/// Why no stack can be created now, and who can change that.
fn no_targets(targets: &ProvisionTargets) -> impl IntoView + use<> {
    let (title, detail) = match targets {
        ProvisionTargets::NotConnected => (
            "Dokploy is not connected",
            "This dashboard creates stacks through Dokploy. Ask an installation administrator to connect Dokploy on the administrator page.",
        ),
        ProvisionTargets::Unavailable => (
            "Dokploy could not be reached",
            "The dashboard could not read where this organization's stacks go. Try again shortly, or ask an installation administrator to check the Dokploy connection.",
        ),
        ProvisionTargets::NoTarget | ProvisionTargets::Choices(_) => (
            "No place to create stacks",
            "No Dokploy environment is allowed for this organization. Ask an installation administrator to allow one on the administrator page.",
        ),
    };
    view! {
        <StatePanel tone=StateTone::Empty title=title.to_string() detail=detail.to_string()/>
    }
}

#[component]
fn NewStackForm(
    organization_id: Uuid,
    choices: Vec<TargetChoice>,
    start: ServerAction<StartProvisioning>,
) -> impl IntoView {
    let https = RwSignal::new(true);
    let options = choices
        .into_iter()
        .map(|choice| view! { <option value=choice.value>{choice.label}</option> })
        .collect_view();
    view! {
        <ActionForm action=start attr:class="stacked-form">
            <input type="hidden" name="organization_id" value=organization_id.to_string()/>
            <label class="field">
                <span class="field-label">"Project name"</span>
                <input
                    class="input" name="name" required autocomplete="off"
                    maxlength=PROJECT_NAME_MAX_CHARS.to_string()
                />
            </label>
            <label class="field">
                <span class="field-label">"Dokploy environment"</span>
                <select class="input" name="target" required aria-describedby="stack-target-hint">
                    {options}
                </select>
                <span class="field-hint" id="stack-target-hint">
                    "Where the stack runs, as an installation administrator allowed for this organization."
                </span>
            </label>
            <label class="field">
                <span class="field-label">"Host name"</span>
                <input
                    class="input url-text" name="host" required autocomplete="off"
                    spellcheck="false" autocapitalize="none" inputmode="url"
                    placeholder="supabase.example.com"
                    maxlength=STACK_HOST_MAX_LEN.to_string()
                    aria-describedby="stack-host-hint"
                />
                <span class="field-hint" id="stack-host-hint">
                    "The stack's public address, without https:// or a path. Its DNS record must point at the Dokploy server, which routes it to the stack's gateway."
                </span>
            </label>
            <label class="checkbox-field">
                <input
                    type="checkbox" name="https" value="true" checked
                    aria-describedby="stack-https-warning"
                    on:change=move |ev| https.set(event_target_checked(&ev))
                />
                <span>"Serve the stack over HTTPS with a Let's Encrypt certificate"</span>
            </label>
            <div id="stack-https-warning" aria-live="polite">
                {move || (!https.get()).then(|| view! {
                    <div class="form-warning">
                        <p>
                            "Without HTTPS, the stack's API keys, the Studio password, and your users' sessions travel in plain text. Use plain HTTP only on a network you trust."
                        </p>
                    </div>
                })}
            </div>
            <div class="form-warning">
                <p>
                    "Dokploy keeps the stack's variables, including its database password, JWT secret, and API keys, in its own database. Anyone with access to this service in Dokploy can read them."
                </p>
            </div>
            <div>
                <button type="submit" class="button button-primary" disabled=move || start.pending().get()>
                    {move || if start.pending().get() { "Creating…" } else { "Create stack" }}
                </button>
            </div>
        </ActionForm>
        {move || action_error(start.value().get())}
    }
}

/// Where one step of a job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepStatus {
    Done,
    Current,
    Failed,
    Pending,
    NotRun,
}

impl StepStatus {
    fn badge(self) -> (&'static str, &'static str) {
        match self {
            Self::Done => ("badge badge-ok", "Done"),
            Self::Current => ("badge badge-current", "In progress"),
            Self::Failed => ("badge badge-error", "Failed"),
            Self::Pending => ("badge badge-muted", "Pending"),
            Self::NotRun => ("badge badge-muted", "Not run"),
        }
    }
}

/// Each step of the job in order, with where it stands. A job stays at
/// the step it finished or failed on. A step this version does not know
/// marks nothing as done.
fn step_statuses(job: &ProvisionJobSummary) -> Vec<(ProvisionStep, StepStatus)> {
    let current = job
        .step
        .and_then(|step| ProvisionStep::ALL.iter().position(|s| *s == step));
    ProvisionStep::ALL
        .into_iter()
        .enumerate()
        .map(|(i, step)| {
            let status = match (job.state, current) {
                (JobState::Succeeded, _) => StepStatus::Done,
                (JobState::Failed, Some(c)) if i < c => StepStatus::Done,
                (JobState::Failed, Some(c)) if i == c => StepStatus::Failed,
                (JobState::Failed, _) => StepStatus::NotRun,
                (_, Some(c)) if i < c => StepStatus::Done,
                (_, Some(c)) if i == c => StepStatus::Current,
                _ => StepStatus::Pending,
            };
            (step, status)
        })
        .collect()
}

/// The job's state as a badge.
fn job_badge(job: &ProvisionJobSummary) -> (&'static str, &'static str) {
    match job.state {
        JobState::Queued if job.step == Some(ProvisionStep::Check) => {
            ("badge badge-muted", "Waiting to start")
        }
        JobState::Queued | JobState::Running => ("badge badge-current", "In progress"),
        JobState::Succeeded => ("badge badge-ok", "Created"),
        JobState::Failed => ("badge badge-error", "Failed"),
    }
}

/// Calls `tick` every `interval` in the browser until it returns false or
/// the current owner is cleaned up. Effects run only in the browser, so
/// server rendering starts nothing. The handle is kept in thread-safe
/// storage: on the server the owner can be cleaned up on another thread
/// than the one that rendered it, where local storage would panic.
fn poll_every(interval: Duration, tick: impl Fn() -> bool + 'static) {
    let poll = StoredValue::new(None::<IntervalHandle>);
    let stop = move || {
        if let Some(handle) = poll.try_update_value(Option::take).flatten() {
            handle.clear();
        }
    };
    // The effect reads no signal, so it runs once.
    let mut tick = Some(tick);
    Effect::new(move |_| {
        if let Some(tick) = tick.take() {
            let handle = set_interval_with_handle(
                move || {
                    if !tick() {
                        stop();
                    }
                },
                interval,
            );
            poll.set_value(handle.ok());
        }
    });
    on_cleanup(stop);
}

/// `/dashboard/org/:org_id/provisioning/:job_id`: the progress of one
/// provisioning job. A malformed ID, an unknown job, and one in another
/// organization all show the same not-found state.
#[component]
pub fn ProvisionJobPage() -> impl IntoView {
    let org_id = param_uuid("org_id");
    let job_id = param_uuid("job_id");
    let job = Resource::new(
        move || (org_id.get(), job_id.get()),
        |(org_id, job_id)| async move {
            match (org_id, job_id) {
                (Some(org_id), Some(job_id)) => get_provision_job(job_id).await.and_then(|job| {
                    if job.organization_id == org_id {
                        Ok(job)
                    } else {
                        Err(AppError::NotFound)
                    }
                }),
                _ => Err(AppError::NotFound),
            }
        },
    );
    poll_every(POLL_INTERVAL, move || {
        let keep_polling = match job.get_untracked() {
            Some(Ok(job)) => !job.state.is_finished(),
            Some(Err(AppError::Unavailable | AppError::Transport)) | None => true,
            Some(Err(_)) => false,
        };
        if keep_polling {
            job.refetch();
        }
        keep_polling
    });
    // The project menu lists the new project once the job registered it.
    let refresh = use_context::<Refresh>();
    Effect::new(move |registered: Option<bool>| {
        let now = job
            .get()
            .and_then(Result::ok)
            .is_some_and(|job| job.project_id.is_some());
        if now
            && registered == Some(false)
            && let Some(refresh) = refresh
        {
            refresh.projects_changed();
        }
        now
    });

    view! {
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading the new stack…"</p> }>
            {move || {
                job.get().map(|result| match result {
                    Ok(job) => view! { <ProvisionJobView job/> }.into_any(),
                    Err(err) => {
                        let title = match err {
                            AppError::Forbidden => "You cannot see this stack",
                            _ => "New stack unavailable",
                        };
                        view! {
                            <Title text="New stack"/>
                            <StatePanel
                                tone=StateTone::Error
                                title=title.to_string()
                                detail=err.to_string()
                            />
                        }
                        .into_any()
                    }
                })
            }}
        </Transition>
    }
}

#[component]
fn ProvisionJobView(job: ProvisionJobSummary) -> impl IntoView {
    let (badge_class, badge_label) = job_badge(&job);
    let steps = step_statuses(&job)
        .into_iter()
        .map(|(step, status)| {
            let (class, label) = status.badge();
            let current = (status == StepStatus::Current).then_some("step");
            view! {
                <li class="job-step" aria-current=current>
                    <span class=class>{label}</span>
                    <span class="job-step-label">{step.label()}</span>
                </li>
            }
        })
        .collect_view();
    // A finished job's message is a failure or something left to do; an
    // unfinished job's says what it is waiting for.
    let message = job.message.clone().map(|text| match job.state {
        JobState::Failed => view! { <p class="form-error" role="alert">{text}</p> }.into_any(),
        JobState::Succeeded => view! {
            <div class="form-warning" role="status"><p>{text}</p></div>
        }
        .into_any(),
        JobState::Queued | JobState::Running => {
            view! { <p class="form-note" role="status">{text}</p> }.into_any()
        }
    });
    let unknown_step = (job.step.is_none() && !job.state.is_finished()).then(|| {
        view! {
            <p class="field-hint">"The job is at a step this version of the dashboard does not know."</p>
        }
    });
    let project = job.project_id.map(|project_id| {
        view! {
            <p>
                <a class="button button-primary" href=project_path(job.organization_id, project_id)>
                    "Go to the project"
                </a>
            </p>
        }
    });
    let refreshing = (!job.state.is_finished()).then(|| {
        view! {
            <p class="field-hint">
                "This page refreshes every few seconds until the job finishes. You can leave it; the job keeps running on the server."
            </p>
        }
    });
    let finished = job.finished_at.map(|at| {
        view! {
            <div><dt>"Finished"</dt><dd>{format!("{} UTC", utc_minutes(at))}</dd></div>
        }
    });
    view! {
        <Title text=job.name.clone()/>
        <section class="panel" aria-labelledby="job-title">
            <div class="section-header">
                <h2 class="section-title" id="job-title">{format!("New stack: {}", job.name)}</h2>
                <span class=badge_class>{badge_label}</span>
            </div>
            <dl class="detail-list">
                <div><dt>"Address"</dt><dd class="url-text">{job.public_url()}</dd></div>
                <div><dt>"Started"</dt><dd>{format!("{} UTC", utc_minutes(job.created_at))}</dd></div>
                {finished}
            </dl>
            <h3 class="subsection-title" id="job-steps-title">"Steps"</h3>
            <ol class="job-steps" aria-labelledby="job-steps-title">{steps}</ol>
            {unknown_step}
            {message}
            {refreshing}
            {project}
        </section>
    }
}

/// The organization's latest provisioning jobs, on its projects page.
/// Nothing shows while they load or when there are none.
#[component]
pub fn RecentStacks(organization_id: Memo<Option<Uuid>>) -> impl IntoView {
    let jobs = Resource::new(
        move || organization_id.get(),
        |id| async move {
            match id {
                Some(id) => list_provision_jobs(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    view! {
        <Transition fallback=|| ()>
            {move || {
                jobs.get().map(|result| match result {
                    Ok(list) if list.is_empty() => ().into_any(),
                    Ok(list) => view! { <RecentStacksTable list/> }.into_any(),
                    Err(err) => view! {
                        <p class="form-error page-notice" role="alert">
                            {format!("New stacks could not be loaded: {err}")}
                        </p>
                    }
                    .into_any(),
                })
            }}
        </Transition>
    }
}

#[component]
fn RecentStacksTable(list: Vec<ProvisionJobSummary>) -> impl IntoView {
    let rows = list
        .into_iter()
        .map(|job| {
            let (class, label) = job_badge(&job);
            let href = provision_job_path(job.organization_id, job.id);
            view! {
                <tr>
                    <td><a href=href>{job.name.clone()}</a></td>
                    <td class="url-text">{job.host.clone()}</td>
                    <td><span class=class>{label}</span></td>
                    <td class="nowrap">{format!("{} UTC", utc_minutes(job.created_at))}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <section class="recent-stacks" aria-labelledby="recent-stacks-title">
            <h2 class="section-title" id="recent-stacks-title">"New stacks"</h2>
            <div class="table-wrap">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th scope="col">"Name"</th>
                            <th scope="col">"Host"</th>
                            <th scope="col">"State"</th>
                            <th scope="col">"Started"</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;

    fn job(state: JobState, step: Option<ProvisionStep>) -> ProvisionJobSummary {
        ProvisionJobSummary {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            name: "Synthetic".into(),
            host: "synthetic.example.test".into(),
            https: true,
            state,
            step,
            message: None,
            project_id: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            finished_at: None,
        }
    }

    fn statuses(state: JobState, step: Option<ProvisionStep>) -> Vec<StepStatus> {
        step_statuses(&job(state, step))
            .into_iter()
            .map(|(_, status)| status)
            .collect()
    }

    #[test]
    fn steps_before_the_current_one_are_done() {
        use StepStatus::*;
        assert_eq!(
            statuses(JobState::Running, Some(ProvisionStep::Mounts)),
            [
                Done, Done, Done, Current, Pending, Pending, Pending, Pending, Pending
            ]
        );
        assert_eq!(
            statuses(JobState::Queued, Some(ProvisionStep::Check))[0],
            Current
        );
    }

    #[test]
    fn a_failed_step_is_marked_and_later_ones_did_not_run() {
        use StepStatus::*;
        assert_eq!(
            statuses(JobState::Failed, Some(ProvisionStep::WaitDeploy)),
            [Done, Done, Done, Done, Done, Done, Failed, NotRun, NotRun]
        );
        assert!(
            statuses(JobState::Failed, None)
                .iter()
                .all(|s| *s == NotRun)
        );
    }

    #[test]
    fn a_finished_job_has_every_step_done() {
        assert!(
            statuses(JobState::Succeeded, Some(ProvisionStep::Health))
                .iter()
                .all(|s| *s == StepStatus::Done)
        );
    }

    /// Regression: the server can clean up a page's owner on another
    /// thread than the one that rendered it. Polling state kept in local
    /// storage panicked there and left the page loading forever.
    #[test]
    fn polling_cleans_up_on_another_thread() {
        let owner = Owner::new();
        owner.with(|| poll_every(POLL_INTERVAL, || true));
        let cleanup = std::thread::spawn(move || owner.cleanup());
        assert!(cleanup.join().is_ok());
    }

    #[test]
    fn an_unknown_step_marks_nothing_done() {
        assert!(
            statuses(JobState::Running, None)
                .iter()
                .all(|s| *s == StepStatus::Pending)
        );
    }
}
