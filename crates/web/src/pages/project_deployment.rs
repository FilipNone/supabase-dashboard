//! The Dokploy service behind a project the dashboard provisioned, on the
//! project overview.
//!
//! Dokploy is asked each time the page loads, so a redeploy, a move, or a
//! deletion made in Dokploy shows here instead of being overwritten. The
//! panel is left out for projects that were registered, not provisioned.
//! Owners and admins can stop, start, and redeploy the service from here;
//! while such an action runs, the panel polls until it finishes.

use std::time::Duration;

use leptos::{form::ActionForm, prelude::*};

use supabase_dashboard_domain::{
    dokploy_compose::{ComposeStatus, DeploymentStatus},
    job::JobState,
    project::ProjectSummary,
    provisioning::{
        StackAction, StackActionSummary, StackDeployment, StackDeploymentRun, StackDeploymentView,
        StackLocation,
    },
};

use crate::{
    components::page::{StatePanel, StateTone},
    pages::{account::utc_minutes, provision::poll_every},
    server_fns::{QueueStackAction, get_project_deployment},
};

/// How often the panel asks again while an action runs.
const ACTION_POLL: Duration = Duration::from_secs(4);

#[component]
pub fn DeploymentPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let act = ServerAction::<QueueStackAction>::new();
    let deployment = Resource::new(
        move || (id, act.version().get()),
        |(id, _)| get_project_deployment(id),
    );
    // Keeps running for the page's life: a new action can start at any
    // time, and only an unfinished one triggers a request.
    poll_every(ACTION_POLL, move || {
        let running = matches!(
            deployment.get_untracked(),
            Some(Ok(StackDeploymentView::Found(found)))
                if found.last_action.as_ref().is_some_and(|last| !last.state.is_finished())
        );
        if running {
            deployment.refetch();
        }
        true
    });
    view! {
        <Transition fallback=|| view! {
            <p class="loading" role="status">"Loading the Dokploy service…"</p>
        }>
            {move || deployment.get().map(|result| match result {
                Ok(StackDeploymentView::NotProvisioned) => ().into_any(),
                Ok(view) => panel(state_view(view, act, id)).into_any(),
                Err(err) => panel(
                    view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Dokploy service unavailable".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                )
                .into_any(),
            })}
        </Transition>
    }
}

fn panel(body: AnyView) -> impl IntoView {
    view! {
        <section class="panel" aria-labelledby="deployment-title">
            <h2 class="section-title" id="deployment-title">"Dokploy service"</h2>
            {body}
        </section>
    }
}

fn state_view(
    view: StackDeploymentView,
    act: ServerAction<QueueStackAction>,
    project: uuid::Uuid,
) -> AnyView {
    match view {
        StackDeploymentView::NotProvisioned => ().into_any(),
        StackDeploymentView::NotConnected => view! {
            <StatePanel
                tone=StateTone::Empty
                title="Dokploy is not connected".to_string()
                detail="The dashboard created this stack through Dokploy, but Dokploy is no longer connected, so its service cannot be read. An installation administrator can connect it again on the administrator page.".to_string()
            />
        }
        .into_any(),
        StackDeploymentView::Unavailable { reason } => view! {
            <StatePanel
                tone=StateTone::Error
                title="Dokploy did not answer".to_string()
                detail=format!("{reason} The stack itself may still be running; the health check above asks it directly.")
            />
        }
        .into_any(),
        StackDeploymentView::Missing { compose_name } => {
            let detail = match compose_name {
                Some(name) => format!(
                    "Dokploy has no service with the ID the dashboard recorded. It was deleted or moved out of reach of the dashboard's API key in Dokploy. The dashboard named it {name}. The project stays registered; unregister it under Settings if the stack is gone."
                ),
                None => "Dokploy has no service with the ID the dashboard recorded. It was deleted in Dokploy, or the dashboard's API key can no longer see it. Ask an owner or admin.".to_owned(),
            };
            view! {
                <StatePanel
                    tone=StateTone::Error
                    title="Service not found in Dokploy".to_string()
                    detail=detail
                />
            }
            .into_any()
        }
        StackDeploymentView::Found(found) => found_view(*found, act, project),
    }
}

fn status_badge(status: Option<ComposeStatus>) -> (&'static str, &'static str) {
    match status {
        Some(ComposeStatus::Done) => ("badge badge-ok", ComposeStatus::Done.label()),
        Some(ComposeStatus::Error) => ("badge badge-error", ComposeStatus::Error.label()),
        Some(ComposeStatus::Running) => ("badge badge-current", ComposeStatus::Running.label()),
        Some(ComposeStatus::Idle) => ("badge badge-muted", ComposeStatus::Idle.label()),
        None => ("badge badge-muted", "Unknown status"),
    }
}

fn run_badge(status: DeploymentStatus) -> &'static str {
    match status {
        DeploymentStatus::Done => "badge badge-ok",
        DeploymentStatus::Error => "badge badge-error",
        DeploymentStatus::Running => "badge badge-current",
        DeploymentStatus::Cancelled => "badge badge-muted",
    }
}

fn found_view(
    found: StackDeployment,
    act: ServerAction<QueueStackAction>,
    project: uuid::Uuid,
) -> AnyView {
    let (class, label) = status_badge(found.status);
    let last = found.last_action.clone().map(last_action_view);
    let busy = found
        .last_action
        .as_ref()
        .is_some_and(|last| !last.state.is_finished());
    let controls = found
        .can_operate
        .then(|| controls_view(act, project, &found.name, busy).into_any());
    let moved = found.moved.then(|| {
        view! {
            <p class="form-error" role="status">
                "This service is no longer in the environment or on the server the dashboard created it in. It was moved in Dokploy; the dashboard keeps the stack where it is now."
            </p>
        }
    });
    let location = found.location.map(location_view);
    let deployments = deployments_view(found.deployments, found.more_deployments);
    view! {
        <dl class="detail-list">
            <div>
                <dt>"Service"</dt>
                <dd><span class="url-text">{found.name}</span></dd>
            </div>
            <div>
                <dt>"Status"</dt>
                <dd><span class=class>{label}</span></dd>
            </div>
            {location}
            {last}
        </dl>
        {moved}
        {controls}
        {deployments}
    }
    .into_any()
}

fn location_view(location: StackLocation) -> impl IntoView {
    let server = location
        .server_name
        .unwrap_or_else(|| "Dokploy's own server".to_owned());
    let link = match location.dokploy_link {
        Some(href) => view! {
            <a href=href rel="noreferrer">"Open in Dokploy"</a>
        }
        .into_any(),
        None => view! {
            <span>
                "The dashboard reaches Dokploy at an internal address, so there is no link. In Dokploy, open "
                {format!("{} / {}", location.project_name, location.environment_name)}
                " and find the service."
            </span>
        }
        .into_any(),
    };
    view! {
        <div>
            <dt>"Dokploy project"</dt>
            <dd>{location.project_name.clone()}</dd>
        </div>
        <div>
            <dt>"Environment"</dt>
            <dd>{location.environment_name.clone()}</dd>
        </div>
        <div>
            <dt>"Server"</dt>
            <dd>{server}</dd>
        </div>
        <div>
            <dt>"Name on the server"</dt>
            <dd><span class="url-text">{location.app_name}</span></dd>
        </div>
        <div>
            <dt>"In Dokploy"</dt>
            <dd>{link}</dd>
        </div>
    }
}

fn deployments_view(runs: Vec<StackDeploymentRun>, more: bool) -> AnyView {
    if runs.is_empty() {
        return view! {
            <StatePanel
                tone=StateTone::Empty
                title="No deployments".to_string()
                detail="Dokploy lists no deployment of this service.".to_string()
            />
        }
        .into_any();
    }
    let rows = runs.into_iter().map(run_row).collect_view();
    let note = more.then(|| {
        view! { <p class="section-text">"Older deployments are listed in Dokploy."</p> }
    });
    view! {
        <div class="table-wrap" role="region" aria-label="Latest deployments, newest first" tabindex="0">
            <table class="data-table">
                <caption class="visually-hidden">"Latest deployments, newest first"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Deployment"</th>
                        <th scope="col">"Started by"</th>
                        <th scope="col">"Status"</th>
                        <th scope="col">"Started (UTC)"</th>
                        <th scope="col">"Finished (UTC)"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {note}
    }
    .into_any()
}

fn run_row(run: StackDeploymentRun) -> impl IntoView {
    let by = if run.from_dashboard {
        "This dashboard"
    } else {
        "Dokploy"
    };
    let time = |at: Option<time::OffsetDateTime>| at.map_or_else(|| "—".to_owned(), utc_minutes);
    view! {
        <tr>
            <td>{run.title.unwrap_or_else(|| "Untitled".to_owned())}</td>
            <td class="nowrap">{by}</td>
            <td class="nowrap"><span class=run_badge(run.status)>{run.status.label()}</span></td>
            <td class="nowrap">{time(run.created_at)}</td>
            <td class="nowrap">{time(run.finished_at)}</td>
        </tr>
    }
}

fn action_badge(state: JobState) -> (&'static str, &'static str) {
    match state {
        JobState::Queued => ("badge badge-current", "Queued"),
        JobState::Running => ("badge badge-current", "Running"),
        JobState::Succeeded => ("badge badge-ok", "Done"),
        JobState::Failed => ("badge badge-error", "Failed"),
    }
}

fn last_action_view(last: StackActionSummary) -> impl IntoView {
    let (class, label) = action_badge(last.state);
    let when = format!("Asked {} (UTC)", utc_minutes(last.created_at));
    view! {
        <div>
            <dt>"Last action"</dt>
            <dd>
                {last.action.label()} " " <span class=class>{label}</span>
                {last.message.map(|message| view! { <span class="field-hint">" " {message}</span> })}
                <span class="field-hint">" " {when}</span>
            </dd>
        </div>
    }
}

/// Stop, start, and redeploy. Each queues a job; the panel follows it.
/// Stopping takes the stack offline, so it asks for a confirmation.
fn controls_view(
    act: ServerAction<QueueStackAction>,
    project: uuid::Uuid,
    name: &str,
    busy: bool,
) -> impl IntoView {
    let project = project.to_string();
    let stop_project = project.clone();
    let start_project = project.clone();
    let error = move || {
        act.value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };
    let disabled = move || busy || act.pending().get();
    let button = |action: StackAction, project: String, class: &'static str| {
        view! {
            <ActionForm action=act attr:class="inline-form compact">
                <input type="hidden" name="id" value=project/>
                <input type="hidden" name="action" value=action.as_str()/>
                <button type="submit" class=class disabled=disabled>
                    {action.label()}
                </button>
            </ActionForm>
        }
    };
    let confirm_label = format!(
        "Stop {name}: its API, Auth, Storage, and Studio stop answering until it is started again. The volumes and data are kept."
    );
    view! {
        <div class="stack-actions" role="group" aria-label="Operate the Dokploy service">
            <ActionForm action=act attr:class="inline-form">
                <input type="hidden" name="id" value=stop_project/>
                <input type="hidden" name="action" value=StackAction::Stop.as_str()/>
                <label class="checkbox-field">
                    <input type="checkbox" name="confirm" value="true" required/>
                    <span>{confirm_label}</span>
                </label>
                <button type="submit" class="button button-danger" disabled=disabled>
                    {StackAction::Stop.label()}
                </button>
            </ActionForm>
            {button(StackAction::Start, start_project, "button")}
            {button(StackAction::Redeploy, project, "button")}
        </div>
        {busy.then(|| view! {
            <p class="field-hint" role="status">"An action is running; the buttons come back when it finishes."</p>
        })}
        {error}
        <p class="field-hint">
            "Redeploy rebuilds the containers from the compose file and variables Dokploy holds, so changes made in Dokploy apply. None of these remove the service or its data."
        </p>
    }
}
