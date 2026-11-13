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
    pages::stack_settings::StackSettingsSection,
    pages::{account::utc_minutes, provision::poll_every},
    server_fns::{QueueStackAction, QueueStackRemoval, QueueStackSettings, get_project_deployment},
};

/// How often the panel asks again while an action runs.
const ACTION_POLL: Duration = Duration::from_secs(4);

#[component]
pub fn DeploymentPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let name = project.name.as_str().to_owned();
    let act = ServerAction::<QueueStackAction>::new();
    let remove = ServerAction::<QueueStackRemoval>::new();
    let apply = ServerAction::<QueueStackSettings>::new();
    // The Stop confirmation is cleared after each request, so every stop
    // is confirmed again: the panel re-renders into the same elements.
    let confirmed = RwSignal::new(false);
    Effect::new(move |_| {
        act.version().track();
        confirmed.set(false);
    });
    let actions = Actions {
        act,
        remove,
        confirmed,
    };
    let deployment = Resource::new(
        move || {
            (
                id,
                act.version().get(),
                remove.version().get(),
                apply.version().get(),
            )
        },
        |(id, _, _, _)| get_project_deployment(id),
    );
    // Keeps running for the page's life: a new action can start at any
    // time, and only an unfinished one triggers a request.
    poll_every(ACTION_POLL, move || {
        let running = deployment
            .with_untracked(|view| matches!(view, Some(Ok(view)) if view.action_running()));
        if running {
            deployment.refetch();
        }
        true
    });
    // Counts actions that finished while the page was open, so the
    // settings section reads the stack again after a change is written.
    let finished = RwSignal::new(0u32);
    Effect::new(move |previous: Option<bool>| {
        let running =
            deployment.with(|view| matches!(view, Some(Ok(view)) if view.action_running()));
        if previous == Some(true) && !running {
            finished.update(|count| *count += 1);
        }
        running
    });
    // One live region beside the re-rendered panel, so an action's
    // progress and outcome are announced.
    let announcement = move || {
        let last = deployment.with(|view| match view {
            Some(Ok(view)) => view.last_action().cloned(),
            _ => None,
        })?;
        let (_, label) = action_badge(&last);
        Some(format!(
            "{}: {label}. {}",
            last.action.label(),
            last.message.unwrap_or_default()
        ))
    };
    view! {
        <Transition fallback=|| view! {
            <p class="loading" role="status">"Loading the Dokploy service…"</p>
        }>
            // Kept across refetches: a Transition shows its children once
            // loaded, so this element persists and its changes are read.
            <p class="visually-hidden" role="status" aria-live="polite">{announcement}</p>
            {move || deployment.get().map(|result| match result {
                Ok(StackDeploymentView::NotProvisioned) => ().into_any(),
                Ok(view) => panel(state_view(view, actions, id, &name)).into_any(),
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
        // Outside the panel's Transition, so polling while an action runs
        // does not reset what is typed into the form.
        <StackSettingsSection project=id apply=apply finished=finished.into()/>
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

/// The panel's two server actions.
#[derive(Clone, Copy)]
struct Actions {
    act: ServerAction<QueueStackAction>,
    remove: ServerAction<QueueStackRemoval>,
    confirmed: RwSignal<bool>,
}

fn state_view(
    view: StackDeploymentView,
    actions: Actions,
    project: uuid::Uuid,
    project_name: &str,
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
        StackDeploymentView::Unavailable {
            reason,
            last_action,
        } => view! {
            <StatePanel
                tone=StateTone::Error
                title="Dokploy did not answer".to_string()
                detail=format!("{reason} The stack itself may still be running; the health check above asks it directly.")
            />
            <dl class="detail-list">{last_action.map(last_action_view)}</dl>
        }
        .into_any(),
        StackDeploymentView::Missing {
            last_action: Some(last),
            ..
        } if last.action.deletes_service() && !last.state.is_finished() => view! {
            <StatePanel
                tone=StateTone::Empty
                title="Removing the service from Dokploy".to_string()
                detail="Dokploy no longer lists the service. The dashboard is recording the removal; this section updates when it has.".to_string()
            />
            <dl class="detail-list">{last_action_view(last)}</dl>
        }
        .into_any(),
        StackDeploymentView::Missing {
            compose_name,
            last_action,
        } => {
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
                <dl class="detail-list">{last_action.map(last_action_view)}</dl>
            }
            .into_any()
        }
        StackDeploymentView::Found(found) => found_view(*found, actions, project, project_name),
        StackDeploymentView::Removed {
            removed_at,
            volumes_deleted,
            app_name,
            last_action,
        } => {
            let detail = if volumes_deleted {
                "The dashboard deleted this stack's Dokploy service and its data volumes. Nothing of it is left to start again."
            } else {
                "The dashboard deleted this stack's Dokploy service and kept its data volumes on the server."
            };
            let volumes = (!volumes_deleted).then(|| match app_name {
                Some(app) => view! {
                    <p class="section-text">
                        "The volumes' names start with " <code class="url-text">{format!("{app}_")}</code>
                        ". Delete them on the server when the data is no longer needed."
                    </p>
                }
                .into_any(),
                None => view! { <p class="section-text">"Ask an owner or admin about the volumes."</p> }.into_any(),
            });
            let verb = if volumes_deleted { "Destroyed" } else { "Removed from Dokploy" };
            let title = format!("{verb} {} (UTC)", utc_minutes(removed_at));
            // The removal's own message already says the project stays
            // registered.
            let hint = last_action.is_none().then(|| view! {
                <p class="field-hint">"The project stays registered until it is unregistered under Settings."</p>
            });
            view! {
                <StatePanel tone=StateTone::Empty title=title detail=detail.to_owned()/>
                {volumes}
                <dl class="detail-list">{last_action.map(last_action_view)}</dl>
                {hint}
            }
            .into_any()
        }
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
    actions: Actions,
    project: uuid::Uuid,
    project_name: &str,
) -> AnyView {
    let stopped = found.status == Some(ComposeStatus::Idle)
        && found.last_action.as_ref().is_some_and(|last| {
            last.action == StackAction::Stop && last.state == JobState::Succeeded
        });
    let (class, label) = if stopped {
        ("badge badge-muted", "Stopped")
    } else {
        status_badge(found.status)
    };
    let last = found.last_action.clone().map(last_action_view);
    let busy = found
        .last_action
        .as_ref()
        .is_some_and(|last| !last.state.is_finished());
    let controls = found
        .can_operate
        .then(|| controls_view(actions, project, &found.name, busy).into_any());
    let removal = (found.can_remove || found.can_destroy).then(|| {
        removal_view(
            actions.remove,
            project,
            project_name,
            found.can_destroy,
            busy,
        )
        .into_any()
    });
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
        {removal}
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

fn action_badge(last: &StackActionSummary) -> (&'static str, &'static str) {
    match last.state {
        // A job waiting between steps is queued again, with a message.
        JobState::Queued if last.message.is_some() => ("badge badge-current", "Running"),
        JobState::Queued => ("badge badge-current", "Queued"),
        JobState::Running => ("badge badge-current", "Running"),
        JobState::Succeeded => ("badge badge-ok", "Done"),
        JobState::Failed => ("badge badge-error", "Failed"),
    }
}

fn last_action_view(last: StackActionSummary) -> impl IntoView {
    let (class, label) = action_badge(&last);
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
fn controls_view(actions: Actions, project: uuid::Uuid, name: &str, busy: bool) -> impl IntoView {
    let act = actions.act;
    let confirmed = actions.confirmed;
    let project = project.to_string();
    let stop_project = project.clone();
    let start_project = project.clone();
    let error = move || {
        act.value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };
    // aria-disabled rather than disabled, so the focused button keeps focus
    // after a click; the server refuses an action while another runs.
    let disabled = move || (busy || act.pending().get()).then_some("true");
    let button = |action: StackAction, project: String, class: &'static str| {
        view! {
            <ActionForm action=act attr:class="inline-form compact">
                <input type="hidden" name="id" value=project/>
                <input type="hidden" name="action" value=action.as_str()/>
                <button type="submit" class=class aria-disabled=disabled>
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
                    <input type="checkbox" name="confirm" value="true" required
                        prop:checked=move || confirmed.get()
                        on:change=move |ev| confirmed.set(event_target_checked(&ev))/>
                    <span>{confirm_label}</span>
                </label>
                <button type="submit" class="button button-danger" aria-disabled=disabled>
                    {StackAction::Stop.label()}
                </button>
            </ActionForm>
            {button(StackAction::Start, start_project, "button")}
            {button(StackAction::Redeploy, project, "button")}
        </div>
        {busy.then(|| view! {
            <p class="field-hint">"An action is running; wait for it to finish before asking for another."</p>
        })}
        {error}
        <p class="field-hint">
            "Redeploy rebuilds the containers from the compose file and variables Dokploy holds, so changes made in Dokploy apply. None of these remove the service or its data."
        </p>
    }
}

/// Remove and destroy, each confirmed by typing the project's name. The
/// server checks the name and the role again.
fn removal_view(
    remove: ServerAction<QueueStackRemoval>,
    project: uuid::Uuid,
    name: &str,
    can_destroy: bool,
    busy: bool,
) -> impl IntoView {
    let disabled = move || (busy || remove.pending().get()).then_some("true");
    // Which form was sent last, so its refusal shows beside it. Pressing
    // Enter in a field clicks the form's submit button too.
    let sent = RwSignal::new(None::<StackAction>);
    let form = move |action: StackAction, id: &'static str, purpose: &str, text: String| {
        let label = format!("Type {name} to {purpose}");
        let text_id = format!("{id}-text");
        let error_id = format!("{id}-error");
        let error_text = move || {
            (sent.get() == Some(action))
                .then(|| remove.value().get().and_then(Result::err))
                .flatten()
                .map(|err| err.to_string())
        };
        let described = {
            let text_id = text_id.clone();
            let error_id = error_id.clone();
            move || match error_text() {
                Some(_) => format!("{text_id} {error_id}"),
                None => text_id.clone(),
            }
        };
        let invalid = move || error_text().map(|_| "true");
        let error = {
            let error_id = error_id.clone();
            move || {
                error_text().map(|err| {
                    view! { <p class="form-error" id=error_id.clone() role="alert">{err}</p> }
                })
            }
        };
        view! {
            <ActionForm action=remove attr:class="stacked-form">
                <h4 class="subsection-title">{action.label()}</h4>
                <p class="section-text" id=text_id>{text}</p>
                <input type="hidden" name="id" value=project.to_string()/>
                <input type="hidden" name="action" value=action.as_str()/>
                <div class="field">
                    <label for=id>{label}</label>
                    <input
                        class="input"
                        id=id
                        name="name"
                        type="text"
                        required
                        autocomplete="off"
                        spellcheck="false"
                        aria-describedby=described
                        aria-invalid=invalid
                    />
                </div>
                {error}
                <div>
                    <button
                        type="submit"
                        class="button button-danger"
                        aria-disabled=disabled
                        on:click=move |_| sent.set(Some(action))
                    >
                        {action.label()}
                    </button>
                </div>
            </ActionForm>
        }
    };
    let remove_text = "Deletes the service in Dokploy: its containers, its folder on the server, and its domain. The database, stored files, and Studio snippets stay on the server in Docker volumes. The project stays registered here.".to_owned();
    let destroy_text = "Deletes the service and its Docker volumes: the database, every stored file, and Studio's snippets. This cannot be undone. Take a backup first if you may need the data.".to_owned();
    view! {
        <div class="danger-zone" role="group" aria-labelledby="danger-title">
            <h3 class="section-title" id="danger-title">"Remove the stack"</h3>
            {form(StackAction::Remove, "remove-name", "remove its service", remove_text)}
            {can_destroy.then(|| {
                form(StackAction::Destroy, "destroy-name", "destroy the stack and its data", destroy_text)
            })}
        </div>
    }
}
