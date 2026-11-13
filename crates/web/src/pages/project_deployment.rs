//! The Dokploy service behind a project the dashboard provisioned, on the
//! project overview.
//!
//! Dokploy is asked each time the page loads, so a redeploy, a move, or a
//! deletion made in Dokploy shows here instead of being overwritten. The
//! panel is left out for projects that were registered, not provisioned.

use leptos::prelude::*;

use supabase_dashboard_domain::{
    dokploy_compose::{ComposeStatus, DeploymentStatus},
    project::ProjectSummary,
    provisioning::{StackDeployment, StackDeploymentRun, StackDeploymentView, StackLocation},
};

use crate::{
    components::page::{StatePanel, StateTone},
    pages::account::utc_minutes,
    server_fns::get_project_deployment,
};

#[component]
pub fn DeploymentPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let deployment = Resource::new(move || id, get_project_deployment);
    view! {
        <Transition fallback=|| view! {
            <p class="loading" role="status">"Loading the Dokploy service…"</p>
        }>
            {move || deployment.get().map(|result| match result {
                Ok(StackDeploymentView::NotProvisioned) => ().into_any(),
                Ok(view) => panel(state_view(view)).into_any(),
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

fn state_view(view: StackDeploymentView) -> AnyView {
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
        StackDeploymentView::Found(found) => found_view(*found),
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

fn found_view(found: StackDeployment) -> AnyView {
    let (class, label) = status_badge(found.status);
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
        </dl>
        {moved}
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
            <td>{by}</td>
            <td><span class=run_badge(run.status)>{run.status.label()}</span></td>
            <td>{time(run.created_at)}</td>
            <td>{time(run.finished_at)}</td>
        </tr>
    }
}
