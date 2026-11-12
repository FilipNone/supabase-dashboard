use leptos::prelude::*;
use leptos_meta::Title;
use supabase_dashboard_domain::health::{ComponentStatus, InstallationHealth};

use crate::components::page::{PageHeader, StatePanel, StateTone};
use crate::server_fns::get_installation_health;

/// Health of this dashboard installation. It does not cover managed projects.
#[component]
pub fn StatusPage() -> impl IntoView {
    let health = Resource::new(|| (), |_| get_installation_health());

    view! {
        <Title text="Status"/>
        <PageHeader
            title="Installation status"
            description="Health of this dashboard's own components. Managed projects are not included."
        >
            <button type="button" class="button" on:click=move |_| health.refetch()>
                "Refresh"
            </button>
        </PageHeader>
        <Transition fallback=|| view! { <p class="loading" role="status">"Checking components…"</p> }>
            {move || {
                health
                    .get()
                    .map(|result| match result {
                        Ok(report) => view! { <HealthTable report/> }.into_any(),
                        Err(_) => view! {
                            <StatePanel
                                tone=StateTone::Error
                                title="Could not load installation status".to_string()
                                detail="The dashboard server did not answer. Check that it is running and try again.".to_string()
                            />
                        }
                        .into_any(),
                    })
            }}
        </Transition>
    }
}

#[component]
fn HealthTable(report: InstallationHealth) -> impl IntoView {
    if report.components.is_empty() {
        return view! {
            <StatePanel tone=StateTone::Empty title="No components reported".to_string()/>
        }
        .into_any();
    }
    view! {
        <div class="table-wrap" role="region" aria-label="Component health" tabindex="0">
            <table class="data-table">
                <caption class="visually-hidden">"Component health"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Component"</th>
                        <th scope="col">"Status"</th>
                        <th scope="col">"Detail"</th>
                    </tr>
                </thead>
                <tbody>
                    {report
                        .components
                        .into_iter()
                        .map(|c| {
                            let badge = match c.status {
                                ComponentStatus::Available => "badge badge-ok",
                                ComponentStatus::Unavailable => "badge badge-error",
                                ComponentStatus::Unknown => "badge badge-muted",
                            };
                            view! {
                                <tr>
                                    <td><code>{c.component}</code></td>
                                    <td><span class=badge>{c.status.label()}</span></td>
                                    <td>{c.detail.unwrap_or_default()}</td>
                                </tr>
                            }
                        })
                        .collect_view()}
                </tbody>
            </table>
        </div>
    }
    .into_any()
}
