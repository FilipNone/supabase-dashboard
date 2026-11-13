//! Adopting a Supabase stack that already runs in Dokploy as a project.
//!
//! The page lists the compose services the organization may adopt. Picking
//! one loads a preview: where it runs, the URLs Dokploy routes to its
//! gateway, and which keys its variables hold, by name only. The server
//! reads the service again and checks everything when the form is sent.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use leptos_router::hooks::{use_navigate, use_query_map};
use supabase_dashboard_domain::{
    adoption::{AdoptableService, AdoptableServices, AdoptionPreview, KeyCheck, KeyState},
    authz::Permission,
    project::PROJECT_NAME_MAX_CHARS,
};
use uuid::Uuid;

use crate::{
    components::page::{PageHeader, StatePanel, StateTone},
    error::AppError,
    pages::project::{action_error, org_path, param_uuid, project_path},
    server_fns::{
        AdoptDokployService, get_adoptable_services, get_adoption_preview, get_organization,
    },
};

/// The page that adopts a stack running in Dokploy.
pub fn adopt_stack_path(organization_id: Uuid) -> String {
    format!("/dashboard/new/{organization_id}/adopt")
}

/// `/dashboard/new/:org_id/adopt`: adopt a stack already running in
/// Dokploy.
#[component]
pub fn AdoptStackPage() -> impl IntoView {
    let org_id = param_uuid("org_id");
    let query = use_query_map();
    let chosen = Memo::new(move |_| query.read().get("service"));
    let org = Resource::new(
        move || org_id.get(),
        |id| async move {
            match id {
                Some(id) => get_organization(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    view! {
        <Title text="Adopt a stack from Dokploy"/>
        <PageHeader
            title="Adopt a stack from Dokploy"
            description="Register a Supabase stack that already runs in Dokploy, such as one made from Dokploy's Supabase template, as a project in this organization. Nothing is changed in Dokploy."
        />
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading organization…"</p> }>
            {move || {
                org.get().map(|result| match result {
                    Ok(org) if !org.role.allows(Permission::ProjectRegister) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="You cannot adopt stacks here".to_string()
                            detail=format!(
                                "Only owners and administrators of {} can adopt stacks.",
                                org.name.as_str()
                            )
                        />
                        <p><a href=org_path(org.id)>"Back to the organization"</a></p>
                    }
                    .into_any(),
                    Ok(org) => {
                        let id = org.id;
                        view! {
                            <ServiceList organization_id=id chosen/>
                            {move || chosen.get().map(|compose_id| view! {
                                <PreviewPanel organization_id=id compose_id/>
                            })}
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

/// The services the organization may adopt.
#[component]
fn ServiceList(organization_id: Uuid, chosen: Memo<Option<String>>) -> impl IntoView {
    let services = Resource::new(
        move || organization_id,
        |id| async move { get_adoptable_services(id).await },
    );
    view! {
        <section class="panel" aria-labelledby="adopt-list-title">
            <h2 class="section-title" id="adopt-list-title">"Compose services in Dokploy"</h2>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading Dokploy services…"</p> }>
                {move || services.get().map(|result| match result {
                    Ok(AdoptableServices::Found { services, truncated, unavailable }) => {
                        found_view(organization_id, services, truncated, &unavailable, chosen)
                            .into_any()
                    }
                    Ok(other) => no_services(&other).into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Could not list Dokploy services".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
        </section>
    }
}

/// Why nothing can be listed, and who can change that.
fn no_services(answer: &AdoptableServices) -> impl IntoView + use<> {
    let (title, detail) = match answer {
        AdoptableServices::NotConnected => (
            "Dokploy is not connected",
            "Ask an installation administrator to connect Dokploy on the administrator page.",
        ),
        AdoptableServices::Unsupported => (
            "This server does not read Dokploy services",
            "Adopting needs a server that reads Dokploy services.",
        ),
        AdoptableServices::NoTarget | AdoptableServices::Found { .. } => (
            "No environment to adopt from",
            "The dashboard only looks in Dokploy environments an installation administrator allowed for this organization on the administrator page. The default environment is shared by every organization without its own, so it is not searched.",
        ),
    };
    view! {
        <StatePanel tone=StateTone::Empty title=title.to_string() detail=detail.to_string()/>
    }
}

fn found_view(
    organization_id: Uuid,
    services: Vec<AdoptableService>,
    truncated: bool,
    unavailable: &[String],
    chosen: Memo<Option<String>>,
) -> impl IntoView + use<> {
    let warning = (!unavailable.is_empty()).then(|| {
        let text = format!(
            "Dokploy could not list the services of {}. Try again shortly.",
            unavailable.join(", ")
        );
        view! { <p class="form-error" role="alert">{text}</p> }
    });
    if services.is_empty() {
        return view! {
            {warning}
            <StatePanel
                tone=StateTone::Empty
                title="No services to adopt".to_string()
                detail="The allowed Dokploy environments have no compose service that a project does not already run as.".to_string()
            />
        }
        .into_any();
    }
    let rows = services
        .into_iter()
        .map(|service| {
            let href = format!(
                "{}?service={}",
                adopt_stack_path(organization_id),
                service.compose_id
            );
            let id = service.compose_id.clone();
            let current = move || (chosen.get().as_deref() == Some(id.as_str())).then_some("page");
            let label = format!("Review {}", service.name);
            view! {
                <tr>
                    <td>{service.name}</td>
                    <td>{service.location}</td>
                    <td><a href=href aria-label=label aria-current=current>"Review"</a></td>
                </tr>
            }
        })
        .collect_view();
    view! {
        {warning}
        <p class="field-hint">
            "Choose a service to see what adopting it would register. Only services running Supabase can be adopted."
        </p>
        <div class="table-wrap" role="region" aria-label="Compose services" tabindex="0">
            <table class="data-table">
                <caption class="visually-hidden">"Compose services"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Service"</th>
                        <th scope="col">"Dokploy project and environment"</th>
                        <th scope="col"><span class="visually-hidden">"Action"</span></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {truncated.then(|| view! {
            <p class="field-hint" role="note">"More services exist than are listed."</p>
        })}
    }
    .into_any()
}

/// The preview of one service and the form that adopts it.
#[component]
fn PreviewPanel(organization_id: Uuid, compose_id: String) -> impl IntoView {
    let preview = Resource::new(
        move || (organization_id, compose_id.clone()),
        |(org, compose)| async move { get_adoption_preview(org, compose).await },
    );
    view! {
        <section class="panel" aria-labelledby="adopt-preview-title">
            <h2 class="section-title" id="adopt-preview-title">"Adopt this service"</h2>
            <Transition fallback=|| view! { <p class="loading" role="status">"Reading the service from Dokploy…"</p> }>
                {move || preview.get().map(|result| match result {
                    Ok(preview) => view! { <AdoptForm organization_id preview/> }.into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="This service cannot be adopted".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
        </section>
    }
}

fn key_row(check: KeyCheck) -> impl IntoView {
    let (class, text) = match check.state {
        KeyState::Found => ("badge badge-ok", "Found".to_owned()),
        KeyState::Missing => ("badge badge-muted", "Not set".to_owned()),
        KeyState::Invalid(reason) => ("badge badge-error", format!("Not usable: {reason}")),
    };
    view! {
        <div>
            <dt><code>{check.variable}</code></dt>
            <dd><span class=class>{text}</span></dd>
        </div>
    }
}

#[component]
fn AdoptForm(organization_id: Uuid, preview: AdoptionPreview) -> impl IntoView {
    let adopt = ServerAction::<AdoptDokployService>::new();
    let navigate = use_navigate();
    Effect::new(move |_| {
        if let Some(Ok(project)) = adopt.value().get() {
            navigate(&project_path(organization_id, project), Default::default());
        }
    });
    let any_key = preview
        .keys
        .iter()
        .any(|check| check.state == KeyState::Found);
    let keys = preview.keys.into_iter().map(key_row).collect_view();
    let details = view! {
        <dl class="detail-list">
            <div>
                <dt>"Service"</dt>
                <dd>{preview.name.clone()}</dd>
            </div>
            <div>
                <dt>"Runs in"</dt>
                <dd>{preview.location}</dd>
            </div>
            {keys}
        </dl>
    };
    if let Some(refusal) = preview.refusal {
        return view! {
            {details}
            <StatePanel
                tone=StateTone::Error
                title="This service cannot be adopted".to_string()
                detail=refusal.message().to_string()
            />
        }
        .into_any();
    }
    let urls = preview
        .urls
        .into_iter()
        .map(|url| {
            let label = url.clone();
            view! { <option value=url>{label}</option> }
        })
        .collect_view();
    view! {
        {details}
        <ActionForm action=adopt attr:class="stacked-form">
            <input type="hidden" name="organization_id" value=organization_id.to_string()/>
            <input type="hidden" name="compose_id" value=preview.compose_id/>
            <label class="field">
                <span class="field-label">"Project name"</span>
                <input
                    class="input" name="name" required autocomplete="off"
                    maxlength=PROJECT_NAME_MAX_CHARS.to_string()
                    value=preview.suggested_name.unwrap_or_default()
                />
            </label>
            <label class="field">
                <span class="field-label">"API URL"</span>
                <select class="input url-text" name="api_url" required aria-describedby="adopt-url-hint">
                    {urls}
                </select>
                <span class="field-hint" id="adopt-url-hint">
                    "The domains Dokploy routes to the stack's API gateway. Health checks and Studio go through this URL."
                </span>
            </label>
            {any_key.then(|| view! {
                <label class="checkbox-field">
                    <input type="checkbox" name="copy_keys" value="true" aria-describedby="adopt-keys-hint"/>
                    <span>"Copy the keys and the Studio login found above into the dashboard"</span>
                </label>
                <p class="field-hint" id="adopt-keys-hint">
                    "They are stored encrypted and never shown again. The service role key bypasses row-level security, and the Studio login gives full control of the project through Studio. Without them, add keys later on the project's setup page."
                </p>
            })}
            <div>
                <button type="submit" class="button button-primary" disabled=move || adopt.pending().get()>
                    {move || if adopt.pending().get() { "Adopting…" } else { "Adopt stack" }}
                </button>
            </div>
        </ActionForm>
        {move || action_error(adopt.value().get())}
    }
    .into_any()
}
