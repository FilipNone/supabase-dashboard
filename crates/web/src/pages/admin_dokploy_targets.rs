//! The Dokploy section's stack targets part: which Dokploy environments,
//! on which servers, each dashboard organization may use for new stacks.
//!
//! Dashboard organizations and Dokploy organizations are separate. An
//! organization with no targets of its own may use only the dashboard's
//! own environment. The server checks every choice against what the stored
//! key can see in Dokploy again; the lists here are only for choosing.

use leptos::{form::ActionForm, prelude::*};
use supabase_dashboard_domain::dokploy_target::{
    AllowedStackTarget, DefaultTarget, DokployTargetInventory, ENVIRONMENT_NAME_MAX_CHARS,
    MAX_TARGETS_PER_ORGANIZATION, OrganizationStackTargets, StackTargetsOverview, TargetLookup,
    TargetStatus,
};

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::account::utc_minutes,
    server_fns::{
        AllowDokployTarget, CreateDokployEnvironment, RemoveDokployTarget, get_dokploy_targets,
    },
};

/// The form whose outcome is shown; each new submission replaces the
/// previous outcome, whichever form it came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Submitted {
    Allow,
    Remove,
    Create,
}

#[derive(Clone, Copy)]
struct TargetActions {
    allow: ServerAction<AllowDokployTarget>,
    remove: ServerAction<RemoveDokployTarget>,
    create: ServerAction<CreateDokployEnvironment>,
}

/// `placement_changes` changes when the placement is confirmed or cleared,
/// which changes the default target.
#[component]
pub fn DokployTargetsPanel(placement_changes: RwSignal<usize>) -> impl IntoView {
    let actions = TargetActions {
        allow: ServerAction::<AllowDokployTarget>::new(),
        remove: ServerAction::<RemoveDokployTarget>::new(),
        create: ServerAction::<CreateDokployEnvironment>::new(),
    };
    let submitted = RwSignal::new(None::<Submitted>);
    Effect::new(move |_| {
        // Reading all three inputs keeps the effect subscribed to each.
        let pending = [
            (actions.allow.input().get().is_some(), Submitted::Allow),
            (actions.remove.input().get().is_some(), Submitted::Remove),
            (actions.create.input().get().is_some(), Submitted::Create),
        ];
        if let Some((_, form)) = pending.into_iter().find(|(pending, _)| *pending) {
            submitted.set(Some(form));
        }
    });
    let targets = Resource::new(
        move || {
            (
                placement_changes.get(),
                actions.allow.version().get(),
                actions.remove.version().get(),
                actions.create.version().get(),
            )
        },
        |_| get_dokploy_targets(),
    );

    view! {
        <h3 class="subsection-title" id="dokploy-targets-title">"Where organizations create stacks"</h3>
        <p class="field-hint">
            "Each new stack goes into a Dokploy environment, on Dokploy's own server or a remote one. Dashboard organizations are not Dokploy organizations: choose here which targets each one may use. An organization with no targets of its own may use only the dashboard's environment."
        </p>
        <Transition fallback=|| view! { <p class="loading" role="status">"Asking Dokploy…"</p> }>
            {move || targets.get().map(|result| match result {
                Ok(overview) => targets_view(overview, actions),
                Err(err) => view! {
                    <StatePanel
                        tone=StateTone::Error
                        title="Could not load the stack targets".to_string()
                        detail=err.to_string()
                    />
                }
                .into_any(),
            })}
        </Transition>
        <div id="dokploy-targets-result">
            {move || match submitted.get()? {
                Submitted::Allow => actions.allow.value().get()?.err().map(error_text),
                Submitted::Remove => actions.remove.value().get()?.err().map(error_text),
                Submitted::Create => actions.create.value().get().map(|result| match result {
                    Ok(()) => view! {
                        <p class="form-ok" role="status">"Environment created in Dokploy."</p>
                    }
                    .into_any(),
                    Err(err) => error_text(err),
                }),
            }}
        </div>
    }
}

fn error_text(err: AppError) -> AnyView {
    view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
}

fn targets_view(overview: StackTargetsOverview, actions: TargetActions) -> AnyView {
    let default_view = default_view(&overview.default_target);
    let (inventory, lookup_view) = match overview.lookup {
        TargetLookup::Found {
            inventory,
            truncated,
        } => {
            let more = truncated.then(|| {
                view! {
                    <p class="field-hint">
                        "The key can see more environments or servers than are listed here."
                    </p>
                }
            });
            (Some(inventory), more.into_any())
        }
        TargetLookup::Failed(message) => (
            None,
            view! {
                <StatePanel
                    tone=StateTone::Error
                    title="Could not ask Dokploy".to_string()
                    detail=message
                />
            }
            .into_any(),
        ),
    };
    let more_organizations = overview.organizations_truncated.then(|| {
        view! {
            <p class="field-hint">"Only the first organizations by name are listed."</p>
        }
    });
    let table = organizations_table(
        &overview.organizations,
        &overview.default_target,
        inventory.as_ref(),
        actions,
    );
    let forms = inventory.map(|inventory| {
        let allow = allow_form(&overview.organizations, &inventory, actions);
        let create = create_environment_form(&inventory, actions);
        view! { {allow} {create} }
    });
    view! { {default_view} {lookup_view} {table} {more_organizations} {forms} }.into_any()
}

fn default_view(default: &DefaultTarget) -> AnyView {
    match default {
        DefaultTarget::Placement { names, .. } => view! {
            <p class="field-hint">
                "Default target: " <strong>{names.label()}</strong> ", where the dashboard runs."
            </p>
        }
        .into_any(),
        DefaultTarget::NoPlacement => view! {
            <p class="field-hint">
                "There is no default target until you confirm where the dashboard runs. Until then, organizations without targets of their own cannot create stacks."
            </p>
        }
        .into_any(),
        DefaultTarget::Unavailable(message) => view! {
            <p class="field-hint">
                <span class="badge badge-error">"Default unavailable"</span> " " {message.clone()}
            </p>
        }
        .into_any(),
    }
}

fn status_badge(status: Option<TargetStatus>) -> AnyView {
    match status {
        Some(TargetStatus::Available) => {
            view! { <span class="badge badge-ok">"Available"</span> }.into_any()
        }
        Some(TargetStatus::EnvironmentMissing) => {
            view! { <span class="badge badge-error">"Environment not found"</span> }.into_any()
        }
        Some(TargetStatus::ServerMissing) => {
            view! { <span class="badge badge-error">"Server not found"</span> }.into_any()
        }
        Some(TargetStatus::ServerUnchecked) | None => {
            view! { <span class="badge badge-muted">"Not checked"</span> }.into_any()
        }
    }
}

fn organizations_table(
    organizations: &[OrganizationStackTargets],
    default: &DefaultTarget,
    inventory: Option<&DokployTargetInventory>,
    actions: TargetActions,
) -> AnyView {
    if organizations.is_empty() {
        return view! {
            <StatePanel
                tone=StateTone::Empty
                title="No organizations".to_string()
                detail="Targets are chosen per organization; none exists yet.".to_string()
            />
        }
        .into_any();
    }
    let default_label = match default {
        DefaultTarget::Placement { names, .. } => names.label(),
        _ => "None".to_owned(),
    };
    let rows = organizations
        .iter()
        .map(|org| {
            let targets = if org.allowed.is_empty() {
                view! {
                    <span class="badge badge-muted">"Default"</span> " " {default_label.clone()}
                }
                .into_any()
            } else {
                let items = org
                    .allowed
                    .iter()
                    .map(|allowed| target_item(org.organization_id, allowed, inventory, actions))
                    .collect_view();
                view! { <ul class="target-list">{items}</ul> }.into_any()
            };
            view! {
                <tr>
                    <td>{org.organization_name.as_str().to_owned()}</td>
                    <td>{targets}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap" role="region" aria-labelledby="dokploy-targets-title" tabindex="0">
            <table class="data-table">
                <thead>
                    <tr>
                        <th scope="col">"Organization"</th>
                        <th scope="col">"May create stacks in"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
    .into_any()
}

fn target_item(
    organization: uuid::Uuid,
    allowed: &AllowedStackTarget,
    inventory: Option<&DokployTargetInventory>,
    actions: TargetActions,
) -> impl IntoView {
    let status = inventory.map(|inventory| TargetStatus::check(&allowed.target, inventory));
    let by = allowed
        .added_by
        .as_ref()
        .map_or("a deleted account", |name| name.as_str())
        .to_owned();
    let added = format!("Added {} (UTC) by {by}", utc_minutes(allowed.added_at));
    let remove = actions.remove;
    let label = allowed.names.label();
    let remove_label = format!("Remove {label}");
    let organization = organization.to_string();
    let id = allowed.id.to_string();
    view! {
        <li class="target-item">
            <span>{label} " " {status_badge(status)}</span>
            <span class="field-hint">{added}</span>
            <ActionForm action=remove attr:class="inline-form compact">
                <input type="hidden" name="organization" value=organization/>
                <input type="hidden" name="id" value=id/>
                <button type="submit" class="button"
                    aria-label=remove_label
                    disabled=move || remove.pending().get()>
                    "Remove"
                </button>
            </ActionForm>
        </li>
    }
}

fn allow_form(
    organizations: &[OrganizationStackTargets],
    inventory: &DokployTargetInventory,
    actions: TargetActions,
) -> AnyView {
    if organizations.is_empty() {
        return ().into_any();
    }
    if inventory.environments.is_empty() {
        return view! {
            <StatePanel
                tone=StateTone::Empty
                title="No environments visible".to_string()
                detail="The key cannot see any Dokploy environment. Give its member access to the projects and environments stacks should go into.".to_string()
            />
        }
        .into_any();
    }
    let organization_options = organizations
        .iter()
        .map(|org| {
            view! {
                <option value=org.organization_id.to_string()>
                    {org.organization_name.as_str().to_owned()}
                </option>
            }
        })
        .collect_view();
    let environment_options = inventory
        .environments
        .iter()
        .map(|env| {
            view! {
                <option value=env.environment_id.as_str().to_owned()>
                    {format!("{} / {}", env.project_name, env.environment_name)}
                </option>
            }
        })
        .collect_view();
    let server_field = match &inventory.servers {
        Some(servers) if !servers.is_empty() => {
            let options = servers
                .iter()
                .map(|server| {
                    view! { <option value=server.id.as_str().to_owned()>{server.name.clone()}</option> }
                })
                .collect_view();
            view! {
                <label class="field">
                    <span class="field-label">"Server"</span>
                    <select class="input" name="server">
                        <option value="">"Dokploy's own server"</option>
                        {options}
                    </select>
                </label>
            }
            .into_any()
        }
        Some(_) => ().into_any(),
        None => view! {
            <p class="field-hint">
                "The key may not list Dokploy's servers, so only Dokploy's own server can be chosen."
            </p>
        }
        .into_any(),
    };
    let allow = actions.allow;
    view! {
        <h4 class="subsection-title">"Allow a target"</h4>
        <ActionForm action=allow attr:class="inline-form">
            <label class="field">
                <span class="field-label">"Organization"</span>
                <select class="input" name="organization" required>{organization_options}</select>
            </label>
            <label class="field">
                <span class="field-label">"Dokploy environment"</span>
                <select class="input" name="environment" required>{environment_options}</select>
            </label>
            {server_field}
            <button type="submit" class="button" disabled=move || allow.pending().get()>
                "Allow"
            </button>
        </ActionForm>
        <p class="field-hint">
            {format!("An organization may have up to {MAX_TARGETS_PER_ORGANIZATION} targets. Removing one changes nothing in Dokploy.")}
        </p>
    }
    .into_any()
}

fn create_environment_form(inventory: &DokployTargetInventory, actions: TargetActions) -> AnyView {
    let projects = inventory.projects();
    if projects.is_empty() {
        return ().into_any();
    }
    let options = projects
        .into_iter()
        .map(|(id, name)| view! { <option value=id.as_str().to_owned()>{name}</option> })
        .collect_view();
    let create = actions.create;
    view! {
        <h4 class="subsection-title">"Create an environment"</h4>
        <ActionForm action=create attr:class="inline-form">
            <label class="field">
                <span class="field-label">"Dokploy project"</span>
                <select class="input" name="project" required>{options}</select>
            </label>
            <label class="field">
                <span class="field-label">"Environment name"</span>
                <input class="input" name="name" type="text" required autocomplete="off"
                    maxlength=ENVIRONMENT_NAME_MAX_CHARS.to_string()
                    pattern="[A-Za-z0-9][A-Za-z0-9 ._\\-]*"
                    title="Letters, digits, spaces, '.', '_', and '-', starting with a letter or digit"/>
            </label>
            <button type="submit" class="button" disabled=move || create.pending().get()>
                {move || if create.pending().get() { "Creating…" } else { "Create environment" }}
            </button>
        </ActionForm>
        <p class="field-hint">
            "Creates an empty environment in Dokploy, which you can then allow above. Dokploy keeps it if the dashboard is disconnected."
        </p>
    }
    .into_any()
}
