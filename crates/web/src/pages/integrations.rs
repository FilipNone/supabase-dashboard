//! An organization's Integrations tab: the providers its projects use. For
//! now only Dokploy, which creates and runs the organization's stacks.

use leptos::prelude::*;
use supabase_dashboard_domain::{authz::Permission, provisioning::ProvisionTargets};
use uuid::Uuid;

use crate::{
    components::page::{StatePanel, StateTone},
    pages::provision::no_targets,
    server_fns::get_provision_targets,
};

/// The Dokploy card. Which targets an organization may use is decided by an
/// installation administrator, so this only shows them; the server limits
/// reading them to roles that can create stacks.
#[component]
pub fn DokployIntegration(organization_id: Uuid, can_create: bool) -> impl IntoView {
    view! {
        <section class="panel" aria-labelledby="dokploy-integration-title">
            <h2 class="section-title" id="dokploy-integration-title">"Dokploy"</h2>
            <p class="section-text">
                "Creates, runs, and removes this organization's stacks. The connection belongs to the whole installation: an installation administrator connects Dokploy and chooses which Dokploy environments each organization may use."
            </p>
            {if can_create {
                view! { <DokployTargets organization_id/> }.into_any()
            } else {
                view! {
                    <p class="field-hint">
                        "Owners and administrators can see where this organization's stacks go."
                    </p>
                }
                .into_any()
            }}
        </section>
    }
}

#[component]
fn DokployTargets(organization_id: Uuid) -> impl IntoView {
    let targets = Resource::new(move || organization_id, get_provision_targets);
    view! {
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading Dokploy targets…"</p> }>
            {move || targets.get().map(|result| match result {
                Ok(ProvisionTargets::Choices(choices)) if !choices.is_empty() => {
                    let count = choices.len();
                    let items = choices
                        .into_iter()
                        .map(|choice| view! { <li>{choice.label}</li> })
                        .collect_view();
                    let base = format!("/dashboard/new/{organization_id}");
                    view! {
                        <p class="section-text">
                            <span class="badge badge-ok">"Connected"</span>
                            " "
                            {if count == 1 {
                                "New stacks go to this Dokploy environment:".to_owned()
                            } else {
                                format!("New stacks can go to these {count} Dokploy environments:")
                            }}
                        </p>
                        <ul class="integration-targets">{items}</ul>
                        <div class="link-actions">
                            <a class="button button-primary" href=format!("{base}/stack")>"Create a stack"</a>
                            <a class="button" href=format!("{base}/adopt")>"Adopt a stack from Dokploy"</a>
                        </div>
                    }
                    .into_any()
                }
                Ok(other) => no_targets(&other).into_any(),
                Err(err) => view! {
                    <StatePanel
                        tone=StateTone::Error
                        title="Could not load Dokploy targets".to_string()
                        detail=err.to_string()
                    />
                }
                .into_any(),
            })}
        </Transition>
    }
}

/// Whether a role sees the targets: the same permission the server checks.
pub fn can_see_targets(role: supabase_dashboard_domain::authz::OrgRole) -> bool {
    role.allows(Permission::ProjectRegister)
}
