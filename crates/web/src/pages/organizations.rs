use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::organization::{ORGANIZATION_NAME_MAX_CHARS, OrganizationSummary};

use crate::components::{
    layout::Refresh,
    page::{PageHeader, StatePanel, StateTone},
};
use crate::server_fns::{CreateOrganization, list_organizations};

/// Organizations the signed-in operator belongs to, and a form to create
/// a new one.
#[component]
pub fn OrganizationsPage() -> impl IntoView {
    let create = ServerAction::<CreateOrganization>::new();
    let refresh = use_context::<Refresh>();
    Effect::new(move |_| {
        if let (Some(Ok(_)), Some(refresh)) = (create.value().get(), refresh) {
            refresh.organizations_changed();
        }
    });
    let organizations = Resource::new(move || create.version().get(), |_| list_organizations());
    let create_error = move || {
        create
            .value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };

    view! {
        <Title text="Organizations"/>
        <PageHeader
            title="Organizations"
            description="Organizations group dashboard members and the self-hosted projects they manage."
        />
        <section class="panel" aria-labelledby="new-org-title">
            <h2 class="section-title" id="new-org-title">"New organization"</h2>
            <ActionForm action=create attr:class="inline-form">
                <label class="field">
                    <span class="field-label">"Name"</span>
                    <input
                        class="input" name="name" required autocomplete="off"
                        maxlength=ORGANIZATION_NAME_MAX_CHARS.to_string()
                    />
                </label>
                <button type="submit" class="button button-primary" disabled=move || create.pending().get()>
                    "Create organization"
                </button>
            </ActionForm>
            {create_error}
        </section>
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading organizations…"</p> }>
            {move || {
                organizations
                    .get()
                    .map(|result| match result {
                        Ok(list) if list.is_empty() => view! {
                            <StatePanel
                                tone=StateTone::Empty
                                title="You are not a member of any organization".to_string()
                                detail="Create one above, or ask an organization owner or administrator to add you.".to_string()
                            />
                        }
                        .into_any(),
                        Ok(list) => view! { <OrganizationGrid list/> }.into_any(),
                        Err(err) => view! {
                            <StatePanel
                                tone=StateTone::Error
                                title="Could not load organizations".to_string()
                                detail=err.to_string()
                            />
                        }
                        .into_any(),
                    })
            }}
        </Transition>
    }
}

#[component]
fn OrganizationGrid(list: Vec<OrganizationSummary>) -> impl IntoView {
    view! {
        <ul class="card-grid" aria-label="Your organizations">
            {list
                .into_iter()
                .map(|org| {
                    let href = format!("/dashboard/org/{}/general", org.id);
                    view! {
                        <li>
                            <a class="card-link" href=href>
                                <span class="card-title">{org.name.as_str().to_owned()}</span>
                                <span class="badge badge-muted">{org.role.label()}</span>
                            </a>
                        </li>
                    }
                })
                .collect_view()}
        </ul>
    }
}
