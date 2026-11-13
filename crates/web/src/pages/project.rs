//! Project registration and the pages of one registered project.
//!
//! Registering a project only records where an existing stack is. The
//! dashboard contacts the stack only when a member runs a service check,
//! using the API keys stored on the settings page.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use leptos_router::{
    components::{A, Outlet},
    hooks::{use_navigate, use_params_map, use_query_map},
};
use supabase_dashboard_domain::{
    authz::Permission,
    connection::{CredentialKind, CredentialState},
    project::{PROJECT_NAME_MAX_CHARS, PROJECT_URL_MAX_LEN, ProjectSummary},
};
use uuid::Uuid;

use crate::{
    components::{
        layout::Refresh,
        page::{PageHeader, StatePanel, StateTone},
    },
    error::AppError,
    pages::{
        project_connect::ConnectPanel,
        project_connection::{ApiKeysPanel, HealthPanel, StudioAccessPanel, StudioLoginPanel},
        project_deployment::DeploymentPanel,
        project_trust::AuthoritiesPanel,
    },
    server_fns::{
        ChangeProjectUrl, RegisterProject, RenameProject, UnregisterProject, get_organization,
        get_project, get_project_credentials,
    },
};

/// Opens the project's Studio. This is a server route
/// (`apps/server/src/studio.rs`), not a page: links to it need
/// `rel="external"` so the client-side router leaves them alone.
pub fn studio_launch_path(id: Uuid) -> String {
    format!("/dashboard/project/{id}")
}

/// Where a project card or the project switcher leads: the project's Studio
/// for roles that may open it, the dashboard's project page otherwise. The
/// flag is true for Studio, whose link must be external.
pub fn project_entry(project: &ProjectSummary) -> (String, bool) {
    if project.role.allows(Permission::StudioOpen) {
        (studio_launch_path(project.id), true)
    } else {
        (project_path(project.organization_id, project.id), false)
    }
}

/// Why the launcher sent the member back here instead of into Studio. The
/// texts are fixed: the query value only selects one of them.
fn studio_refusal(code: &str) -> Option<&'static str> {
    match code {
        "forbidden" => Some(
            "Your role can't open this project's Studio. Studio gives full access to the \
             database, so only owners, admins, and developers can open it.",
        ),
        "not_configured" => Some(
            "Studio can't be opened until an owner or admin saves the gateway's Studio login \
             under Settings.",
        ),
        "disabled" => Some(
            "Studio access is turned off on this dashboard. An administrator turns it on by \
             setting SUPABASE_DASHBOARD_STUDIO_DOMAIN.",
        ),
        _ => None,
    }
}

/// The dashboard's own page for a project: status, health, and settings.
pub fn project_path(organization_id: Uuid, id: Uuid) -> String {
    format!("/dashboard/org/{organization_id}/projects/{id}")
}

pub(crate) fn org_path(id: Uuid) -> String {
    format!("/dashboard/org/{id}")
}

pub(crate) fn param_uuid(name: &'static str) -> Memo<Option<Uuid>> {
    let params = use_params_map();
    Memo::new(move |_| params.read().get(name).and_then(|raw| raw.parse().ok()))
}

pub(crate) fn action_error<T>(value: Option<Result<T, AppError>>) -> Option<impl IntoView> {
    value
        .and_then(Result::err)
        .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
}

/// `/dashboard/new/:org_id`: register an existing self-hosted stack.
#[component]
pub fn NewProjectPage() -> impl IntoView {
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
    let register = ServerAction::<RegisterProject>::new();
    let navigate = use_navigate();
    let refresh = use_context::<Refresh>();
    Effect::new(move |_| {
        if let Some(Ok(project)) = register.value().get() {
            if let Some(refresh) = refresh {
                refresh.projects_changed();
            }
            navigate(
                &format!(
                    "{}/setup",
                    project_path(project.organization_id, project.id)
                ),
                Default::default(),
            );
        }
    });
    // The HTTP confirmation only appears for an http:// URL.
    let url = RwSignal::new(String::new());
    let plain_http = move || {
        url.read()
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("http://")
    };

    view! {
        <Title text="Register a project"/>
        <PageHeader
            title="Register a project"
            description="Add an existing self-hosted Supabase stack to this organization. The dashboard records its address; it does not change the stack."
        />
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading organization…"</p> }>
            {move || {
                org.get().map(|result| match result {
                    Ok(org) if !org.role.allows(Permission::ProjectRegister) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="You cannot register projects here".to_string()
                            detail=format!(
                                "Only owners and administrators of {} can register projects.",
                                org.name.as_str()
                            )
                        />
                        <p><a href=org_path(org.id)>"Back to the organization"</a></p>
                    }
                    .into_any(),
                    Ok(org) => view! {
                        <section class="panel" aria-labelledby="register-title">
                            <h2 class="section-title" id="register-title">
                                {format!("New project in {}", org.name.as_str())}
                            </h2>
                            <ActionForm action=register attr:class="stacked-form">
                                <input type="hidden" name="organization_id" value=org.id.to_string()/>
                                <label class="field">
                                    <span class="field-label">"Project name"</span>
                                    <input
                                        class="input" name="name" required autocomplete="off"
                                        maxlength=PROJECT_NAME_MAX_CHARS.to_string()
                                    />
                                </label>
                                <label class="field">
                                    <span class="field-label">"API URL"</span>
                                    <input
                                        class="input" name="api_url" type="url" required
                                        autocomplete="off" spellcheck="false" inputmode="url"
                                        placeholder="https://supabase.example.com"
                                        maxlength=PROJECT_URL_MAX_LEN.to_string()
                                        aria-describedby="api-url-hint"
                                        on:input=move |ev| url.set(event_target_value(&ev))
                                    />
                                    <span class="field-hint" id="api-url-hint">
                                        "The address of the stack's API gateway, the same value as SUPABASE_PUBLIC_URL or API_EXTERNAL_URL in its configuration. Do not include keys or passwords."
                                    </span>
                                </label>
                                {move || plain_http().then(|| view! {
                                    <label class="checkbox-field">
                                        <input type="checkbox" name="allow_unencrypted" value="true"/>
                                        <span>
                                            "This URL uses plain HTTP. I confirm that the network between the dashboard and this stack is trusted."
                                        </span>
                                    </label>
                                })}
                                <div>
                                    <button
                                        type="submit" class="button button-primary"
                                        disabled=move || register.pending().get()
                                    >
                                        "Register project"
                                    </button>
                                </div>
                            </ActionForm>
                            {move || action_error(register.value().get())}
                        </section>
                    }
                    .into_any(),
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

#[derive(Clone, Copy)]
struct ProjectContext {
    project: Resource<Result<ProjectSummary, AppError>>,
    rename: ServerAction<RenameProject>,
    change_url: ServerAction<ChangeProjectUrl>,
}

/// `/dashboard/org/:org_id/projects/:project_id`: loads the project and
/// renders its tabs. A malformed ID, an unknown project, one in another
/// organization, and one whose organization does not match the path all
/// show the same not-found state.
#[component]
pub fn ProjectLayout() -> impl IntoView {
    let org_id = param_uuid("org_id");
    let id = param_uuid("project_id");
    let rename = ServerAction::<RenameProject>::new();
    let change_url = ServerAction::<ChangeProjectUrl>::new();
    // Reload only after a save succeeds. A refused save keeps the form as the
    // user left it, so they can correct the value or confirm plain HTTP.
    let saved = RwSignal::new(0u32);
    let query = use_query_map();
    let refusal = move || {
        query
            .read()
            .get("studio")
            .and_then(|code| studio_refusal(&code))
            .map(|text| view! { <p class="form-error page-notice" role="alert">{text}</p> })
    };
    let project = Resource::new(
        move || (org_id.get(), id.get(), saved.get()),
        |(org_id, id, _)| async move {
            match (org_id, id) {
                (Some(org_id), Some(id)) => get_project(id).await.and_then(|p| {
                    if p.organization_id == org_id {
                        Ok(p)
                    } else {
                        Err(AppError::NotFound)
                    }
                }),
                _ => Err(AppError::NotFound),
            }
        },
    );
    provide_context(ProjectContext {
        project,
        rename,
        change_url,
    });
    // A new name shows in the top bar's project menu too.
    let refresh = use_context::<Refresh>();
    Effect::new(move |_| {
        if let Some(Ok(_)) = rename.value().get() {
            saved.update(|n| *n = n.wrapping_add(1));
            if let Some(refresh) = refresh {
                refresh.projects_changed();
            }
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(_)) = change_url.value().get() {
            saved.update(|n| *n = n.wrapping_add(1));
        }
    });

    view! {
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading project…"</p> }>
            {move || {
                project.get().map(|result| match result {
                    Ok(project) => {
                        let base = project_path(project.organization_id, project.id);
                        let open_studio = project.role.allows(Permission::StudioOpen).then(|| view! {
                            <div class="page-actions">
                                <a class="button button-primary" href=studio_launch_path(project.id) rel="external">
                                    "Open Studio"
                                </a>
                            </div>
                        });
                        view! {
                            <Title text=project.name.as_str().to_owned()/>
                            <header class="page-header">
                                <div>
                                    <h1 class="page-title">{project.name.as_str().to_owned()}</h1>
                                    <p class="page-description url-text">{project.api_url.as_str().to_owned()}</p>
                                </div>
                                {open_studio}
                            </header>
                            {refusal}
                            <nav class="tabs" aria-label="Project">
                                <A href=base.clone() exact=true attr:class="tab">"Overview"</A>
                                <A href=format!("{base}/settings") attr:class="tab">"Settings"</A>
                            </nav>
                            <Outlet/>
                        }
                        .into_any()
                    }
                    Err(err) => view! {
                        <Title text="Project"/>
                        <StatePanel
                            tone=StateTone::Error
                            title="Project unavailable".to_string()
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

/// What opening Studio means for this member. Studio has no roles of its
/// own, so the note says plainly what it gives access to.
fn studio_access_note(project: &ProjectSummary) -> &'static str {
    if project.role.allows(Permission::StudioOpen) {
        "You can open this project's Studio. Studio gives full access to the database, \
         including running any SQL as its owner, and shows the stack's API keys and JWT secret."
    } else {
        "Your role can't open Studio, because Studio gives full access to the database and \
         shows the stack's keys. Ask an owner or admin for the developer role if you need it."
    }
}

/// Why the dashboard needs each stored value, for the setup checklist.
fn setup_purpose(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::AnonKey => {
            "Checks Auth, Storage, Realtime, and Edge Functions through the gateway."
        }
        CredentialKind::ServiceRoleKey => {
            "Checks the REST API. It bypasses row-level security and stays on the dashboard server."
        }
        CredentialKind::StudioLogin => {
            "Lets members open Studio here. Until the gateway's Studio password is one only the \
             dashboard knows, anyone who has it can open Studio directly, without the \
             dashboard's roles or audit log."
        }
    }
}

/// The badge for one checklist step, or `None` once the value is stored
/// and readable.
fn setup_state(state: &CredentialState) -> Option<(&'static str, &'static str)> {
    match state {
        CredentialState::Set { .. } => None,
        CredentialState::NotSet => Some(("badge badge-muted", "Not saved")),
        CredentialState::Unreadable { .. } => {
            Some(("badge badge-error", "Unreadable, enter it again"))
        }
    }
}

/// Shown on the overview until the anon key, the service role key, and the
/// Studio login are all stored and readable, so a newly registered project
/// says what it still needs. Every member sees it; only those who may
/// replace credentials get the links.
#[component]
fn SetupChecklist(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let settings = format!("{}/settings", project_path(project.organization_id, id));
    let setup = format!("{}/setup", project_path(project.organization_id, id));
    let can_save = project.role.allows(Permission::ProjectCredentialsReplace);
    let overview = Resource::new(move || id, get_project_credentials);
    view! {
        <Transition fallback=|| ()>
            {move || {
                let overview = overview.get().and_then(Result::ok)?;
                let missing: Vec<(CredentialKind, (&'static str, &'static str))> = CredentialKind::ALL
                    .into_iter()
                    .filter_map(|kind| {
                        let state = overview
                            .credentials
                            .iter()
                            .find(|c| c.kind == kind)
                            .map_or(&CredentialState::NotSet, |c| &c.state);
                        setup_state(state).map(|badge| (kind, badge))
                    })
                    .collect();
                if missing.is_empty() {
                    return None;
                }
                let saved = CredentialKind::ALL.len() - missing.len();
                let summary = format!(
                    "{saved} of {} saved. Until the rest are saved, the checks that need them are skipped{}.",
                    CredentialKind::ALL.len(),
                    if missing.iter().any(|(kind, _)| *kind == CredentialKind::StudioLogin) {
                        " and nobody can open Studio through the dashboard"
                    } else {
                        ""
                    }
                );
                let steps = missing
                    .into_iter()
                    .map(|(kind, (class, label))| {
                        let anchor = if kind == CredentialKind::StudioLogin { "studio-login" } else { "api-keys" };
                        let link = can_save.then(|| {
                            let href = format!("{settings}#{anchor}");
                            let text = match kind {
                                CredentialKind::AnonKey => "Save the anon key in Settings",
                                CredentialKind::ServiceRoleKey => "Save the service role key in Settings",
                                CredentialKind::StudioLogin => "Save the Studio login in Settings",
                            };
                            view! { <a href=href>{text}</a> }
                        });
                        view! {
                            <li>
                                <span class="setup-step-title">
                                    {kind.label()} " " <span class=class>{label}</span>
                                </span>
                                <span class="field-hint">
                                    {setup_purpose(kind)}
                                    {format!(" From {} in the stack's configuration.", kind.env_name())}
                                </span>
                                {link}
                            </li>
                        }
                    })
                    .collect_view();
                let blocked = (!overview.storage_available).then(|| view! {
                    <p class="form-error" role="alert">
                        "This dashboard server has no encryption key configured, so nothing can be saved yet. Set SUPABASE_DASHBOARD_SECRET_KEY_FILE and restart it."
                    </p>
                });
                let who = if can_save {
                    view! {
                        <p><a href=setup.clone()>"Go through the setup steps"</a></p>
                    }
                    .into_any()
                } else {
                    view! { <p class="field-hint">"An owner or admin can save them."</p> }.into_any()
                };
                Some(view! {
                    <section class="panel panel-warning" aria-labelledby="setup-title">
                        <h2 class="section-title" id="setup-title">"Finish connecting this project"</h2>
                        <p>{summary}</p>
                        {blocked}
                        <ul class="setup-steps">{steps}</ul>
                        {who}
                        <p class="field-hint">"Then run Check now under Service health to confirm the keys work."</p>
                    </section>
                })
            }}
        </Transition>
    }
}

fn loaded_project(ctx: ProjectContext) -> Option<ProjectSummary> {
    ctx.project.get().and_then(Result::ok)
}

/// `/dashboard/org/:org_id/projects/:project_id/setup`: where registering
/// a project leads. The steps that connect it, in the order they depend on
/// each other, each saved on its own: the API keys, the project's own
/// certificate authorities when its gateway uses HTTPS, the Studio login
/// (tried against the gateway, so after the authorities), and a first
/// check. The same forms are on the settings page.
#[component]
pub fn ProjectSetupPage() -> impl IntoView {
    let Some(ctx) = use_context::<ProjectContext>() else {
        return ().into_any();
    };
    view! {
        {move || loaded_project(ctx).map(|project| {
            let https = project.api_url.is_encrypted();
            let can_save = project.role.allows(Permission::ProjectCredentialsReplace);
            let overview = project_path(project.organization_id, project.id);
            let authorities_step = https.then(|| view! {
                <li>
                    <a href="#authorities">"Certificate authorities"</a>
                    " (optional): only if the gateway's certificate comes from a private authority."
                </li>
            });
            let who = (!can_save).then(|| view! {
                <p class="field-hint">"Only owners and administrators can save these. You can still run a check."</p>
            });
            view! {
                <section class="panel" aria-labelledby="setup-steps-title">
                    <h2 class="section-title" id="setup-steps-title">"Set up this project"</h2>
                    <p class="section-text">
                        "The project is registered. These steps give the dashboard what it needs to check the stack and open its Studio. Each one saves on its own, and the same forms are on the Settings tab."
                    </p>
                    <ol class="setup-progress">
                        <li><a href="#api-keys">"API keys"</a>": the anon and service role keys, used by the service checks."</li>
                        {authorities_step}
                        <li><a href="#studio-login">"Studio login"</a>": the gateway's Studio user name and password, so members can open Studio."</li>
                        <li><a href="#first-check">"First check"</a>": run Check now to confirm the keys work."</li>
                    </ol>
                    {who}
                </section>
                <ApiKeysPanel project=project.clone()/>
                {https.then(|| view! { <AuthoritiesPanel project=project.clone()/> })}
                <StudioLoginPanel project=project.clone()/>
                <div id="first-check">
                    <HealthPanel project=project.clone()/>
                </div>
                <p><a class="button" href=overview>"Done, go to the overview"</a></p>
            }
            .into_any()
        })}
    }
    .into_any()
}

/// Registry details and the last service check.
#[component]
pub fn ProjectOverviewPage() -> impl IntoView {
    let Some(ctx) = use_context::<ProjectContext>() else {
        return ().into_any();
    };
    view! {
        {move || loaded_project(ctx).map(|project| {
            let transport = if project.api_url.is_encrypted() {
                view! { <span class="badge badge-ok">"HTTPS"</span> }.into_any()
            } else {
                view! { <span class="badge badge-error">"Plain HTTP"</span> }.into_any()
            };
            view! {
                <section class="panel" aria-labelledby="project-details-title">
                    <h2 class="section-title" id="project-details-title">"Project details"</h2>
                    <dl class="detail-list">
                        <div>
                            <dt>"API URL"</dt>
                            <dd><span class="url-text">{project.api_url.as_str().to_owned()}</span> {transport}</dd>
                        </div>
                        <div>
                            <dt>"Organization"</dt>
                            <dd><a href=org_path(project.organization_id)>"Open organization"</a></dd>
                        </div>
                        <div>
                            <dt>"Registered"</dt>
                            <dd>{format!("{} (UTC)", project.created_at.date())}</dd>
                        </div>
                        <div>
                            <dt>"Your role"</dt>
                            <dd>{project.role.label()}</dd>
                        </div>
                        <div>
                            <dt>"Studio"</dt>
                            <dd>{studio_access_note(&project)}</dd>
                        </div>
                    </dl>
                </section>
                {view! { <SetupChecklist project=project.clone()/> }.into_any()}
                {view! { <HealthPanel project=project.clone()/> }.into_any()}
                {view! { <DeploymentPanel project=project.clone()/> }.into_any()}
                {view! { <ConnectPanel project=project.clone()/> }.into_any()}
            }
            .into_any()
        })}
    }
    .into_any()
}

/// Rename, change the API URL, manage API keys, and unregister.
#[component]
pub fn ProjectSettingsPage() -> impl IntoView {
    let Some(ctx) = use_context::<ProjectContext>() else {
        return ().into_any();
    };
    let rename = ctx.rename;
    let unregister = ServerAction::<UnregisterProject>::new();
    let navigate = use_navigate();
    let organization = Memo::new(move |_| loaded_project(ctx).map(|p| p.organization_id));
    let refresh = use_context::<Refresh>();
    Effect::new(move |_| {
        if let (Some(Ok(())), Some(org)) = (unregister.value().get(), organization.get_untracked())
        {
            if let Some(refresh) = refresh {
                refresh.projects_changed();
            }
            navigate(&org_path(org), Default::default());
        }
    });
    let rename_feedback = move || {
        rename.value().get().map(|result| match result {
            Ok(_) => {
                view! { <p class="form-ok" role="status">"Project name saved."</p> }.into_any()
            }
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };

    view! {
        {move || loaded_project(ctx).map(|project| {
            let can_rename = project.role.allows(Permission::ProjectUpdate);
            let can_unregister = project.role.allows(Permission::ProjectUnregister);
            let can_read_log = project.role.allows(Permission::AuditRead);
            let id = project.id.to_string();
            let name = project.name.as_str().to_owned();
            let danger_zone = can_unregister.then(|| unregister_section(unregister, id.clone(), name.clone()));
            let url_zone = url_section(ctx.change_url, id.clone(), project.api_url.as_str().to_owned(), can_rename);
            view! {
                <section class="panel" aria-labelledby="project-general-title">
                    <h2 class="section-title" id="project-general-title">"General settings"</h2>
                    <ActionForm action=rename attr:class="inline-form">
                        <input type="hidden" name="id" value=id.clone()/>
                        <label class="field">
                            <span class="field-label">"Project name"</span>
                            <input
                                class="input" name="name" required autocomplete="off"
                                maxlength=PROJECT_NAME_MAX_CHARS.to_string()
                                value=name.clone()
                                readonly=!can_rename
                            />
                        </label>
                        {can_rename.then(|| view! {
                            <button type="submit" class="button button-primary"
                                disabled=move || rename.pending().get()>
                                "Save"
                            </button>
                        })}
                    </ActionForm>
                    {(!can_rename).then(|| view! {
                        <p class="field-hint">"Only owners and administrators can rename projects."</p>
                    })}
                    {rename_feedback}
                </section>
                {url_zone}
                <AuthoritiesPanel project=project.clone()/>
                <StudioLoginPanel project=project.clone()/>
                <ApiKeysPanel project=project.clone()/>
                {can_read_log.then(|| view! { <StudioAccessPanel project=project.clone()/> })}
                {danger_zone}
            }
        })}
    }
    .into_any()
}

/// Moving a project to a new address only changes the registry entry;
/// neither the old nor the new address is contacted.
fn url_section(
    change_url: ServerAction<ChangeProjectUrl>,
    id: String,
    current: String,
    can_change: bool,
) -> impl IntoView {
    let url = RwSignal::new(current.clone());
    let plain_http = move || {
        url.read()
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("http://")
    };
    let feedback = move || {
        change_url.value().get().map(|result| match result {
            Ok(_) => view! { <p class="form-ok" role="status">"API URL saved."</p> }.into_any(),
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };
    view! {
        <section class="panel" aria-labelledby="project-url-title">
            <h2 class="section-title" id="project-url-title">"API URL"</h2>
            <ActionForm action=change_url attr:class="stacked-form">
                <input type="hidden" name="id" value=id/>
                <label class="field">
                    <span class="field-label">"API URL"</span>
                    <input
                        class="input" name="api_url" type="url" required
                        autocomplete="off" spellcheck="false" inputmode="url"
                        maxlength=PROJECT_URL_MAX_LEN.to_string()
                        value=current
                        readonly=!can_change
                        aria-describedby="project-url-hint"
                        on:input=move |ev| url.set(event_target_value(&ev))
                    />
                    <span class="field-hint" id="project-url-hint">
                        "Use this when the stack moved to a new address. Changing it does not move or contact the stack."
                    </span>
                </label>
                {move || (can_change && plain_http()).then(|| view! {
                    <label class="checkbox-field">
                        <input type="checkbox" name="allow_unencrypted" value="true"/>
                        <span>
                            "This URL uses plain HTTP. I confirm that the network between the dashboard and this stack is trusted."
                        </span>
                    </label>
                })}
                {can_change.then(|| view! {
                    <div>
                        <button type="submit" class="button button-primary"
                            disabled=move || change_url.pending().get()>
                            "Save URL"
                        </button>
                    </div>
                })}
            </ActionForm>
            {(!can_change).then(|| view! {
                <p class="field-hint">"Only owners and administrators can change the API URL."</p>
            })}
            {feedback}
        </section>
    }
}

fn unregister_section(
    unregister: ServerAction<UnregisterProject>,
    id: String,
    name: String,
) -> impl IntoView {
    view! {
        <section class="panel panel-danger" aria-labelledby="unregister-title">
            <h2 class="section-title" id="unregister-title">"Unregister project"</h2>
            <p class="section-text">
                "Removes this project from the dashboard. The stack, its services, and its data are not changed or deleted, and you can register it again later."
            </p>
            <ActionForm action=unregister attr:class="stacked-form">
                <input type="hidden" name="id" value=id/>
                <label class="field">
                    <span class="field-label">{format!("Type {name} to confirm")}</span>
                    <input class="input" name="confirmation" required autocomplete="off" spellcheck="false"/>
                </label>
                <div>
                    <button type="submit" class="button button-danger"
                        disabled=move || unregister.pending().get()>
                        "Unregister project"
                    </button>
                </div>
            </ActionForm>
            {move || action_error(unregister.value().get())}
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_refusal_codes_show_a_message() {
        for code in ["forbidden", "not_configured", "disabled"] {
            assert!(studio_refusal(code).is_some(), "{code}");
        }
        for code in ["", "Forbidden", "<script>", "ok"] {
            assert!(studio_refusal(code).is_none(), "{code}");
        }
    }
}
