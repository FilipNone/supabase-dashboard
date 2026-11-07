use leptos::prelude::*;
use leptos_router::{
    components::{A, Outlet},
    hooks::use_location,
};
use uuid::Uuid;

use serde::{Deserialize, Serialize};
use supabase_dashboard_domain::{account::AccountSummary, project::ProjectSummary};

use super::theme_switcher::ThemeSwitcher;
use crate::{
    pages::project::project_path,
    server_fns::{get_current_account, get_project, list_organizations, list_projects},
};

/// Counters that pages bump after changing something the frame shows, so
/// the top bar reloads it.
#[derive(Clone, Copy)]
pub struct Refresh {
    pub account: RwSignal<u32>,
    pub organizations: RwSignal<u32>,
    pub projects: RwSignal<u32>,
}

impl Refresh {
    pub fn organizations_changed(self) {
        self.organizations.update(|n| *n = n.wrapping_add(1));
    }

    pub fn projects_changed(self) {
        self.projects.update(|n| *n = n.wrapping_add(1));
    }
}

/// The signed-in operator, loaded once per frame and shared with the top
/// bar and sidebar.
#[derive(Clone, Copy)]
pub struct CurrentAccount(pub Resource<Result<Option<AccountSummary>, ServerFnError>>);

impl CurrentAccount {
    pub fn get(self) -> Option<AccountSummary> {
        self.0.get().and_then(Result::ok).flatten()
    }

    /// Whether to show administrator links. The server checks the flag
    /// again on every administrator call.
    pub fn admin(self) -> bool {
        self.get()
            .is_some_and(|account| account.is_installation_admin)
    }
}

/// Primary application frame: sidebar, top bar, and the routed page.
///
/// Only routes that exist are linked.
#[component]
pub fn DashboardLayout() -> impl IntoView {
    let refresh = Refresh {
        account: RwSignal::new(0),
        organizations: RwSignal::new(0),
        projects: RwSignal::new(0),
    };
    provide_context(refresh);
    let account = CurrentAccount(Resource::new(
        move || refresh.account.get(),
        |_| get_current_account(),
    ));
    provide_context(account);
    view! {
        <a class="skip-link" href="#main-content">"Skip to content"</a>
        <div class="app-frame">
            <aside class="sidebar" aria-label="Primary">
                <a class="sidebar-brand" href="/dashboard/organizations" aria-label="Dashboard home">
                    <span class="brand-mark" aria-hidden="true"></span>
                </a>
                <nav class="sidebar-nav">
                    <A href="/dashboard/organizations" attr:class="nav-item">
                        <NavIcon kind=Icon::Organizations/>
                        <span class="nav-label">"Organizations"</span>
                    </A>
                    <A href="/dashboard/status" attr:class="nav-item">
                        <NavIcon kind=Icon::Status/>
                        <span class="nav-label">"Status"</span>
                    </A>
                    <A href="/dashboard/account/me" attr:class="nav-item">
                        <NavIcon kind=Icon::Account/>
                        <span class="nav-label">"Account"</span>
                    </A>
                    <Transition fallback=|| ()>
                        {move || {
                            account.admin().then(|| view! {
                                <A href="/dashboard/admin" attr:class="nav-item">
                                    <NavIcon kind=Icon::Admin/>
                                    <span class="nav-label">"Admin"</span>
                                </A>
                            })
                        }}
                    </Transition>
                </nav>
            </aside>
            <div class="frame-main">
                <header class="topbar">
                    <nav class="breadcrumbs" aria-label="Context">
                        <span class="crumb-static">"Dashboard"</span>
                        <span class="crumb-sep" aria-hidden="true">"/"</span>
                        <ContextSwitchers/>
                    </nav>
                    <div class="topbar-actions">
                        <ThemeSwitcher/>
                        <AccountMenu/>
                    </div>
                </header>
                <main id="main-content" class="content" tabindex="-1">
                    <Outlet/>
                </main>
            </div>
        </div>
    }
}

/// Which organization or project the current page belongs to, read from
/// the path. These are identifiers only; the server checks access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageScope {
    None,
    Organization(Uuid),
    Project(Uuid),
}

fn page_scope(path: &str) -> PageScope {
    let id_after = |prefix: &str| {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.split('/').next())
            .and_then(|id| id.parse::<Uuid>().ok())
    };
    if let Some(id) = id_after("/dashboard/project/") {
        PageScope::Project(id)
    } else if let Some(id) = id_after("/dashboard/org/").or_else(|| id_after("/dashboard/new/")) {
        PageScope::Organization(id)
    } else {
        PageScope::None
    }
}

/// The organization and project the current page belongs to, and that
/// organization's projects for the project menu.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ScopeContext {
    organization: Option<Uuid>,
    project: Option<Uuid>,
    projects: Vec<ProjectSummary>,
}

async fn load_scope(scope: PageScope) -> ScopeContext {
    let (organization, project) = match scope {
        PageScope::None => return ScopeContext::default(),
        PageScope::Organization(id) => (id, None),
        // On a project page the organization comes from the project.
        PageScope::Project(id) => match get_project(id).await {
            Ok(project) => (project.organization_id, Some(project.id)),
            Err(_) => return ScopeContext::default(),
        },
    };
    ScopeContext {
        organization: Some(organization),
        project,
        projects: list_projects(organization).await.unwrap_or_default(),
    }
}

/// Breadcrumb menus for the organization and, inside one, its projects.
/// They are `<details>` elements, so they open with the keyboard and work
/// before the WASM bundle loads. Phones show only the innermost one.
#[component]
fn ContextSwitchers() -> impl IntoView {
    let location = use_location();
    let scope = Memo::new(move |_| page_scope(&location.pathname.get()));
    let refresh = use_context::<Refresh>();
    let organizations = Resource::new(
        move || refresh.map(|r| r.organizations.get()),
        |_| list_organizations(),
    );
    let context = Resource::new(
        move || (scope.get(), refresh.map(|r| r.projects.get())),
        |(scope, _)| load_scope(scope),
    );
    view! {
        <Transition fallback=|| view! { <span class="crumb-empty">"Organizations"</span> }>
            {move || {
                let list = organizations.get()?.unwrap_or_default();
                let context = context.get()?;
                let organization = context
                    .organization
                    .and_then(|id| list.iter().find(|org| org.id == id).cloned());
                let in_project = context.project.is_some();
                let project_menu = organization.as_ref().map(|org| {
                    view! {
                        <span class="crumb-sep" aria-hidden="true">"/"</span>
                        <ProjectMenu
                            organization=org.id
                            current=context.project
                            projects=context.projects.clone()
                        />
                    }
                });
                let items = list
                    .iter()
                    .map(|org| {
                        let href = format!("/dashboard/org/{}", org.id);
                        let selected = (context.organization == Some(org.id)).then_some("page");
                        view! {
                            <li>
                                <a href=href aria-current=selected>{org.name.as_str().to_owned()}</a>
                            </li>
                        }
                    })
                    .collect_view();
                let label = organization.map_or_else(
                    || "Select organization".to_owned(),
                    |org| org.name.as_str().to_owned(),
                );
                Some(view! {
                    <details class="switcher" class:crumb-outer=in_project>
                        <summary class="switcher-button">
                            <span class="visually-hidden">"Organization: "</span>
                            {label}
                        </summary>
                        <div class="switcher-menu">
                            <ul>{items}</ul>
                            <a class="switcher-all" href="/dashboard/organizations">
                                "All organizations"
                            </a>
                        </div>
                    </details>
                    {project_menu}
                })
            }}
        </Transition>
    }
}

#[component]
fn ProjectMenu(
    organization: Uuid,
    current: Option<Uuid>,
    projects: Vec<ProjectSummary>,
) -> impl IntoView {
    let label = current
        .and_then(|id| projects.iter().find(|p| p.id == id))
        .map_or_else(
            || "Select project".to_owned(),
            |p| p.name.as_str().to_owned(),
        );
    let items = projects
        .into_iter()
        .map(|project| {
            let selected = (current == Some(project.id)).then_some("page");
            view! {
                <li>
                    <a href=project_path(project.id) aria-current=selected>
                        {project.name.as_str().to_owned()}
                    </a>
                </li>
            }
        })
        .collect_view();
    view! {
        <details class="switcher" class:crumb-outer=current.is_none()>
            <summary class="switcher-button">
                <span class="visually-hidden">"Project: "</span>
                {label}
            </summary>
            <div class="switcher-menu">
                <ul>{items}</ul>
                <a class="switcher-all" href=format!("/dashboard/org/{organization}")>
                    "All projects"
                </a>
            </div>
        </details>
    }
}

/// Signed-in operator and the sign-out form. Sign-out is a POST so a link
/// or image on another site cannot end the session.
#[component]
fn AccountMenu() -> impl IntoView {
    let Some(account) = use_context::<CurrentAccount>() else {
        return ().into_any();
    };
    view! {
        <Transition fallback=|| ()>
            {move || {
                account
                    .get()
                    .map(|account| {
                        let email = account.email.to_string();
                        let title = email.clone();
                        view! {
                            <div class="account-menu">
                                <a class="account-name" href="/dashboard/account/me" title=title>
                                    {account.display_name.as_str().to_owned()}
                                    <span class="visually-hidden">" (" {email} "), account settings"</span>
                                </a>
                                <form method="post" action="/auth/sign-out">
                                    <button type="submit" class="button">"Sign out"</button>
                                </form>
                            </div>
                        }
                    })
            }}
        </Transition>
    }
    .into_any()
}

#[derive(Clone, Copy)]
enum Icon {
    Organizations,
    Status,
    Account,
    Admin,
}

#[component]
fn NavIcon(kind: Icon) -> impl IntoView {
    let path = match kind {
        Icon::Organizations => "M3 21V7l9-4 9 4v14M9 21v-6h6v6M3 21h18",
        Icon::Status => "M3 12h4l3-8 4 16 3-8h4",
        Icon::Account => "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
        Icon::Admin => "M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6l8-3zM9 12l2 2 4-4",
    };
    view! {
        <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d=path fill="none" stroke="currentColor" stroke-width="1.6"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

#[cfg(test)]
mod tests {
    use super::{PageScope, page_scope};

    #[test]
    fn page_scope_reads_ids_from_known_paths_only() {
        let id = uuid::Uuid::nil();
        assert_eq!(
            page_scope(&format!("/dashboard/project/{id}/settings")),
            PageScope::Project(id)
        );
        assert_eq!(
            page_scope(&format!("/dashboard/project/{id}")),
            PageScope::Project(id)
        );
        assert_eq!(
            page_scope(&format!("/dashboard/org/{id}/team")),
            PageScope::Organization(id)
        );
        assert_eq!(
            page_scope(&format!("/dashboard/new/{id}")),
            PageScope::Organization(id)
        );
        assert_eq!(page_scope("/dashboard/project/not-a-uuid"), PageScope::None);
        assert_eq!(page_scope("/dashboard/organizations"), PageScope::None);
        assert_eq!(
            page_scope(&format!("/elsewhere/project/{id}")),
            PageScope::None
        );
    }
}
