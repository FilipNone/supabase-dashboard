use leptos::prelude::*;
use leptos_router::{
    components::{A, Outlet},
    hooks::use_location,
};
use uuid::Uuid;

use super::theme_switcher::ThemeSwitcher;
use supabase_dashboard_domain::account::AccountSummary;

use crate::server_fns::{get_current_account, list_organizations};

/// Counters that pages bump after changing something the frame shows, so
/// the top bar reloads it.
#[derive(Clone, Copy)]
pub struct Refresh {
    pub account: RwSignal<u32>,
    pub organizations: RwSignal<u32>,
}

impl Refresh {
    pub fn organizations_changed(self) {
        self.organizations.update(|n| *n = n.wrapping_add(1));
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
/// Only routes that exist are linked. The project switcher arrives with
/// projects in M2.
#[component]
pub fn DashboardLayout() -> impl IntoView {
    let refresh = Refresh {
        account: RwSignal::new(0),
        organizations: RwSignal::new(0),
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
                        <OrganizationSwitcher/>
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

/// Breadcrumb menu listing the operator's organizations. It is a
/// `<details>` element, so it opens with the keyboard and works before the
/// WASM bundle loads.
#[component]
fn OrganizationSwitcher() -> impl IntoView {
    let location = use_location();
    let current_id = Memo::new(move |_| {
        let path = location.pathname.get();
        path.strip_prefix("/dashboard/org/")
            .or_else(|| path.strip_prefix("/dashboard/new/"))
            .and_then(|rest| rest.split('/').next())
            .and_then(|id| id.parse::<Uuid>().ok())
    });
    let refresh = use_context::<Refresh>().map(|r| r.organizations);
    let organizations = Resource::new(move || refresh.map(|r| r.get()), |_| list_organizations());
    view! {
        <Transition fallback=|| view! { <span class="crumb-empty">"Organizations"</span> }>
            {move || {
                organizations.get().map(|result| {
                    let list = result.unwrap_or_default();
                    let current = current_id.get();
                    let label = current
                        .and_then(|id| list.iter().find(|org| org.id == id))
                        .map_or_else(
                            || "Select organization".to_owned(),
                            |org| org.name.as_str().to_owned(),
                        );
                    let items = list
                        .into_iter()
                        .map(|org| {
                            let href = format!("/dashboard/org/{}", org.id);
                            let selected = (Some(org.id) == current).then_some("page");
                            view! {
                                <li>
                                    <a href=href aria-current=selected>
                                        {org.name.as_str().to_owned()}
                                    </a>
                                </li>
                            }
                        })
                        .collect_view();
                    view! {
                        <details class="switcher">
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
                    }
                })
            }}
        </Transition>
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
