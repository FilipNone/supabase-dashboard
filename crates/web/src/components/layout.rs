use leptos::prelude::*;
use leptos_router::components::{A, Outlet};

use super::theme_switcher::ThemeSwitcher;
use crate::server_fns::get_current_account;

/// Primary application frame: sidebar, top bar, and the routed page.
///
/// Only routes that exist are linked. Organization and project switchers show
/// an explicit empty state until accounts and organizations land (M1).
#[component]
pub fn DashboardLayout() -> impl IntoView {
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
                </nav>
            </aside>
            <div class="frame-main">
                <header class="topbar">
                    <nav class="breadcrumbs" aria-label="Context">
                        <span class="crumb-static">"Dashboard"</span>
                        <span class="crumb-sep" aria-hidden="true">"/"</span>
                        <span class="crumb-empty" title="Organizations are not available yet">
                            "No organization"
                        </span>
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

/// Signed-in operator and the sign-out form. Sign-out is a POST so a link
/// or image on another site cannot end the session.
#[component]
fn AccountMenu() -> impl IntoView {
    let account = Resource::new(|| (), |_| get_current_account());
    view! {
        <Transition fallback=|| ()>
            {move || {
                account
                    .get()
                    .and_then(Result::ok)
                    .flatten()
                    .map(|account| {
                        let email = account.email.to_string();
                        let title = email.clone();
                        view! {
                            <div class="account-menu">
                                <span class="account-name" title=title>
                                    {account.display_name.as_str().to_owned()}
                                    <span class="visually-hidden">" (" {email} ")"</span>
                                </span>
                                <form method="post" action="/auth/sign-out">
                                    <button type="submit" class="button">"Sign out"</button>
                                </form>
                            </div>
                        }
                    })
            }}
        </Transition>
    }
}

#[derive(Clone, Copy)]
enum Icon {
    Organizations,
    Status,
}

#[component]
fn NavIcon(kind: Icon) -> impl IntoView {
    let path = match kind {
        Icon::Organizations => "M3 21V7l9-4 9 4v14M9 21v-6h6v6M3 21h18",
        Icon::Status => "M3 12h4l3-8 4 16 3-8h4",
    };
    view! {
        <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d=path fill="none" stroke="currentColor" stroke-width="1.6"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
