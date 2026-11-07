use leptos::prelude::*;
use leptos_router::components::{A, Outlet};

use super::theme_switcher::ThemeSwitcher;

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
                    <ThemeSwitcher/>
                </header>
                <main id="main-content" class="content" tabindex="-1">
                    <Outlet/>
                </main>
            </div>
        </div>
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
