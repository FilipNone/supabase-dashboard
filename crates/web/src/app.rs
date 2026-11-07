use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::{
    components::{ParentRoute, Route, Router, Routes},
    path,
};
use supabase_dashboard_domain::theme::ThemePreference;

use crate::components::layout::DashboardLayout;
use crate::pages::{
    not_found::NotFound,
    organization::{OrganizationGeneralPage, OrganizationLayout, OrganizationTeamPage},
    organizations::OrganizationsPage,
    sign_in::SignInPage,
    status::StatusPage,
};

/// Server-rendered HTML document. The theme comes from a non-secret cookie
/// so the first paint already uses the operator's chosen theme.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    let theme = initial_theme();
    view! {
        <!DOCTYPE html>
        <html lang="en" data-theme=theme.as_str()>
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <meta name="color-scheme" content="light dark"/>
                <link rel="icon" type="image/svg+xml" href="/favicon.svg"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

/// Reads the theme cookie from the current request during SSR.
pub fn initial_theme() -> ThemePreference {
    #[cfg(feature = "ssr")]
    {
        use_context::<http::request::Parts>()
            .and_then(|parts| {
                parts
                    .headers
                    .get(http::header::COOKIE)
                    .and_then(|value| value.to_str().ok())
                    .map(ThemePreference::from_cookie_header)
            })
            .unwrap_or_default()
    }
    #[cfg(not(feature = "ssr"))]
    {
        ThemePreference::default()
    }
}

/// Landing page for `/` and `/dashboard`. The server answers those paths
/// with an HTTP redirect, because streaming SSR cannot change the status
/// code once rendering starts.
pub const HOME_PATH: &str = "/dashboard/organizations";

/// The only dashboard page reachable without a session.
pub const SIGN_IN_PATH: &str = "/dashboard/sign-in";

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/supabase-dashboard.css"/>
        <Title formatter=|text: String| {
            if text.is_empty() { "Dashboard".to_string() } else { format!("{text} | Dashboard") }
        }/>
        <Router>
            <Routes fallback=|| view! { <NotFound/> }>
                <Route path=path!("/dashboard/sign-in") view=SignInPage/>
                <ParentRoute path=path!("/dashboard") view=DashboardLayout>
                    <Route path=path!("organizations") view=OrganizationsPage/>
                    <Route path=path!("status") view=StatusPage/>
                    <ParentRoute path=path!("org/:org_id") view=OrganizationLayout>
                        <Route path=path!("general") view=OrganizationGeneralPage/>
                        <Route path=path!("team") view=OrganizationTeamPage/>
                    </ParentRoute>
                </ParentRoute>
            </Routes>
        </Router>
    }
}
