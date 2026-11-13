use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::{
    components::{ParentRoute, Route, Router, Routes},
    path,
};
use supabase_dashboard_domain::theme::ThemePreference;

use crate::components::layout::DashboardLayout;
use crate::pages::{
    account::{AccountLayout, AccountProfilePage, AccountSecurityPage},
    admin::AdminPage,
    adopt::AdoptStackPage,
    invite::InvitePage,
    not_found::NotFound,
    organization::{
        OrganizationGeneralPage, OrganizationLayout, OrganizationProjectsPage, OrganizationTeamPage,
    },
    organizations::OrganizationsPage,
    project::{
        NewProjectPage, ProjectLayout, ProjectOverviewPage, ProjectSettingsPage, ProjectSetupPage,
    },
    provision::{NewStackPage, ProvisionJobPage},
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

/// Reachable without a session; signed-in operators are sent home.
pub const SIGN_IN_PATH: &str = "/dashboard/sign-in";

/// Longest page address the sign-in page carries back.
const RETURN_PATH_MAX_LEN: usize = 2048;

/// Where to go after signing in, when the sign-in page was reached from
/// another page (`?next=`). Only dashboard pages on this host qualify, in
/// printable ASCII without a backslash, so `next` cannot point the browser at
/// another site (`//host`, `/\host`) or put odd bytes in a `Location` header.
pub fn sign_in_return_path(raw: &str) -> Option<&str> {
    let safe = raw.len() <= RETURN_PATH_MAX_LEN
        && raw.starts_with("/dashboard/")
        && !raw.starts_with(SIGN_IN_PATH)
        && raw.bytes().all(|b| b.is_ascii_graphic() && b != b'\\');
    safe.then_some(raw)
}

/// Reachable with or without a session. Invitation links point here with
/// the code in the fragment.
pub const INVITE_PATH: &str = "/dashboard/invite";

/// Public server functions behind the invitation page. They must match the
/// `prefix` and `endpoint` of their `#[server]` attributes.
pub const INVITE_PREVIEW_PATH: &str = "/auth/invitation/preview";
pub const INVITE_SIGN_UP_PATH: &str = "/auth/invitation/sign-up";

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
                <Route path=path!("/dashboard/invite") view=InvitePage/>
                <ParentRoute path=path!("/dashboard") view=DashboardLayout>
                    <Route path=path!("organizations") view=OrganizationsPage/>
                    <Route path=path!("status") view=StatusPage/>
                    <Route path=path!("admin") view=AdminPage/>
                    <ParentRoute path=path!("account") view=AccountLayout>
                        <Route path=path!("me") view=AccountProfilePage/>
                        <Route path=path!("security") view=AccountSecurityPage/>
                    </ParentRoute>
                    <ParentRoute path=path!("org/:org_id/projects/:project_id") view=ProjectLayout>
                        <Route path=path!("") view=ProjectOverviewPage/>
                        <Route path=path!("settings") view=ProjectSettingsPage/>
                        <Route path=path!("setup") view=ProjectSetupPage/>
                    </ParentRoute>
                    <ParentRoute path=path!("org/:org_id") view=OrganizationLayout>
                        <Route path=path!("") view=OrganizationProjectsPage/>
                        <Route path=path!("general") view=OrganizationGeneralPage/>
                        <Route path=path!("team") view=OrganizationTeamPage/>
                        <Route path=path!("provisioning/:job_id") view=ProvisionJobPage/>
                    </ParentRoute>
                    <Route path=path!("new/:org_id") view=NewProjectPage/>
                    <Route path=path!("new/:org_id/stack") view=NewStackPage/>
                    <Route path=path!("new/:org_id/adopt") view=AdoptStackPage/>
                </ParentRoute>
            </Routes>
        </Router>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_dashboard_pages_are_return_paths() {
        for ok in [
            "/dashboard/organizations",
            "/dashboard/project/01a1c0a7-db5e-72a1-a5f2-6614555142e3?path=%2Fproject%2Fdefault",
            "/dashboard/org/x/projects/y/settings",
        ] {
            assert_eq!(sign_in_return_path(ok), Some(ok), "{ok}");
        }
        let long = format!("/dashboard/{}", "a".repeat(RETURN_PATH_MAX_LEN));
        for bad in [
            "",
            "/",
            "/dashboard",
            "//evil.test/dashboard/",
            "/\\evil.test",
            "https://evil.test/dashboard/",
            "dashboard/organizations",
            "/dashboard/sign-in",
            "/dashboard/sign-in?next=/dashboard/status",
            "/dashboard/a b",
            "/dashboard/a\r\nSet-Cookie: x=1",
            "/dashboard/\\evil.test",
            "/dashboard/é",
            long.as_str(),
        ] {
            assert_eq!(sign_in_return_path(bad), None, "{bad}");
        }
    }
}
