//! The overview's connection guidance: where each service answers under
//! the project's gateway and which key an application uses with it.
//!
//! No key is shown here. Studio already has the REST API documentation for
//! the project's tables and its own API keys page, so this panel links to
//! those for the roles that may open Studio instead of repeating them.

use leptos::prelude::*;
use supabase_dashboard_domain::{authz::Permission, project::ProjectSummary};

use crate::pages::project::studio_launch_path;

/// Studio pages the panel links to, through the dashboard's launcher.
const STUDIO_API_DOCS: &str = "/project/default/integrations/data_api/docs";
const STUDIO_API_KEYS: &str = "/project/default/settings/api-keys";

fn client_snippet(api_url: &str) -> String {
    format!(
        "import {{ createClient }} from '@supabase/supabase-js'\n\n\
         const supabase = createClient(\n  '{api_url}',\n  process.env.SUPABASE_ANON_KEY,\n)"
    )
}

/// Connection guidance for applications that use this project.
#[component]
pub fn ConnectPanel(project: ProjectSummary) -> impl IntoView {
    let api_url = project.api_url.as_str().to_owned();
    let rows = project
        .api_url
        .client_endpoints()
        .into_iter()
        .map(|endpoint| {
            view! {
                <tr>
                    <th scope="row">{endpoint.service}</th>
                    <td><code class="url-text">{endpoint.url}</code></td>
                </tr>
            }
        })
        .collect_view();
    let plain_http = (!project.api_url.is_encrypted()).then(|| {
        view! {
            <p class="form-error" role="note">
                "This gateway uses plain HTTP, so keys and user sessions cross the network unencrypted. Serve it over HTTPS before applications outside a private network use it."
            </p>
        }
    });
    let studio_links = project.role.allows(Permission::StudioOpen).then(|| {
        let launcher = studio_launch_path(project.id);
        let docs = format!("{launcher}?path={STUDIO_API_DOCS}");
        let keys = format!("{launcher}?path={STUDIO_API_KEYS}");
        view! {
            <p>
                "Studio documents the REST API for this project's tables and shows the stack's keys: "
                <a href=docs rel="external">"API documentation"</a>
                ", "
                <a href=keys rel="external">"API keys"</a>
                "."
            </p>
        }
    });

    view! {
        <section class="panel" id="connect" aria-labelledby="connect-title">
            <h2 class="section-title" id="connect-title">"Connect to this project"</h2>
            <p class="section-text">
                "Applications reach every service through the gateway at the API URL. Browser and mobile apps use the anon key, which row-level security limits. The service role key bypasses row-level security, so keep it on servers you control. The dashboard does not show either key; they are ANON_KEY and SERVICE_ROLE_KEY in the stack's configuration, or SUPABASE_PUBLISHABLE_KEY and SUPABASE_SECRET_KEY where the stack uses the newer opaque keys."
            </p>
            {plain_http}
            <div class="table-wrap">
                <table class="data-table">
                    <caption class="visually-hidden">"Service addresses"</caption>
                    <thead>
                        <tr><th scope="col">"Service"</th><th scope="col">"Address"</th></tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            <p class="field-hint">
                "These addresses follow from the API URL. Service health above shows which ones answered the last check."
            </p>
            <h3 class="subsection-title">"supabase-js"</h3>
            <pre class="code-block" tabindex="0" aria-label="supabase-js client setup"><code>{client_snippet(&api_url)}</code></pre>
            {studio_links}
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_snippet_names_the_url_and_reads_the_key_from_the_environment() {
        let snippet = client_snippet("https://api.example.test");
        assert!(snippet.contains("createClient(\n  'https://api.example.test',"));
        assert!(snippet.contains("process.env.SUPABASE_ANON_KEY"));
    }
}
