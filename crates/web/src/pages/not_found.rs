use leptos::prelude::*;
use leptos_meta::Title;

use crate::components::page::{StatePanel, StateTone};

#[component]
pub fn NotFound() -> impl IntoView {
    #[cfg(feature = "ssr")]
    {
        if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
            response.set_status(http::StatusCode::NOT_FOUND);
        }
    }
    view! {
        <Title text="Page not found"/>
        <main class="standalone" id="main-content">
            <StatePanel
                tone=StateTone::Empty
                title="Page not found".to_string()
                detail="The page you requested does not exist.".to_string()
            />
            <a class="button" href="/dashboard/organizations">"Go to dashboard"</a>
        </main>
    }
}
