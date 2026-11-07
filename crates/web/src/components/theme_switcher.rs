use leptos::prelude::*;
use supabase_dashboard_domain::theme::{THEME_COOKIE, ThemePreference};

use crate::app::initial_theme;

/// Segmented control for System / Light / Dark.
///
/// The choice is stored in a non-HttpOnly cookie so the server can render
/// the right theme on the next request. The cookie holds no secret.
#[component]
pub fn ThemeSwitcher() -> impl IntoView {
    let (theme, set_theme) = signal(initial_theme());

    view! {
        <div class="segmented" role="group" aria-label="Color theme">
            {ThemePreference::ALL
                .into_iter()
                .map(|option| {
                    view! {
                        <button
                            type="button"
                            class="segmented-item"
                            aria-pressed=move || (theme.get() == option).to_string()
                            on:click=move |_| {
                                set_theme.set(option);
                                apply_theme(option);
                            }
                        >
                            {option.label()}
                        </button>
                    }
                })
                .collect_view()}
        </div>
    }
}

#[cfg(feature = "hydrate")]
fn apply_theme(theme: ThemePreference) {
    use wasm_bindgen::JsCast;

    let document = document();
    if let Some(root) = document.document_element() {
        // Failure leaves the previous theme in place; nothing to recover.
        let _ = root.set_attribute("data-theme", theme.as_str());
    }
    if let Ok(html) = document.dyn_into::<web_sys::HtmlDocument>() {
        let cookie = format!(
            "{THEME_COOKIE}={}; Path=/; Max-Age=31536000; SameSite=Lax",
            theme.as_str()
        );
        let _ = html.set_cookie(&cookie);
    }
}

#[cfg(not(feature = "hydrate"))]
fn apply_theme(_theme: ThemePreference) {
    let _ = THEME_COOKIE;
}
