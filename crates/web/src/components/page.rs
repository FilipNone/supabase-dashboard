use leptos::prelude::*;

/// Standard page heading with optional description and actions.
#[component]
pub fn PageHeader(
    title: &'static str,
    #[prop(optional)] description: Option<&'static str>,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <header class="page-header">
            <div>
                <h1 class="page-title">{title}</h1>
                {description.map(|text| view! { <p class="page-description">{text}</p> })}
            </div>
            <div class="page-actions">{children.map(|c| c())}</div>
        </header>
    }
}

/// Empty, error, and unsupported states share one visual treatment; the
/// `tone` selects the color and ARIA role.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StateTone {
    Empty,
    Error,
}

#[component]
pub fn StatePanel(
    tone: StateTone,
    title: String,
    #[prop(optional)] detail: Option<String>,
) -> impl IntoView {
    let (class, role) = match tone {
        StateTone::Empty => ("state-panel", "status"),
        StateTone::Error => ("state-panel state-error", "alert"),
    };
    view! {
        <div class=class role=role>
            <p class="state-title">{title}</p>
            {detail.map(|text| view! { <p class="state-detail">{text}</p> })}
        </div>
    }
}
