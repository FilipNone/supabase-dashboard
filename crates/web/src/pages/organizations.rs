use leptos::prelude::*;
use leptos_meta::Title;

use crate::components::page::{PageHeader, StatePanel, StateTone};

#[component]
pub fn OrganizationsPage() -> impl IntoView {
    view! {
        <Title text="Organizations"/>
        <PageHeader
            title="Organizations"
            description="Organizations group dashboard members and the self-hosted projects they manage."
        />
        <StatePanel
            tone=StateTone::Empty
            title="No organizations yet".to_string()
            detail="Sign-in and organization management are not available in this build. They are planned for milestone M1.".to_string()
        />
    }
}
