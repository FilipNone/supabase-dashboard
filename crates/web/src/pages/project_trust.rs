//! The settings page's certificate section: private authorities trusted
//! for this project's gateway only.
//!
//! Certificates are public, so every member sees which ones are stored.
//! Only the roles that replace keys can change them, and the server checks
//! that the pasted text holds nothing but usable certificates.

use leptos::{form::ActionForm, prelude::*};
use supabase_dashboard_domain::{
    authority::{
        AuthorityInfo, MAX_PROJECT_AUTHORITIES, MAX_PROJECT_AUTHORITIES_BYTES, ProjectTrust,
    },
    authz::Permission,
    project::ProjectSummary,
};
use time::OffsetDateTime;

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::{account::utc_minutes, project_connection::expiry_badge},
    server_fns::{RemoveProjectAuthorities, ReplaceProjectAuthorities, get_project_authorities},
};

fn authority_row(info: AuthorityInfo, read_at: OffsetDateTime) -> impl IntoView {
    let (class, label) = expiry_badge(info.expiry(read_at));
    view! {
        <li>
            <p class="authority-subject">{info.subject}" "<span class=class>{label}</span></p>
            <p class="authority-fingerprint">
                <span class="visually-hidden">"SHA-256 fingerprint: "</span>
                <code>{info.sha256}</code>
            </p>
        </li>
    }
}

fn stored_view(trust: Option<ProjectTrust>) -> AnyView {
    match trust {
        None => view! {
            <p><span class="badge badge-muted">"None stored"</span></p>
        }
        .into_any(),
        Some(trust) if trust.authorities.is_empty() => view! {
            <p class="form-error" role="alert">
                "The stored certificates can no longer be read, so checks of this project trust only the shared roots. Replace or remove them."
            </p>
        }
        .into_any(),
        Some(trust) => {
            let read_at = trust.read_at;
            let count = trust.authorities.len();
            let rows = trust
                .authorities
                .into_iter()
                .map(|info| authority_row(info, read_at))
                .collect_view();
            view! {
                <p class="section-text">
                    {format!(
                        "{count} {} stored, last changed {} UTC.",
                        if count == 1 { "certificate" } else { "certificates" },
                        utc_minutes(trust.updated_at)
                    )}
                </p>
                <ul class="authority-list">{rows}</ul>
            }
            .into_any()
        }
    }
}

fn saved_feedback(result: Result<ProjectTrust, AppError>) -> AnyView {
    match result {
        Ok(trust) => {
            let count = trust.authorities.len();
            let text = format!(
                "Saved {count} {}. The next check of this project uses {}.",
                if count == 1 {
                    "certificate"
                } else {
                    "certificates"
                },
                if count == 1 { "it" } else { "them" }
            );
            view! { <p class="form-ok" role="status">{text}</p> }.into_any()
        }
        Err(err) => view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any(),
    }
}

/// Private certificate authorities for one project's gateway.
#[component]
pub fn AuthoritiesPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let can_manage = project.role.allows(Permission::ProjectCredentialsReplace);
    let replace = ServerAction::<ReplaceProjectAuthorities>::new();
    let remove = ServerAction::<RemoveProjectAuthorities>::new();
    let trust = Resource::new(
        move || (replace.version().get(), remove.version().get()),
        move |_| get_project_authorities(id),
    );
    // Clear the pasted text once it is saved; a refusal keeps it so it can
    // be corrected.
    let form = NodeRef::<leptos::html::Form>::new();
    Effect::new(move |_| {
        if matches!(replace.value().get(), Some(Ok(_))) {
            #[cfg(feature = "hydrate")]
            if let Some(form) = form.get() {
                form.reset();
            }
        }
    });
    let id = id.to_string();
    let manage = move |stored: bool| {
        let id = id.clone();
        can_manage.then(move || {
            let remove_id = id.clone();
            view! {
                <ActionForm action=replace node_ref=form attr:class="stacked-form">
                    <input type="hidden" name="id" value=id.clone()/>
                    <label class="field">
                        <span class="field-label">
                            {if stored { "Replace with these certificates (PEM)" } else { "Certificates (PEM)" }}
                        </span>
                        <textarea
                            class="input textarea" name="pem" required rows="6"
                            spellcheck="false" autocomplete="off"
                            maxlength=MAX_PROJECT_AUTHORITIES_BYTES.to_string()
                            aria-describedby="authorities-hint"
                            placeholder="-----BEGIN CERTIFICATE-----"
                        ></textarea>
                        <span class="field-hint" id="authorities-hint">
                            {format!("Up to {MAX_PROJECT_AUTHORITIES} certificates. Paste only the authority's certificates, never a private key.")}
                        </span>
                    </label>
                    <div>
                        <button type="submit" class="button button-primary"
                            disabled=move || replace.pending().get()>
                            "Save certificates"
                        </button>
                    </div>
                </ActionForm>
                {stored.then(|| view! {
                    <ActionForm action=remove>
                        <input type="hidden" name="id" value=remove_id/>
                        <button type="submit" class="button" disabled=move || remove.pending().get()>
                            "Remove certificates"
                        </button>
                    </ActionForm>
                })}
            }
        })
    };

    view! {
        <section class="panel" id="authorities" aria-labelledby="authorities-title">
            <h2 class="section-title" id="authorities-title">"Certificate authorities"</h2>
            <p class="section-text">
                "If this project's gateway uses a certificate from a private authority, store that authority's certificate here. Health checks and Studio traffic for this project then trust it in addition to the public roots. Other projects do not."
            </p>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading…"</p> }>
                {move || trust.get().map(|result| match result {
                    Ok(trust) => {
                        let stored = trust.is_some();
                        view! { {stored_view(trust)} {manage.clone()(stored)} }.into_any()
                    }
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Certificate authorities unavailable".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
            {move || replace.value().get().map(saved_feedback)}
            {move || remove.value().get().map(|result| match result {
                Ok(()) => view! {
                    <p class="form-ok" role="status">"Certificates removed. Checks of this project trust only the shared roots."</p>
                }
                .into_any(),
                Err(err) => view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any(),
            })}
            {(!can_manage).then(|| view! {
                <p class="field-hint">"Only owners and administrators can change these certificates."</p>
            })}
        </section>
    }
}
