//! Service health on the project overview and API keys on its settings
//! page.
//!
//! Health shows the last saved check with its time, never a guess. Keys are
//! write-only: the page shows whether each one is stored and when it was
//! last replaced, and a password field to replace it.

use leptos::{form::ActionForm, prelude::*};
use supabase_dashboard_domain::{
    connection::{
        API_KEY_MAX_LEN, CredentialKind, CredentialOverview, CredentialState, CredentialStatus,
        HealthReport, STUDIO_PASSWORD_MAX_LEN, STUDIO_PASSWORD_MIN_LEN, STUDIO_USERNAME_MAX_LEN,
        SavedCredential, ServiceCheck, ServiceStatus, SkipReason, StackService,
    },
    project::ProjectSummary,
};

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::account::utc_minutes,
    server_fns::{
        CheckProjectHealth, RemoveProjectCredential, ReplaceProjectCredential, ReplaceStudioLogin,
        get_project_credentials, get_project_health,
    },
};

fn feedback<T>(value: Option<Result<T, AppError>>, ok: &'static str) -> Option<AnyView> {
    value.map(|result| match result {
        Ok(_) => view! { <p class="form-ok" role="status">{ok}</p> }.into_any(),
        Err(err) => view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any(),
    })
}

/// The overview's health section: the last saved check and a button to run
/// a new one. Any member can run a check.
#[component]
pub fn HealthPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let check = ServerAction::<CheckProjectHealth>::new();
    let report = Resource::new(
        move || check.version().get(),
        move |_| get_project_health(id),
    );

    view! {
        <section class="panel" aria-labelledby="health-title">
            <div class="section-header">
                <h2 class="section-title" id="health-title">"Service health"</h2>
                <ActionForm action=check>
                    <input type="hidden" name="id" value=id.to_string()/>
                    <button type="submit" class="button" disabled=move || check.pending().get()>
                        {move || if check.pending().get() { "Checking…" } else { "Check now" }}
                    </button>
                </ActionForm>
            </div>
            {move || check.value().get().and_then(Result::err).map(|err| view! {
                <p class="form-error" role="alert">{err.to_string()}</p>
            })}
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading the last check…"</p> }>
                {move || report.get().map(|result| match result {
                    Ok(Some(report)) => report_view(report).into_any(),
                    Ok(None) => view! {
                        <StatePanel
                            tone=StateTone::Empty
                            title="Not checked yet".to_string()
                            detail="Run a check to see whether the stack's Auth and REST services answer. Checks use the API keys stored under Settings.".to_string()
                        />
                    }
                    .into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Health unavailable".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
        </section>
    }
}

fn report_view(report: HealthReport) -> impl IntoView {
    let rows = report.checks.into_iter().map(check_row).collect_view();
    view! {
        <p class="section-text">
            {format!(
                "Last checked {} (UTC). This is the result of that check, not live status.",
                utc_minutes(report.checked_at)
            )}
        </p>
        <div class="table-wrap">
            <table class="data-table">
                <caption class="visually-hidden">"Service health"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Service"</th>
                        <th scope="col">"Status"</th>
                        <th scope="col">"Version"</th>
                        <th scope="col">"Response time"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
}

fn check_row(check: ServiceCheck) -> impl IntoView {
    let (badge_class, label, detail) = describe(check.service, &check.status);
    view! {
        <tr>
            <td>{check.service.label()}</td>
            <td>
                <span class=badge_class>{label}</span>
                {detail.map(|text| view! { <span class="field-hint status-detail">{text}</span> })}
            </td>
            <td>{check.version.unwrap_or_else(|| "Not reported".to_owned())}</td>
            <td class="nowrap">
                {check.latency_ms.map_or_else(|| "–".to_owned(), |ms| format!("{ms} ms"))}
            </td>
        </tr>
    }
}

/// Badge class, short label, and an optional explanation.
fn describe(
    service: StackService,
    status: &ServiceStatus,
) -> (&'static str, String, Option<&'static str>) {
    let studio = service == StackService::Studio;
    match status {
        ServiceStatus::Healthy => ("badge badge-ok", "Healthy".into(), None),
        ServiceStatus::KeyRejected { http_status } if studio => (
            "badge badge-error",
            format!("Login rejected (HTTP {http_status})"),
            Some("The gateway refused the stored Studio login. Replace it under Settings."),
        ),
        ServiceStatus::KeyRejected { http_status } => (
            "badge badge-error",
            format!("Key rejected (HTTP {http_status})"),
            Some("The gateway refused the stored key. Replace it under Settings."),
        ),
        ServiceStatus::Unprotected { http_status } => (
            "badge badge-error",
            format!("No password (HTTP {http_status})"),
            Some(
                "The gateway opens Studio without a password, so anyone who can reach the API URL can use it without the dashboard. Set DASHBOARD_PASSWORD on the stack and restart its gateway.",
            ),
        ),
        ServiceStatus::Unhealthy { http_status } if (300..400).contains(http_status) => (
            "badge badge-error",
            format!("Redirected (HTTP {http_status})"),
            Some("The dashboard does not follow redirects. Check the API URL."),
        ),
        ServiceStatus::Unhealthy { http_status } => (
            "badge badge-error",
            format!("Error (HTTP {http_status})"),
            None,
        ),
        ServiceStatus::Unreachable { reason } => (
            "badge badge-error",
            "Unreachable".into(),
            Some(reason.message()),
        ),
        ServiceStatus::NotChecked { reason } => (
            "badge badge-muted",
            "Not checked".into(),
            Some(match reason {
                SkipReason::MissingKey if studio => "No Studio login is stored for this project.",
                SkipReason::MissingKey => "No API key is stored for this project.",
                SkipReason::UnreadableKey => {
                    "The stored key was encrypted with a different server key. Enter it again under Settings."
                }
            }),
        ),
    }
}

/// The settings page's key section.
#[component]
pub fn ApiKeysPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let can_manage = project
        .role
        .allows(supabase_dashboard_domain::authz::Permission::ProjectCredentialsReplace);
    let replace = ServerAction::<ReplaceProjectCredential>::new();
    let remove = ServerAction::<RemoveProjectCredential>::new();
    let overview = Resource::new(
        move || (replace.version().get(), remove.version().get()),
        move |_| get_project_credentials(id),
    );

    view! {
        <section class="panel" aria-labelledby="api-keys-title">
            <h2 class="section-title" id="api-keys-title">"API keys"</h2>
            <p class="section-text">
                "Keys from the stack's configuration that the dashboard uses to check and manage it. They are encrypted on the dashboard server and never shown again after you save them. The service role key bypasses row-level security; it is used only by the server."
            </p>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading keys…"</p> }>
                {move || overview.get().map(|result| match result {
                    Ok(overview) => keys_view(overview, id.to_string(), can_manage, replace, remove).into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Keys unavailable".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
            {move || feedback(replace.value().get(), "Key saved.")}
            {move || feedback(remove.value().get(), "Key removed.")}
            {(!can_manage).then(|| view! {
                <p class="field-hint">"Only owners and administrators can change API keys."</p>
            })}
        </section>
    }
}

fn keys_view(
    overview: CredentialOverview,
    id: String,
    can_manage: bool,
    replace: ServerAction<ReplaceProjectCredential>,
    remove: ServerAction<RemoveProjectCredential>,
) -> impl IntoView {
    let unavailable = (!overview.storage_available).then(|| {
        view! {
            <StatePanel
                tone=StateTone::Error
                title="Key storage is not configured".to_string()
                detail="The dashboard server has no encryption key, so it cannot store or use API keys. Set SUPABASE_DASHBOARD_SECRET_KEY_FILE and restart it; see the deployment guide.".to_string()
            />
        }
    });
    let can_save = can_manage && overview.storage_available;
    let rows = overview
        .credentials
        .into_iter()
        .filter(|status| CredentialKind::API_KEYS.contains(&status.kind))
        .map(|status| key_row(status, id.clone(), can_manage, can_save, replace, remove))
        .collect_view();
    view! {
        {unavailable}
        <div class="key-list">{rows}</div>
    }
}

fn key_row(
    status: CredentialStatus,
    id: String,
    can_manage: bool,
    can_save: bool,
    replace: ServerAction<ReplaceProjectCredential>,
    remove: ServerAction<RemoveProjectCredential>,
) -> impl IntoView {
    let kind = status.kind;
    let field_id = format!("key-{}", kind.as_str());
    let hint_id = format!("{field_id}-hint");
    let (badge, state_text, stored) = state_badge(&status.state);
    let kind_value = kind.as_str();
    view! {
        <div class="key-item">
            <h3 class="subsection-title">
                {kind.label()} " " <span class=badge>{state_text}</span>
            </h3>
            {
                let (id, field_id, hint_id) = (id.clone(), field_id.clone(), hint_id.clone());
                can_save.then(move || view! {
                <ActionForm action=replace attr:class="inline-form">
                    <input type="hidden" name="id" value=id.clone()/>
                    <input type="hidden" name="kind" value=kind_value/>
                    <label class="field" for=field_id.clone()>
                        <span class="field-label">
                            {if stored { "Replace with a new key" } else { "Key" }}
                        </span>
                        <input
                            class="input" id=field_id.clone() name="value" type="password" required
                            autocomplete="off" spellcheck="false"
                            maxlength=API_KEY_MAX_LEN.to_string()
                            aria-describedby=hint_id.clone()
                        />
                    </label>
                    <button type="submit" class="button button-primary"
                        disabled=move || replace.pending().get()>
                        "Save key"
                    </button>
                </ActionForm>
                })
            }
            <p class="field-hint" id=hint_id>
                {format!("{} in the stack's .env file.", kind.env_name())}
                {matches!(kind, CredentialKind::AnonKey)
                    .then_some(" Used for the Auth check.")}
                {matches!(kind, CredentialKind::ServiceRoleKey)
                    .then_some(" Used for the REST check, which current gateway configurations limit to this key.")}
            </p>
            {(can_manage && stored).then(|| view! {
                <ActionForm action=remove>
                    <input type="hidden" name="id" value=id.clone()/>
                    <input type="hidden" name="kind" value=kind_value/>
                    <button type="submit" class="button" disabled=move || remove.pending().get()>
                        "Remove key"
                    </button>
                </ActionForm>
            })}
        </div>
    }
}

fn state_badge(state: &CredentialState) -> (&'static str, String, bool) {
    match *state {
        CredentialState::NotSet => ("badge badge-muted", "Not set".to_owned(), false),
        CredentialState::Set { updated_at } => (
            "badge badge-ok",
            format!("Set {} (UTC)", utc_minutes(updated_at)),
            true,
        ),
        CredentialState::Unreadable { updated_at } => (
            "badge badge-error",
            format!(
                "Unreadable, saved {} (UTC) under a different server key",
                utc_minutes(updated_at)
            ),
            true,
        ),
    }
}

/// What saving a Studio login found at the gateway. A login the gateway
/// refused arrives as an error and was not stored.
fn studio_saved(result: Result<SavedCredential, AppError>) -> AnyView {
    match result {
        Ok(SavedCredential::Confirmed | SavedCredential::NotChecked) => view! {
            <p class="form-ok" role="status">"Studio login saved. The gateway accepted it."</p>
        }
        .into_any(),
        Ok(SavedCredential::Unconfirmed { status }) => {
            let (_, label, detail) = describe(StackService::Studio, &status);
            view! {
                <div class="form-warning" role="status">
                    <p>{format!("Studio login saved, but the gateway did not confirm it: {label}.")}</p>
                    {detail.map(|text| view! { <p>{text}</p> })}
                </div>
            }
            .into_any()
        }
        Err(err) => view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any(),
    }
}

/// The settings page's Studio section: the gateway login the dashboard
/// adds when it opens the project's Studio for a member.
#[component]
pub fn StudioLoginPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let can_manage = project
        .role
        .allows(supabase_dashboard_domain::authz::Permission::ProjectCredentialsReplace);
    let replace = ServerAction::<ReplaceStudioLogin>::new();
    let remove = ServerAction::<RemoveProjectCredential>::new();
    let overview = Resource::new(
        move || (replace.version().get(), remove.version().get()),
        move |_| get_project_credentials(id),
    );
    let form = move |overview: CredentialOverview| {
        let state = overview
            .credentials
            .iter()
            .find(|c| c.kind == CredentialKind::StudioLogin)
            .map_or(CredentialState::NotSet, |c| c.state.clone());
        let (badge, text, stored) = state_badge(&state);
        let can_save = can_manage && overview.storage_available;
        let id = id.to_string();
        view! {
            <p><span class=badge>{text}</span></p>
            {let id = id.clone(); can_save.then(move || view! {
                <ActionForm action=replace attr:class="stacked-form">
                    <input type="hidden" name="id" value=id.clone()/>
                    <label class="field">
                        <span class="field-label">"User name (DASHBOARD_USERNAME)"</span>
                        <input
                            class="input" name="username" required autocomplete="off"
                            spellcheck="false" value="supabase"
                            maxlength=STUDIO_USERNAME_MAX_LEN.to_string()
                        />
                    </label>
                    <label class="field">
                        <span class="field-label">
                            {if stored { "New password (DASHBOARD_PASSWORD)" } else { "Password (DASHBOARD_PASSWORD)" }}
                        </span>
                        <input
                            class="input" name="password" type="password" required
                            autocomplete="new-password" spellcheck="false"
                            minlength=STUDIO_PASSWORD_MIN_LEN.to_string()
                            maxlength=STUDIO_PASSWORD_MAX_LEN.to_string()
                            aria-describedby="studio-password-hint"
                        />
                        <span class="field-hint" id="studio-password-hint">
                            {format!("At least {STUDIO_PASSWORD_MIN_LEN} characters. Use a long random value that only the dashboard knows, set the same value on the stack, and restart its gateway.")}
                        </span>
                    </label>
                    <div>
                        <button type="submit" class="button button-primary"
                            disabled=move || replace.pending().get()>
                            "Save Studio login"
                        </button>
                    </div>
                </ActionForm>
            })}
            {(can_manage && stored).then(|| view! {
                <ActionForm action=remove>
                    <input type="hidden" name="id" value=id.clone()/>
                    <input type="hidden" name="kind" value=CredentialKind::StudioLogin.as_str()/>
                    <button type="submit" class="button" disabled=move || remove.pending().get()>
                        "Remove Studio login"
                    </button>
                </ActionForm>
            })}
        }
    };

    view! {
        <section class="panel" aria-labelledby="studio-login-title">
            <h2 class="section-title" id="studio-login-title">"Studio access"</h2>
            <p class="section-text">
                "The stack's gateway protects Studio with a user name and password. The dashboard keeps them encrypted on the server and adds them when a member opens Studio, so members never see them. Anyone who opens Studio can run any SQL and read the stack's keys; owners, admins, and developers can open it, viewers cannot."
            </p>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading…"</p> }>
                {move || overview.get().map(|result| match result {
                    Ok(overview) => form(overview).into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Studio login unavailable".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
            {move || replace.value().get().map(studio_saved)}
            {move || feedback(remove.value().get(), "Studio login removed.")}
            {(!can_manage).then(|| view! {
                <p class="field-hint">"Only owners and administrators can change the Studio login."</p>
            })}
        </section>
    }
}
