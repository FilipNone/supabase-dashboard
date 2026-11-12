//! Service health on the project overview and API keys on its settings
//! page.
//!
//! Health shows the last saved check with its time, never a guess. Keys are
//! write-only: the page shows whether each one is stored and when it was
//! last replaced, and a password field to replace it.

use leptos::{form::ActionForm, prelude::*};
use uuid::Uuid;

use supabase_dashboard_domain::{
    connection::{
        API_KEY_MAX_LEN, CredentialKind, CredentialOverview, CredentialState, CredentialStatus,
        HEALTH_HISTORY_MAX_ENTRIES, HEALTH_HISTORY_RETENTION_DAYS, HealthHistory,
        HealthHistoryEntry, HealthReport, KeyExpiry, STUDIO_PASSWORD_MAX_LEN,
        STUDIO_PASSWORD_MIN_LEN, STUDIO_USERNAME_MAX_LEN, SavedCredential, ServiceCheck,
        ServiceStatus, SkipReason, StackService, VersionSupport,
    },
    project::ProjectSummary,
    studio_access::{
        STUDIO_ACCESS_EXPORT_MAX, STUDIO_ACCESS_PAGE, StudioAccessEntry, StudioAccessLog,
        StudioAccessMember,
    },
};

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::{
        account::{utc_minutes, utc_seconds},
        health_chart::health_chart,
    },
    server_fns::{
        CheckProjectHealth, RemoveProjectCredential, ReplaceProjectCredential, ReplaceStudioLogin,
        get_project_credentials, get_project_health, get_project_health_history,
        get_studio_access_log,
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
    let history = Resource::new(
        move || check.version().get(),
        move |_| get_project_health_history(id),
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
                            detail="Run a check to see whether the stack's Auth, REST, Storage, Realtime, Edge Functions, and Studio services answer. Checks use the API keys and the Studio login stored under Settings.".to_string()
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
            <Transition fallback=|| ()>
                {move || history.get().map(|result| match result {
                    Ok(history) => history_view(history).into_any(),
                    Err(err) => view! {
                        <p class="form-error" role="alert">
                            {format!("Past checks could not be loaded. {err}")}
                        </p>
                    }
                    .into_any(),
                })}
            </Transition>
        </section>
    }
}

/// Past checks: counts over the retention period and the newest few.
fn history_view(history: HealthHistory) -> impl IntoView {
    let kept = format!(
        "Checks are kept for {HEALTH_HISTORY_RETENTION_DAYS} days, at most \
         {HEALTH_HISTORY_MAX_ENTRIES} per project."
    );
    let summary = match history.since {
        None => format!("No checks in the last {HEALTH_HISTORY_RETENTION_DAYS} days. {kept}"),
        Some(since) => format!(
            "{} of {} {} since {} (UTC) found a failing service. {kept}",
            history.with_failures,
            history.total,
            if history.total == 1 {
                "check"
            } else {
                "checks"
            },
            utc_minutes(since),
        ),
    };
    // Erased so the hydrate build's nested view types stay within the
    // compiler's query depth in release builds.
    let chart =
        (history.total > 0).then(|| health_chart(history.hours, history.read_at).into_any());
    let table = (!history.recent.is_empty()).then(|| {
        let rows = history.recent.into_iter().map(history_row).collect_view();
        view! {
            <div class="table-wrap" role="region" aria-label="Recent checks, newest first" tabindex="0">
                <table class="data-table">
                    <caption class="visually-hidden">"Recent checks, newest first"</caption>
                    <thead>
                        <tr>
                            <th scope="col">"Checked (UTC)"</th>
                            <th scope="col">"Result"</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        }
        .into_any()
    });
    view! {
        <h3 class="subsection-title">"Recent checks"</h3>
        <p class="section-text">{summary}</p>
        {chart}
        {table}
    }
}

fn history_row(entry: HealthHistoryEntry) -> impl IntoView {
    let names = |services: &[StackService]| {
        services
            .iter()
            .map(|service| service.label())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (class, label) = if entry.failing.is_empty() {
        ("badge badge-ok", "No failures")
    } else {
        ("badge badge-error", "Failing")
    };
    let failing = (!entry.failing.is_empty()).then(|| names(&entry.failing));
    let skipped = (!entry.not_checked.is_empty())
        .then(|| format!("Not checked: {}", names(&entry.not_checked)));
    view! {
        <tr>
            <td class="nowrap">{utc_seconds(entry.checked_at)}</td>
            <td>
                <span class=class>{label}</span>
                {failing.map(|text| view! { <span class="status-detail">{text}</span> })}
                {skipped.map(|text| view! { <span class="field-hint status-detail">{text}</span> })}
            </td>
        </tr>
    }
}

fn report_view(report: HealthReport) -> impl IntoView {
    let certificate = report.certificate_expiry().map(certificate_note);
    let rows = report.checks.into_iter().map(check_row).collect_view();
    view! {
        <p class="section-text">
            {format!(
                "Last checked {} (UTC). This is the result of that check, not live status.",
                utc_minutes(report.checked_at)
            )}
        </p>
        {certificate}
        <div class="table-wrap" role="region" aria-label="Service health" tabindex="0">
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

/// The gateway's TLS certificate expiry, flagged when it was less than
/// [`KeyExpiry::WARN_DAYS`] away at the time of the check.
fn certificate_note(expiry: KeyExpiry) -> impl IntoView {
    let date = expiry.at.to_offset(time::UtcOffset::UTC).date();
    let warning = expiry.expires_soon().then(|| {
        let left = match expiry.days_left {
            0 => "Less than a day left at this check".to_owned(),
            1 => "1 day left at this check".to_owned(),
            n => format!("{n} days left at this check"),
        };
        view! {
            " "
            <span class="badge badge-error">{left}</span>
        }
    });
    let text = if expiry.expired {
        format!("The gateway's TLS certificate expired on {date} (UTC).")
    } else {
        format!("The gateway's TLS certificate expires on {date} (UTC).")
    };
    let expired = expiry.expired.then(|| {
        view! {
            " "
            <span class="badge badge-error">"Expired at this check"</span>
        }
    });
    view! {
        <p class="section-text">
            {text}
            {warning}
            {expired}
        </p>
    }
}

/// The reported version, and how it compares with the tested one.
fn version_cell(service: StackService, version: Option<String>) -> impl IntoView {
    let Some(version) = version else {
        return view! { "Not reported" }.into_any();
    };
    let note = service
        .version_support(&version)
        .map(|support| match support {
            VersionSupport::Tested => "Tested version".to_owned(),
            VersionSupport::Older { tested } => {
                format!("Older than the tested v{tested}; some Studio pages may fail.")
            }
            VersionSupport::Newer { tested } => {
                format!("Newer than the tested v{tested}.")
            }
            VersionSupport::Unrecognized => {
                "Not a version number the dashboard can compare.".to_owned()
            }
        });
    view! {
        {version}
        {note.map(|text| view! { <span class="field-hint status-detail">{text}</span> })}
    }
    .into_any()
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
            <td>{version_cell(check.service, check.version)}</td>
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
        ServiceStatus::KeyRejected { http_status } if service == StackService::Functions => (
            "badge badge-error",
            format!("Key rejected (HTTP {http_status})"),
            Some(
                "The Edge Functions router refused the stored key. Replace it under Settings, or check the stack's JWT_SECRET.",
            ),
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
        ServiceStatus::Unhealthy { http_status: 404 } if !studio => (
            "badge badge-error",
            "Not found (HTTP 404)".into(),
            Some(
                "The gateway has no route for this service. The stack may not run it, or its gateway configuration leaves it out.",
            ),
        ),
        ServiceStatus::Unhealthy { http_status } => (
            "badge badge-error",
            format!("Error (HTTP {http_status})"),
            None,
        ),
        ServiceStatus::NotRouted { http_status } => (
            "badge badge-error",
            format!("No route (HTTP {http_status})"),
            Some(
                "The gateway sent the request to Studio's login, so it has no route for this service. The stored key was not checked.",
            ),
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
    // The action forgets its input once it completes; the result is shown
    // under the key that was submitted, so remember which one that was.
    let submitted = RwSignal::new(None::<CredentialKind>);
    Effect::new(move |_| {
        if let Some(input) = replace.input().get() {
            submitted.set(Some(input.kind));
        }
    });
    let overview = Resource::new(
        move || (replace.version().get(), remove.version().get()),
        move |_| get_project_credentials(id),
    );

    view! {
        <section class="panel" id="api-keys" aria-labelledby="api-keys-title">
            <h2 class="section-title" id="api-keys-title">"API keys"</h2>
            <p class="section-text">
                "Keys from the stack's configuration that the dashboard uses to check and manage it. They are encrypted on the dashboard server and never shown again after you save them. The service role key bypasses row-level security; it is used only by the server."
            </p>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading keys…"</p> }>
                {move || overview.get().map(|result| match result {
                    Ok(overview) => {
                        keys_view(overview, id.to_string(), can_manage, replace, remove, submitted)
                            .into_any()
                    }
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
    submitted: RwSignal<Option<CredentialKind>>,
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
        .map(|status| {
            key_row(
                status,
                id.clone(),
                can_manage,
                can_save,
                (replace, remove),
                submitted,
            )
        })
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
    (replace, remove): (
        ServerAction<ReplaceProjectCredential>,
        ServerAction<RemoveProjectCredential>,
    ),
    submitted: RwSignal<Option<CredentialKind>>,
) -> impl IntoView {
    let kind = status.kind;
    let field_id = format!("key-{}", kind.as_str());
    let hint_id = format!("{field_id}-hint");
    let result_id = format!("{field_id}-result");
    // The last save of this key, if it was the last key submitted.
    let result = move || {
        (submitted.get() == Some(kind))
            .then(|| replace.value().get())
            .flatten()
    };
    let failed = move || matches!(result(), Some(Err(_)));
    let (badge, state_text, stored) = state_badge(&status.state);
    let expiry = match status.state {
        CredentialState::Set {
            expires: Some(expiry),
            ..
        } => Some(expiry_badge(expiry)),
        _ => None,
    };
    let kind_value = kind.as_str();
    view! {
        <div class="key-item">
            <h3 class="subsection-title">
                {kind.label()} " " <span class=badge>{state_text}</span>
                {expiry.map(|(class, text)| view! { " " <span class=class>{text}</span> })}
            </h3>
            {
                let (id, field_id, hint_id, result_id) =
                    (id.clone(), field_id.clone(), hint_id.clone(), result_id.clone());
                let described_by = format!("{hint_id} {result_id}");
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
                            aria-describedby=described_by.clone()
                            aria-invalid=move || failed().then_some("true")
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
                    .then_some(" Used for the Auth, Storage, Realtime, and Edge Functions checks.")}
                {matches!(kind, CredentialKind::ServiceRoleKey)
                    .then_some(" Used for the REST check, which current gateway configurations limit to this key.")}
            </p>
            <div id=result_id>{move || feedback(result(), "Key saved.")}</div>
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
        CredentialState::Set { updated_at, .. } => (
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

/// The key's own expiry claim. The gateway passes an expired key on, and
/// the services behind it then refuse it.
pub(crate) fn expiry_badge(expiry: KeyExpiry) -> (&'static str, String) {
    let date = expiry.at.to_offset(time::UtcOffset::UTC).date();
    if expiry.expired {
        ("badge badge-error", format!("Expired {date}"))
    } else if expiry.expires_soon() {
        let days = match expiry.days_left {
            0 => "today".to_owned(),
            1 => "tomorrow".to_owned(),
            n => format!("in {n} days"),
        };
        ("badge badge-error", format!("Expires {date}, {days}"))
    } else {
        ("badge badge-muted", format!("Expires {date}"))
    }
}

/// What saving a Studio login found at the gateway. A login the gateway
/// refused arrives as an error and was not stored.
fn studio_saved(result: Result<SavedCredential, AppError>) -> AnyView {
    match result {
        Ok(SavedCredential::Confirmed) => view! {
            <p class="form-ok" role="status">"Studio login saved. The gateway accepted it."</p>
        }
        .into_any(),
        Ok(SavedCredential::NotChecked) => view! {
            <p class="form-ok" role="status">"Studio login saved."</p>
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
        <section class="panel" id="studio-login" aria-labelledby="studio-login-title">
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

/// Requests members sent through the project's Studio host, newest first.
/// Only shown to roles that may read it; the server checks again.
#[component]
pub fn StudioAccessPanel(project: ProjectSummary) -> impl IntoView {
    let id = project.id;
    let reload = RwSignal::new(0_u32);
    // Where each page after the newest starts; the last one is shown. Only
    // one page of entries is held in the browser at a time.
    let pages = RwSignal::new(Vec::<i64>::new());
    // The member whose requests are shown; `None` shows everyone's.
    let member = RwSignal::new(None::<Uuid>);
    let log = Resource::new(
        move || {
            (
                reload.get(),
                member.get(),
                pages.with(|pages| pages.last().copied()),
            )
        },
        move |(_, member, before)| get_studio_access_log(id, member, before),
    );
    // The filter sits outside the reloading part of the panel, so changing
    // it keeps focus on it. It shows the members from the latest answer.
    let choices = RwSignal::new((Vec::<StudioAccessMember>::new(), false));
    Effect::new(move |_| {
        if let Some(Ok(StudioAccessLog::On {
            members,
            more_members,
            ..
        })) = log.get()
        {
            choices.set((members, more_members));
        }
    });
    view! {
        <section class="panel" aria-labelledby="studio-log-title">
            <div class="section-header">
                <h2 class="section-title" id="studio-log-title">"Studio access log"</h2>
                <button
                    type="button"
                    class="button"
                    on:click=move |_| {
                        pages.set(Vec::new());
                        reload.update(|n| *n = n.wrapping_add(1));
                    }
                >
                    "Refresh"
                </button>
            </div>
            {move || {
                let shown = member.with(Option::is_some)
                    || choices.with(|(members, _)| !members.is_empty());
                shown.then(|| access_member_filter(id, member, choices, pages).into_any())
            }}
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading the access log…"</p> }>
                {move || log.get().map(|result| match result {
                    Ok(StudioAccessLog::Off) => view! {
                        <p class="section-text">
                            "This installation does not record Studio requests. The server's operator can turn the log on with "
                            <code>"SUPABASE_DASHBOARD_STUDIO_ACCESS_LOG_DAYS"</code>"."
                        </p>
                    }
                    .into_any(),
                    Ok(StudioAccessLog::On { retention_days, entries, older, .. }) => {
                        let filtered = member.with_untracked(Option::is_some);
                        access_log_view(retention_days, entries, older, filtered, pages).into_any()
                    }
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Access log unavailable".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
        </section>
    }
}

/// Picks whose requests the log shows. Changing it starts again from the
/// newest page.
fn access_member_filter(
    project_id: Uuid,
    member: RwSignal<Option<Uuid>>,
    choices: RwSignal<(Vec<StudioAccessMember>, bool)>,
    pages: RwSignal<Vec<i64>>,
) -> impl IntoView {
    let options = move || {
        choices.with(|(members, _)| {
            members
                .iter()
                .map(|choice| {
                    let account_id = choice.account_id;
                    view! {
                        <option
                            value=account_id.to_string()
                            prop:selected=move || member.get() == Some(account_id)
                        >
                            {format!("{} ({})", choice.display_name, choice.email)}
                        </option>
                    }
                })
                .collect_view()
        })
    };
    let export_href = move || {
        let base = format!("/dashboard/project/{project_id}/studio-access.csv");
        match member.get() {
            Some(account_id) => format!("{base}?member={account_id}"),
            None => base,
        }
    };
    let more = move || {
        choices.with(|(_, more)| *more).then(|| {
            view! {
                <p class="field-hint">
                    "More members have requests than the list can show; only the first ones by name are listed."
                </p>
            }
        })
    };
    view! {
        <div class="inline-form">
            <label class="field">
                <span class="field-label">"Member"</span>
                <select
                    class="input"
                    on:change=move |ev| {
                        member.set(Uuid::parse_str(&event_target_value(&ev)).ok());
                        pages.set(Vec::new());
                    }
                >
                    <option value="" prop:selected=move || member.get().is_none()>"All members"</option>
                    {options}
                </select>
            </label>
            // A file download, not a page: the router must not handle it.
            <a class="button" rel="external" download href=export_href>"Export CSV"</a>
        </div>
        {more}
        <p class="field-hint">
            {format!(
                "The export holds the newest {} requests at most, for the member chosen above.",
                grouped(STUDIO_ACCESS_EXPORT_MAX)
            )}
        </p>
    }
}

/// `10000` as `10,000`.
fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn access_log_view(
    retention_days: u16,
    entries: Vec<StudioAccessEntry>,
    older: Option<i64>,
    filtered: bool,
    pages: RwSignal<Vec<i64>>,
) -> impl IntoView {
    let days = if retention_days == 1 { "day" } else { "days" };
    let page = pages.with_untracked(Vec::len) + 1;
    let first_page = page == 1;
    let has_pages = !first_page || older.is_some();
    // Buttons that lead nowhere are marked `aria-disabled` rather than
    // `disabled`: a disabled button drops keyboard focus to the page body,
    // which happened whenever the pressed button had no further page.
    let off = |off: bool| off.then_some("true");
    let pager = move |where_: &'static str| {
        has_pages.then(|| {
            view! {
                <nav class="pager" aria-label=format!("Access log pages, {where_}")>
                    <button
                        type="button"
                        class="button"
                        aria-disabled=off(first_page)
                        on:click=move |_| {
                            if !first_page {
                                pages.set(Vec::new());
                            }
                        }
                    >
                        "Newest"
                    </button>
                    <button
                        type="button"
                        class="button"
                        aria-disabled=off(first_page)
                        on:click=move |_| {
                            if !first_page {
                                pages.update(|pages| {
                                    pages.pop();
                                });
                            }
                        }
                    >
                        "Newer"
                    </button>
                    // Announced once, from the top pager only.
                    <span class="field-hint" aria-live=(where_ == "top").then_some("polite")>
                        {format!("Page {page}")}
                    </span>
                    <button
                        type="button"
                        class="button"
                        aria-disabled=off(older.is_none())
                        on:click=move |_| {
                            if let Some(before) = older {
                                pages.update(|pages| pages.push(before));
                            }
                        }
                    >
                        "Older"
                    </button>
                </nav>
            }
        })
    };
    if entries.is_empty() {
        let text = if first_page && filtered {
            format!("This member sent no Studio requests in the last {retention_days} {days}.")
        } else if first_page {
            format!("No Studio requests in the last {retention_days} {days}.")
        } else {
            "No older requests are left. The oldest ones may have passed the retention period since this page was opened.".to_owned()
        };
        return view! {
            <p class="section-text">{text}</p>
            {pager("bottom")}
        }
        .into_any();
    }
    let rows = entries.into_iter().map(access_row).collect_view();
    view! {
        <p class="section-text">
            {format!(
                "Requests from the last {retention_days} {days}, newest first, {STUDIO_ACCESS_PAGE} per page. \
                 Only the method, path, and status are kept; query strings, SQL, and data are not."
            )}
        </p>
        {pager("top")}
        <div class="table-wrap" role="region" aria-label="Studio requests" tabindex="0">
            <table class="data-table access-table">
                <caption class="visually-hidden">{format!("Studio requests, newest first, page {page}")}</caption>
                <thead>
                    <tr>
                        <th scope="col">"Time (UTC)"</th>
                        <th scope="col">"Member"</th>
                        <th scope="col">"Request"</th>
                        <th scope="col">"Status"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {pager("bottom")}
    }
    .into_any()
}

fn access_row(entry: StudioAccessEntry) -> impl IntoView {
    let member = match entry.member {
        Some(member) => view! {
            <span>{member.display_name}</span>
            <span class="field-hint status-detail">{member.email}</span>
        }
        .into_any(),
        None => view! { <span class="field-hint">"Deleted account"</span> }.into_any(),
    };
    let class = if entry.status < 400 {
        "badge badge-ok"
    } else {
        "badge badge-error"
    };
    view! {
        <tr>
            <td class="nowrap">{utc_seconds(entry.at)}</td>
            <td>{member}</td>
            <td class="request"><code class="request-path">{format!("{} {}", entry.method, entry.path)}</code></td>
            <td><span class=class>{entry.status}</span></td>
        </tr>
    }
}

#[cfg(test)]
mod tests {
    use super::grouped;

    #[test]
    fn numbers_are_grouped_by_thousands() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(10_000), "10,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }
}
