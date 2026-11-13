//! A provisioned stack's settings, on the project overview, for owners
//! and admins.
//!
//! The form reads the settings from the service's variables in Dokploy.
//! "Review changes" asks the server what would change, and lists the
//! changed variable names and the services that restart; "Apply and
//! redeploy" queues the change. The server checks the role, the values,
//! and that the stack did not change since the review.
//!
//! Above the form, the section lists by name the variables edited in
//! Dokploy since the dashboard wrote them, and lets the operator accept
//! them so they stop being listed.

use leptos::{form::ActionForm, prelude::*};

use supabase_dashboard_domain::stack_settings::{
    EnvChanges, EnvTracking, SettingKind, SettingState, StackConfigPreview, StackSettingView,
    StackSettingsView,
};

use crate::{
    error::AppError,
    server_fns::{
        AcceptStackVariables, PreviewStackSettings, QueueStackSettings, SettingsFields,
        get_stack_settings,
    },
};

#[component]
pub fn StackSettingsSection(
    project: uuid::Uuid,
    apply: ServerAction<QueueStackSettings>,
    /// Counts the stack's actions that finished while the page was open.
    finished: Signal<u32>,
) -> impl IntoView {
    let review = ServerAction::<PreviewStackSettings>::new();
    let accept = ServerAction::<AcceptStackVariables>::new();
    // Counts refused applies and answered accepts: the settings are read
    // again, because a refusal usually means they changed in Dokploy
    // since the page read them, and an accept changes the list.
    let reloads = RwSignal::new(0u32);
    // Read again once a queued change has been written, not when it is
    // queued: the section keeps its elements, and focus, until then.
    let settings = Resource::new(
        move || (project, finished.get(), reloads.get()),
        |(id, _, _)| get_stack_settings(id),
    );
    // The review shows until a field changes or the stack's action ends.
    let reviewing = RwSignal::new(false);
    // A change was queued from this page and has not finished.
    let queued = RwSignal::new(false);
    Effect::new(move |_| {
        if review.value().with(|value| matches!(value, Some(Ok(_)))) {
            reviewing.set(true);
        }
    });
    Effect::new(move |_| {
        apply.value().with(|value| match value {
            Some(Ok(_)) => queued.set(true),
            Some(Err(_)) => {
                reviewing.set(false);
                reloads.update(|n| *n += 1);
            }
            None => {}
        });
    });
    Effect::new(move |_| {
        if accept.value().with(Option::is_some) {
            reviewing.set(false);
            reloads.update(|n| *n += 1);
        }
    });
    // A new review replaces the outcome of the last apply or accept.
    Effect::new(move |_| {
        if review.pending().get() {
            apply.value().set(None);
            accept.value().set(None);
        }
    });
    Effect::new(move |previous: Option<u32>| {
        let now = finished.get();
        if previous.is_some_and(|previous| previous != now) {
            reviewing.set(false);
            queued.set(false);
        }
        now
    });
    view! {
        <Transition fallback=|| ()>
            {move || settings.get().map(|result| match result {
                Ok(Some(view)) => {
                    // Not the first reading: the values on screen are stale.
                    let reread = finished.get_untracked() > 0 || reloads.get_untracked() > 0;
                    let actions = Actions { review, apply, accept };
                    section(view, project, actions, reviewing, queued, reread).into_any()
                }
                // Not provisioned, removed, or not an owner or admin.
                Ok(None) | Err(AppError::Forbidden) | Err(AppError::NotFound) => ().into_any(),
                Err(err) => view! {
                    <section class="panel" aria-labelledby="stack-settings-title">
                        <h2 class="section-title" id="stack-settings-title">"Stack settings"</h2>
                        <p class="section-text">{format!("The settings could not be read. {err}")}</p>
                    </section>
                }
                .into_any(),
            })}
        </Transition>
    }
}

#[derive(Clone, Copy)]
struct Actions {
    review: ServerAction<PreviewStackSettings>,
    apply: ServerAction<QueueStackSettings>,
    accept: ServerAction<AcceptStackVariables>,
}

fn section(
    view: StackSettingsView,
    project: uuid::Uuid,
    Actions {
        review,
        apply,
        accept,
    }: Actions,
    reviewing: RwSignal<bool>,
    queued: RwSignal<bool>,
    reread: bool,
) -> impl IntoView {
    let form = NodeRef::<leptos::html::Form>::new();
    let heading = NodeRef::<leptos::html::H2>::new();
    if reread {
        // The section's elements are updated in place, which leaves what
        // was typed in a field; resetting the form shows the values just
        // read. The review and its Apply button are gone, so focus moves
        // to the heading instead of the page.
        Effect::new(move |_| {
            if let Some(form) = form.get() {
                form.reset();
            }
            let lost = document()
                .active_element()
                .is_none_or(|active| document().body().is_some_and(|body| *body == active));
            if lost && let Some(heading) = heading.get() {
                let _ = heading.focus();
            }
        });
    }
    let apply_error = move || {
        apply
            .value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };
    let running = view.busy;
    let busy = move || running || queued.get();
    let disabled = move || (busy() || review.pending().get()).then_some("true");
    let review_error = move || {
        review
            .value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };
    let tracking = tracking_view(view.tracking, project, accept, Signal::derive(busy));
    let fields = view.settings.into_iter().map(field_view).collect_view();
    let summary = move || {
        if !reviewing.get() {
            return None;
        }
        let (fields, preview) = review.value().get()?.ok()?;
        Some(review_view(project, fields, preview, apply, queued))
    };
    view! {
        <section class="panel" aria-labelledby="stack-settings-title">
            <h2 class="section-title" id="stack-settings-title" tabindex="-1" node_ref=heading>"Stack settings"</h2>
            <p class="section-text">
                "These are variables of the stack's service in Dokploy. Applying a change writes them there and redeploys the stack; only the services that read a changed setting restart. A setting changed in Dokploy meanwhile stops the change before anything is written."
            </p>
            {tracking}
            <ActionForm action=review node_ref=form attr:class="stacked-form settings-form">
                <input type="hidden" name="id" value=project.to_string()/>
                // A review describes the values it was made from; changing
                // a field withdraws it.
                <div class="settings-fields"
                    on:input=move |_| reviewing.set(false)
                    on:change=move |_| reviewing.set(false)>
                    {fields}
                </div>
                {review_error}
                <div>
                    <button type="submit" class="button" aria-disabled=disabled>"Review changes"</button>
                </div>
            </ActionForm>
            {move || busy().then(|| view! {
                <p class="field-hint">"An action on this stack is running; wait for it to finish before changing settings."</p>
            })}
            {apply_error}
            {move || queued.get().then(|| view! {
                <p class="form-ok" role="status">
                    "Queued. The Dokploy service section follows the change; these settings are read again when it finishes."
                </p>
            })}
            <div aria-live="polite">{summary}</div>
        </section>
    }
}

/// Which variables were edited in Dokploy since the dashboard wrote
/// them, by name, and the form that accepts them.
fn tracking_view(
    tracking: EnvTracking,
    project: uuid::Uuid,
    accept: ServerAction<AcceptStackVariables>,
    busy: Signal<bool>,
) -> impl IntoView {
    let seen = tracking.seen();
    let form = move |label: &'static str| accept_form(project, seen.clone(), label, accept, busy);
    let outcome = move || {
        accept.value().get().map(|result| match result {
            Ok(()) => view! {
                <p class="form-ok" role="status">
                    "Accepted. Later edits in Dokploy are listed against the variables as they were just read."
                </p>
            }
            .into_any(),
            Err(err) => view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any(),
        })
    };
    let body = match tracking {
        EnvTracking::Compared(changes) if changes.is_empty() => view! {
            <p class="field-hint">
                "No variable of this service was changed in Dokploy since the dashboard last wrote or accepted them."
            </p>
        }
        .into_any(),
        EnvTracking::Compared(changes) => {
            changes_view(changes, form("Accept these edits")).into_any()
        }
        EnvTracking::NotRecorded => view! {
            <div class="field-hint">
                <p>
                    "The dashboard has no record of the variables it wrote to this service, so it cannot tell which ones were changed in Dokploy. Recording them now lists later edits."
                </p>
                {form("Record the current variables")}
            </div>
        }
        .into_any(),
        EnvTracking::Unreadable => view! {
            <div class="field-hint">
                <p>
                    "The record of the variables the dashboard wrote is encrypted with a credential key this server does not have, so changes made in Dokploy cannot be shown. Recording them again with this server's key lists later edits."
                </p>
                {form("Record the current variables again")}
            </div>
        }
        .into_any(),
    };
    view! { {body} {outcome} }
}

/// Accepting writes nothing to Dokploy; it changes what later edits are
/// compared with.
fn accept_form(
    project: uuid::Uuid,
    seen: String,
    label: &'static str,
    accept: ServerAction<AcceptStackVariables>,
    busy: Signal<bool>,
) -> impl IntoView {
    let disabled = move || (busy.get() || accept.pending().get()).then_some("true");
    view! {
        <ActionForm action=accept attr:class="inline-form">
            <input type="hidden" name="id" value=project.to_string()/>
            <input type="hidden" name="seen" value=seen/>
            <button type="submit" class="button" aria-disabled=disabled>{label}</button>
        </ActionForm>
    }
}

fn changes_view(changes: EnvChanges, accept: impl IntoView) -> impl IntoView {
    let names = |names: Vec<String>| {
        names
            .into_iter()
            .map(|name| view! { <li><code class="url-text">{name}</code></li> })
            .collect_view()
    };
    let group = |title: &'static str, list: Vec<String>| {
        (!list.is_empty()).then(|| {
            view! {
                <p>{title}</p>
                <ul class="plain-list">{names(list)}</ul>
            }
        })
    };
    view! {
        <div class="form-warning env-changes">
            <p>
                <strong>"Variables were changed in Dokploy"</strong>
                " since the dashboard last wrote or accepted them. The dashboard keeps these edits; the settings below show the values in effect. Values are not shown here."
            </p>
            {group("Changed:", changes.changed)}
            {group("Added:", changes.added)}
            {group("Removed:", changes.removed)}
            <p>"Accepting them changes nothing in Dokploy; it stops listing them until they are edited again."</p>
            {accept}
        </div>
    }
}

fn field_view(setting: StackSettingView) -> impl IntoView {
    let id = format!("setting-{}", setting.name.to_lowercase().replace('_', "-"));
    let name = setting.name.to_lowercase();
    let help_id = format!("{id}-help");
    let note = match setting.state {
        SettingState::Editable => None,
        SettingState::NotInComposeFile => Some(format!(
            "This stack's compose file does not read {}, so it cannot be changed here. Stacks created before the dashboard could change it keep the value in their compose file.",
            setting.name
        )),
        SettingState::Unreadable => Some(format!(
            "{} is set in Dokploy in a form the dashboard does not rewrite. Change it in Dokploy.",
            setting.name
        )),
    };
    let locked = note.is_some();
    let value = setting.value.unwrap_or_default();
    let control = match setting.kind {
        SettingKind::Bool => {
            let on = value == "true";
            view! {
                <select class="input" id=id.clone() name=name aria-describedby=help_id.clone() disabled=locked>
                    <option value="true" selected=on>"On"</option>
                    <option value="false" selected=!on>"Off"</option>
                </select>
            }
            .into_any()
        }
        SettingKind::Seconds { min, max } => view! {
            <input class="input" id=id.clone() name=name type="number" inputmode="numeric"
                min=min max=max step="1" required value=value
                aria-describedby=help_id.clone() disabled=locked/>
        }
        .into_any(),
        SettingKind::Url => view! {
            <input class="input" id=id.clone() name=name type="url" required value=value
                autocomplete="off" spellcheck="false"
                aria-describedby=help_id.clone() disabled=locked/>
        }
        .into_any(),
        SettingKind::UrlList | SettingKind::SchemaList => {
            let required = setting.kind == SettingKind::SchemaList;
            view! {
                <input class="input" id=id.clone() name=name type="text" required=required value=value
                    autocomplete="off" spellcheck="false"
                    aria-describedby=help_id.clone() disabled=locked/>
            }
            .into_any()
        }
    };
    view! {
        <div class="field">
            <label for=id>{setting.label}</label>
            {control}
            <p class="field-hint" id=help_id>
                {setting.help}
                " "
                <code class="url-text">{setting.name}</code>
                {note.map(|note| view! { <span class="setting-note">" " {note}</span> })}
            </p>
        </div>
    }
}

fn review_view(
    project: uuid::Uuid,
    fields: SettingsFields,
    preview: StackConfigPreview,
    apply: ServerAction<QueueStackSettings>,
    queued: RwSignal<bool>,
) -> impl IntoView {
    let disabled = move || (queued.get() || apply.pending().get()).then_some("true");
    let hidden = [
        ("site_url", fields.site_url),
        ("additional_redirect_urls", fields.additional_redirect_urls),
        ("disable_signup", fields.disable_signup),
        ("enable_email_autoconfirm", fields.enable_email_autoconfirm),
        ("enable_anonymous_users", fields.enable_anonymous_users),
        ("jwt_expiry", fields.jwt_expiry),
        ("pgrst_db_schemas", fields.pgrst_db_schemas),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value.map(|value| view! { <input type="hidden" name=name value=value/> })
    })
    .collect_view();
    let base = preview.base;
    let count = preview.changed.len();
    let title = if count == 1 {
        "1 setting changes".to_owned()
    } else {
        format!("{count} settings change")
    };
    let changed = preview
        .changed
        .into_iter()
        .map(|name| view! { <li><code class="url-text">{name}</code></li> })
        .collect_view();
    let restarts = preview.restarts.join(", ");
    view! {
        <div class="settings-review">
            <h3 class="subsection-title">{title}</h3>
            <ul class="plain-list">{changed}</ul>
            <p class="section-text">
                "Applying redeploys the stack. Docker Compose recreates: " {restarts}
                ". They stop answering for a few seconds while they restart."
            </p>
            <ActionForm action=apply attr:class="inline-form">
                <input type="hidden" name="id" value=project.to_string()/>
                {hidden}
                <input type="hidden" name="base" value=base/>
                <button type="submit" class="button button-primary" aria-disabled=disabled>
                    "Apply and redeploy"
                </button>
            </ActionForm>
        </div>
    }
}
