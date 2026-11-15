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
//!
//! A secret setting has a password field that is never filled in: the
//! page shows only whether the variable is set. The review names it; the
//! value goes from the field to the server with the review and again with
//! the apply, and never comes back.
//!
//! The sign-in providers' settings follow the others, one group per
//! provider with the callback URL to register with it.

use leptos::{form::ActionForm, prelude::*};

use supabase_dashboard_domain::stack_settings::{
    AuthProviderView, EnvChanges, EnvTracking, MAX_CLIENT_ID_LEN, MAX_SECRET_LEN,
    SecretSettingView, SettingKind, SettingState, StackConfigPreview, StackSettingView,
    StackSettingsView, auth_provider,
};

use crate::{
    error::AppError,
    server_fns::{
        AcceptStackVariables, PreviewStackSettings, QueueStackSettings, REMOVE_SUFFIX,
        SettingsFields, get_stack_settings,
    },
};

/// The plain setting the secret settings' fields follow.
const SECRETS_AFTER: &str = "SMTP_USER";

#[component]
pub fn StackSettingsSection(
    project: uuid::Uuid,
    apply: ServerAction<QueueStackSettings>,
    /// Counts the stack's actions that finished while the page was open.
    finished: Signal<u32>,
    /// Whether an action on the stack runs now, as the deployment panel
    /// last read it.
    running: Signal<bool>,
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
            // A refusal because the action ran no longer holds.
            apply.value().set(None);
            accept.value().set(None);
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
                    let state = State { reviewing, queued, running };
                    section(view, project, actions, state, reread).into_any()
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

#[derive(Clone, Copy)]
struct State {
    /// The review shows.
    reviewing: RwSignal<bool>,
    /// A change was queued from this page and has not finished.
    queued: RwSignal<bool>,
    /// An action on the stack runs, as the deployment panel last read it.
    running: Signal<bool>,
}

fn section(
    view: StackSettingsView,
    project: uuid::Uuid,
    Actions {
        review,
        apply,
        accept,
    }: Actions,
    State {
        reviewing,
        queued,
        running: action_running,
    }: State,
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
    let busy = move || running || queued.get() || action_running.get();
    let disabled = move || (busy() || review.pending().get()).then_some("true");
    let review_error = move || {
        review
            .value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };
    let tracking = tracking_view(view.tracking, project, accept, Signal::derive(busy));
    // The secret settings' password fields, read when a review is applied.
    let secret_inputs: SecretInputs = view
        .secrets
        .iter()
        .map(|secret| (secret.name.clone(), NodeRef::new()))
        .collect();
    let input_of = {
        let secret_inputs = secret_inputs.clone();
        move |name: &str| {
            secret_inputs
                .iter()
                .find(|(input, _)| input == name)
                .map(|(_, node)| *node)
                .unwrap_or_default()
        }
    };
    // The providers' settings go in their own groups.
    let of_provider = |name: &str| {
        view.providers
            .iter()
            .filter_map(|provider| auth_provider(&provider.key))
            .any(|p| [p.enabled.name, p.client_id.name, p.secret.name].contains(&name))
    };
    let (mut provider_settings, settings): (Vec<_>, Vec<_>) = view
        .settings
        .into_iter()
        .partition(|s| of_provider(&s.name));
    let (mut provider_secrets, secrets): (Vec<_>, Vec<_>) =
        view.secrets.into_iter().partition(|s| of_provider(&s.name));
    let anchored = settings.iter().any(|s| s.name == SECRETS_AFTER);
    let mut secrets = Some(secrets);
    let mut secret_fields = {
        let input_of = input_of.clone();
        move || {
            secrets.take().map(|secrets| {
                secrets
                    .into_iter()
                    .map(|secret| {
                        let node = input_of(&secret.name);
                        secret_field_view(secret, node)
                    })
                    .collect_view()
            })
        }
    };
    let mut fields = Vec::new();
    for setting in settings {
        // The mail server's settings start their own group.
        let heading = (setting.name == "SMTP_HOST").then(|| {
            view! {
                <h3 class="subsection-title settings-group">"Auth mail server"</h3>
                <p class="field-hint">
                    "Auth emails sign-up confirmations, magic links, invitations, and password recovery links through this server."
                </p>
            }
        });
        let after = (setting.name == SECRETS_AFTER)
            .then(&mut secret_fields)
            .flatten();
        fields.push(view! { {heading} {field_view(setting)} {after} }.into_any());
    }
    if !anchored {
        fields.push(secret_fields().into_any());
    }
    let mut providers = Vec::new();
    for provider in view.providers {
        let Some(variables) = auth_provider(&provider.key) else {
            continue;
        };
        let mut take = |name: &str| {
            provider_settings
                .iter()
                .position(|s| s.name == name)
                .map(|at| provider_settings.remove(at))
        };
        let enabled = take(variables.enabled.name);
        let client_id = take(variables.client_id.name);
        let secret = provider_secrets
            .iter()
            .position(|s| s.name == variables.secret.name)
            .map(|at| provider_secrets.remove(at));
        let secret = secret.map(|secret| {
            let node = input_of(&secret.name);
            secret_field_view(secret, node)
        });
        providers.push(provider_view(provider, enabled, client_id, secret).into_any());
    }
    if !providers.is_empty() {
        fields.push(
            view! {
                <h3 class="subsection-title settings-group">"Sign-in providers"</h3>
                <p class="field-hint">
                    "Users of the stack's apps can sign in with these accounts as well as an email address. Register an OAuth app with each provider first."
                </p>
                {providers}
            }
            .into_any(),
        );
    }
    let fields = fields.collect_view();
    let summary = move || {
        if !reviewing.get() {
            return None;
        }
        let (fields, preview) = review.value().get()?.ok()?;
        Some(review_view(
            project,
            fields,
            preview,
            secret_inputs.clone(),
            apply,
            Withdraw { reviewing, queued },
        ))
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
                    "Recorded the variables as Dokploy has them now. Later edits there are listed against these."
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
    let name = SettingsFields::field_name(&setting.name);
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
        SettingKind::UrlList
        | SettingKind::SchemaList
        | SettingKind::Host
        | SettingKind::Username => {
            let required = setting.kind == SettingKind::SchemaList;
            view! {
                <input class="input" id=id.clone() name=name type="text" required=required value=value
                    autocomplete="off" spellcheck="false"
                    aria-describedby=help_id.clone() disabled=locked/>
            }
            .into_any()
        }
        SettingKind::Port => view! {
            <input class="input" id=id.clone() name=name type="number" inputmode="numeric"
                min="1" max="65535" step="1" required value=value
                aria-describedby=help_id.clone() disabled=locked/>
        }
        .into_any(),
        SettingKind::EmailAddress => view! {
            <input class="input" id=id.clone() name=name type="email" value=value
                autocomplete="off" spellcheck="false"
                aria-describedby=help_id.clone() disabled=locked/>
        }
        .into_any(),
        SettingKind::ClientId => view! {
            <input class="input" id=id.clone() name=name type="text" value=value
                autocomplete="off" spellcheck="false" maxlength=MAX_CLIENT_ID_LEN.to_string()
                aria-describedby=help_id.clone() disabled=locked/>
        }
        .into_any(),
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

/// A sign-in provider's group: what to register with it, its callback URL,
/// and its fields.
fn provider_view(
    provider: AuthProviderView,
    enabled: Option<StackSettingView>,
    client_id: Option<StackSettingView>,
    secret: Option<impl IntoView>,
) -> impl IntoView {
    let callback = match provider.callback_url {
        Some(url) => view! {
            <p class="field-hint">
                "Callback URL: " <code class="url-text">{url}</code>
            </p>
        }
        .into_any(),
        None => view! {
            <p class="field-hint">
                "The callback URL is the stack's public URL followed by " <code class="url-text">"/auth/v1/callback"</code>
                ". The dashboard cannot read the public URL from this stack's variables."
            </p>
        }
        .into_any(),
    };
    view! {
        <fieldset class="settings-provider">
            <legend class="subsection-title">{provider.label}</legend>
            <p class="field-hint">{provider.help}</p>
            {callback}
            {enabled.map(field_view)}
            {client_id.map(field_view)}
            {secret}
        </fieldset>
    }
}

/// The password fields of the secret settings, by variable name.
type SecretInputs = Vec<(String, NodeRef<leptos::html::Input>)>;

/// The review's state, for the apply form.
#[derive(Clone, Copy)]
struct Withdraw {
    reviewing: RwSignal<bool>,
    queued: RwSignal<bool>,
}

/// A secret setting's field: a password input that is never filled in,
/// whether the variable is set, and a box to remove it when it is.
fn secret_field_view(
    setting: SecretSettingView,
    node_ref: NodeRef<leptos::html::Input>,
) -> impl IntoView {
    let id = format!("setting-{}", setting.name.to_lowercase().replace('_', "-"));
    let name = SettingsFields::field_name(&setting.name);
    let help_id = format!("{id}-help");
    let note = match setting.state {
        SettingState::Editable => None,
        SettingState::NotInComposeFile => Some(format!(
            "This stack's compose file does not read {}, so it cannot be changed here.",
            setting.name
        )),
        SettingState::Unreadable => Some(format!(
            "{} is set in Dokploy in a form the dashboard does not rewrite. Change it in Dokploy.",
            setting.name
        )),
    };
    let locked = note.is_some();
    let status = if setting.set {
        "Set in Dokploy."
    } else {
        "Not set."
    };
    let remove_label = setting.remove_label;
    let remove = (setting.set && !locked).then(|| {
        view! {
            <label class="checkbox-field">
                <input type="checkbox" name=format!("{name}{REMOVE_SUFFIX}") value="true"/>
                <span>{remove_label}</span>
            </label>
        }
    });
    view! {
        <div class="field">
            <label for=id.clone()>{setting.label}</label>
            <input class="input" id=id name=name type="password" autocomplete="new-password"
                spellcheck="false" maxlength=MAX_SECRET_LEN.to_string()
                aria-describedby=help_id.clone() disabled=locked node_ref=node_ref/>
            <p class="field-hint" id=help_id>
                <strong class="setting-status">{status}</strong>
                " "
                {setting.help}
                " "
                <code class="url-text">{setting.name}</code>
                {note.map(|note| view! { <span class="setting-note">" " {note}</span> })}
            </p>
            {remove}
        </div>
    }
}

fn review_view(
    project: uuid::Uuid,
    fields: SettingsFields,
    preview: StackConfigPreview,
    inputs: SecretInputs,
    apply: ServerAction<QueueStackSettings>,
    Withdraw { reviewing, queued }: Withdraw,
) -> impl IntoView {
    let disabled = move || (queued.get() || apply.pending().get()).then_some("true");
    let base = preview.base;
    let changed_secrets = preview.secrets.clone();
    // New secret values are read from their fields, not kept in the review.
    let on_submit = {
        let base = base.clone();
        move |ev: leptos::ev::SubmitEvent| {
            ev.prevent_default();
            if queued.get_untracked() || apply.pending().get_untracked() {
                return;
            }
            let mut fields = fields.clone();
            for secret in &changed_secrets {
                if secret.removed {
                    fields.insert(
                        &format!("{}{REMOVE_SUFFIX}", secret.name),
                        "true".to_owned(),
                    );
                    continue;
                }
                let typed = inputs
                    .iter()
                    .find(|(name, _)| *name == secret.name)
                    .and_then(|(_, node)| node.get_untracked())
                    .map(|input| input.value())
                    .unwrap_or_default();
                if typed.is_empty() {
                    // The field was cleared since the review.
                    reviewing.set(false);
                    return;
                }
                fields.insert(&secret.name, typed);
            }
            apply.dispatch(QueueStackSettings {
                id: project,
                base: base.clone(),
                fields,
            });
        }
    };
    let schemas_changed = preview
        .changed
        .iter()
        .any(|name| name == "PGRST_DB_SCHEMAS");
    let count = preview.changed.len();
    let title = if count == 1 {
        "1 setting changes".to_owned()
    } else {
        format!("{count} settings change")
    };
    let secrets = preview.secrets;
    let changed = preview
        .changed
        .into_iter()
        .map(|name| {
            let note = secrets.iter().find(|s| s.name == name).map(|s| {
                if s.removed {
                    " (removed)"
                } else {
                    " (new value, hidden)"
                }
            });
            view! { <li><code class="url-text">{name}</code>{note}</li> }
        })
        .collect_view();
    // The dashboard cannot see the stack's database, so it cannot check
    // that the schemas exist; PostgREST refuses to start when one does
    // not, and the redeployment fails.
    let schemas = schemas_changed.then(|| {
            view! {
                <p class="form-warning">
                    "Check that every exposed schema exists in the database first. The dashboard cannot check it, and with a schema that does not exist the REST API does not start and the redeployment fails."
                </p>
            }
        });
    let restarts = preview.restarts.join(", ");
    view! {
        <div class="settings-review">
            <h3 class="subsection-title">{title}</h3>
            <ul class="plain-list">{changed}</ul>
            <p class="section-text">
                "Applying redeploys the stack. Docker Compose recreates: " {restarts}
                ". They stop answering for a few seconds while they restart."
            </p>
            {schemas}
            <form class="inline-form" on:submit=on_submit>
                <button type="submit" class="button button-primary" aria-disabled=disabled>
                    "Apply and redeploy"
                </button>
            </form>
        </div>
    }
}

#[cfg(test)]
#[cfg(feature = "ssr")]
mod tests {
    use supabase_dashboard_domain::stack_settings::{secret_setting, stack_setting};

    use super::*;

    fn rendered(name: &str, value: &str) -> String {
        let owner = Owner::new();
        owner.set();
        let setting = stack_setting(name).unwrap();
        field_view(StackSettingView {
            name: setting.name.to_owned(),
            label: setting.label.to_owned(),
            help: setting.help.to_owned(),
            kind: setting.kind,
            value: Some(value.to_owned()),
            state: SettingState::Editable,
        })
        .to_html()
    }

    #[test]
    fn mail_server_fields_have_labels_types_and_their_form_names() {
        let host = rendered("SMTP_HOST", "smtp.example.com");
        assert!(host.contains(r#"for="setting-smtp-host""#), "{host}");
        assert!(host.contains(r#"name="smtp_host""#), "{host}");
        assert!(host.contains(r#"type="text""#), "{host}");
        assert!(!host.contains("required"), "{host}");
        let port = rendered("SMTP_PORT", "587");
        assert!(port.contains(r#"type="number""#), "{port}");
        assert!(port.contains(r#"max="65535""#), "{port}");
        let from = rendered("SMTP_ADMIN_EMAIL", "");
        assert!(from.contains(r#"type="email""#), "{from}");
        assert!(from.contains(r#"aria-describedby="setting-smtp-admin-email-help""#));
    }

    fn secret_view(name: &str, set: bool, state: SettingState) -> SecretSettingView {
        let setting = secret_setting(name).unwrap();
        SecretSettingView {
            name: setting.name.to_owned(),
            label: setting.label.to_owned(),
            help: setting.help.to_owned(),
            remove_label: setting.remove_label.to_owned(),
            set,
            state,
        }
    }

    fn rendered_secret(set: bool, state: SettingState) -> String {
        let owner = Owner::new();
        owner.set();
        secret_field_view(secret_view("SMTP_PASS", set, state), NodeRef::new()).to_html()
    }

    #[test]
    fn the_password_field_is_never_filled_in_and_says_whether_one_is_set() {
        let set = rendered_secret(true, SettingState::Editable);
        assert!(set.contains(r#"for="setting-smtp-pass""#), "{set}");
        assert!(set.contains(r#"name="smtp_pass""#), "{set}");
        assert!(set.contains(r#"type="password""#), "{set}");
        assert!(set.contains(r#"autocomplete="new-password""#), "{set}");
        assert!(set.contains(r#"maxlength="512""#), "{set}");
        assert!(set.contains(r#"aria-describedby="setting-smtp-pass-help""#));
        // The only value attribute is the remove box's.
        assert_eq!(set.matches("value=").count(), 1, "{set}");
        assert!(
            set.contains(r#"name="smtp_pass_remove" value="true""#),
            "{set}"
        );
        assert!(set.contains("Set in Dokploy."), "{set}");
        assert!(!set.contains("disabled"), "{set}");

        let unset = rendered_secret(false, SettingState::Editable);
        assert!(unset.contains("Not set."), "{unset}");
        assert!(!unset.contains("value="), "{unset}");
        assert!(!unset.contains("smtp_pass_remove"), "{unset}");

        let locked = rendered_secret(true, SettingState::Unreadable);
        assert!(locked.contains("disabled"), "{locked}");
        assert!(locked.contains("does not rewrite"), "{locked}");
        assert!(!locked.contains("smtp_pass_remove"), "{locked}");
    }

    fn setting_view(name: &str, value: &str) -> StackSettingView {
        let setting = stack_setting(name).unwrap();
        StackSettingView {
            name: setting.name.to_owned(),
            label: setting.label.to_owned(),
            help: setting.help.to_owned(),
            kind: setting.kind,
            value: Some(value.to_owned()),
            state: SettingState::Editable,
        }
    }

    #[test]
    fn a_provider_shows_its_callback_url_and_never_its_secret() {
        let owner = Owner::new();
        owner.set();
        let provider = |callback_url: Option<&str>| AuthProviderView {
            key: "GITHUB".to_owned(),
            label: "GitHub".to_owned(),
            help: "Register an OAuth app.".to_owned(),
            callback_url: callback_url.map(str::to_owned),
        };
        let html = provider_view(
            provider(Some("https://api.example.test/auth/v1/callback")),
            Some(setting_view("GITHUB_ENABLED", "true")),
            Some(setting_view("GITHUB_CLIENT_ID", "Iv1.0123abcd")),
            Some(secret_field_view(
                secret_view("GITHUB_SECRET", true, SettingState::Editable),
                NodeRef::new(),
            )),
        )
        .to_html();
        assert!(html.contains("<legend"), "{html}");
        assert!(html.contains("GitHub"), "{html}");
        assert!(
            html.contains("https://api.example.test/auth/v1/callback"),
            "{html}"
        );
        assert!(html.contains(r#"name="github_enabled""#), "{html}");
        assert!(html.contains(r#"for="setting-github-enabled""#), "{html}");
        assert!(html.contains(r#"name="github_client_id""#), "{html}");
        assert!(html.contains(r#"value="Iv1.0123abcd""#), "{html}");
        assert!(html.contains(r#"maxlength="256""#), "{html}");
        assert!(html.contains(r#"for="setting-github-secret""#), "{html}");
        assert!(
            html.contains(r#"name="github_secret" type="password""#),
            "{html}"
        );
        assert!(
            html.contains(r#"name="github_secret_remove" value="true""#),
            "{html}"
        );
        assert!(html.contains("Remove the client secret"), "{html}");
        assert!(html.contains("Set in Dokploy."), "{html}");

        let unknown = provider_view(provider(None), None, None, None::<()>).to_html();
        assert!(unknown.contains("/auth/v1/callback"), "{unknown}");
        assert!(unknown.contains("cannot read the public URL"), "{unknown}");
    }

    #[test]
    fn every_setting_has_its_own_form_field() {
        use supabase_dashboard_domain::stack_settings::{secret_settings, stack_settings};
        let mut names: Vec<String> = stack_settings()
            .map(|s| SettingsFields::field_name(s.name))
            .chain(secret_settings().flat_map(|s| {
                let field = SettingsFields::field_name(s.name);
                [format!("{field}{REMOVE_SUFFIX}"), field]
            }))
            .collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
