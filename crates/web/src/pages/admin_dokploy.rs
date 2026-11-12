//! The administrator page's Dokploy section: connect the installation to
//! Dokploy, replace its API key, or remove the connection.
//!
//! The key is write-only. The page shows whether one is stored, the URL,
//! the version Dokploy reported, and who connected or replaced it and when.
//! The server refuses every call here for anyone who is not an
//! installation administrator.

use leptos::{form::ActionForm, prelude::*};
use supabase_dashboard_domain::{
    dokploy::{DOKPLOY_KEY_MAX_LEN, DokployChange, DokployConnectionSummary, DokployOverview},
    project::PROJECT_URL_MAX_LEN,
};

use crate::{
    components::dialog::{ConfirmDialog, DialogCancel},
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::{account::utc_minutes, admin_dokploy_placement::DokployPlacementPanel},
    server_fns::{ConnectDokploy, DisconnectDokploy, ReplaceDokployKey, get_dokploy_connection},
};

fn feedback<T>(value: Option<Result<T, AppError>>, ok: &'static str) -> Option<AnyView> {
    value.map(|result| match result {
        Ok(_) => view! { <p class="form-ok" role="status">{ok}</p> }.into_any(),
        Err(err) => view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any(),
    })
}

const KEY_ADVICE: &str = "Create the key as a Dokploy member made for this dashboard rather than as your own account, so it can be revoked without affecting anyone's access. Leave its rate limit off: a limited key is refused once the limit is reached. Dokploy does not tell the dashboard when the key in use expires, so note its expiry date if you set one.";

#[component]
pub fn DokployPanel() -> impl IntoView {
    let connect = ServerAction::<ConnectDokploy>::new();
    let replace = ServerAction::<ReplaceDokployKey>::new();
    let remove = ServerAction::<DisconnectDokploy>::new();
    let overview = Resource::new(
        move || {
            (
                connect.version().get(),
                replace.version().get(),
                remove.version().get(),
            )
        },
        |_| get_dokploy_connection(),
    );
    // Clear a key once it is stored. A refused key stays so it can be
    // corrected, but the field never starts filled.
    let replace_form = NodeRef::<leptos::html::Form>::new();
    Effect::new(move |_| {
        if matches!(replace.value().get(), Some(Ok(_))) {
            #[cfg(feature = "hydrate")]
            if let Some(form) = replace_form.get() {
                form.reset();
            }
        }
    });
    let actions = Actions {
        connect,
        replace,
        remove,
        replace_form,
    };

    view! {
        <section class="panel" aria-labelledby="dokploy-title">
            <h2 class="section-title" id="dokploy-title">"Dokploy"</h2>
            <p class="section-text">
                "The Dokploy installation this dashboard will deploy and manage stacks through. Connecting checks the API key and Dokploy's version, then stores the key encrypted on the dashboard server. It is never shown again."
            </p>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading the Dokploy connection…"</p> }>
                {move || overview.get().map(|result| match result {
                    Ok(overview) => overview_view(overview, actions),
                    Err(AppError::Forbidden) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Administrators only".to_string()
                            detail="Only installation administrators can see or change the Dokploy connection.".to_string()
                        />
                    }
                    .into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Could not load the Dokploy connection".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
            {move || feedback(remove.value().get(), "Connection removed. Nothing changed in Dokploy.")}
        </section>
    }
}

#[derive(Clone, Copy)]
struct Actions {
    connect: ServerAction<ConnectDokploy>,
    replace: ServerAction<ReplaceDokployKey>,
    remove: ServerAction<DisconnectDokploy>,
    replace_form: NodeRef<leptos::html::Form>,
}

fn overview_view(overview: DokployOverview, actions: Actions) -> AnyView {
    let unavailable = (!overview.storage_available).then(|| {
        view! {
            <StatePanel
                tone=StateTone::Error
                title="Key storage is not configured".to_string()
                detail="The dashboard server has no encryption key, so it cannot store or use a Dokploy key. Set SUPABASE_DASHBOARD_SECRET_KEY_FILE and restart it; see the deployment guide.".to_string()
            />
        }
    });
    let body = match overview.connection {
        Some(connection) => connected_view(connection, overview.storage_available, actions),
        None => not_connected_view(overview.storage_available, actions),
    };
    view! { {unavailable} {body} }.into_any()
}

fn not_connected_view(storage_available: bool, actions: Actions) -> AnyView {
    let connect = actions.connect;
    let failed = move || matches!(connect.value().get(), Some(Err(_)));
    let form = storage_available.then(|| {
        view! {
            <ActionForm action=connect attr:class="stacked-form">
                <label class="field" for="dokploy-url">
                    <span class="field-label">"Dokploy URL"</span>
                    <input
                        class="input" id="dokploy-url" name="url" type="url" required
                        autocomplete="off" spellcheck="false" inputmode="url"
                        placeholder="https://dokploy.example.com"
                        maxlength=PROJECT_URL_MAX_LEN.to_string()
                        aria-describedby="dokploy-url-hint dokploy-connect-result"
                        aria-invalid=move || failed().then_some("true")
                    />
                </label>
                <p class="field-hint" id="dokploy-url-hint">
                    "The address you open Dokploy at, without /api. The dashboard server must be allowed to reach it; see the deployment guide."
                </p>
                <label class="field" for="dokploy-key">
                    <span class="field-label">"API key"</span>
                    <input
                        class="input" id="dokploy-key" name="key" type="password" required
                        autocomplete="off" spellcheck="false"
                        maxlength=DOKPLOY_KEY_MAX_LEN.to_string()
                        aria-describedby="dokploy-key-hint dokploy-connect-result"
                        aria-invalid=move || failed().then_some("true")
                    />
                </label>
                <p class="field-hint" id="dokploy-key-hint">{KEY_ADVICE}</p>
                <div>
                    <button type="submit" class="button button-primary"
                        disabled=move || connect.pending().get()>
                        {move || if connect.pending().get() { "Connecting…" } else { "Connect" }}
                    </button>
                </div>
            </ActionForm>
        }
    });
    view! {
        <StatePanel
            tone=StateTone::Empty
            title="Not connected".to_string()
            detail="This installation is not connected to Dokploy.".to_string()
        />
        {form}
        <div id="dokploy-connect-result">
            {move || connect.value().get().and_then(Result::err).map(|err| view! {
                <p class="form-error" role="alert">{err.to_string()}</p>
            })}
        </div>
    }
    .into_any()
}

fn change_text(change: &DokployChange) -> String {
    let by = change
        .by
        .as_ref()
        .map_or("a deleted account", |name| name.as_str());
    format!("{} (UTC) by {by}", utc_minutes(change.at))
}

fn connected_view(
    connection: DokployConnectionSummary,
    storage_available: bool,
    actions: Actions,
) -> AnyView {
    let Actions {
        connect,
        replace,
        remove,
        replace_form,
    } = actions;
    let failed = move || matches!(replace.value().get(), Some(Err(_)));
    let transport = if connection.url.is_encrypted() {
        view! { <span class="badge badge-ok">"HTTPS"</span> }.into_any()
    } else {
        view! { <span class="badge badge-error">"Plain HTTP"</span> }.into_any()
    };
    let key_state = if connection.key_readable {
        view! { <span class="badge badge-ok">"Stored"</span> }.into_any()
    } else {
        view! {
            <span class="badge badge-error">"Unreadable"</span>
            " "
            <span class="field-hint">"It was stored under an encryption key this server does not have. Replace it, or remove the connection."</span>
        }
        .into_any()
    };
    let replaced = connection.key_replaced.as_ref().map(|change| {
        view! {
            <div>
                <dt>"Key replaced"</dt>
                <dd>{change_text(change)}</dd>
            </div>
        }
    });
    let details = view! {
        <dl class="detail-list">
            <div>
                <dt>"URL"</dt>
                <dd><span class="url-text">{connection.url.as_str().to_owned()}</span> " " {transport}</dd>
            </div>
            <div>
                <dt>"Version"</dt>
                <dd>{connection.version.to_string()}</dd>
            </div>
            <div>
                <dt>"API key"</dt>
                <dd>{key_state}</dd>
            </div>
            <div>
                <dt>"Connected"</dt>
                <dd>{change_text(&connection.connected)}</dd>
            </div>
            {replaced}
            <div>
                <dt>"Key last checked"</dt>
                <dd>{format!("{} (UTC)", utc_minutes(connection.verified_at))}</dd>
            </div>
        </dl>
    }
    .into_any();
    // Dokploy can be asked only with a key this server can read.
    let placement =
        (storage_available && connection.key_readable).then(|| view! { <DokployPlacementPanel/> });
    let replace_form_view = storage_available.then(|| {
        view! {
            <h3 class="subsection-title">"Replace the API key"</h3>
            <ActionForm action=replace node_ref=replace_form attr:class="stacked-form">
                <label class="field" for="dokploy-new-key">
                    <span class="field-label">"New API key"</span>
                    <input
                        class="input" id="dokploy-new-key" name="key" type="password" required
                        autocomplete="off" spellcheck="false"
                        maxlength=DOKPLOY_KEY_MAX_LEN.to_string()
                        aria-describedby="dokploy-new-key-hint dokploy-replace-result"
                        aria-invalid=move || failed().then_some("true")
                    />
                </label>
                <p class="field-hint" id="dokploy-new-key-hint">
                    "The new key must connect before it replaces the stored one. " {KEY_ADVICE}
                </p>
                <div>
                    <button type="submit" class="button button-primary"
                        disabled=move || replace.pending().get()>
                        {move || if replace.pending().get() { "Checking…" } else { "Replace key" }}
                    </button>
                </div>
            </ActionForm>
            <div id="dokploy-replace-result">
                {move || feedback(replace.value().get(), "Key replaced. Dokploy accepted it.")}
            </div>
        }
    });
    // A fresh connection's confirmation; the form it came from is gone.
    let connected = move || {
        matches!(connect.value().get(), Some(Ok(_))).then(|| {
            view! { <p class="form-ok" role="status">"Connected. Dokploy accepted the key."</p> }
        })
    };
    view! {
        {connected}
        {details}
        {placement}
        {replace_form_view}
        <h3 class="subsection-title">"Remove the connection"</h3>
        <p class="field-hint">
            "Deletes the dashboard's record of this connection and its stored key. Nothing in Dokploy changes; revoke the key in Dokploy as well if it is no longer needed."
        </p>
        <div class="row-actions">
            <ConfirmDialog trigger="Remove connection" title="Remove the Dokploy connection?">
                <ActionForm action=remove attr:class="dialog-form">
                    <p>
                        "The dashboard forgets "
                        <span class="url-text">{connection.url.as_str().to_owned()}</span>
                        " and its key. Projects and services in Dokploy are not touched, and the key stays valid in Dokploy until you revoke it there."
                    </p>
                    <div class="dialog-actions">
                        <DialogCancel/>
                        <button type="submit" class="button button-danger"
                            disabled=move || remove.pending().get()>
                            "Remove connection"
                        </button>
                    </div>
                </ActionForm>
            </ConfirmDialog>
        </div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use supabase_dashboard_domain::account::DisplayName;
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn a_change_names_who_made_it_or_says_the_account_is_gone() {
        let at = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(
            change_text(&DokployChange {
                at,
                by: Some(DisplayName::parse("Alice").unwrap()),
            }),
            "1970-01-01 00:00 (UTC) by Alice"
        );
        assert_eq!(
            change_text(&DokployChange { at, by: None }),
            "1970-01-01 00:00 (UTC) by a deleted account"
        );
    }
}
