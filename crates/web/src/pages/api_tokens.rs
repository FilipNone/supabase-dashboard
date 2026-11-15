//! The operator's own API tokens: create, list, and revoke.
//!
//! A new token is shown once, in the answer to the request that created
//! it. The server keeps only a hash, so the list never holds more than the
//! token's first characters.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::api_token::{
    API_TOKEN_NAME_MAX_CHARS, ApiTokenLifetime, ApiTokenScope, ApiTokenState, ApiTokenSummary,
    IssuedApiToken, MAX_ACTIVE_API_TOKENS,
};

use crate::{
    components::dialog::{ConfirmDialog, DialogCancel},
    components::page::{StatePanel, StateTone},
    pages::account::utc_minutes,
    server_fns::{CreateApiToken, RevokeApiToken, list_api_tokens},
};

/// Where the API is served, for the example on a new token.
const API_EXAMPLE_PATH: &str = "/api/v1/organizations";

#[component]
pub fn AccountTokensPage() -> impl IntoView {
    let create = ServerAction::<CreateApiToken>::new();
    let revoke = ServerAction::<RevokeApiToken>::new();
    let tokens = Resource::new(
        move || (create.version().get(), revoke.version().get()),
        |_| list_api_tokens(),
    );
    view! {
        <Title text="API tokens"/>
        <CreateTokenPanel create/>
        <section class="panel" aria-labelledby="tokens-title">
            <h2 class="section-title" id="tokens-title">"Your API tokens"</h2>
            <p class="field-hint">
                {format!(
                    "Revoked and expired tokens stay listed for 30 days. You can have up to {MAX_ACTIVE_API_TOKENS} working tokens."
                )}
            </p>
            {move || {
                revoke.value().get().and_then(Result::err).map(|err| {
                    view! { <p class="form-error" role="alert">{err.to_string()}</p> }
                })
            }}
            {move || {
                revoke.value().get().and_then(Result::ok).map(|()| {
                    view! { <p class="form-ok" role="status">"Token revoked. It no longer works."</p> }
                })
            }}
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading API tokens…"</p> }>
                {move || {
                    tokens.get().map(|result| match result {
                        Ok(list) if list.is_empty() => view! {
                            <StatePanel
                                tone=StateTone::Empty
                                title="No API tokens yet".to_string()
                                detail="Create one above to read your organizations and projects from a script.".to_string()
                            />
                        }
                        .into_any(),
                        Ok(list) => view! { <TokenTable list revoke/> }.into_any(),
                        Err(err) => view! {
                            <StatePanel
                                tone=StateTone::Error
                                title="Could not load API tokens".to_string()
                                detail=err.to_string()
                            />
                        }
                        .into_any(),
                    })
                }}
            </Transition>
        </section>
    }
}

#[component]
fn CreateTokenPanel(create: ServerAction<CreateApiToken>) -> impl IntoView {
    let lifetimes = ApiTokenLifetime::ALL
        .into_iter()
        .map(|lifetime| {
            view! {
                <option value=lifetime.days().to_string() selected=lifetime == ApiTokenLifetime::Days30>
                    {lifetime.label()}
                </option>
            }
        })
        .collect_view();
    let scopes = ApiTokenScope::ALL
        .into_iter()
        .map(|scope| {
            let (name, hint_id) = match scope {
                ApiTokenScope::OrganizationsRead => ("organizations_read", "scope-orgs-hint"),
                ApiTokenScope::ProjectsRead => ("projects_read", "scope-projects-hint"),
            };
            view! {
                <label class="checkbox-field">
                    <input type="checkbox" name=name value="true" checked aria-describedby=hint_id/>
                    <span>
                        {scope.label()}
                        " "
                        <code>{scope.as_str()}</code>
                        <span class="field-hint" id=hint_id>{scope.description()}</span>
                    </span>
                </label>
            }
        })
        .collect_view();
    let result = move || {
        create.value().get().map(|result| match result {
            Ok(issued) => view! { <IssuedToken issued/> }.into_any(),
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };
    view! {
        <section class="panel" aria-labelledby="create-token-title">
            <h2 class="section-title" id="create-token-title">"Create an API token"</h2>
            <p class="field-hint">
                "A token reads the dashboard's API as you, with your current roles, limited to what you tick below. Tokens only read: they cannot change anything, open Studio, or read a project's keys."
            </p>
            <ActionForm action=create attr:class="stacked-form">
                <label class="field">
                    <span class="field-label">"Name"</span>
                    <input
                        class="input" name="name" required autocomplete="off"
                        maxlength=API_TOKEN_NAME_MAX_CHARS.to_string()
                        aria-describedby="token-name-hint"
                    />
                    <span class="field-hint" id="token-name-hint">"Something that tells you where it is used, such as \"Uptime monitor\"."</span>
                </label>
                <label class="field">
                    <span class="field-label">"Expires after"</span>
                    <select class="input" name="lifetime">{lifetimes}</select>
                </label>
                <fieldset class="field">
                    <legend class="field-label">"Access"</legend>
                    {scopes}
                </fieldset>
                <div>
                    <button type="submit" class="button button-primary" disabled=move || create.pending().get()>
                        {move || if create.pending().get() { "Creating…" } else { "Create token" }}
                    </button>
                </div>
            </ActionForm>
            {result}
        </section>
    }
}

/// A new token. Shown once: the server keeps only a hash of it.
#[component]
fn IssuedToken(issued: IssuedApiToken) -> impl IntoView {
    let secret = issued.secret.expose().to_owned();
    let example = format!(
        "curl -H \"Authorization: Bearer {secret}\" {}{API_EXAMPLE_PATH}",
        origin()
    );
    let note = format!(
        "Copy it now: it is shown only once and cannot be recovered. It expires on {} (UTC).",
        issued.token.expires_at.date(),
    );
    view! {
        <div class="issued-link" role="status">
            <label class="field">
                <span class="field-label">{format!("Token \u{201c}{}\u{201d}", issued.token.name)}</span>
                <input class="input mono" readonly value=secret aria-describedby="issued-token-note"/>
            </label>
            <p class="field-hint" id="issued-token-note">{note}</p>
            <label class="field">
                <span class="field-label">"Example"</span>
                <input class="input mono" readonly value=example/>
            </label>
        </div>
    }
}

fn origin() -> String {
    #[cfg(feature = "hydrate")]
    if let Ok(origin) = window().location().origin() {
        return origin;
    }
    String::new()
}

#[component]
fn TokenTable(list: Vec<ApiTokenSummary>, revoke: ServerAction<RevokeApiToken>) -> impl IntoView {
    let rows = list
        .into_iter()
        .map(|token| {
            let badge = match token.state {
                ApiTokenState::Active => "badge badge-ok",
                ApiTokenState::Expired | ApiTokenState::Revoked => "badge badge-muted",
            };
            let access = token
                .scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let action = (token.state == ApiTokenState::Active).then(|| {
                let confirm = format!("Revoke {}", token.name);
                view! {
                    <div class="row-actions">
                        <ConfirmDialog trigger="Revoke" title=format!("{confirm}?")>
                            <ActionForm action=revoke attr:class="dialog-form">
                                <input type="hidden" name="token_id" value=token.id.to_string()/>
                                <p>"Programs using this token stop working at once. This cannot be undone."</p>
                                <div class="dialog-actions">
                                    <DialogCancel/>
                                    <button type="submit" class="button button-danger">{confirm}</button>
                                </div>
                            </ActionForm>
                        </ConfirmDialog>
                    </div>
                }
            });
            view! {
                <tr>
                    <td>{token.name.to_string()}</td>
                    <td class="nowrap"><code>{format!("{}…", token.display_prefix)}</code></td>
                    <td>{access}</td>
                    <td class="nowrap">{utc_minutes(token.created_at)}</td>
                    <td class="nowrap">{utc_minutes(token.expires_at)}</td>
                    <td class="nowrap">{token.last_used_at.map_or_else(|| "Never".to_owned(), utc_minutes)}</td>
                    <td><span class=badge>{token.state.label()}</span></td>
                    <td>{action}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap" role="region" aria-label="API tokens" tabindex="0">
            <table class="data-table">
                <caption class="visually-hidden">"API tokens"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Name"</th>
                        <th scope="col">"Token"</th>
                        <th scope="col">"Access"</th>
                        <th scope="col">"Created (UTC)"</th>
                        <th scope="col">"Expires (UTC)"</th>
                        <th scope="col">"Last used (UTC)"</th>
                        <th scope="col">"State"</th>
                        <th scope="col"><span class="visually-hidden">"Actions"</span></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
}
