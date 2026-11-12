//! The Dokploy section's placement part: which Dokploy service the
//! dashboard itself runs as.
//!
//! The server looks for the Dokploy domain that is the dashboard's public
//! host and offers its service. Nothing is used until an installation
//! administrator confirms a service; with no match or several, they pick
//! one from the services the key can see. Dokploy is asked again each time
//! the section loads, so a service moved or deleted in Dokploy shows here.

use leptos::{form::ActionForm, prelude::*};
use supabase_dashboard_domain::dokploy_placement::{
    ConfirmedPlacement, DokployServiceInfo, DokployServiceRef, MAX_LISTED_SERVICES,
    PlacementLookup, PlacementOverview, PlacementStatus,
};

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::account::utc_minutes,
    server_fns::{ClearDokployPlacement, ConfirmDokployPlacement, get_dokploy_placement},
};

/// `changes` counts confirmations and clears, so the stack targets panel,
/// whose default depends on the placement, can load again.
#[component]
pub fn DokployPlacementPanel(changes: RwSignal<usize>) -> impl IntoView {
    let confirm = ServerAction::<ConfirmDokployPlacement>::new();
    let clear = ServerAction::<ClearDokployPlacement>::new();
    Effect::new(move |_| {
        let count = confirm.version().get() + clear.version().get();
        if changes.get_untracked() != count {
            changes.set(count);
        }
    });
    let placement = Resource::new(
        move || (confirm.version().get(), clear.version().get()),
        |_| get_dokploy_placement(),
    );
    let actions = PlacementActions { confirm, clear };

    view! {
        <h3 class="subsection-title" id="dokploy-placement-title">"Where the dashboard runs"</h3>
        <p class="field-hint">
            "The Dokploy service this dashboard is deployed as. New stacks will go into its project and environment unless you choose another. Nothing is used until you confirm it."
        </p>
        <Transition fallback=|| view! { <p class="loading" role="status">"Asking Dokploy…"</p> }>
            {move || placement.get().map(|result| match result {
                Ok(overview) => placement_view(overview, actions),
                Err(err) => view! {
                    <StatePanel
                        tone=StateTone::Error
                        title="Could not load the placement".to_string()
                        detail=err.to_string()
                    />
                }
                .into_any(),
            })}
        </Transition>
        <div id="dokploy-placement-result">
            {move || confirm.value().get().and_then(Result::err).map(error_text)}
            {move || clear.value().get().and_then(Result::err).map(error_text)}
        </div>
    }
}

fn error_text(err: AppError) -> AnyView {
    view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
}

#[derive(Clone, Copy)]
struct PlacementActions {
    confirm: ServerAction<ConfirmDokployPlacement>,
    clear: ServerAction<ClearDokployPlacement>,
}

/// The value the confirm form sends for `service`.
fn service_value(service: &DokployServiceRef) -> String {
    format!("{}:{}", service.kind.as_str(), service.id.as_str())
}

/// `Project / environment / service (Compose)`, plus the server when the
/// service runs on a remote one.
fn service_label(info: &DokployServiceInfo) -> String {
    let server = info
        .server_name
        .as_ref()
        .map(|name| format!(", on {name}"))
        .unwrap_or_default();
    format!(
        "{} / {} / {} ({}{server})",
        info.project_name,
        info.environment_name,
        info.name,
        info.service.kind.label()
    )
}

fn placement_view(overview: PlacementOverview, actions: PlacementActions) -> AnyView {
    let no_public_url = overview.public_host.is_none().then(|| {
        view! {
            <p class="field-hint">
                "SUPABASE_DASHBOARD_PUBLIC_URL is not set, so the dashboard cannot look for its own domain in Dokploy. Choose its service below."
            </p>
        }
    });
    let confirmed = overview
        .confirmed
        .clone()
        .map(|confirmed| confirmed_view(confirmed, &overview.lookup, actions));
    let lookup = lookup_view(&overview, actions);
    view! { {no_public_url} {confirmed} {lookup} }.into_any()
}

fn status_badge(status: Option<&PlacementStatus>) -> AnyView {
    match status {
        Some(PlacementStatus::Current) => {
            view! { <span class="badge badge-ok">"Current"</span> }.into_any()
        }
        Some(PlacementStatus::DomainChanged) => {
            view! { <span class="badge badge-muted">"Domain differs"</span> }.into_any()
        }
        Some(PlacementStatus::Moved { .. }) => {
            view! { <span class="badge badge-error">"Moved"</span> }.into_any()
        }
        Some(PlacementStatus::Missing) => {
            view! { <span class="badge badge-error">"Not found"</span> }.into_any()
        }
        None => view! { <span class="badge badge-muted">"Not checked"</span> }.into_any(),
    }
}

fn confirmed_view(
    confirmed: ConfirmedPlacement,
    lookup: &PlacementLookup,
    actions: PlacementActions,
) -> AnyView {
    let status = match lookup {
        PlacementLookup::Found { status, .. } => status.clone(),
        PlacementLookup::Failed(_) => None,
    };
    let by = confirmed
        .confirmed_by
        .as_ref()
        .map_or("a deleted account", |name| name.as_str())
        .to_owned();
    let placement = confirmed.placement;
    let message = status
        .as_ref()
        .map(|status| view! { <p class="field-hint">{status.message()}</p> });
    // A moved service can be confirmed again where it is now.
    let reconfirm = match &status {
        Some(PlacementStatus::Moved { now }) => Some(confirm_form(
            actions,
            &now.service,
            "Confirm the new placement",
        )),
        _ => None,
    };
    let clear = actions.clear;
    view! {
        <dl class="detail-list">
            <div>
                <dt>"Service"</dt>
                <dd>
                    {format!("{} ({})", placement.service_name, placement.service.kind.label())}
                    " " {status_badge(status.as_ref())}
                </dd>
            </div>
            <div>
                <dt>"Project"</dt>
                <dd>{placement.project_name}</dd>
            </div>
            <div>
                <dt>"Environment"</dt>
                <dd>{placement.environment_name}</dd>
            </div>
            <div>
                <dt>"Confirmed"</dt>
                <dd>{format!("{} (UTC) by {by}", utc_minutes(confirmed.confirmed_at))}</dd>
            </div>
        </dl>
        {message}
        <div class="row-actions">
            {reconfirm}
            <ActionForm action=clear>
                <button type="submit" class="button" disabled=move || clear.pending().get()>
                    "Forget this placement"
                </button>
            </ActionForm>
        </div>
    }
    .into_any()
}

fn confirm_form(
    actions: PlacementActions,
    service: &DokployServiceRef,
    label: &'static str,
) -> AnyView {
    let confirm = actions.confirm;
    let value = service_value(service);
    view! {
        <ActionForm action=confirm>
            <input type="hidden" name="service" value=value/>
            <button type="submit" class="button button-primary"
                disabled=move || confirm.pending().get()>
                {label}
            </button>
        </ActionForm>
    }
    .into_any()
}

fn lookup_view(overview: &PlacementOverview, actions: PlacementActions) -> AnyView {
    let (matches, services, truncated, status) = match &overview.lookup {
        PlacementLookup::Failed(message) => {
            return view! {
                <StatePanel
                    tone=StateTone::Error
                    title="Could not ask Dokploy".to_string()
                    detail=message.clone()
                />
            }
            .into_any();
        }
        PlacementLookup::Found {
            matches,
            services,
            truncated,
            status,
        } => (matches, services, *truncated, status),
    };
    // A current placement needs no choice; forget it to choose again.
    if matches!(status, Some(PlacementStatus::Current)) {
        return ().into_any();
    }
    if services.is_empty() {
        return view! {
            <StatePanel
                tone=StateTone::Empty
                title="No services visible".to_string()
                detail="The key cannot see any application or compose service in Dokploy. Give its member access to the dashboard's service, with permission to read services and domains.".to_string()
            />
        }
        .into_any();
    }
    let host = overview.public_host.clone().unwrap_or_default();
    let suggestion = match matches.as_slice() {
        [only] if overview.confirmed.is_none() => Some(
            view! {
                <p class="field-hint">
                    "Dokploy routes " <span class="url-text">{host.clone()}</span>
                    " to " <strong>{service_label(only)}</strong> "."
                </p>
                <div class="row-actions">{confirm_form(actions, &only.service, "Confirm this service")}</div>
            }
            .into_any(),
        ),
        [] if overview.public_host.is_some() => Some(
            view! {
                <p class="field-hint">
                    "No Dokploy domain the key can see is " <span class="url-text">{host.clone()}</span>
                    ". The dashboard may be reached through another proxy, or its domain belongs to a service the key cannot see."
                </p>
            }
            .into_any(),
        ),
        [_, _, ..] => Some(
            view! {
                <p class="field-hint">
                    {format!("{} services have a Dokploy domain that is ", matches.len())}
                    <span class="url-text">{host.clone()}</span> ". Choose the one this dashboard runs as."
                </p>
            }
            .into_any(),
        ),
        _ => None,
    };
    // Matches first, then the rest in Dokploy's order.
    let mut ordered: Vec<&DokployServiceInfo> = matches.iter().collect();
    ordered.extend(services.iter().filter(|info| !matches.contains(info)));
    let options = ordered
        .into_iter()
        .map(|info| {
            let label = if matches.contains(info) {
                format!("{} — serves {host}", service_label(info))
            } else {
                service_label(info)
            };
            view! { <option value=service_value(&info.service)>{label}</option> }
        })
        .collect_view();
    let more = truncated.then(|| {
        view! {
            <p class="field-hint">
                {format!("The key can see more services than the first {MAX_LISTED_SERVICES} listed here.")}
            </p>
        }
    });
    let confirm = actions.confirm;
    let chooser = view! {
        <ActionForm action=confirm attr:class="inline-form">
            <label class="field">
                <span class="field-label">"Dokploy service"</span>
                <select class="input" name="service" required>{options}</select>
            </label>
            <button type="submit" class="button" disabled=move || confirm.pending().get()>
                "Confirm"
            </button>
        </ActionForm>
        {more}
    }
    .into_any();
    // With one suggested service, the full list is one step away.
    let single_suggestion = overview.confirmed.is_none() && matches.len() == 1;
    let chooser = if single_suggestion {
        view! {
            <details class="placement-choice">
                <summary>"Choose another service"</summary>
                {chooser}
            </details>
        }
        .into_any()
    } else {
        chooser
    };
    view! { {suggestion} {chooser} }.into_any()
}

#[cfg(test)]
mod tests {
    use supabase_dashboard_domain::dokploy_placement::{DokployId, DokployServiceKind};

    use super::*;

    #[test]
    fn services_are_labelled_with_their_place_and_sent_by_kind_and_id() {
        let mut info = DokployServiceInfo {
            service: DokployServiceRef {
                kind: DokployServiceKind::Compose,
                id: DokployId::parse("abc_1").unwrap(),
            },
            name: "dashboard".to_owned(),
            project_id: DokployId::parse("p").unwrap(),
            project_name: "Infra".to_owned(),
            environment_id: DokployId::parse("e").unwrap(),
            environment_name: "production".to_owned(),
            server_id: None,
            server_name: None,
        };
        assert_eq!(service_value(&info.service), "compose:abc_1");
        assert_eq!(
            service_label(&info),
            "Infra / production / dashboard (Compose)"
        );
        info.server_name = Some("edge-1".to_owned());
        assert_eq!(
            service_label(&info),
            "Infra / production / dashboard (Compose, on edge-1)"
        );
    }
}
