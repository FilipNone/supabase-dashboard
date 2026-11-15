//! Audit log tables: an organization's log on its Audit tab, and an
//! account's own log in its settings. Both page through the server one
//! page at a time; only the shown page is held in the browser.

use leptos::prelude::*;
use supabase_dashboard_domain::audit::{
    AUDIT_PAGE, AuditActor, AuditEntry, AuditEntryOutcome, AuditLogPage, action_label,
};
use uuid::Uuid;

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::account::utc_seconds,
    server_fns::{get_account_audit_log, get_organization_audit_log},
};

/// Whose log a panel shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLogSubject {
    Organization(Uuid),
    /// The signed-in account's own log.
    Account,
}

/// The log with a refresh button, a member filter for an organization, and
/// pagers. The server decides who may read it.
#[component]
pub fn AuditLogPanel(subject: AuditLogSubject) -> impl IntoView {
    let reload = RwSignal::new(0_u32);
    // Where each page after the newest starts; the last one is shown.
    let pages = RwSignal::new(Vec::<Uuid>::new());
    // The member whose events are shown; `None` shows everyone's.
    let member = RwSignal::new(None::<Uuid>);
    let log = Resource::new(
        move || {
            (
                reload.get(),
                member.get(),
                pages.with(|pages| pages.last().copied()),
            )
        },
        move |(_, member, before)| async move {
            match subject {
                AuditLogSubject::Organization(id) => {
                    get_organization_audit_log(id, member, before).await
                }
                AuditLogSubject::Account => get_account_audit_log(before).await,
            }
        },
    );
    // The filter sits outside the reloading part, so changing it keeps
    // focus on it. It offers the members from the latest answer.
    let choices = RwSignal::new((Vec::<AuditActor>::new(), false));
    Effect::new(move |_| {
        if let Some(Ok(page)) = log.get() {
            choices.set((page.members, page.more_members));
        }
    });
    let organization = matches!(subject, AuditLogSubject::Organization(_));
    let intro = if organization {
        "Who did what in this organization and its projects, newest first. \
         Refused attempts are listed too. Events hold no keys, passwords, or project data."
    } else {
        "What you did in the dashboard, and what was done to your account, such as failed \
         sign-ins with your email or an administrator disabling it. Newest first."
    };
    view! {
        <section class="panel" aria-labelledby="audit-log-title">
            <div class="section-header">
                <h2 class="section-title" id="audit-log-title">"Audit log"</h2>
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
            <p class="section-text">{intro}</p>
            {move || {
                let shown = organization
                    && (member.with(Option::is_some)
                        || choices.with(|(members, _)| !members.is_empty()));
                shown.then(|| member_filter(member, choices, pages).into_any())
            }}
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading the audit log…"</p> }>
                {move || log.get().map(|result| match result {
                    Ok(page) => {
                        let filtered = member.with_untracked(Option::is_some);
                        log_view(page, filtered, organization, pages).into_any()
                    }
                    Err(AppError::Forbidden) => view! {
                        <StatePanel
                            tone=StateTone::Empty
                            title="Owners and administrators only".to_string()
                            detail="Your role in this organization cannot read its audit log.".to_string()
                        />
                    }
                    .into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Audit log unavailable".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })}
            </Transition>
        </section>
    }
}

fn member_filter(
    member: RwSignal<Option<Uuid>>,
    choices: RwSignal<(Vec<AuditActor>, bool)>,
    pages: RwSignal<Vec<Uuid>>,
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
    let more = move || {
        choices.with(|(_, more)| *more).then(|| {
            view! {
                <p class="field-hint">
                    "More members have events than the list can show; only the first ones by name are listed."
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
        </div>
        {more}
    }
}

fn log_view(
    page: AuditLogPage,
    filtered: bool,
    organization: bool,
    pages: RwSignal<Vec<Uuid>>,
) -> impl IntoView {
    let AuditLogPage { entries, older, .. } = page;
    let number = pages.with_untracked(Vec::len) + 1;
    let first_page = number == 1;
    let has_pages = !first_page || older.is_some();
    // `aria-disabled` rather than `disabled`, so a pressed button with no
    // further page keeps keyboard focus.
    let off = |off: bool| off.then_some("true");
    let pager = move |where_: &'static str| {
        has_pages.then(|| {
            view! {
                <nav class="pager" aria-label=format!("Audit log pages, {where_}")>
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
                    <span class="field-hint" aria-live=(where_ == "top").then_some("polite")>
                        {format!("Page {number}")}
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
        let text = match (first_page, filtered) {
            (true, true) => "This member has no events here.",
            (true, false) => "No events yet.",
            (false, _) => "No older events.",
        };
        return view! {
            <p class="section-text">{text}</p>
            {pager("bottom")}
        }
        .into_any();
    }
    let rows = entries
        .into_iter()
        .map(|entry| audit_row(entry, organization))
        .collect_view();
    view! {
        <p class="field-hint">{format!("{AUDIT_PAGE} events per page.")}</p>
        {pager("top")}
        <div class="table-wrap" role="region" aria-label="Audit events" tabindex="0">
            <table class="data-table audit-table">
                <caption class="visually-hidden">{format!("Audit events, newest first, page {number}")}</caption>
                <thead>
                    <tr>
                        <th scope="col">"Time (UTC)"</th>
                        {organization.then(|| view! { <th scope="col">"Member"</th> })}
                        <th scope="col">"Action"</th>
                        <th scope="col">"Target"</th>
                        <th scope="col">"Outcome"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {pager("bottom")}
    }
    .into_any()
}

fn audit_row(entry: AuditEntry, organization: bool) -> impl IntoView {
    let actor = organization.then(|| {
        let cell = match entry.actor {
            Some(actor) => view! {
                <span>{actor.display_name}</span>
                <span class="field-hint status-detail">{actor.email}</span>
            }
            .into_any(),
            None => view! { <span class="field-hint">"No account"</span> }.into_any(),
        };
        view! { <td>{cell}</td> }
    });
    let target = target_text(entry.target_type.as_deref(), entry.target_id.as_deref());
    let class = match entry.outcome {
        AuditEntryOutcome::Success => "badge badge-ok",
        AuditEntryOutcome::Denied | AuditEntryOutcome::Failure => "badge badge-error",
    };
    let label = action_label(&entry.action).to_owned();
    view! {
        <tr>
            <td class="nowrap">{utc_seconds(entry.at)}</td>
            {actor}
            <td>
                <span>{label}</span>
                <code class="field-hint status-detail">{entry.action}</code>
            </td>
            <td>{target.map(|text| view! { <code class="request-path">{text}</code> })}</td>
            <td><span class=class>{entry.outcome.label()}</span></td>
        </tr>
    }
}

/// The target as `kind id`, with an organization member's
/// `<organization>:<account>` shown as the account only, since the log is
/// already the organization's.
fn target_text(kind: Option<&str>, id: Option<&str>) -> Option<String> {
    let kind = kind?;
    let label = kind.replace('_', " ");
    Some(match (kind, id) {
        ("organization_member", Some(id)) => {
            let account = id.split_once(':').map_or(id, |(_, account)| account);
            format!("member {account}")
        }
        (_, Some(id)) => format!("{label} {id}"),
        (_, None) => label,
    })
}

#[cfg(test)]
mod tests {
    use super::target_text;

    #[test]
    fn targets_name_their_kind() {
        assert_eq!(target_text(None, Some("x")), None);
        assert_eq!(
            target_text(Some("project"), Some("p1")).as_deref(),
            Some("project p1")
        );
        assert_eq!(
            target_text(Some("organization_member"), Some("o1:a1")).as_deref(),
            Some("member a1")
        );
        assert_eq!(
            target_text(Some("organization_invitation"), None).as_deref(),
            Some("organization invitation")
        );
    }
}
