//! Installation administration: every dashboard account, with the means to
//! disable and re-enable them, and a read-only list of every organization
//! and registered project.
//!
//! The server refuses these calls for anyone who is not an installation
//! administrator; the sidebar link is hidden for them only as a courtesy.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::{
    account::AdminAccountSummary,
    admin::{ADMIN_RESOURCE_LIST_LIMIT, AdminOrganizationSummary, AdminProjectSummary},
};

use crate::{
    components::dialog::{ConfirmDialog, DialogCancel},
    components::page::{PageHeader, StatePanel, StateTone},
    error::AppError,
    server_fns::{AdminSetAccountDisabled, admin_list_accounts, admin_list_resources},
};

#[component]
pub fn AdminPage() -> impl IntoView {
    let toggle = ServerAction::<AdminSetAccountDisabled>::new();
    let accounts = Resource::new(move || toggle.version().get(), |_| admin_list_accounts());
    let toggle_error = move || {
        toggle
            .value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };
    view! {
        <Title text="Administration"/>
        <PageHeader
            title="Administration"
            description="Dashboard accounts, organizations, and projects of this installation. Accounts here are operators, not users of a managed project."
        />
        <section class="panel" aria-labelledby="accounts-title">
            <h2 class="section-title" id="accounts-title">"Accounts"</h2>
            <p class="field-hint">
                "A disabled account cannot sign in and is signed out everywhere. It keeps its organization memberships, so enabling it again restores its access."
            </p>
            {toggle_error}
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading accounts…"</p> }>
                {move || {
                    accounts.get().map(|result| match result {
                        Ok(list) => view! { <AccountTable list toggle/> }.into_any(),
                        Err(AppError::Forbidden) => view! {
                            <StatePanel
                                tone=StateTone::Error
                                title="Administrators only".to_string()
                                detail="Only installation administrators can see this page.".to_string()
                            />
                        }
                        .into_any(),
                        Err(err) => view! {
                            <StatePanel
                                tone=StateTone::Error
                                title="Could not load accounts".to_string()
                                detail=err.to_string()
                            />
                        }
                        .into_any(),
                    })
                }}
            </Transition>
        </section>
        <RegisteredResources/>
    }
}

/// Every organization and project. Read-only: an administrator who is not
/// a member of an organization cannot open its projects from here.
#[component]
fn RegisteredResources() -> impl IntoView {
    let resources = Resource::new(|| (), |()| admin_list_resources());
    view! {
        <section class="panel" aria-labelledby="resources-title">
            <h2 class="section-title" id="resources-title">"Registered resources"</h2>
            <p class="field-hint">
                "Every organization and project on this installation. This list does not give you access to them: to open a project, an owner or administrator of its organization has to invite you."
            </p>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading resources…"</p> }>
                {move || {
                    resources.get().map(|result| match result {
                        Ok(found) => view! {
                            <h3 class="subsection-title">"Organizations"</h3>
                            <OrganizationTable list=found.organizations truncated=found.organizations_truncated/>
                            <h3 class="subsection-title">"Projects"</h3>
                            <ProjectTable list=found.projects truncated=found.projects_truncated/>
                        }
                        .into_any(),
                        Err(AppError::Forbidden) => ().into_any(),
                        Err(err) => view! {
                            <StatePanel
                                tone=StateTone::Error
                                title="Could not load resources".to_string()
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

fn truncation_note(truncated: bool, what: &'static str) -> Option<impl IntoView> {
    truncated.then(|| {
        view! {
            <p class="field-hint" role="note">
                {format!("Showing the oldest {ADMIN_RESOURCE_LIST_LIMIT} {what}. More exist.")}
            </p>
        }
    })
}

#[component]
fn OrganizationTable(list: Vec<AdminOrganizationSummary>, truncated: bool) -> impl IntoView {
    if list.is_empty() {
        return view! {
            <StatePanel
                tone=StateTone::Empty
                title="No organizations yet".to_string()
                detail="Organizations appear here once an operator creates one.".to_string()
            />
        }
        .into_any();
    }
    let rows = list
        .into_iter()
        .map(|org| {
            view! {
                <tr>
                    <td>{org.name.as_str().to_owned()}</td>
                    <td>{org.member_count.to_string()}</td>
                    <td>{org.project_count.to_string()}</td>
                    <td class="nowrap">{org.created_at.date().to_string()}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap">
            <table class="data-table">
                <caption class="visually-hidden">"Organizations"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Name"</th>
                        <th scope="col">"Members"</th>
                        <th scope="col">"Projects"</th>
                        <th scope="col">"Created (UTC)"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {truncation_note(truncated, "organizations")}
    }
    .into_any()
}

#[component]
fn ProjectTable(list: Vec<AdminProjectSummary>, truncated: bool) -> impl IntoView {
    if list.is_empty() {
        return view! {
            <StatePanel
                tone=StateTone::Empty
                title="No projects registered".to_string()
                detail="Projects appear here once an owner or administrator registers a stack.".to_string()
            />
        }
        .into_any();
    }
    let rows = list
        .into_iter()
        .map(|project| {
            let transport = if project.api_url.is_encrypted() {
                view! { <span class="badge badge-ok">"HTTPS"</span> }.into_any()
            } else {
                view! { <span class="badge badge-error">"Plain HTTP"</span> }.into_any()
            };
            view! {
                <tr>
                    <td>{project.name.as_str().to_owned()}</td>
                    <td>{project.organization_name.as_str().to_owned()}</td>
                    <td><span class="url-text">{project.api_url.as_str().to_owned()}</span> {transport}</td>
                    <td class="nowrap">{project.created_at.date().to_string()}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap">
            <table class="data-table">
                <caption class="visually-hidden">"Registered projects"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Name"</th>
                        <th scope="col">"Organization"</th>
                        <th scope="col">"API URL"</th>
                        <th scope="col">"Registered (UTC)"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {truncation_note(truncated, "projects")}
    }
    .into_any()
}

#[component]
fn AccountTable(
    list: Vec<AdminAccountSummary>,
    toggle: ServerAction<AdminSetAccountDisabled>,
) -> impl IntoView {
    let rows = list
        .into_iter()
        .map(|account| {
            let name = account.display_name.as_str().to_owned();
            let action = if account.is_you {
                ().into_any()
            } else if account.disabled {
                let label = format!("Enable {name}");
                view! {
                    <ActionForm action=toggle attr:class="inline-form compact">
                        <input type="hidden" name="account_id" value=account.id.to_string()/>
                        <input type="hidden" name="disabled" value="false"/>
                        <button type="submit" class="button">{label}</button>
                    </ActionForm>
                }
                .into_any()
            } else {
                let confirm = format!("Disable {name}");
                view! {
                    <div class="row-actions">
                        <ConfirmDialog trigger="Disable" title=format!("{}?", confirm)>
                            <ActionForm action=toggle attr:class="dialog-form">
                                <input type="hidden" name="account_id" value=account.id.to_string()/>
                                <input type="hidden" name="disabled" value="true"/>
                                <p>"They are signed out everywhere and cannot sign in until enabled again."</p>
                                <div class="dialog-actions">
                                    <DialogCancel/>
                                    <button type="submit" class="button button-danger">{confirm}</button>
                                </div>
                            </ActionForm>
                        </ConfirmDialog>
                    </div>
                }
                .into_any()
            };
            let status = if account.disabled { "Disabled" } else { "Active" };
            view! {
                <tr>
                    <td>
                        {name.clone()}
                        {account.is_you.then(|| view! { <span class="badge badge-muted">"You"</span> })}
                        {account.is_installation_admin.then(|| view! { <span class="badge badge-muted">"Admin"</span> })}
                    </td>
                    <td>{account.email.to_string()}</td>
                    <td>{status}</td>
                    <td>{account.organization_count.to_string()}</td>
                    <td class="nowrap">{account.created_at.date().to_string()}</td>
                    <td>{action}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap">
            <table class="data-table">
                <caption class="visually-hidden">"Dashboard accounts"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Name"</th>
                        <th scope="col">"Email"</th>
                        <th scope="col">"Status"</th>
                        <th scope="col">"Organizations"</th>
                        <th scope="col">"Created (UTC)"</th>
                        <th scope="col"><span class="visually-hidden">"Actions"</span></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
}
