//! Installation administration: every dashboard account, with the means to
//! disable and re-enable them.
//!
//! The server refuses these calls for anyone who is not an installation
//! administrator; the sidebar link is hidden for them only as a courtesy.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::account::AdminAccountSummary;

use crate::{
    components::page::{PageHeader, StatePanel, StateTone},
    error::AppError,
    server_fns::{AdminSetAccountDisabled, admin_list_accounts},
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
            description="Dashboard accounts of this installation. These are operators, not users of a managed project."
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
    }
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
                        <details class="confirm">
                            <summary class="button">"Disable"</summary>
                            <ActionForm action=toggle attr:class="confirm-body">
                                <input type="hidden" name="account_id" value=account.id.to_string()/>
                                <input type="hidden" name="disabled" value="true"/>
                                <p>"They are signed out everywhere and cannot sign in until enabled again."</p>
                                <button type="submit" class="button button-danger">{confirm}</button>
                            </ActionForm>
                        </details>
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
