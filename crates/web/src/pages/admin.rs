//! Installation administration: every dashboard account, with the means to
//! disable and re-enable them, a read-only list of every organization and
//! registered project, and the installation's Dokploy connection.
//!
//! The server refuses these calls for anyone who is not an installation
//! administrator; the sidebar link is hidden for them only as a courtesy.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::{
    account::AdminAccountSummary,
    admin::{
        ADMIN_FAILED_JOB_DAYS, ADMIN_FAILED_JOB_LIMIT, ADMIN_RESOURCE_LIST_LIMIT, AdminFailedJob,
        AdminOrganizationSummary, AdminProjectSummary,
    },
    connection::KeyExpiry,
    job::JobKind,
};

use crate::{
    components::dialog::{ConfirmDialog, DialogCancel},
    components::page::{PageHeader, StatePanel, StateTone},
    error::AppError,
    pages::{account::utc_minutes, admin_dokploy::DokployPanel, organization::health_badges},
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
        <DokployPanel/>
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
                            <h3 class="subsection-title">"Failed jobs"</h3>
                            <FailedJobTable list=found.failed_jobs truncated=found.failed_jobs_truncated/>
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

/// One sentence on the listed projects' last checks, so failures stand out
/// without reading every row.
fn health_summary(list: &[AdminProjectSummary]) -> String {
    let failing = list
        .iter()
        .filter(|p| p.health.as_ref().is_some_and(|h| !h.failing.is_empty()))
        .count();
    let unknown = list
        .iter()
        .filter(|p| p.health.as_ref().is_none_or(|h| h.stale))
        .count();
    let certificates = list
        .iter()
        .filter(|p| {
            p.health
                .as_ref()
                .and_then(|h| h.certificate)
                .is_some_and(|c| c.expired || c.expires_soon())
        })
        .count();
    let projects = |n: usize| if n == 1 { "project" } else { "projects" };
    let checks = match (failing, unknown) {
        (0, 0) => "No listed project failed its last check.".to_owned(),
        (failing, 0) => format!(
            "{failing} {} failed {} last check.",
            projects(failing),
            if failing == 1 { "its" } else { "their" }
        ),
        (0, unknown) => format!(
            "No checked project failed its last check; {unknown} {} never checked or last checked over a day ago.",
            if unknown == 1 { "was" } else { "were" }
        ),
        (failing, unknown) => format!(
            "{failing} {} failed {} last check; {unknown} {} never checked or last checked over a day ago.",
            projects(failing),
            if failing == 1 { "its" } else { "their" },
            if unknown == 1 { "was" } else { "were" }
        ),
    };
    match certificates {
        0 => checks,
        1 => format!(
            "{checks} 1 project's gateway certificate has expired or expires within {} days.",
            KeyExpiry::WARN_DAYS
        ),
        n => format!(
            "{checks} {n} projects' gateway certificates have expired or expire within {} days.",
            KeyExpiry::WARN_DAYS
        ),
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

/// What a failed job was asked to do.
fn job_label(job: &AdminFailedJob) -> &'static str {
    match (job.kind, job.action) {
        (JobKind::ProvisionStack, _) => "Create stack",
        (JobKind::StackAction, Some(action)) => action.label(),
        (JobKind::StackAction, None) => "Stack action",
    }
}

#[component]
fn FailedJobTable(list: Vec<AdminFailedJob>, truncated: bool) -> impl IntoView {
    if list.is_empty() {
        return view! {
            <StatePanel
                tone=StateTone::Empty
                title="No failed jobs".to_string()
                detail=format!("No background job failed in the last {ADMIN_FAILED_JOB_DAYS} days.")
            />
        }
        .into_any();
    }
    let rows = list
        .into_iter()
        .map(|job| {
            let label = job_label(&job);
            let project = match (job.project_name, job.project_id) {
                (Some(name), Some(_)) => name,
                (Some(name), None) => format!("{name} (not registered)"),
                (None, _) => "Unregistered project".to_owned(),
            };
            view! {
                <tr>
                    <td>{label}</td>
                    <td>{project}</td>
                    <td>{job.organization_name.as_str().to_owned()}</td>
                    <td class="wrap-text">{job.message.unwrap_or_else(|| "No reason was recorded.".to_owned())}</td>
                    <td class="nowrap">{utc_minutes(job.failed_at)}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <p class="field-hint">
            {format!("Jobs that failed in the last {ADMIN_FAILED_JOB_DAYS} days, newest first. Members of each organization see the same reasons on their project pages.")}
        </p>
        <div class="table-wrap" role="region" aria-label="Failed jobs" tabindex="0">
            <table class="data-table">
                <caption class="visually-hidden">"Failed jobs"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Job"</th>
                        <th scope="col">"Project"</th>
                        <th scope="col">"Organization"</th>
                        <th scope="col">"Reason"</th>
                        <th scope="col">"Failed (UTC)"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {truncated.then(|| view! {
            <p class="field-hint" role="note">
                {format!("Showing the newest {ADMIN_FAILED_JOB_LIMIT}. More failed in that period.")}
            </p>
        })}
    }
    .into_any()
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
        <div class="table-wrap" role="region" aria-label="Organizations" tabindex="0">
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
    let summary = health_summary(&list);
    let rows = list
        .into_iter()
        .map(|project| {
            let health = health_badges(project.health.as_ref());
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
                    <td><div class="health-cell">{health}</div></td>
                    <td class="nowrap">{project.created_at.date().to_string()}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <p class="section-text" role="status">{summary}</p>
        <div class="table-wrap" role="region" aria-label="Registered projects" tabindex="0">
            <table class="data-table">
                <caption class="visually-hidden">"Registered projects"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Name"</th>
                        <th scope="col">"Organization"</th>
                        <th scope="col">"API URL"</th>
                        <th scope="col">"Last check"</th>
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
        <div class="table-wrap" role="region" aria-label="Dashboard accounts" tabindex="0">
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

#[cfg(test)]
mod tests {
    use supabase_dashboard_domain::{
        connection::{HealthDigest, StackService},
        organization::OrganizationName,
        project::{ProjectName, ProjectUrl},
    };
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn failed_jobs_are_labelled_by_what_they_did() {
        let job = |kind, action| AdminFailedJob {
            id: Uuid::nil(),
            kind,
            action,
            organization_id: Uuid::nil(),
            organization_name: OrganizationName::parse("Acme").unwrap(),
            project_id: None,
            project_name: None,
            message: None,
            failed_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(
            job_label(&job(JobKind::ProvisionStack, None)),
            "Create stack"
        );
        assert_eq!(
            job_label(&job(
                JobKind::StackAction,
                Some(supabase_dashboard_domain::provisioning::StackAction::Configure)
            )),
            "Change settings"
        );
        assert_eq!(job_label(&job(JobKind::StackAction, None)), "Stack action");
    }

    fn project(health: Option<(Vec<StackService>, bool)>) -> AdminProjectSummary {
        let id = Uuid::nil();
        AdminProjectSummary {
            id,
            organization_id: id,
            organization_name: OrganizationName::parse("Acme").unwrap(),
            name: ProjectName::parse("Prod").unwrap(),
            api_url: ProjectUrl::parse("https://supabase.example.test").unwrap(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            health: health.map(|(failing, stale)| HealthDigest {
                project_id: id,
                checked_at: OffsetDateTime::UNIX_EPOCH,
                failing,
                not_checked: Vec::new(),
                stale,
                certificate: None,
            }),
        }
    }

    #[test]
    fn the_summary_counts_failing_and_unknown_projects() {
        let healthy = project(Some((Vec::new(), false)));
        let failing = project(Some((vec![StackService::Auth], false)));
        let stale_failing = project(Some((vec![StackService::Rest], true)));
        let never = project(None);
        assert_eq!(
            health_summary(std::slice::from_ref(&healthy)),
            "No listed project failed its last check."
        );
        assert_eq!(
            health_summary(&[healthy, failing.clone()]),
            "1 project failed its last check."
        );
        assert_eq!(
            health_summary(std::slice::from_ref(&never)),
            "No checked project failed its last check; 1 was never checked or last checked over a day ago."
        );
        assert_eq!(
            health_summary(&[failing, stale_failing, never]),
            "2 projects failed their last check; 2 were never checked or last checked over a day ago."
        );
    }

    #[test]
    fn the_summary_counts_certificates_that_need_renewing() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let with = |days: i64| {
            let mut p = project(Some((Vec::new(), false)));
            if let Some(h) = p.health.as_mut() {
                h.certificate = Some(KeyExpiry::new(now + time::Duration::days(days), now));
            }
            p
        };
        assert_eq!(
            health_summary(&[with(90)]),
            "No listed project failed its last check."
        );
        assert_eq!(
            health_summary(&[with(90), with(5)]),
            "No listed project failed its last check. 1 project's gateway certificate has expired or expires within 30 days."
        );
        assert_eq!(
            health_summary(&[with(-1), with(5)]),
            "No listed project failed its last check. 2 projects' gateway certificates have expired or expire within 30 days."
        );
    }
}
