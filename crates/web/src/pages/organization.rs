//! Pages for one organization: projects, settings, and team.
//!
//! Controls are shown or hidden according to the operator's role so the page
//! only offers actions that can work. The server checks the role again on
//! every call; hiding a control is not the authorization.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use leptos_router::{
    components::{A, Outlet},
    hooks::{use_navigate, use_params_map},
};
use supabase_dashboard_domain::{
    authz::{OrgRole, Permission},
    invitation::{InvitationSummary, IssuedInvitation},
    organization::{MemberSummary, ORGANIZATION_NAME_MAX_CHARS, OrganizationSummary},
    project::ProjectSummary,
};
use uuid::Uuid;

use crate::{
    app::INVITE_PATH,
    components::dialog::{ConfirmDialog, DialogCancel},
    components::{
        layout::Refresh,
        page::{StatePanel, StateTone},
    },
    error::AppError,
    pages::project::{project_entry, project_path},
    server_fns::{
        ChangeMemberRole, CreateInvitation, RemoveMember, RenameOrganization, RevokeInvitation,
        get_organization, list_invitations, list_members, list_projects,
    },
};

#[derive(Clone, Copy)]
struct OrgContext {
    id: Memo<Option<Uuid>>,
    org: Resource<Result<OrganizationSummary, AppError>>,
    rename: ServerAction<RenameOrganization>,
}

/// Loads the organization named in the URL and renders its tabs. A
/// malformed ID, an unknown organization, and one the operator does not
/// belong to all show the same not-found state.
#[component]
pub fn OrganizationLayout() -> impl IntoView {
    let params = use_params_map();
    let id = Memo::new(move |_| {
        params
            .read()
            .get("org_id")
            .and_then(|raw| raw.parse::<Uuid>().ok())
    });
    let rename = ServerAction::<RenameOrganization>::new();
    let org = Resource::new(
        move || (id.get(), rename.version().get()),
        |(id, _)| async move {
            match id {
                Some(id) => get_organization(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    provide_context(OrgContext { id, org, rename });
    // The top-bar switcher shows the name too.
    let refresh = use_context::<Refresh>();
    Effect::new(move |_| {
        if let (Some(Ok(_)), Some(refresh)) = (rename.value().get(), refresh) {
            refresh.organizations_changed();
        }
    });

    view! {
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading organization…"</p> }>
            {move || {
                org.get()
                    .map(|result| match result {
                        Ok(org) => {
                            let base = format!("/dashboard/org/{}", org.id);
                            view! {
                                <Title text=org.name.as_str().to_owned()/>
                                <header class="page-header">
                                    <div>
                                        <h1 class="page-title">{org.name.as_str().to_owned()}</h1>
                                        <p class="page-description">
                                            "Your role: " {org.role.label()}
                                        </p>
                                    </div>
                                </header>
                                <nav class="tabs" aria-label="Organization">
                                    <A href=base.clone() exact=true attr:class="tab">"Projects"</A>
                                    <A href=format!("{base}/general") attr:class="tab">"General"</A>
                                    <A href=format!("{base}/team") attr:class="tab">"Team"</A>
                                </nav>
                                <Outlet/>
                            }
                            .into_any()
                        }
                        Err(err) => view! {
                            <Title text="Organization"/>
                            <StatePanel
                                tone=StateTone::Error
                                title="Organization unavailable".to_string()
                                detail=err.to_string()
                            />
                            <p><a href="/dashboard/organizations">"Back to organizations"</a></p>
                        }
                        .into_any(),
                    })
            }}
        </Transition>
    }
}

fn loaded_org(ctx: OrgContext) -> Option<OrganizationSummary> {
    ctx.org.get().and_then(Result::ok)
}

/// The organization's registered projects. The overview page of an
/// organization, as in the reference dashboard.
#[component]
pub fn OrganizationProjectsPage() -> impl IntoView {
    let Some(ctx) = use_context::<OrgContext>() else {
        return ().into_any();
    };
    let projects = Resource::new(
        move || ctx.id.get(),
        |id| async move {
            match id {
                Some(id) => list_projects(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    let can_register =
        move || loaded_org(ctx).is_some_and(|org| org.role.allows(Permission::ProjectRegister));
    let new_href = move || ctx.id.get().map(|id| format!("/dashboard/new/{id}"));
    view! {
        <div class="section-header">
            <h2 class="section-title">"Projects"</h2>
            {move || can_register().then(|| view! {
                <a class="button button-primary" href=new_href()>"Register project"</a>
            })}
        </div>
        <Transition fallback=|| view! { <p class="loading" role="status">"Loading projects…"</p> }>
            {move || {
                projects.get().map(|result| match result {
                    Ok(list) if list.is_empty() => {
                        let detail = if can_register() {
                            "Register an existing self-hosted Supabase stack to manage it here."
                        } else {
                            "An owner or administrator can register an existing self-hosted Supabase stack."
                        };
                        view! {
                            <StatePanel
                                tone=StateTone::Empty
                                title="No projects yet".to_string()
                                detail=detail.to_string()
                            />
                        }
                        .into_any()
                    }
                    Ok(list) => view! { <ProjectGrid list/> }.into_any(),
                    Err(err) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Could not load projects".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })
            }}
        </Transition>
    }
    .into_any()
}

#[component]
fn ProjectGrid(list: Vec<ProjectSummary>) -> impl IntoView {
    view! {
        <ul class="card-grid" aria-label="Projects">
            {list
                .into_iter()
                .map(|project| {
                    let insecure = (!project.api_url.is_encrypted())
                        .then(|| view! { <span class="badge badge-error">"Plain HTTP"</span> });
                    let (href, studio) = project_entry(&project);
                    // The card opens Studio when the member may; the
                    // dashboard's own page stays one link away.
                    let status = studio.then(|| view! {
                        <a class="card-aside" href=project_path(project.organization_id, project.id)>
                            "Status and settings"
                        </a>
                    });
                    view! {
                        <li>
                            <div class="card-link card-stack project-card">
                                <a class="card-title card-cover" href=href rel=studio.then_some("external")>
                                    {project.name.as_str().to_owned()}
                                    {studio.then(|| view! { <span class="visually-hidden">" (opens Studio)"</span> })}
                                </a>
                                <span class="card-meta url-text">{project.api_url.as_str().to_owned()}</span>
                                {insecure}
                                {status}
                            </div>
                        </li>
                    }
                })
                .collect_view()}
        </ul>
    }
}

/// Organization settings: currently the name.
#[component]
pub fn OrganizationGeneralPage() -> impl IntoView {
    let Some(ctx) = use_context::<OrgContext>() else {
        return ().into_any();
    };
    let rename = ctx.rename;
    let feedback = move || {
        rename.value().get().map(|result| match result {
            Ok(_) => {
                view! { <p class="form-ok" role="status">"Organization name saved."</p> }.into_any()
            }
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };
    view! {
        {move || {
            loaded_org(ctx).map(|org| {
                let can_edit = org.role.allows(Permission::OrgUpdate);
                view! {
                    <section class="panel" aria-labelledby="org-general-title">
                        <h2 class="section-title" id="org-general-title">"General settings"</h2>
                        <ActionForm action=rename attr:class="inline-form">
                            <input type="hidden" name="id" value=org.id.to_string()/>
                            <label class="field">
                                <span class="field-label">"Organization name"</span>
                                <input
                                    class="input" name="name" required autocomplete="off"
                                    maxlength=ORGANIZATION_NAME_MAX_CHARS.to_string()
                                    value=org.name.as_str().to_owned()
                                    readonly=!can_edit
                                />
                            </label>
                            {can_edit.then(|| view! {
                                <button type="submit" class="button button-primary"
                                    disabled=move || rename.pending().get()>
                                    "Save"
                                </button>
                            })}
                        </ActionForm>
                        {(!can_edit).then(|| view! {
                            <p class="field-hint">"Only owners and administrators can rename the organization."</p>
                        })}
                        {feedback}
                    </section>
                }
            })
        }}
    }
    .into_any()
}

/// Members of the organization, with role changes and removal for those
/// allowed to manage members, and a way to leave for everyone.
#[component]
pub fn OrganizationTeamPage() -> impl IntoView {
    let Some(ctx) = use_context::<OrgContext>() else {
        return ().into_any();
    };
    let change = ServerAction::<ChangeMemberRole>::new();
    let remove = ServerAction::<RemoveMember>::new();
    let leave = ServerAction::<RemoveMember>::new();
    let members = Resource::new(
        move || (ctx.id.get(), change.version().get(), remove.version().get()),
        |(id, _, _)| async move {
            match id {
                Some(id) => list_members(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );

    // After leaving, this organization is no longer visible.
    let navigate = use_navigate();
    let refresh = use_context::<Refresh>();
    Effect::new(move |_| {
        if matches!(leave.value().get(), Some(Ok(()))) {
            if let Some(refresh) = refresh {
                refresh.organizations_changed();
            }
            navigate("/dashboard/organizations", Default::default());
        }
    });

    let action_error = move || {
        [
            change.value().get(),
            remove.value().get(),
            leave.value().get(),
        ]
        .into_iter()
        .flatten()
        .find_map(Result::err)
        .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };

    view! {
        {move || {
            loaded_org(ctx)
                .filter(|org| org.role.allows(Permission::MembersManage))
                .map(|org| view! { <InviteMember org/> })
        }}
        <Invitations ctx/>
        <section class="panel" aria-labelledby="team-title">
            <h2 class="section-title" id="team-title">"Members"</h2>
            <p class="field-hint">
                "Owners, administrators, and developers can open each project's Studio. Studio has \
                 no roles of its own: it gives full access to the database and shows the stack's \
                 API keys and JWT secret. Read-only members see project status in the dashboard only."
            </p>
            {action_error}
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading members…"</p> }>
                {move || {
                    let actor = loaded_org(ctx).map(|org| org.role);
                    members
                        .get()
                        .map(|result| match (result, actor) {
                            (Ok(list), Some(actor)) => {
                                let org_id = ctx.id.get().map(|id| id.to_string()).unwrap_or_default();
                                view! { <MemberTable list actor org_id change remove leave/> }.into_any()
                            }
                            (Err(err), _) => view! {
                                <StatePanel
                                    tone=StateTone::Error
                                    title="Could not load members".to_string()
                                    detail=err.to_string()
                                />
                            }
                            .into_any(),
                            (Ok(_), None) => ().into_any(),
                        })
                }}
            </Transition>
        </section>
    }
    .into_any()
}

/// Hidden fields naming the organization and member a form acts on.
#[component]
fn MemberTarget(target: (String, String)) -> impl IntoView {
    let (organization_id, account_id) = target;
    view! {
        <input type="hidden" name="organization_id" value=organization_id/>
        <input type="hidden" name="account_id" value=account_id/>
    }
}

#[component]
fn MemberTable(
    list: Vec<MemberSummary>,
    actor: OrgRole,
    org_id: String,
    change: ServerAction<ChangeMemberRole>,
    remove: ServerAction<RemoveMember>,
    leave: ServerAction<RemoveMember>,
) -> impl IntoView {
    let can_manage = actor.allows(Permission::MembersManage);
    let rows = list
        .into_iter()
        .map(|member| {
            // Mirrors the server rule: only owners touch the owner role.
            let editable = can_manage
                && !member.is_you
                && (actor == OrgRole::Owner || member.role != OrgRole::Owner);
            let target = (org_id.clone(), member.account_id.to_string());
            let name = member.display_name.as_str().to_owned();
            let controls = if editable {
                let options = assignable_roles(actor)
                    .map(|role| {
                        view! {
                            <option value=role.as_str() selected=role == member.role>
                                {role.label()}
                            </option>
                        }
                    })
                    .collect_view();
                let select_label = format!("Role for {name}");
                let confirm = format!("Remove {name}");
                let remove_target = target.clone();
                view! {
                    <div class="row-actions">
                        <ActionForm action=change attr:class="inline-form compact">
                            <MemberTarget target=target.clone()/>
                            <select class="input" name="role" aria-label=select_label>{options}</select>
                            <button type="submit" class="button">"Change role"</button>
                        </ActionForm>
                        <ConfirmDialog trigger="Remove" title=format!("{}?", confirm)>
                            <ActionForm action=remove attr:class="dialog-form">
                                <MemberTarget target=remove_target.clone()/>
                                <p>"They lose access to this organization immediately."</p>
                                <div class="dialog-actions">
                                    <DialogCancel/>
                                    <button type="submit" class="button button-danger">{confirm}</button>
                                </div>
                            </ActionForm>
                        </ConfirmDialog>
                    </div>
                }
                .into_any()
            } else if member.is_you {
                view! {
                    <div class="row-actions">
                    <ConfirmDialog trigger="Leave" title="Leave organization?">
                        <ActionForm action=leave attr:class="dialog-form">
                            <MemberTarget target=target.clone()/>
                            <p>"You lose access until someone adds you again."</p>
                            <div class="dialog-actions">
                                <DialogCancel/>
                                <button type="submit" class="button button-danger">"Leave organization"</button>
                            </div>
                        </ActionForm>
                    </ConfirmDialog>
                    </div>
                }
                .into_any()
            } else {
                ().into_any()
            };
            view! {
                <tr>
                    <td>
                        {name.clone()}
                        {member.is_you.then(|| view! { <span class="badge badge-muted">"You"</span> })}
                    </td>
                    <td>{member.email.to_string()}</td>
                    <td>{member.role.label()}</td>
                    <td>{controls}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap">
            <table class="data-table">
                <caption class="visually-hidden">"Organization members"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Name"</th>
                        <th scope="col">"Email"</th>
                        <th scope="col">"Role"</th>
                        <th scope="col"><span class="visually-hidden">"Actions"</span></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
}

/// Roles `actor` may hand out. Mirrors the server rule that only owners
/// grant the owner role.
fn assignable_roles(actor: OrgRole) -> impl Iterator<Item = OrgRole> {
    OrgRole::ALL
        .into_iter()
        .filter(move |role| actor == OrgRole::Owner || *role != OrgRole::Owner)
}

/// The full link for an invitation code. The code goes in the fragment so
/// it is not sent to the server when the link is opened.
fn invitation_link(code: &str) -> String {
    #[cfg(feature = "hydrate")]
    if let Ok(origin) = window().location().origin() {
        return format!("{origin}{INVITE_PATH}#{code}");
    }
    format!("{INVITE_PATH}#{code}")
}

#[component]
fn InviteMember(org: OrganizationSummary) -> impl IntoView {
    let Some(ctx) = use_context::<InvitationActions>() else {
        return ().into_any();
    };
    let create = ctx.create;
    let options = assignable_roles(org.role)
        .map(|role| {
            view! {
                <option value=role.as_str() selected=role == OrgRole::Developer>{role.label()}</option>
            }
        })
        .collect_view();
    let result = move || {
        create.value().get().map(|result| match result {
            Ok(issued) => view! { <IssuedLink issued/> }.into_any(),
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };
    view! {
        <section class="panel" aria-labelledby="invite-title">
            <h2 class="section-title" id="invite-title">"Invite a member"</h2>
            <ActionForm action=create attr:class="inline-form">
                <input type="hidden" name="organization_id" value=org.id.to_string()/>
                <label class="field">
                    <span class="field-label">"Email"</span>
                    <input class="input" type="email" name="email" required autocomplete="off" maxlength="254"/>
                </label>
                <label class="field">
                    <span class="field-label">"Role"</span>
                    <select class="input" name="role">{options}</select>
                </label>
                <button type="submit" class="button button-primary" disabled=move || create.pending().get()>
                    "Create invitation"
                </button>
            </ActionForm>
            {result}
        </section>
    }
    .into_any()
}

/// The link for a new invitation. Shown once: the server keeps only a hash
/// of the code and cannot show it again.
#[component]
fn IssuedLink(issued: IssuedInvitation) -> impl IntoView {
    let link = invitation_link(issued.code.expose());
    let note = format!(
        "Send this link to {} yourself; the dashboard does not send email yet. \
         It is shown only once, works for that address only, and expires on {} (UTC).",
        issued.invitation.email.as_str(),
        issued.invitation.expires_at.date(),
    );
    view! {
        <div class="issued-link" role="status">
            <label class="field">
                <span class="field-label">"Invitation link"</span>
                <input class="input mono" readonly value=link aria-describedby="issued-link-note"/>
            </label>
            <p class="field-hint" id="issued-link-note">{note}</p>
        </div>
    }
}

/// Invitation actions shared by the invite form and the invitation list,
/// so the list refreshes after either changes something.
#[derive(Clone, Copy)]
struct InvitationActions {
    create: ServerAction<CreateInvitation>,
    revoke: ServerAction<RevokeInvitation>,
}

#[component]
fn Invitations(ctx: OrgContext) -> impl IntoView {
    let actions = InvitationActions {
        create: ServerAction::<CreateInvitation>::new(),
        revoke: ServerAction::<RevokeInvitation>::new(),
    };
    provide_context(actions);
    let invitations = Resource::new(
        move || {
            (
                ctx.id.get(),
                actions.create.version().get(),
                actions.revoke.version().get(),
            )
        },
        |(id, _, _)| async move {
            match id {
                Some(id) => list_invitations(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    let revoke_error = move || {
        actions
            .revoke
            .value()
            .get()
            .and_then(Result::err)
            .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
    };
    view! {
        <Transition fallback=|| ()>
            {move || {
                let actor = loaded_org(ctx).map(|org| org.role);
                invitations.get().map(|result| match (result, actor) {
                    (Ok(list), _) if list.is_empty() => ().into_any(),
                    (Ok(list), Some(actor)) => {
                        let org_id = ctx.id.get().map(|id| id.to_string()).unwrap_or_default();
                        view! {
                            <section class="panel" aria-labelledby="invitations-title">
                                <h2 class="section-title" id="invitations-title">"Open invitations"</h2>
                                {revoke_error}
                                <InvitationTable list actor org_id revoke=actions.revoke/>
                            </section>
                        }
                        .into_any()
                    }
                    (Ok(_), None) => ().into_any(),
                    (Err(err), _) => view! {
                        <StatePanel
                            tone=StateTone::Error
                            title="Could not load invitations".to_string()
                            detail=err.to_string()
                        />
                    }
                    .into_any(),
                })
            }}
        </Transition>
    }
}

#[component]
fn InvitationTable(
    list: Vec<InvitationSummary>,
    actor: OrgRole,
    org_id: String,
    revoke: ServerAction<RevokeInvitation>,
) -> impl IntoView {
    let can_manage = actor.allows(Permission::MembersManage);
    let rows = list
        .into_iter()
        .map(|invitation| {
            let email = invitation.email.as_str().to_owned();
            let withdrawable =
                can_manage && (actor == OrgRole::Owner || invitation.role != OrgRole::Owner);
            let controls = withdrawable.then(|| {
                let org_id = org_id.clone();
                let invitation_id = invitation.id.to_string();
                let confirm = format!("Withdraw invitation for {email}");
                view! {
                    <div class="row-actions">
                        <ConfirmDialog trigger="Withdraw" title=format!("{}?", confirm)>
                            <ActionForm action=revoke attr:class="dialog-form">
                                <input type="hidden" name="organization_id" value=org_id/>
                                <input type="hidden" name="invitation_id" value=invitation_id/>
                                <p>"The link stops working immediately."</p>
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
                    <td>{email.clone()}</td>
                    <td>{invitation.role.label()}</td>
                    <td>
                        {invitation
                            .invited_by
                            .map_or_else(|| "Deleted account".to_owned(), |name| name.as_str().to_owned())}
                    </td>
                    <td>{invitation.expires_at.date().to_string()}</td>
                    <td>{controls}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap">
            <table class="data-table">
                <caption class="visually-hidden">"Open invitations"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Email"</th>
                        <th scope="col">"Role"</th>
                        <th scope="col">"Invited by"</th>
                        <th scope="col">"Expires (UTC)"</th>
                        <th scope="col"><span class="visually-hidden">"Actions"</span></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
}
