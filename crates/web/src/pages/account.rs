//! The signed-in operator's own account: profile and security.
//!
//! These pages only ever act on the operator's own account; the server
//! takes the account from the session, never from the request.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use leptos_router::components::{A, Outlet};
use supabase_dashboard_domain::account::{
    AccountSummary, DISPLAY_NAME_MAX_CHARS, PASSWORD_MIN_CHARS, SessionSummary,
};
use time::OffsetDateTime;

use crate::{
    components::dialog::{ConfirmDialog, DialogCancel},
    components::{
        layout::Refresh,
        page::{PageHeader, StatePanel, StateTone},
    },
    error::AppError,
    server_fns::{
        ChangePassword, RevokeOtherSessions, RevokeSession, UpdateProfile, get_current_account,
        list_sessions,
    },
};

/// Header and tabs shared by the account pages.
#[component]
pub fn AccountLayout() -> impl IntoView {
    view! {
        <PageHeader title="Account settings" description="Your own profile and sign-in security."/>
        <nav class="tabs" aria-label="Account">
            <A href="/dashboard/account/me" attr:class="tab">"Profile"</A>
            <A href="/dashboard/account/security" attr:class="tab">"Security"</A>
        </nav>
        <Outlet/>
    }
}

#[component]
pub fn AccountProfilePage() -> impl IntoView {
    let refresh = use_context::<Refresh>();
    let update = ServerAction::<UpdateProfile>::new();
    let account = Resource::new(move || update.version().get(), |_| get_current_account());
    // The top bar shows the display name too.
    Effect::new(move |_| {
        if let (Some(Ok(_)), Some(refresh)) = (update.value().get(), refresh) {
            refresh.account.update(|n| *n = n.wrapping_add(1));
        }
    });
    let feedback = move || {
        update.value().get().map(|result| match result {
            Ok(_) => view! { <p class="form-ok" role="status">"Profile saved."</p> }.into_any(),
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };
    view! {
        <Title text="Profile"/>
        <section class="panel" aria-labelledby="profile-title">
            <h2 class="section-title" id="profile-title">"Profile"</h2>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading profile…"</p> }>
                {move || {
                    account.get().map(|result| match result {
                        Ok(Some(account)) => view! { <ProfileForm account update/> }.into_any(),
                        Ok(None) => view! {
                            <StatePanel tone=StateTone::Error title=AppError::Unauthenticated.to_string()/>
                        }
                        .into_any(),
                        Err(_) => view! {
                            <StatePanel tone=StateTone::Error title=AppError::Unavailable.to_string()/>
                        }
                        .into_any(),
                    })
                }}
            </Transition>
            {feedback}
        </section>
    }
}

#[component]
fn ProfileForm(account: AccountSummary, update: ServerAction<UpdateProfile>) -> impl IntoView {
    view! {
        <ActionForm action=update attr:class="stacked-form">
            <label class="field">
                <span class="field-label">"Display name"</span>
                <input
                    class="input" name="display_name" required autocomplete="name"
                    maxlength=DISPLAY_NAME_MAX_CHARS.to_string()
                    value=account.display_name.as_str().to_owned()
                />
            </label>
            <label class="field">
                <span class="field-label">"Email"</span>
                <input
                    class="input" type="email" readonly autocomplete="username"
                    value=account.email.to_string() aria-describedby="email-hint"
                />
                <span class="field-hint" id="email-hint">
                    "Your email is your sign-in name. Changing it is not supported yet."
                </span>
            </label>
            <div>
                <button type="submit" class="button button-primary" disabled=move || update.pending().get()>
                    "Save"
                </button>
            </div>
        </ActionForm>
        {account.is_installation_admin.then(|| view! {
            <p class="field-hint">"You are an administrator of this dashboard installation."</p>
        })}
    }
}

#[component]
pub fn AccountSecurityPage() -> impl IntoView {
    let change = ServerAction::<ChangePassword>::new();
    let revoke = ServerAction::<RevokeSession>::new();
    let revoke_others = ServerAction::<RevokeOtherSessions>::new();
    let sessions = Resource::new(
        move || {
            (
                change.version().get(),
                revoke.version().get(),
                revoke_others.version().get(),
            )
        },
        |_| list_sessions(),
    );
    view! {
        <Title text="Security"/>
        <PasswordPanel change/>
        <section class="panel" aria-labelledby="sessions-title">
            <h2 class="section-title" id="sessions-title">"Sessions"</h2>
            <p class="field-hint">
                "Browsers where you are signed in. Signing out a session takes effect on its next request."
            </p>
            {move || {
                let errors = [revoke.value().get().map(|r| r.map(|()| 0)), revoke_others.value().get()];
                errors
                    .into_iter()
                    .flatten()
                    .find_map(Result::err)
                    .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
            }}
            {move || {
                revoke_others.value().get().and_then(Result::ok).map(|count| {
                    view! { <p class="form-ok" role="status">{signed_out_message(count)}</p> }
                })
            }}
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading sessions…"</p> }>
                {move || {
                    sessions.get().map(|result| match result {
                        Ok(list) => view! { <SessionTable list revoke revoke_others/> }.into_any(),
                        Err(err) => view! {
                            <StatePanel
                                tone=StateTone::Error
                                title="Could not load sessions".to_string()
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

fn signed_out_message(count: u64) -> String {
    match count {
        0 => "No other sessions were signed in.".to_owned(),
        1 => "1 other session was signed out.".to_owned(),
        n => format!("{n} other sessions were signed out."),
    }
}

#[component]
fn PasswordPanel(change: ServerAction<ChangePassword>) -> impl IntoView {
    // Clear the password fields after a success; a refusal keeps what was
    // typed so it can be corrected.
    let form = NodeRef::<leptos::html::Form>::new();
    Effect::new(move |_| {
        if matches!(change.value().get(), Some(Ok(_))) {
            #[cfg(feature = "hydrate")]
            if let Some(form) = form.get() {
                form.reset();
            }
        }
    });
    let feedback = move || {
        change.value().get().map(|result| match result {
            Ok(count) => view! {
                <p class="form-ok" role="status">
                    {format!("Password changed. {}", signed_out_message(count))}
                </p>
            }
            .into_any(),
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };
    view! {
        <section class="panel" aria-labelledby="password-title">
            <h2 class="section-title" id="password-title">"Password"</h2>
            <ActionForm action=change node_ref=form attr:class="stacked-form">
                        <label class="field">
                            <span class="field-label">"Current password"</span>
                            <input
                                class="input" type="password" name="current_password" required
                                autocomplete="current-password" maxlength="256"
                            />
                        </label>
                        <label class="field">
                            <span class="field-label">"New password"</span>
                            <input
                                class="input" type="password" name="new_password" required
                                autocomplete="new-password" maxlength="256"
                                minlength=PASSWORD_MIN_CHARS.to_string()
                                aria-describedby="new-password-hint"
                            />
                            <span class="field-hint" id="new-password-hint">
                                {format!(
                                    "At least {PASSWORD_MIN_CHARS} characters. Your other sessions are signed out when it changes."
                                )}
                            </span>
                        </label>
                        <label class="field">
                            <span class="field-label">"Confirm new password"</span>
                            <input
                                class="input" type="password" name="new_password_confirmation" required
                                autocomplete="new-password" maxlength="256"
                            />
                        </label>
                        <div>
                            <button type="submit" class="button button-primary" disabled=move || change.pending().get()>
                                "Change password"
                            </button>
                        </div>
                    </ActionForm>
            {feedback}
        </section>
    }
}

#[component]
fn SessionTable(
    list: Vec<SessionSummary>,
    revoke: ServerAction<RevokeSession>,
    revoke_others: ServerAction<RevokeOtherSessions>,
) -> impl IntoView {
    let has_others = list.iter().any(|session| !session.is_current);
    let rows = list
        .into_iter()
        .map(|session| {
            let device = session
                .user_agent
                .as_deref()
                .map_or_else(|| "Unknown browser".to_owned(), describe_user_agent);
            let full_agent = session.user_agent.clone().unwrap_or_default();
            let action = if session.is_current {
                view! { <span class="badge badge-muted">"This browser"</span> }.into_any()
            } else {
                let confirm = format!("Sign out {device}");
                view! {
                    <div class="row-actions">
                        <ConfirmDialog trigger="Sign out" title=format!("{}?", confirm)>
                            <ActionForm action=revoke attr:class="dialog-form">
                                <input type="hidden" name="session_id" value=session.id.to_string()/>
                                <p>"That browser has to sign in again."</p>
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
            view! {
                <tr>
                    <td title=full_agent>{device}</td>
                    <td class="nowrap">{utc_minutes(session.created_at)}</td>
                    <td class="nowrap">{utc_minutes(session.last_seen_at)}</td>
                    <td class="nowrap">{utc_minutes(session.expires_at)}</td>
                    <td>{action}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="table-wrap" role="region" aria-label="Signed-in sessions" tabindex="0">
            <table class="data-table">
                <caption class="visually-hidden">"Signed-in sessions"</caption>
                <thead>
                    <tr>
                        <th scope="col">"Browser"</th>
                        <th scope="col">"Signed in (UTC)"</th>
                        <th scope="col">"Last active (UTC)"</th>
                        <th scope="col">"Expires (UTC)"</th>
                        <th scope="col"><span class="visually-hidden">"Actions"</span></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {has_others.then(|| view! {
            <ConfirmDialog trigger="Sign out all other sessions" title="Sign out other sessions?">
                <ActionForm action=revoke_others attr:class="dialog-form">
                    <p>"Every other browser has to sign in again. This one stays signed in."</p>
                    <div class="dialog-actions">
                        <DialogCancel/>
                        <button type="submit" class="button button-danger">"Sign out other sessions"</button>
                    </div>
                </ActionForm>
            </ConfirmDialog>
        })}
    }
}

/// `2026-11-07 14:05`, in UTC.
/// A UTC time to the second, for lists where several entries can fall in
/// the same minute.
pub fn utc_seconds(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{} {:02}:{:02}:{:02}",
        at.date(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

pub fn utc_minutes(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!("{} {:02}:{:02}", at.date(), at.hour(), at.minute())
}

/// A short "Browser on OS" label from a user-agent string. Only for display;
/// the full string is shown on hover. Order matters because most browsers
/// also claim to be Safari or Chrome.
pub fn describe_user_agent(agent: &str) -> String {
    let browser = [
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Chromium/", "Chromium"),
        ("Safari/", "Safari"),
        ("curl/", "curl"),
    ]
    .into_iter()
    .find(|(marker, _)| agent.contains(marker))
    .map(|(_, name)| name);
    let os = [
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iPadOS"),
        ("Windows", "Windows"),
        ("Mac OS X", "macOS"),
        ("CrOS", "ChromeOS"),
        ("Linux", "Linux"),
    ]
    .into_iter()
    .find(|(marker, _)| agent.contains(marker))
    .map(|(_, name)| name);
    match (browser, os) {
        (Some(browser), Some(os)) => format!("{browser} on {os}"),
        (Some(browser), None) => browser.to_owned(),
        (None, Some(os)) => format!("Browser on {os}"),
        (None, None) => "Unknown browser".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agents_get_short_labels() {
        let cases = [
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
                "Firefox on Linux",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
                "Edge on Windows",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
                "Safari on macOS",
            ),
            (
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
                "Chrome on Android",
            ),
            ("curl/8.10.1", "curl"),
            ("something else", "Unknown browser"),
        ];
        for (agent, expected) in cases {
            assert_eq!(describe_user_agent(agent), expected, "{agent}");
        }
    }

    #[test]
    fn timestamps_are_shown_to_the_minute_in_utc() {
        let at = time::Date::from_calendar_date(2026, time::Month::November, 7)
            .unwrap()
            .with_hms(14, 5, 59)
            .unwrap()
            .assume_offset(time::UtcOffset::from_hms(2, 0, 0).unwrap());
        assert_eq!(utc_minutes(at), "2026-11-07 12:05");
    }

    #[test]
    fn sign_out_counts_read_naturally() {
        assert_eq!(signed_out_message(0), "No other sessions were signed in.");
        assert_eq!(signed_out_message(1), "1 other session was signed out.");
        assert_eq!(signed_out_message(3), "3 other sessions were signed out.");
    }
}
