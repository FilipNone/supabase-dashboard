//! Accepting an invitation.
//!
//! Invitation links carry their code in the URL fragment, which browsers do
//! not send to the server or in `Referer` headers. After hydration the page
//! reads the code, removes it from the address bar, and asks the server what
//! it is for. Someone without a link can paste one instead.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use leptos_router::hooks::use_navigate;
use supabase_dashboard_domain::{
    account::{DISPLAY_NAME_MAX_CHARS, PASSWORD_MIN_CHARS},
    invitation::{InvitationCode, InvitationPreview},
};

use crate::{
    app::SIGN_IN_PATH,
    error::AppError,
    server_fns::{AcceptInvitation, InvitationPageData, SignUpWithInvitation, preview_invitation},
};

const CODE_LEN: usize = 64;

/// Pulls an invitation code out of a pasted link or bare code. Returns
/// `None` unless it is exactly 64 hex characters.
pub fn extract_code(input: &str) -> Option<String> {
    let raw = input.rsplit('#').next().unwrap_or(input).trim();
    (raw.len() == CODE_LEN && raw.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| raw.to_ascii_lowercase())
}

/// Reads the code from the fragment and removes it from the address bar and
/// the current history entry.
#[cfg(feature = "hydrate")]
fn take_code_from_fragment() -> Option<String> {
    let window = window();
    let code = extract_code(&window.location().hash().ok()?)?;
    if let (Ok(history), Ok(path)) = (window.history(), window.location().pathname()) {
        // Failure leaves the fragment in place; nothing else to do.
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path));
    }
    Some(code)
}

#[component]
pub fn InvitePage() -> impl IntoView {
    let code = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        #[cfg(feature = "hydrate")]
        if let Some(found) = take_code_from_fragment() {
            code.set(Some(found));
        }
    });
    let data = LocalResource::new(move || {
        let code = code.get();
        async move {
            match code {
                Some(code) => preview_invitation(InvitationCode::new(code))
                    .await
                    .map(Some),
                None => Ok(None),
            }
        }
    });

    view! {
        <Title text="Invitation"/>
        <main id="main-content" class="auth-page">
            <div class="auth-card">
                <span class="brand-mark" aria-hidden="true"></span>
                <Suspense fallback=|| view! { <p class="loading" role="status">"Reading invitation…"</p> }>
                    {move || {
                        data.get().map(|result| match result {
                            Ok(None) => view! {
                                <div>
                                    <h1 class="auth-title">"Accept an invitation"</h1>
                                    <p class="auth-subtitle">"Paste the invitation link you received."</p>
                                </div>
                                <PasteCode code/>
                            }
                            .into_any(),
                            Ok(Some(InvitationPageData { invitation: None, .. })) => view! {
                                <div>
                                    <h1 class="auth-title">"Invitation not valid"</h1>
                                    <p class="auth-subtitle">
                                        "It may have expired, been used, or been withdrawn. Ask the person who invited you for a new link."
                                    </p>
                                </div>
                                <PasteCode code/>
                            }
                            .into_any(),
                            Ok(Some(InvitationPageData { invitation: Some(invitation), signed_in_as })) => {
                                let code = code.get_untracked().unwrap_or_default();
                                let signed_in_email = signed_in_as.map(|account| account.email);
                                view! { <InvitationDetails invitation signed_in_email code/> }.into_any()
                            }
                            Err(err) => view! {
                                <h1 class="auth-title">"Invitation"</h1>
                                <p class="form-error" role="alert">{err.to_string()}</p>
                            }
                            .into_any(),
                        })
                    }}
                </Suspense>
            </div>
        </main>
    }
}

/// A field for pasting a link or code by hand.
#[component]
fn PasteCode(code: RwSignal<Option<String>>) -> impl IntoView {
    let input = RwSignal::new(String::new());
    let invalid = RwSignal::new(false);
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        match extract_code(&input.get()) {
            Some(found) => {
                invalid.set(false);
                code.set(Some(found));
            }
            None => invalid.set(true),
        }
    };
    view! {
        <form class="auth-form" on:submit=submit>
            <label class="field">
                <span class="field-label">"Invitation link or code"</span>
                <input
                    class="input" required autocomplete="off" spellcheck="false"
                    aria-invalid=move || invalid.get().to_string()
                    prop:value=move || input.get()
                    on:input=move |ev| input.set(event_target_value(&ev))
                />
            </label>
            {move || invalid.get().then(|| view! {
                <p class="form-error" role="alert">"That is not a valid invitation link or code."</p>
            })}
            <button type="submit" class="button button-primary">"Continue"</button>
        </form>
        <p class="auth-note"><a href=SIGN_IN_PATH>"Go to sign in"</a></p>
    }
}

#[component]
fn InvitationDetails(
    invitation: InvitationPreview,
    signed_in_email: Option<supabase_dashboard_domain::account::Email>,
    code: String,
) -> impl IntoView {
    let organization = invitation.organization_name.as_str().to_owned();
    let email = invitation.email.as_str().to_owned();
    let summary = format!(
        "You are invited to join as {}. The invitation is for {email} and expires on {} (UTC).",
        invitation.role.label(),
        invitation.expires_at.date(),
    );
    let next_step = match signed_in_email {
        Some(current) if current == invitation.email => {
            view! { <AcceptForm code/> }.into_any()
        }
        Some(current) => view! {
            <p class="auth-note">
                {format!(
                    "You are signed in as {}. Sign out, sign in as {email}, then open the invitation link again.",
                    current.as_str()
                )}
            </p>
            <form method="post" action="/auth/sign-out">
                <button type="submit" class="button">"Sign out"</button>
            </form>
        }
        .into_any(),
        None if invitation.account_exists => view! {
            <p class="auth-note">
                {format!("An account for {email} already exists. Sign in with it, then open the invitation link again.")}
            </p>
            <a class="button button-primary" href=SIGN_IN_PATH>"Sign in"</a>
        }
        .into_any(),
        None => view! { <SignUpForm code email=email.clone() organization=organization.clone()/> }.into_any(),
    };
    view! {
        <div>
            <h1 class="auth-title">{format!("Join {organization}")}</h1>
            <p class="auth-subtitle">{summary}</p>
        </div>
        {next_step}
    }
}

#[component]
fn AcceptForm(code: String) -> impl IntoView {
    let accept = ServerAction::<AcceptInvitation>::new();
    let navigate = use_navigate();
    Effect::new(move |_| {
        if let Some(Ok(organization_id)) = accept.value().get() {
            navigate(
                &format!("/dashboard/org/{organization_id}"),
                Default::default(),
            );
        }
    });
    view! {
        <ActionForm action=accept attr:class="auth-form">
            <input type="hidden" name="code" value=code/>
            <button type="submit" class="button button-primary" disabled=move || accept.pending().get()>
                "Accept invitation"
            </button>
        </ActionForm>
        {move || action_error(accept.value().get())}
    }
}

#[component]
fn SignUpForm(code: String, email: String, organization: String) -> impl IntoView {
    let sign_up = ServerAction::<SignUpWithInvitation>::new();
    let joined =
        format!("Your account is ready and you have joined {organization}. Sign in to continue.");
    // Only success swaps the form out, so a refusal keeps what was typed.
    let done = Memo::new(move |_| matches!(sign_up.value().get(), Some(Ok(_))));
    view! {
        {move || match done.get() {
            true => view! {
                <p class="form-ok" role="status">{joined.clone()}</p>
                <a class="button button-primary" href=SIGN_IN_PATH>"Sign in"</a>
            }
            .into_any(),
            false => {
                let code = code.clone();
                let email = email.clone();
                view! {
                <ActionForm action=sign_up attr:class="auth-form">
                    <input type="hidden" name="code" value=code/>
                    <label class="field">
                        <span class="field-label">"Email"</span>
                        <input class="input" type="email" value=email readonly autocomplete="username"/>
                    </label>
                    <label class="field">
                        <span class="field-label">"Your name"</span>
                        <input
                            class="input" name="display_name" required autocomplete="name"
                            maxlength=DISPLAY_NAME_MAX_CHARS.to_string()
                        />
                    </label>
                    <label class="field">
                        <span class="field-label">"Password"</span>
                        <input
                            class="input" type="password" name="password" required
                            autocomplete="new-password" maxlength="256"
                            minlength=PASSWORD_MIN_CHARS.to_string()
                            aria-describedby="password-hint"
                        />
                        <span class="field-hint" id="password-hint">
                            {format!("At least {PASSWORD_MIN_CHARS} characters.")}
                        </span>
                    </label>
                    <label class="field">
                        <span class="field-label">"Confirm password"</span>
                        <input
                            class="input" type="password" name="password_confirmation" required
                            autocomplete="new-password" maxlength="256"
                        />
                    </label>
                    <button type="submit" class="button button-primary" disabled=move || sign_up.pending().get()>
                        "Create account and join"
                    </button>
                </ActionForm>
                {move || action_error(sign_up.value().get())}
                }
                .into_any()
            }
        }}
    }
}

fn action_error<T>(value: Option<Result<T, AppError>>) -> Option<impl IntoView> {
    value
        .and_then(Result::err)
        .map(|err| view! { <p class="form-error" role="alert">{err.to_string()}</p> })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_taken_from_links_or_pasted_alone() {
        let code = "ab".repeat(32);
        assert_eq!(extract_code(&code), Some(code.clone()));
        assert_eq!(extract_code(&format!(" {code}\n")), Some(code.clone()));
        assert_eq!(
            extract_code(&format!(
                "https://dash.example.test/dashboard/invite#{code}"
            )),
            Some(code.clone())
        );
        assert_eq!(extract_code(&format!("#{code}")), Some(code.clone()));
        assert_eq!(extract_code(&"AB".repeat(32)), Some(code));
        assert_eq!(extract_code(&"ab".repeat(31)), None);
        assert_eq!(extract_code(&"zz".repeat(32)), None);
        assert_eq!(
            extract_code("https://dash.example.test/dashboard/invite"),
            None
        );
        assert_eq!(extract_code(""), None);
    }
}
