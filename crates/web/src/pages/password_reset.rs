//! Resetting a forgotten password by email.
//!
//! The forgot-password page asks for an address and always answers the
//! same way, so it does not reveal which addresses have accounts. The link
//! in the email opens the reset page with the code in the URL fragment,
//! which browsers do not send to the server; after hydration the page reads
//! the code, removes it from the address bar, and asks the server whether
//! it is still open.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::account::{
    PASSWORD_MIN_CHARS, PASSWORD_RESET_LIMIT, PasswordResetCode, PasswordResetPreview,
};

use crate::{
    app::{FORGOT_PASSWORD_PATH, SIGN_IN_PATH},
    error::AppError,
    server_fns::{
        CompletePasswordReset, RequestPasswordReset, password_reset_available,
        preview_password_reset,
    },
};

#[component]
pub fn ForgotPasswordPage() -> impl IntoView {
    let available = Resource::new(|| (), |()| password_reset_available());
    view! {
        <Title text="Reset password"/>
        <main id="main-content" class="auth-page">
            <div class="auth-card">
                <span class="brand-mark" aria-hidden="true"></span>
                <div>
                    <h1 class="auth-title">"Reset your password"</h1>
                </div>
                <Suspense fallback=|| view! { <p class="loading" role="status">"Loading…"</p> }>
                    {move || {
                        available.get().map(|result| match result {
                            Ok(true) => view! { <RequestForm/> }.into_any(),
                            Ok(false) => view! {
                                <p class="auth-subtitle">
                                    "This dashboard cannot send email, so passwords are reset on the server. \
                                     Ask an installation administrator to run "
                                    <code>"supabase-dashboard-server reset-password"</code>
                                    " for your account."
                                </p>
                            }
                            .into_any(),
                            Err(err) => view! {
                                <p class="form-error" role="alert">{err.to_string()}</p>
                            }
                            .into_any(),
                        })
                    }}
                </Suspense>
                <p class="auth-note"><a href=SIGN_IN_PATH>"Back to sign in"</a></p>
            </div>
        </main>
    }
}

#[component]
fn RequestForm() -> impl IntoView {
    let request = ServerAction::<RequestPasswordReset>::new();
    let sent = Memo::new(move |_| matches!(request.value().get(), Some(Ok(()))));
    view! {
        {move || match sent.get() {
            true => view! {
                <p class="form-ok" role="status">
                    {format!(
                        "If an account uses that address, a reset link is on its way. It works once, \
                         for an hour. Each account gets at most {PASSWORD_RESET_LIMIT} links an hour, \
                         and a new link replaces the previous one."
                    )}
                </p>
            }
            .into_any(),
            false => view! {
                <p class="auth-subtitle">
                    "Enter the email address of your dashboard account and we will email you a link to choose a new password."
                </p>
                <ActionForm action=request attr:class="auth-form">
                    <label class="field">
                        <span class="field-label">"Email"</span>
                        <input
                            class="input" type="email" name="email" required
                            autocomplete="username" maxlength="254"
                            placeholder="you@example.com"
                        />
                    </label>
                    <button type="submit" class="button button-primary" disabled=move || request.pending().get()>
                        "Email me a reset link"
                    </button>
                </ActionForm>
                {move || action_error(request.value().get())}
            }
            .into_any(),
        }}
    }
}

/// Reads the code from the fragment and removes it from the address bar and
/// the current history entry.
#[cfg(feature = "hydrate")]
fn take_code_from_fragment() -> Option<String> {
    let window = window();
    let code = crate::pages::invite::extract_code(&window.location().hash().ok()?)?;
    if let (Ok(history), Ok(path)) = (window.history(), window.location().pathname()) {
        // Failure leaves the fragment in place; nothing else to do.
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path));
    }
    Some(code)
}

#[component]
pub fn ResetPasswordPage() -> impl IntoView {
    let code = RwSignal::new(None::<String>);
    // Whether the page has looked at the fragment yet; before hydration it
    // cannot.
    let read = RwSignal::new(false);
    Effect::new(move |_| {
        #[cfg(feature = "hydrate")]
        if let Some(found) = take_code_from_fragment() {
            code.set(Some(found));
        }
        read.set(true);
    });
    // `None` until the fragment has been read, then whether the link is
    // open.
    let data = LocalResource::new(move || {
        let code = code.get();
        let read = read.get();
        async move {
            match (read, code) {
                (false, _) => Ok(None),
                (true, Some(code)) => preview_password_reset(PasswordResetCode::new(code))
                    .await
                    .map(Some),
                (true, None) => Ok(Some(None)),
            }
        }
    });

    view! {
        <Title text="Choose a new password"/>
        <main id="main-content" class="auth-page">
            <div class="auth-card">
                <span class="brand-mark" aria-hidden="true"></span>
                <Suspense fallback=|| view! { <p class="loading" role="status">"Reading the link…"</p> }>
                    {move || {
                        data.get().map(|result| match result {
                            Ok(Some(Some(preview))) => {
                                let code = code.get_untracked().unwrap_or_default();
                                view! { <NewPasswordForm preview code/> }.into_any()
                            }
                            Ok(None) => view! {
                                <p class="loading" role="status">"Reading the link…"</p>
                            }
                            .into_any(),
                            Ok(Some(None)) => view! {
                                <div>
                                    <h1 class="auth-title">"Link not valid"</h1>
                                    <p class="auth-subtitle">
                                        "Reset links work once, for an hour, and stop working when a newer one is sent \
                                         or the password changes. Ask for a new link."
                                    </p>
                                </div>
                                <a class="button button-primary" href=FORGOT_PASSWORD_PATH>"Ask for a new link"</a>
                            }
                            .into_any(),
                            Err(err) => view! {
                                <h1 class="auth-title">"Reset password"</h1>
                                <p class="form-error" role="alert">{err.to_string()}</p>
                            }
                            .into_any(),
                        })
                    }}
                </Suspense>
                <p class="auth-note"><a href=SIGN_IN_PATH>"Back to sign in"</a></p>
            </div>
        </main>
    }
}

#[component]
fn NewPasswordForm(preview: PasswordResetPreview, code: String) -> impl IntoView {
    let complete = ServerAction::<CompletePasswordReset>::new();
    // Only success swaps the form out, so a refusal keeps what was typed.
    let done = Memo::new(move |_| matches!(complete.value().get(), Some(Ok(()))));
    let email = preview.email.as_str().to_owned();
    let expires = format!(
        "This link expires at {:02}:{:02} UTC. Setting a new password signs this account out \
         everywhere and revokes its API tokens.",
        preview.expires_at.hour(),
        preview.expires_at.minute()
    );
    view! {
        <div>
            <h1 class="auth-title">"Choose a new password"</h1>
            <p class="auth-subtitle" id="reset-note">{expires}</p>
        </div>
        {move || match done.get() {
            true => view! {
                <p class="form-ok" role="status">"Your password was changed. Sign in with the new one."</p>
                <a class="button button-primary" href=SIGN_IN_PATH>"Sign in"</a>
            }
            .into_any(),
            false => {
                let code = code.clone();
                let email = email.clone();
                view! {
                    <ActionForm action=complete attr:class="auth-form">
                        <input type="hidden" name="code" value=code/>
                        <label class="field">
                            <span class="field-label">"Email"</span>
                            <input class="input" type="email" value=email readonly autocomplete="username"/>
                        </label>
                        <label class="field">
                            <span class="field-label">"New password"</span>
                            <input
                                class="input" type="password" name="password" required
                                autocomplete="new-password" maxlength="256"
                                minlength=PASSWORD_MIN_CHARS.to_string()
                                aria-describedby="new-password-hint"
                            />
                            <span class="field-hint" id="new-password-hint">
                                {format!("At least {PASSWORD_MIN_CHARS} characters.")}
                            </span>
                        </label>
                        <label class="field">
                            <span class="field-label">"Confirm new password"</span>
                            <input
                                class="input" type="password" name="password_confirmation" required
                                autocomplete="new-password" maxlength="256"
                            />
                        </label>
                        <button type="submit" class="button button-primary" disabled=move || complete.pending().get()>
                            "Set new password"
                        </button>
                    </ActionForm>
                    {move || action_error(complete.value().get())}
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
