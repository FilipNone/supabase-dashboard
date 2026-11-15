//! Confirming a new sign-in email.
//!
//! The link in the confirmation email opens this page with the code in the
//! URL fragment, which browsers do not send to the server. After hydration
//! the page reads the code, removes it from the address bar, and asks the
//! server whether it is still open. The change is made only when the
//! operator presses the button, never on page load, so a mail scanner that
//! opens the link changes nothing. No session is needed: the code is the
//! credential.

use leptos::{form::ActionForm, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::account::{EmailChangeCode, EmailChangePreview};

use crate::{
    app::HOME_PATH,
    pages::project::action_error,
    server_fns::{ConfirmEmailChange, preview_email_change},
};

/// Where operators ask for a new link.
const ACCOUNT_PAGE: &str = "/dashboard/account/me";

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
pub fn ConfirmEmailPage() -> impl IntoView {
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
                (true, Some(code)) => preview_email_change(EmailChangeCode::new(code))
                    .await
                    .map(Some),
                (true, None) => Ok(Some(None)),
            }
        }
    });

    view! {
        <Title text="Confirm sign-in email"/>
        <main id="main-content" class="auth-page">
            <div class="auth-card">
                <span class="brand-mark" aria-hidden="true"></span>
                <Suspense fallback=|| view! { <p class="loading" role="status">"Reading the link…"</p> }>
                    {move || {
                        data.get().map(|result| match result {
                            Ok(Some(Some(preview))) => {
                                let code = code.get_untracked().unwrap_or_default();
                                view! { <ConfirmForm preview code/> }.into_any()
                            }
                            Ok(None) => view! {
                                <p class="loading" role="status">"Reading the link…"</p>
                            }
                            .into_any(),
                            Ok(Some(None)) => view! {
                                <div>
                                    <h1 class="auth-title">"Link not valid"</h1>
                                    <p class="auth-subtitle">
                                        "Confirmation links work once, for an hour, and stop working when a newer one \
                                         is requested or the password changes. Your sign-in email has not changed. \
                                         Ask for a new link under Account settings."
                                    </p>
                                </div>
                                <a class="button button-primary" href=ACCOUNT_PAGE>"Account settings"</a>
                            }
                            .into_any(),
                            Err(err) => view! {
                                <h1 class="auth-title">"Confirm sign-in email"</h1>
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

#[component]
fn ConfirmForm(preview: EmailChangePreview, code: String) -> impl IntoView {
    let confirm = ServerAction::<ConfirmEmailChange>::new();
    // Only success swaps the form out, so a refusal keeps the button where
    // keyboard focus is.
    let done = Memo::new(move |_| matches!(confirm.value().get(), Some(Ok(_))));
    let new_email = preview.new_email.as_str().to_owned();
    let expires = format!(
        "This link expires at {:02}:{:02} UTC. Until you confirm, the account keeps signing in \
         with its current email.",
        preview.expires_at.hour(),
        preview.expires_at.minute()
    );
    view! {
        {move || match done.get() {
            true => view! {
                <div>
                    <h1 class="auth-title">"Sign-in email changed"</h1>
                    <p class="form-ok" role="status">
                        {format!(
                            "The account now signs in with {new_email}. A notice went to the previous address."
                        )}
                    </p>
                </div>
                <a class="button button-primary" href=HOME_PATH>"Go to the dashboard"</a>
            }
            .into_any(),
            false => {
                let code = code.clone();
                view! {
                    <div>
                        <h1 class="auth-title">"Confirm your new sign-in email"</h1>
                        <p class="auth-subtitle">
                            "Sign in to this dashboard with "<strong>{new_email.clone()}</strong>" from now on?"
                        </p>
                        <p class="auth-note">{expires.clone()}</p>
                    </div>
                    <ActionForm action=confirm attr:class="auth-form">
                        <input type="hidden" name="code" value=code/>
                        <button type="submit" class="button button-primary" disabled=move || confirm.pending().get()>
                            "Confirm new email"
                        </button>
                    </ActionForm>
                    {move || action_error(confirm.value().get())}
                }
                .into_any()
            }
        }}
    }
}
