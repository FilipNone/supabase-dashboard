use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::hooks::use_query_map;

use crate::{
    app::{FORGOT_PASSWORD_PATH, OIDC_SIGN_IN_PATH, sign_in_return_path},
    server_fns::get_sign_in_options,
};

/// Operator sign-in. A plain HTML form posted to `/auth/sign-in`, so it
/// works before the WASM bundle loads. The server redirects back here with a
/// fixed `error` code on failure; nothing the operator typed is echoed. A
/// safe `next` page is passed through the form, so the operator ends up where
/// they were going, such as a project's Studio.
///
/// When the deployment configured an OpenID Connect provider, a second
/// form starts single sign-on, also as a plain POST carrying `next`.
#[component]
pub fn SignInPage() -> impl IntoView {
    let query = use_query_map();
    let options = Resource::new(|| (), |()| get_sign_in_options());
    let return_to = move || {
        query
            .read()
            .get("next")
            .filter(|next| sign_in_return_path(next).is_some())
            .map(|next| view! { <input type="hidden" name="next" value=next/> })
    };
    let message = move || {
        query.read().get("error").map(|code| match code.as_str() {
            "throttled" => "Too many failed attempts for this account. Wait a few minutes and try again.",
            "unavailable" => "Sign-in is temporarily unavailable. Try again shortly.",
            "setup" => "No operator account exists yet. An administrator must create the first one on the server with `supabase-dashboard-server create-owner`.",
            "oidc" => "Single sign-on did not complete. Try again, or sign in with your password.",
            "oidc_cancelled" => "Single sign-on was cancelled at the provider.",
            "oidc_unlinked" => "This identity is not linked to a dashboard account that can sign in. Sign in with your password, then link it under Account settings, Security.",
            _ => "Invalid email or password.",
        })
    };

    view! {
        <Title text="Sign in"/>
        <main id="main-content" class="auth-page">
            <div class="auth-card">
                <span class="brand-mark" aria-hidden="true"></span>
                <div>
                    <h1 class="auth-title">"Welcome back"</h1>
                    <p class="auth-subtitle">"Sign in to your dashboard account"</p>
                </div>
                {move || message().map(|text| view! {
                    <p class="form-error" role="alert" id="sign-in-error">{text}</p>
                })}
                <form method="post" action="/auth/sign-in" class="auth-form">
                    {return_to}
                    <label class="field">
                        <span class="field-label">"Email"</span>
                        <input
                            class="input" type="email" name="email" required
                            autocomplete="username" maxlength="254"
                            placeholder="you@example.com"
                        />
                    </label>
                    <label class="field">
                        <span class="field-label">"Password"</span>
                        <input
                            class="input" type="password" name="password" required
                            autocomplete="current-password" maxlength="256"
                        />
                    </label>
                    <button type="submit" class="button button-primary">"Sign in"</button>
                </form>
                <Transition fallback=|| ()>
                    {move || {
                        options
                            .get()
                            .and_then(Result::ok)
                            .and_then(|options| options.oidc_provider_name)
                            .map(|name| {
                                view! {
                                    <div class="auth-divider" role="separator" aria-label="or">
                                        <span aria-hidden="true">"or"</span>
                                    </div>
                                    <form method="post" action=OIDC_SIGN_IN_PATH class="auth-form">
                                        {return_to}
                                        <button type="submit" class="button" name="provider" value="oidc">
                                            {format!("Sign in with {name}")}
                                        </button>
                                    </form>
                                }
                            })
                    }}
                </Transition>
                <p class="auth-note"><a href=FORGOT_PASSWORD_PATH>"Forgot your password?"</a></p>
                <p class="auth-note">
                    "There is no public sign-up. To join, ask an organization owner or admin for an invitation link."
                </p>
            </div>
        </main>
    }
}
