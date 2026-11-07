use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::hooks::use_query_map;

/// Operator sign-in. A plain HTML form posted to `/auth/sign-in`, so it
/// works before the WASM bundle loads. The server redirects back here with a
/// fixed `error` code on failure; nothing the operator typed is echoed.
#[component]
pub fn SignInPage() -> impl IntoView {
    let query = use_query_map();
    let message = move || {
        query.read().get("error").map(|code| match code.as_str() {
            "throttled" => "Too many failed attempts for this account. Wait a few minutes and try again.",
            "unavailable" => "Sign-in is temporarily unavailable. Try again shortly.",
            "setup" => "No operator account exists yet. An administrator must create the first one on the server with `supabase-dashboard-server create-owner`.",
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
                <p class="auth-note">
                    "There is no public sign-up. To join, ask an organization owner or admin for an invitation link."
                </p>
            </div>
        </main>
    }
}
