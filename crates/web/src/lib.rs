//! Leptos browser UI.
//!
//! Built twice: with `ssr` into the server binary, and with `hydrate` into the
//! WASM bundle. Code reachable from `hydrate` must not touch secrets or
//! server-only crates.

pub mod app;
pub mod components;
pub mod error;
pub mod pages;
pub mod server_fns;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(app::App);
}
