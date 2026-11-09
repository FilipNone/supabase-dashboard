//! Adapters for services outside the dashboard: today, the API gateway of a
//! registered self-hosted Supabase stack, for service checks and for
//! forwarding Studio traffic.
//!
//! Server-only: this crate opens network connections and must never be a
//! dependency of the browser build.

pub mod gateway;
pub mod net;
pub mod studio_proxy;
