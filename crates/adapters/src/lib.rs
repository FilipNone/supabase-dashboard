//! Adapters for services outside the dashboard: today, the API gateway of a
//! registered self-hosted Supabase stack.
//!
//! Server-only: this crate opens network connections and must never be a
//! dependency of the browser build.

pub mod gateway;
pub mod meta;
pub mod net;
pub mod sql;
