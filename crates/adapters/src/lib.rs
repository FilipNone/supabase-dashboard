//! Adapters for services outside the dashboard: the API gateway of a
//! registered self-hosted Supabase stack, for service checks and for
//! forwarding Studio traffic, and Dokploy, the first deployment provider.
//!
//! Server-only: this crate opens network connections and must never be a
//! dependency of the browser build.

pub mod dokploy;
pub mod gateway;
pub mod net;
pub mod studio_proxy;
pub mod tls;
