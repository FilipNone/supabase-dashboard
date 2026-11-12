//! Application services: the use cases HTTP handlers, the CLI, and future
//! background jobs call. Authorization and business rules live here, not in
//! handlers.
//!
//! Server-only: this crate must never be a dependency of the browser build.

pub mod auth;
pub mod connections;
pub mod dokploy;
pub mod key_claims;
pub mod key_rotation;
pub mod organizations;
pub mod password;
pub mod projects;
pub mod secrets;
pub mod stack_secrets;
pub mod studio;
pub mod studio_access;
pub mod throttle;
pub mod token;
