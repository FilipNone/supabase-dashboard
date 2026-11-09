//! Framework-free domain types shared by the server and the browser UI.
//!
//! This crate must not depend on HTTP frameworks, database drivers, or UI
//! libraries. Everything here compiles for both the server and `wasm32`.

pub mod account;
pub mod admin;
pub mod authz;
pub mod connection;
pub mod health;
pub mod invitation;
pub mod organization;
pub mod project;
pub mod schema;
pub mod sql;
pub mod theme;
