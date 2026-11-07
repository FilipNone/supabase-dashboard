//! Framework-free domain types shared by the server and the browser UI.
//!
//! This crate must not depend on HTTP frameworks, database drivers, or UI
//! libraries. Everything here compiles for both the server and `wasm32`.

pub mod authz;
pub mod health;
pub mod theme;
