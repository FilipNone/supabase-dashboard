# supabase-dashboard

A self-hosted web dashboard, written in Rust, for managing several self-hosted Supabase deployments from one place. The goal is a UI that feels familiar to users of the hosted Supabase dashboard, plus server and deployment management that self-hosted installs lack.

This is an independent project. It is not made, endorsed, or supported by Supabase.

## Status

Early development (milestone M0). What works today:

- Axum server with Leptos server rendering and WASM hydration
- Control-plane PostgreSQL connection with embedded migrations
- Liveness and readiness endpoints, request IDs, body and time limits
- The dashboard shell with light, dark, and system themes

There are no accounts, organizations, or project connections yet. `ROADMAP.md` has the plan and current status.

## Getting started

See [docs/development.md](docs/development.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

Files adapted from other projects keep their original license; each one says so in its header. The Supabase name and logos are trademarks of Supabase, Inc. and are not covered by either license.
