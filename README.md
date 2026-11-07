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

Apache-2.0. See [LICENSE](LICENSE).
