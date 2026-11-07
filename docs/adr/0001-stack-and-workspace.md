# ADR 0001: stack, toolchain, workspace layout, and license

Status: accepted (M0), 2026-11-07

## Context

AGENTS.md asks for a Rust server and Rust browser UI, a control-plane metadata database separate from managed projects, and an evaluation of Axum/Tokio, Leptos SSR with WASM hydration, and SQLx/PostgreSQL before scaffolding.

## Decision

| Concern | Choice | Pinned version |
| --- | --- | --- |
| Toolchain | Rust stable via `rust-toolchain.toml`, with the `wasm32-unknown-unknown` target | 1.98.0 |
| HTTP server | Axum on Tokio | axum 0.8, tokio 1.x |
| Middleware | tower-http (request IDs, tracing, body limits, timeouts) | 0.6, matching `leptos_axum` |
| Browser UI | Leptos with SSR and WASM hydration | leptos 0.8, leptos_axum 0.8 |
| UI build | cargo-leptos (generates the wasm-bindgen loader JS) | 0.3.11 |
| Metadata DB | PostgreSQL through SQLx with embedded, versioned migrations | sqlx 0.9 |
| Logging | `tracing` + `tracing-subscriber` | 0.1 / 0.3 |

Exact resolved versions live in `Cargo.lock`, which is committed. Shared versions are declared once under `[workspace.dependencies]`.

Why these:

- Leptos is the only option in the shortlist that renders on the server and hydrates the same Rust components in the browser, so pages work before WASM loads and the app stays in Rust end to end. Its Axum integration is first-party.
- Axum and Tokio are the default async stack around tower; tower-http covers the request-ID, body-limit, and timeout requirements without custom code.
- SQLx gives async PostgreSQL access with parameterized queries and embedded migrations without an ORM layer. Queries use the runtime-checked API for now so builds do not need a live database; compile-time checked queries can come later with an offline query cache.

## Workspace layout (as implemented)

```text
apps/server/        binary: configuration, startup, HTTP routes, graceful shutdown
crates/domain/      framework-free types shared by server and browser
crates/persistence/ control-plane PostgreSQL pool and migrations (server only)
crates/web/         Leptos UI; `ssr` feature for the server, `hydrate` for WASM
style/, assets/     CSS theme tokens and static files
```

`crates/application` and `crates/adapters` from the AGENTS.md proposal will be added when the first authorized use case (M1) and the first Supabase adapter (M2) exist. Splitting earlier would only create empty crates.

Boundary rules:

- `domain` depends on no HTTP, database, or UI crate.
- `web` with the `hydrate` feature must not pull in `persistence`, SQLx, or Tokio's networking. CI builds the WASM target separately to catch leaks.
- Secrets are wrapped in `secrecy::SecretString` on the server and have no `Serialize` implementation.

## Secret storage strategy

No managed-project credentials are stored in M0. When M2 adds them:

- Encrypt each credential with AES-256-GCM using the RustCrypto `aes-gcm` crate (or an equivalent reviewed library), with a random nonce per value.
- The key comes from the deployment (a file or environment variable), never from the metadata database. Each ciphertext records a key ID so keys can be rotated by re-encrypting rows in a background job.
- Losing the key makes stored credentials unrecoverable; operators then re-enter them. Backups of the metadata database are useless to an attacker without the key, and the key must be backed up separately.

## Metadata backup and recovery requirements

- The metadata database is an ordinary PostgreSQL database; `pg_dump`/`pg_restore` is the baseline procedure. A tested runbook is an M4 item.
- Migrations are forward-only and embedded in the server binary. The server refuses to start if the database has a migration it does not know about (SQLx default), which prevents running an older binary against a newer schema.

## License

The application is dual licensed under `MIT OR Apache-2.0` (see `LICENSE-MIT` and `LICENSE-APACHE`), the usual choice for Rust projects. Users can take the MIT terms, which only require keeping the copyright notice, or the Apache-2.0 terms, which add an explicit patent grant. Apache-2.0 alone was used at first and was replaced because it is the stricter of the two.

Files adapted from Apache-2.0 upstream sources, such as the Supabase fixture compose file, stay under Apache-2.0 and say so in their header. Any other reused upstream file still needs its license and notices checked individually. Supabase trademarks and logos are not covered by any code license.

## Consequences

- Building the UI needs `cargo-leptos` installed (`cargo install cargo-leptos --version 0.3.11 --locked`). Plain `cargo check`/`test` work without it.
- Leptos 0.8 is pre-1.0; upgrades may need code changes. Versions are pinned and updated deliberately.
