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
crates/application/ authorized use cases, credential encryption, adapter traits (server only)
crates/persistence/ control-plane PostgreSQL pool and migrations (server only)
crates/adapters/    HTTP clients for managed stacks and the outbound address policy (server only)
crates/web/         Leptos UI; `ssr` feature for the server, `hydrate` for WASM
style/, assets/     CSS theme tokens and static files
```

`crates/application` came with the first authorized use cases in M1 and `crates/adapters` with the first stack check in M2.

Boundary rules:

- `domain` depends on no HTTP, database, or UI crate.
- `application` defines the traits adapters implement (for example `StackProbe`) and does not depend on `adapters`; only the server binary wires the two together.
- `web` with the `hydrate` feature must not pull in `persistence`, `application`, `adapters`, SQLx, reqwest, or Tokio's networking. CI builds the WASM target separately to catch leaks.
- Secrets are wrapped in `secrecy::SecretString` on the server and have no `Serialize` implementation.

## Secret storage strategy

Implemented in M2 for project API keys (`crates/application/src/secrets.rs`):

- Each credential is encrypted with AES-256-GCM from the RustCrypto `aes-gcm` crate (0.11), with a random 96-bit nonce per value from the operating system. The associated data names the project and the key slot, so a ciphertext moved to another row fails to decrypt.
- The key comes from the deployment (`SUPABASE_DASHBOARD_SECRET_KEY_FILE` or `SUPABASE_DASHBOARD_SECRET_KEY`), never from the metadata database. Each row records a key ID (a truncated SHA-256 of the key under a fixed label), so rows sealed under another key are reported as unreadable instead of failing as errors. Rotation: retired keys go in `SUPABASE_DASHBOARD_PREVIOUS_SECRET_KEYS_FILE` and only decrypt, and the `rotate-secret-key` server command reseals every row under the current key. Each row is replaced only if its nonce is unchanged, so a value replaced during the run is not overwritten.
- Losing the key makes stored credentials unrecoverable; operators then re-enter them. Backups of the metadata database are useless to an attacker without the key, and the key must be backed up separately.

## Outbound HTTP

Stack checks use reqwest 0.13 with rustls and the `ring` provider, the same provider SQLx already pulls in, and the Mozilla roots from `webpki-roots`. This avoids building `aws-lc-rs` (reqwest's default) for the arm64 image. The operating system's certificate store is not consulted. Stacks behind a private CA are reached by listing its certificates in `SUPABASE_DASHBOARD_EXTRA_CA_FILE`, which adds them to the bundled roots. A custom DNS resolver applies the address policy in `crates/adapters/src/net.rs` to every resolved address, and address literals are checked before a request is sent. Redirects and environment proxies are disabled.

## Metadata backup and recovery requirements

- The metadata database is an ordinary PostgreSQL database; `pg_dump`/`pg_restore` is the baseline procedure. A tested runbook is an M4 item.
- Migrations are forward-only and embedded in the server binary. The server refuses to start if the database has a migration it does not know about (SQLx default), which prevents running an older binary against a newer schema.

## License

The application is dual licensed under `MIT OR Apache-2.0` (see `LICENSE-MIT` and `LICENSE-APACHE`), the usual choice for Rust projects. Users can take the MIT terms, which only require keeping the copyright notice, or the Apache-2.0 terms, which add an explicit patent grant. Apache-2.0 alone was used at first and was replaced because it is the stricter of the two.

Files adapted from Apache-2.0 upstream sources, such as the Supabase fixture compose file, stay under Apache-2.0 and say so in their header. Any other reused upstream file still needs its license and notices checked individually. Supabase trademarks and logos are not covered by any code license.

## Consequences

- Building the UI needs `cargo-leptos` installed (`cargo install cargo-leptos --version 0.3.11 --locked`). Plain `cargo check`/`test` work without it.
- Leptos 0.8 is pre-1.0; upgrades may need code changes. Versions are pinned and updated deliberately.
