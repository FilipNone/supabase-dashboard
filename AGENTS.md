# AGENTS.md

## Project

Supabase Dashboard is a self-hosted web application written in Rust for managing multiple self-hosted Supabase deployments. The interface and workflows should be familiar to users of <https://supabase.com/dashboard>, with additional server and deployment management. Repository: <https://github.com/FilipNone/supabase-dashboard>.

This is an independent project, not an official Supabase product. Use `supabase-dashboard` for machine names. Do not carry over PhotoCraft, Photoshop, craft-libs, or image-editor requirements.

Read `ROADMAP.md` before choosing work. It is the source of truth for scope, priorities, milestones, and current implementation status. At project initialization, there is no Cargo workspace or application code; the structure below is a proposal, not an inventory of implemented features.

## Product boundaries

- Build a browser-based dashboard, not a native desktop editor. Use Rust for application logic on the server and in the browser. HTML, CSS, configuration, SQL migrations, and generated WASM loader JavaScript are allowed; do not introduce a hand-written JavaScript/TypeScript application or a Node-based backend without approval.
- Match Supabase's navigation, information hierarchy, and important workflows. Check behavior and current references before claiming parity. Preserve keyboard navigation, accessibility, responsive layouts, and both dark and light themes.
- A project's pages are the stack's own Supabase Studio, opened through the dashboard (`docs/adr/0002-studio-access.md`). Do not rebuild Studio's table editor, SQL editor, database, Auth, Storage, Realtime, Functions, or logs pages in the dashboard. The dashboard owns sign-in, organizations, roles, the project registry, access to each Studio, health, provisioning, configuration Studio cannot change when self-hosted, and servers.
- Nobody reaches a project's Studio without a dashboard session and a role that allows `StudioOpen`. Studio has no roles of its own, so opening it grants full database access and shows the stack's keys; never let a read-only role open it. The Studio gateway forwards only to the project's registered gateway, adds Studio's credentials on the server, and checks the session on every request.
- Manage existing deployments before implementing provisioning. A registered deployment is not automatically owned by this dashboard; disconnecting it must not delete its services or data.
- A dashboard organization groups dashboard members and projects. A dashboard project maps to a self-hosted Supabase stack. These are control-plane records owned by this application.
- Dashboard accounts and roles are separate from the application users managed through a project's Supabase Auth service. Never grant dashboard access based on membership in a managed project's Auth database.
- Self-hosted Supabase does not expose the hosted platform's Management API or its multi-organization/project control plane. Implement those capabilities here using verified service and deployment adapters. Never assume a `supabase.com` access token manages a self-hosted stack.
- Supabase Auth, Storage, PostgREST, Realtime, Edge Functions, PostgreSQL, and postgres-meta have different interfaces and privileges. Detect versions and supported capabilities, and report unsupported operations explicitly.
- Billing and managed-cloud subscriptions are out of scope. Cluster support is later work; do not equate a list of servers with database high availability or automatic failover.

## Architecture

The initial direction is a Rust HTTP control plane and a Rust browser UI. Evaluate Axum/Tokio, Leptos with SSR/WASM hydration, and SQLx/PostgreSQL during M0; record the decision and pin versions before scaffolding. This is a proposed stack, not an installed dependency set.

Keep the control plane's metadata database separate from managed project databases. It must be possible to sign in and diagnose an unavailable project without depending on that project's services.

Start with a small workspace; split crates only when there is a concrete boundary. Suggested responsibilities:

```text
apps/server/           HTTP entry point, configuration, startup, background jobs
crates/domain/         IDs, accounts, organizations, projects, roles, capabilities
crates/application/    authorized use cases and adapter interfaces
crates/persistence/    control-plane queries and migrations
crates/adapters/       Supabase services and deployment-provider implementations
crates/web/            Rust browser UI, routes, view state, shared design tokens
tests/                 integration fixtures and end-to-end scenarios
docs/                  architecture and operational docs as they are implemented
```

The domain must not depend on HTTP frameworks, database drivers, or UI libraries. Browser-compatible code must not import server-only secret storage, SQL clients, container access, or process execution. Enforce this with module boundaries and build checks once the workspace exists.

Keep authorization and business rules in application services. HTTP handlers, background jobs, and any future CLI or agent API call the same services. Read endpoints are queries; mutations are explicit operations with validated inputs, target identity, authorization, and audit outcomes. An agent interface must not bypass human-facing permissions or destructive-operation confirmation.

## Security requirements

This application holds infrastructure credentials and can destroy data. Security work precedes remote access and mutation features.

1. Authenticate dashboard users and authorize every server-side operation against its organization, project, and role. Deny by default. Check object ownership, including reads, exports, job status, and downloads; hiding a UI control is not authorization.
2. Keep database passwords, secret/service-role keys, SSH credentials, provider tokens, and encryption keys on the server. Never serialize them into HTML, hydration state, WASM, browser storage, URLs, logs, errors, screenshots, or audit payloads. Support deliberate secret replacement without sending the stored value back to the UI.
3. Use a reviewed secret manager or encryption library with a deployment-supplied key outside the metadata database. Do not invent cryptography. Define key rotation and backup/recovery behavior before storing production credentials.
4. Use secure, HttpOnly session cookies, explicit SameSite policy, CSRF protection for cookie-authenticated mutations, session expiry/revocation, and login rate limiting. Require HTTPS outside explicit local development. Use maintained identity/password libraries; do not hand-roll password hashing or OAuth/OIDC validation.
5. Remote targets are an SSRF boundary. Allow only explicitly enrolled destinations and protocols. Private-network targets are expected but require explicit enrollment; block unrelated loopback/link-local/cloud metadata destinations and validate resolved addresses and redirects at connection time. Do not expose a generic URL proxy.
6. Keep postgres-meta and administrative service endpoints private. Route administrative browser actions through the authorized backend. A reverse proxy password on Studio is not this application's organization/project authorization model: the dashboard holds that password, adds it on the server, and decides who may open Studio. Each project's Studio runs on its own host so projects cannot read each other's cookies.
7. Require target-specific confirmation for destructive operations. Distinguish unregistering a project from deleting a stack, database, bucket, or volume. Record actor, target, action, timestamp, and outcome without credentials or user-data contents. Check authorization again when queued work executes.
8. Parameterize SQL values and quote identifiers through database-aware APIs. User-authored SQL is an intentional privileged feature: restrict it by role, isolate its credentials/pool, apply database-side timeouts and result limits, and support cancellation. Do not classify arbitrary SQL as safe with string matching.
9. Never run shell commands assembled from user input. Pass structured arguments to allowlisted operations, bound output/time, and verify SSH host keys. Do not mount a Docker socket into the public web process by default; deployment executors need an explicit privilege boundary.
10. Provisioning and provider mutations use durable jobs with idempotency, bounded retries, and reconciliation after interruption. Never retry destructive or non-idempotent actions blindly. Surface partial failure and recovery steps rather than silently deleting resources.

Do not contact, mutate, import data from, or test against production Supabase instances without explicit authorization. Use synthetic data and isolated disposable stacks. Never commit credentials, database dumps, deployment `.env` files, or real customer data.

## Rust and reliability

- Production code returns typed errors instead of `unwrap()`, `expect()`, `panic!`, `todo!`, or `unimplemented!` on reachable paths. Tests may assert and unwrap. Add regression tests for crash fixes.
- Forbid unsafe code in workspace-owned crates by default. Any exception requires a documented justification and review.
- Validate input sizes and ranges. Bound request bodies, uploads, query results, pagination, queues, log buffers, and recursive traversal. Use checked arithmetic where input can overflow.
- Use async I/O for remote work. Move blocking work off the request executor and keep network calls out of UI rendering. Propagate deadlines and cancellation; distinguish timeout, authentication failure, unsupported capability, and unavailable service.
- Preserve unknown provider fields when needed for round trips. Version persisted configuration and provide tested migrations; do not silently discard settings or mutate deployment environment files with string replacement.
- Handle timestamps with an established Rust date/time crate in UTC. Keep display timezone handling separate from storage.
- Pin the Rust toolchain, centralize dependency versions, and commit `Cargo.lock` for the application. Check dependency licenses and advisories; do not add libraries without a concrete use.

## UI and compatibility

- Use shared theme tokens for colors, spacing, typography, and focus states. Follow the reference dashboard rather than inventing unrelated landing-page layouts.
- Each data view needs loading, empty, error, permission-denied, unsupported, and disconnected states. Distinguish cached/stale results from current health. No fake success messages or active-looking controls without a working operation.
- Use pagination or virtualization for table rows, logs, and large project lists. Do not fetch whole tables or stream unbounded logs into browser memory.
- Keep navigation IDs distinct from credentials. Route parameters such as `:org_id` and `:project_id` are identifiers, never authentication tokens.
- Maintain a service/version capability matrix with evidence from integration tests. Do not promise every Supabase Cloud page works against a self-hosted stack.
- Inspect UI changes in a browser at desktop and mobile widths, in both themes. Test keyboard focus, form labels, dialogs, and accessible errors. Use synthetic fixtures for screenshots.
- Supabase source and assets have their own licenses and trademark terms. Verify the applicable license before reusing anything, preserve required notices, and do not imply endorsement. No upstream assets or branding are automatically licensed by this guide.

## Testing and completion

Every behavior change needs tests at the appropriate boundary. Prioritize authorization/isolation, secret redaction, SSRF validation, migration compatibility, timeouts, and interrupted jobs alongside successful workflows. Exercise every supported Supabase adapter against a pinned disposable stack. Production systems are not test fixtures.

Once the workspace exists, the baseline Rust checks are:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Add and document the chosen framework's server and WASM/UI build commands during M0. Test the supported feature combinations separately; server-only dependencies must not leak into browser builds. Run relevant integration and browser checks for changed surfaces. Do not claim checks passed when there is no Cargo manifest or when infrastructure was unavailable.

Before finishing, inspect the diff for secrets and unrelated changes, report checks actually run and remaining limitations, and update `ROADMAP.md` when milestone status changes. Do not invent completion percentages. Do not create extra tracking documents or generated artifacts unless needed for the task.

## Repository workflow

- Keep changes small and aligned with the current milestone. Read existing code before changing architecture; consult current official documentation for third-party APIs.
- Preserve user changes and other agents' work. Coordinate file ownership; re-read shared manifests before editing. Use separate Cargo target directories for concurrent builds only when necessary and disk space permits.
- Do not run destructive Git commands, change Git identity, commit, push, or publish a release unless requested. Never bypass hooks or force-push without explicit authorization.
- Keep CI specific to this repository. There is no inherited dependency on PhotoCraft workflows, contributor files, corpora, or release infrastructure.
- When adding documentation, describe actual behavior separately from proposed design. Do not reference files, commands, tests, or crates as existing until they have been created.
