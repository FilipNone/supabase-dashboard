# Supabase Dashboard roadmap

Updated: 2026-11-07

## Goal and status

Build a self-hosted dashboard in Rust that looks and works like <https://supabase.com/dashboard> for the operations supported by self-hosted Supabase, and adds management of multiple deployments and servers.

Repository: <https://github.com/FilipNone/supabase-dashboard>.

Status: M0 nearly complete; M1 started. A Cargo workspace exists with an Axum server, Leptos SSR/hydrated UI shell, control-plane PostgreSQL migrations, and CI (see `docs/development.md` and `docs/adr/0001-stack-and-workspace.md`). Operators can be bootstrapped from the command line and can sign in and out; every page and API path requires a session. There are no organizations or project connections yet. Current focus: organizations and membership, then a secure vertical slice that registers an existing deployment and shows its health and schema.

Priority scale: P1 = required for the first usable release; P2 = next release after the foundation; P3 = later or dependent on research. Milestones indicate dependency order, not dates or delivery estimates.

## Scope decisions

- The primary target is a browser-based application with a Rust backend and Rust UI compiled to WASM where needed. HTML/CSS and generated browser bootstrap code are allowed. No native desktop shell is planned.
- Evaluate Axum/Tokio, Leptos SSR/WASM, and SQLx/PostgreSQL in M0. Framework choice and exact versions remain provisional until a buildable proof of concept is checked.
- Keep the dashboard's identity, organization membership, project registry, and job state in its own metadata database. Managed project outages must not prevent dashboard login.
- One dashboard project initially maps to one self-hosted Supabase stack. Multiple projects require multiple registered stacks, not a nonexistent self-hosted organization API.
- Import and inspect existing stacks before provisioning new ones. Local/remote deployment ownership must be explicit; removing a registry entry must never imply deleting its database or volumes.
- Supabase's hosted Management API is unavailable in self-hosted installations. Use verified PostgreSQL, postgres-meta, service APIs, and deployment-provider integrations behind server-side adapters. Discover capabilities instead of assuming cloud API parity.
- Hosted billing is out of scope. Branching, PITR, cloud metrics, and other managed services require separate infrastructure and are not implied by visual parity.
- Dashboard SSO authenticates operators. Configuring a managed project's end-user Auth providers is a separate feature with separate credentials and permissions.

## Roadmap review

The original list covered account/organization pages and integrations but omitted the project-level database, SQL, Auth, and Storage workflows that make the reference dashboard useful. It also had no implementation order or acceptance criteria. The plan below retains those requests and adds the missing product and security foundations.

The main technical risks are privileged credentials, isolation between organizations, remote-target SSRF, and recovery from partially completed infrastructure changes. Address these before exposing mutations. The reference dashboard's authenticated pages have not been visually verified in this review; the route list is a compatibility target, not a claim about its current exact routing or feature availability.

## Milestones

### M0: foundation (P1)

- [x] Record the architecture decision, Rust toolchain, selected framework versions, and application license; verify any reused upstream licenses separately. (ADR 0001, `MIT OR Apache-2.0`; the fixture compose is adapted from Apache-2.0 upstream files with attribution.)
- [x] Create a minimal Cargo workspace with a running server, Rust UI, health endpoint, configuration validation, and graceful shutdown.
- [x] Establish separate control-plane PostgreSQL storage, versioned migrations, secret-storage strategy, and backup/recovery requirements. (Strategy and requirements are documented in ADR 0001; encryption is implemented when M2 first stores credentials; the tested restore runbook is an M4 item.)
- [ ] Build the reference-style shell: primary sidebar, organization/project switchers, page headers, tables, dialogs, dark/light/system themes, and responsive navigation. (Done: sidebar, top bar, page header, table, empty/error states, themes, responsive navigation, checked at 1280px and 390px in both themes. Remaining: dialogs and working switchers, which need M1 organizations to show anything real.)
- [x] Add structured redacted logs, request IDs, typed API errors, bounded requests, and documented local development setup. (`ApiError` gives a JSON envelope with stable codes; new variants are added with the endpoints that need them.)
- [x] Add formatting, clippy, unit/integration checks, server/UI builds, and a synthetic disposable Supabase fixture with pinned component versions. Document an explicit supported-version baseline. (`docs/supabase-compatibility.md`; the fixture covers db, auth, rest, and meta.)

Acceptance: a fresh checkout builds and runs using documented commands; migrations work on a fresh database; server and browser builds pass; the shell is reviewed at desktop/mobile widths in both themes. No production credentials are required.

### M1: accounts and organizations (P1)

- [ ] Implement secure initial-owner bootstrap, login/logout, account editing, and session revocation. Disable public registration by default. (Done: `create-owner` bootstrap that refuses to run twice and never takes the password as an argument; email/password sign-in with Argon2id; sign-out; hashed session tokens with absolute and idle expiry; no public sign-up. Session revocation exists in the application service but has no UI yet. Remaining: account editing and password change.)
- [ ] Define organization/project permissions and test an initial owner/admin/developer/viewer role matrix server-side. (Started: the matrix and last-owner rule live in `crates/domain/src/authz.rs` with exhaustive unit tests. `OrganizationService` checks them on every organization and membership operation, with database-backed tests for each role. Project permissions are enforced once projects exist in M2.)
- [ ] Add organization creation/editing, switching, invitations, membership removal, and last-owner protection. (Started: application service and storage for creating and renaming organizations, listing members, changing roles, removing members, and leaving. Membership changes lock the organization row, so concurrent demotions cannot remove the last owner. Remaining: the UI, switching, and invitations.)
- [ ] Implement dashboard account security and an initial administrator view for users and registered resources.
- [ ] Add audit events for security-sensitive actions and admin changes, with secret redaction. (Started: owner bootstrap, sign-in success and denial, sign-out, and session revocation are recorded with actor, target, outcome, and request ID and no credentials. Admin changes come with the features that make them.)
- [ ] Add CSRF protection, login rate limits, secure cookies, and cross-organization access tests. Establish a tested recovery path for the chosen login method. (Done: `Sec-Fetch-Site`/`Origin` check on every unsafe request, `__Host-` HttpOnly SameSite=Lax cookie over HTTPS, per-email failure throttle. The throttle is in memory, so it is per server process. Cross-organization tests cover the organization service: a non-member gets the same not-found answer for another organization's ID as for a made-up one. Remaining: the same tests at the HTTP boundary, and a recovery path.)

Acceptance: two organizations cannot read or mutate each other's records, including through guessed IDs and job/download endpoints. Disabled users and revoked sessions lose access. Invitations expire and cannot be reused. Default/bootstrap credentials cannot remain active unnoticed.

### M2: register existing deployments (P1)

- [ ] Add a project connection wizard for explicitly enrolled self-hosted targets, with TLS verification and server-side credential storage.
- [ ] Detect reachable services, component versions, permissions, and supported capabilities; distinguish unknown health from failure.
- [ ] Show project cards, project overview, service health, and connection diagnostics. Support metadata edits and explicit credential replacement.
- [ ] Implement schema/table/column browsing and bounded, paginated read-only data access, with safe identifier handling.
- [ ] Add disconnect/unregister behavior that preserves the remote stack and its data.
- [ ] Test forbidden destinations, redirects/DNS changes, expired credentials, unreachable services, permission errors, and unsupported versions.

Acceptance: an operator registers a disposable stack, browses schema/data, and reconnects after a service outage without affecting other projects. Secrets never appear in browser responses or logs. Unregistering leaves the stack intact.

### M3: database and SQL workflows (P1)

- [ ] Add a table editor with validated row insert/update/delete, explicit handling of primary keys and unsupported types, and clear affected-row results.
- [ ] Add SQL execution with role checks, isolated connections, database-side timeouts, bounded results, and cancellation.
- [ ] Store saved SQL snippets in the control plane with explicit ownership and sharing rules; do not assume self-hosted Studio provides cloud saved queries.
- [ ] Add schema/table editing, indexes, roles, extensions, RLS policy inspection/editing, and previews for destructive schema changes.
- [ ] Add project API documentation and connection guidance without disclosing privileged secrets.

Acceptance: table and SQL workflows run against the supported fixture stack. Unauthorized users cannot execute SQL or mutate schema. Long queries can be cancelled, results are bounded, and destructive actions identify the project and require confirmation.

### M4: project lifecycle and remote servers (P2)

- [ ] Define a deployment-provider interface and implement one documented provider first; evaluate Dokploy as the first provider before introducing a separate Docker/SSH executor.
- [ ] Add enrolled remote servers with verified identity, connectivity checks, access restrictions, and resource inventory.
- [ ] Provision a new isolated stack through a durable background job with generated secrets, health checks, progress, and reconciliation after restart.
- [ ] Edit supported stack configuration with a preview, validation, restart requirements, and recovery instructions.
- [ ] Separate project unregister, stack removal, and data/volume destruction in both permissions and UI; document backup prerequisites.
- [ ] Document and test metadata backup/restore. Add provider-aware project backup/restore only after an isolated restore drill succeeds.

Acceptance: provision, reconfigure, and remove a disposable project through the chosen provider without touching another project's services or storage. Restarting the dashboard mid-job does not duplicate resources or lose the operation's status. Unknown outcomes require reconciliation rather than blind retries.

### M5: project service management (P2)

- [ ] Add managed Supabase Auth user/session administration and supported Auth configuration, separately from dashboard account administration.
- [ ] Add Storage bucket/object management, upload/download limits, policy controls, and confirmed deletion.
- [ ] Add Realtime status and supported publication/configuration management.
- [ ] Add Edge Functions listing, deployment, secrets replacement, and execution/log views where the deployment adapter supports them.
- [ ] Add bounded, redacted logs, health history, usage, and metrics with an explicit source, retention policy, and capability requirements.
- [ ] Expand the administrator dashboard with failed jobs and per-project capability/health summaries.

Acceptance: each page has tested authorized success, permission-denied, service-unavailable, and unsupported states. Missing provider support is visible. Log/usage data is measured rather than fabricated or substituted with cloud billing figures.

### M6: identity and provider integrations (P2)

- [ ] Add dashboard OAuth/OIDC login, with Authentik as a tested provider, verified issuer/audience/state/nonce handling, and safe explicit account linking. Evaluate SAML only if required.
- [ ] Add dashboard email delivery for invitations and chosen account-recovery flows, initially SMTP and/or Resend through a replaceable adapter. Keep this distinct from a managed project's SMTP configuration.
- [ ] Add organization SSO enforcement only after testing owner recovery, existing sessions, and lockout prevention.
- [ ] Add GitHub project integration with least-privilege repository access, verified webhook signatures, and explicit deployment/migration permissions. Linking this source repository does not implement this product feature.
- [ ] Complete Dokploy integration against a recorded supported API version, including enrollment, provisioning, and interrupted-job reconciliation.
- [ ] Add a DNS-provider adapter for previewed record changes, ownership checks, propagation status, and safe rollback. Select the first provider before implementation.
- [ ] Add scoped/revocable dashboard API tokens, integration settings, and account/organization audit views.

Acceptance: each integration has documented credentials, scopes, version support, error handling, and disposable test coverage. Tokens stay server-side; webhook replay or a repository link alone cannot authorize arbitrary deployment commands.

### M7: advanced operations and documentation (P3)

- [ ] Define cluster support precisely: server grouping/scheduling, PostgreSQL HA, replication, failover, and backups are separate capabilities. Choose supported infrastructure before promising availability guarantees.
- [ ] Add capacity placement and multi-server operation only after failure/recovery tests for the selected architecture.
- [ ] Add organization security controls, supported application integrations, organization documents, and audit-log drains with delivery/retention guarantees.
- [ ] Publish installation, upgrade, migration, recovery, and troubleshooting documentation; publish a GitHub wiki when the core deployment flow is stable.
- [ ] Track reference-dashboard workflow and visual parity with screenshots, keyboard tests, capability mappings, and explicit unsupported features.

Acceptance: no cluster/HA claim ships without tested failure and recovery behavior. A new operator can install, upgrade, back up, and restore the dashboard using published instructions.

## Route targets

These are planned application routes. `:org_id`, `:project_id`, and `:resource_id` are non-secret identifiers; they replace the original ambiguous `token` placeholders. Authentication credentials must never appear in route paths. An invitation acceptance token is a dedicated, short-lived credential and must be handled and redacted separately.

| Route under `/dashboard` | Purpose | Milestone |
| --- | --- | --- |
| `/organizations` | Organization selector | M1 |
| `/new/:org_id` | Register an existing project; add provisioning when supported | M2, M4 |
| `/org/:org_id` | Organization overview and project list | M2 |
| `/org/:org_id/team` | Invitations and membership | M1 |
| `/org/:org_id/general` | Organization settings | M1 |
| `/org/:org_id/integrations` | GitHub, Dokploy, DNS/provider connections | M6 |
| `/org/:org_id/usage` | Measured resource usage | M5 |
| `/org/:org_id/security` | Organization security policy | M7 |
| `/org/:org_id/sso` | Dashboard organization SSO | M6 |
| `/org/:org_id/apps` | Supported application integrations | M7 |
| `/org/:org_id/audit` | Organization audit events | M6 |
| `/org/:org_id/audit-log-drains` | External audit delivery | M7 |
| `/org/:org_id/documents` | Organization documents | M7 |
| `/account/me` | Profile and account editing | M1 |
| `/account/tokens` | Scoped dashboard API tokens | M6 |
| `/account/security` | Session and login security | M1 |
| `/account/audit` | Account security history | M6 |
| `/project/:project_id` | Overview, service health, diagnostics | M2 |
| `/project/:project_id/editor[/:resource_id]` | Table browsing and editing | M2, M3 |
| `/project/:project_id/sql` | SQL editor and saved queries | M3 |
| `/project/:project_id/database` | Schema, roles, extensions, RLS | M3 |
| `/project/:project_id/auth` | Managed project's Auth administration | M5 |
| `/project/:project_id/storage` | Buckets and objects | M5 |
| `/project/:project_id/realtime` | Realtime status/configuration | M5 |
| `/project/:project_id/functions` | Edge Functions | M5 |
| `/project/:project_id/logs` | Bounded service logs | M5 |
| `/project/:project_id/api` | Project API documentation | M3 |
| `/project/:project_id/settings` | Connection metadata, then deployment settings | M2, M4 |
| `/servers` | Enrolled server inventory | M4 |
| `/admin` | Installation administrator view | M1, M5 |

`/org/:org_id/billing` remains out of scope. Do not add a functional-looking billing page. Route names may be adjusted after visual/workflow review; redirects need consideration only after routes have shipped.

## First usable release

Complete M0 through M3 before calling the dashboard usable. The release must support secure operator login, organization isolation, registration of an existing self-hosted stack, health/schema inspection, and bounded table/SQL operations with confirmation and audit coverage where applicable. Creating or deleting infrastructure is a separate M4 release scope.

Release checks include a fresh installation, migration from the previous supported metadata schema when one exists, secret-redaction and authorization tests, integration tests against pinned Supabase services, browser checks in both themes, and a documented metadata recovery procedure. No percentage or date is assigned until implementation and test evidence exist.

## References

- [Supabase dashboard](https://supabase.com/dashboard): UI/workflow reference; authenticated views require authorized access.
- [Self-hosting overview](https://supabase.com/docs/guides/self-hosting): single-project model and differences from the hosted platform, including the unavailable Management API.
- [Self-hosting with Docker](https://supabase.com/docs/guides/self-hosting/docker): service deployment and production security requirements.
- [Supabase Studio](https://github.com/supabase/supabase/tree/master/apps/studio): reference implementation; verify the license and the current self-hosted feature set before reuse.

## Revision history

- 2026-11-07: M1 sign-in slice: operator accounts, owner bootstrap command, sessions, sign-in/sign-out pages, Origin check, login throttle, and audit events. Updated M1 notes.
- 2026-11-07: relicensed the application from Apache-2.0 to `MIT OR Apache-2.0`.
- 2026-11-07: M0 scaffold landed: workspace, server, UI shell, metadata migrations, CI, and the Supabase fixture. Updated M0 checkboxes with what remains.
- 2026-11-05: reviewed the initial feature/page list, retained its requested areas, added missing project workflows, and organized implementation around security boundaries, adapter capabilities, milestone dependencies, and testable acceptance criteria.
