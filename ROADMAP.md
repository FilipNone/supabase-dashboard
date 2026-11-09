# Supabase Dashboard roadmap

Updated: 2026-11-09

## Goal and status

Build a self-hosted dashboard in Rust that looks and works like <https://supabase.com/dashboard> for the operations supported by self-hosted Supabase, and adds management of multiple deployments and servers.

Repository: <https://github.com/FilipNone/supabase-dashboard>.

Status: M0 nearly complete; M1 started. A Cargo workspace exists with an Axum server, Leptos SSR/hydrated UI shell, control-plane PostgreSQL migrations, and CI (see `docs/development.md` and `docs/adr/0001-stack-and-workspace.md`). Operators can be bootstrapped from the command line, sign in and out, edit their profile, change their password, and sign out other sessions. Installation admins can list accounts, disable or re-enable them, and see every organization and registered project. Every page and API path requires a session, except the invitation page. Operators can create and rename organizations, switch between them, and manage member roles, removal, and leaving from the browser. Owners and admins can invite people by email; the invitee accepts with an existing account or creates one from the link. Owners and admins can register an existing stack as a project by its API URL, rename it, change its API URL, and unregister it; every member can see the organization's projects. Owners and admins can store a project's anon and service role keys, encrypted on the server, and any member can run a health check that reports whether the stack's Auth and REST services answer, with the Auth version. Any member can browse a project's schemas, tables, and columns and page through table rows (read-only, through postgres-meta). Owners, admins, and developers can run SQL from the project's SQL editor, with a database-side timeout, bounded results, and cancel. Current focus: a secure vertical slice that registers an existing deployment and shows its health and schema.

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
- [x] Establish separate control-plane PostgreSQL storage, versioned migrations, secret-storage strategy, and backup/recovery requirements. (Strategy and requirements are documented in ADR 0001; credential encryption landed with M2 API key storage; the tested restore runbook is an M4 item.)
- [x] Build the reference-style shell: primary sidebar, organization/project switchers, page headers, tables, dialogs, dark/light/system themes, and responsive navigation. (Done: sidebar, top bar, page header, table, empty/error states, themes, responsive navigation, checked at 1280px and 390px in both themes. The organization switcher in the top bar lists the operator's organizations and marks the current one. Inside an organization a project switcher lists its projects; on a project page both show the project's organization and the project, and phones show only the innermost menu. Checked at 1280px dark and 390px light. Confirmations (disabling an account, signing out sessions, removing or leaving members, withdrawing invitations) open a modal dialog on the native `<dialog>` element: focus moves into it, Escape and Cancel close it, focus returns to the button that opened it, and submitting closes it so the outcome shows on the page. Checked at 1280px dark and 390px light.)
- [x] Add structured redacted logs, request IDs, typed API errors, bounded requests, and documented local development setup. (`ApiError` gives a JSON envelope with stable codes; new variants are added with the endpoints that need them.)
- [x] Add formatting, clippy, unit/integration checks, server/UI builds, and a synthetic disposable Supabase fixture with pinned component versions. Document an explicit supported-version baseline. (`docs/supabase-compatibility.md`; the fixture covers db, auth, rest, and meta.)

Acceptance: a fresh checkout builds and runs using documented commands; migrations work on a fresh database; server and browser builds pass; the shell is reviewed at desktop/mobile widths in both themes. No production credentials are required.

### M1: accounts and organizations (P1)

- [x] Implement secure initial-owner bootstrap, login/logout, account editing, and session revocation. Disable public registration by default. (Done: `create-owner` bootstrap that refuses to run twice and never takes the password as an argument; email/password sign-in with Argon2id; sign-out; hashed session tokens with absolute and idle expiry; no public sign-up. Account settings at `/dashboard/account/me` and `/dashboard/account/security`: operators change their display name, change their password after confirming the current one, list their live sessions, and sign out any other session or all of them. A password change signs out every other session in the same transaction, and wrong current passwords count toward the sign-in throttle. Changing the sign-in email is not supported yet.)
- [ ] Define organization/project permissions and test an initial owner/admin/developer/viewer role matrix server-side. (Started: the matrix and last-owner rule live in `crates/domain/src/authz.rs` with exhaustive unit tests. `OrganizationService` checks them on every organization and membership operation, with database-backed tests for each role. `ProjectService` applies the same matrix to registering, renaming, and unregistering projects, with database-backed tests per role.)
- [x] Add organization creation/editing, switching, invitations, membership removal, and last-owner protection. (Done: application service and storage for creating and renaming organizations, listing members, changing roles, removing members, and leaving. Membership changes lock the organization row, so concurrent demotions cannot remove the last owner. The browser UI has an organization list with a create form, a General tab for renaming, a Team tab for role changes, removal, and leaving (each removal behind a named confirmation), and a top-bar switcher. Invitations: owners and admins create them on the Team tab for an email and role (only owners can invite owners) and can withdraw open ones. Each invitation has a 256-bit code that is stored only as a SHA-256 hash, expires after 7 days, and works once, only for the invited email. The link carries the code in the URL fragment, and the acceptance page removes it from the address bar. Someone with an account signs in and accepts; someone without one creates an account from the link, which never makes them an installation admin. Until dashboard email delivery exists, the inviter copies the link, which is shown once. Known gap: an invitee who has to sign in first must open the link again afterwards.)
- [x] Implement dashboard account security and an initial administrator view for users and registered resources. (Done: installation admins can list dashboard accounts and disable or re-enable them, which revokes their sessions and is audited. The same page lists every organization with member and project counts and every registered project with its organization and API URL, up to 500 of each with a note when more exist. The list is read-only and grants no access: an admin who is not a member of an organization still cannot open its projects. Refused attempts to load it are audited.)
- [ ] Add audit events for security-sensitive actions and admin changes, with secret redaction. (Started: owner bootstrap, sign-in success and denial, sign-out, session revocation, profile changes, and password changes (including refused attempts) are recorded with actor, target, outcome, and request ID and no credentials. Admin changes come with the features that make them.)
- [x] Add CSRF protection, login rate limits, secure cookies, and cross-organization access tests. Establish a tested recovery path for the chosen login method. (Done: `Sec-Fetch-Site`/`Origin` check on every unsafe request, `__Host-` HttpOnly SameSite=Lax cookie over HTTPS, per-email failure throttle. The throttle is in memory, so it is per server process. Cross-organization tests cover the organization service: a non-member gets the same not-found answer for another organization's ID as for a made-up one. An HTTP test signs in two operators and checks that one cannot read or rename the other's organization through server functions or the page, and that a cross-site rename with a valid cookie is refused. Recovery: the `reset-password` server command sets a new password for an account and signs it out everywhere; it needs the same server and database access as owner bootstrap and is tested at the application level.)

Acceptance: two organizations cannot read or mutate each other's records, including through guessed IDs and job/download endpoints. Disabled users and revoked sessions lose access. Invitations expire and cannot be reused (covered by application and HTTP tests). Default/bootstrap credentials cannot remain active unnoticed.

### M2: register existing deployments (P1)

- [ ] Add a project connection wizard for explicitly enrolled self-hosted targets, with TLS verification and server-side credential storage. (Started: the anon and service role keys are entered on the project's settings page, validated, and stored with AES-256-GCM under a key supplied by the deployment. They are never sent back to the browser; the page shows only whether each is set and when. Replacing and removing keys is limited to owners and admins and audited. HTTPS checks verify certificates against the Mozilla root store. Still missing: a guided wizard at registration, private CA support, and key rotation.)
- [ ] Detect reachable services, component versions, permissions, and supported capabilities; distinguish unknown health from failure. (Started: a check asks the gateway for Auth health with the anon key and the PostgREST root with the service role key, and records healthy, key rejected, HTTP error, unreachable with a fixed reason, or not checked because a key is missing or unreadable. The Auth version is read from its health response. Verified against the Kong fixture. The table editor also reports, as a fixed state, when postgres-meta is not routed by the gateway, refuses the key, or fails. Not done: other services, permissions, a capability matrix, and periodic checks.)
- [ ] Show project cards, project overview, service health, and connection diagnostics. Support metadata edits and explicit credential replacement. (Started: the organization page lists project cards, and each project has an overview and a settings page where it can be renamed or pointed at a new API URL (same checks as registration, audited, and nothing is sent to the stack). The overview shows the last saved health check with its time and a Check now button, rate limited to one check per project every 10 seconds. The settings page has the API key section. Diagnostics beyond the per-service reason are not done.)
- [ ] Implement schema/table/column browsing and bounded, paginated read-only data access, with safe identifier handling. (Started: the project's Table editor tab lists schemas and the tables in the chosen schema. A table opens on its Data tab, which shows 50 rows per page, and a Definition tab shows its columns with types, defaults, constraints, enum labels, primary key, RLS state, size, and row estimate. The server reads everything from postgres-meta through the stack's gateway (`/pg/`) with the stored service role key, which never reaches the browser; every member role can browse. Rows come from one generated `SELECT` sent to `/pg/query` in a read-only transaction with a 5 second statement timeout; names are always quoted and come from postgres-meta, never from the browser. Pages are ordered by primary key, values are cut to 200 characters, only the first 50 columns are shown, and paging stops at page 2000. Lists are capped (500 schemas, 1000 tables per schema), sorted by name, and say when they were cut off, because postgres-meta does not order its results. Schema names with commas are refused, since postgres-meta splits its schema filter on commas. The Definition tab also lists the table's foreign keys in both directions, with column pairs in key order and the update and delete actions, read from `pg_constraint` by a generated statement whose only input is the table's OID. Views, materialized views, and foreign tables are listed with the tables and marked by kind. View rows are paged like tables without a primary key; a materialized view that was never refreshed, and foreign tables (whose reads go to the remote source), show a notice instead of rows. Clicking a column header on the Data tab sorts by that column, ascending, then descending, then back to the default order; the primary key breaks ties so pages stay stable, a column that is no longer there is ignored, and a type PostgreSQL cannot order (such as `json`) shows its own notice. Up to 10 filters (`=`, `<>`, `>`, `>=`, `<`, `<=`, `like`, `ilike`, `is null`, `is not null`) narrow the rows, combined with AND and kept in the address; their values are quoted by PostgreSQL with a parameterized `quote_literal` query before the read, a filter on a column that is gone is reported rather than dropped, and a value that does not fit the column's type has its own notice. Not done: keyset paging for deep pages.)
- [x] Add disconnect/unregister behavior that preserves the remote stack and its data. (Unregistering requires typing the project name and deletes only the registry row. Nothing is sent to the stack.)
- [ ] Test forbidden destinations, redirects/DNS changes, expired credentials, unreachable services, permission errors, and unsupported versions. (Started: adapter tests cover refused loopback, names resolving to loopback, cloud metadata addresses, redirects not followed, timeouts, oversized bodies, closed ports, TLS failure, and rejected keys. Every resolved address is checked at connection time. Not covered yet: expired JWT keys and unsupported versions.)

Acceptance: an operator registers a disposable stack, browses schema/data, and reconnects after a service outage without affecting other projects. Secrets never appear in browser responses or logs. Unregistering leaves the stack intact.

### M3: database and SQL workflows (P1)

- [ ] Add a table editor with validated row insert/update/delete, explicit handling of primary keys and unsupported types, and clear affected-row results.
- [ ] Add SQL execution with role checks, isolated connections, database-side timeouts, bounded results, and cancellation. (Started: the project's SQL editor tab runs SQL as written through postgres-meta's `POST /pg/query`, which opens a fresh single connection for each request, with the stored service role key kept on the server. Only owners, admins, and developers may run SQL; read-only members get a notice, and a refused run is audited. Every run that reaches the stack is audited as `sql.execute` with its outcome; the SQL text, rows, and error messages are never written to the audit log or server logs. The database stops a statement after 20 seconds (`statementTimeoutSecs`), and the dashboard gives up on the HTTP request after 26. Each run's connection is tagged with its own `application_name`; Cancel calls `pg_cancel_backend` on the backend with that name, passed as a query parameter. A member can have one run per project at a time, and the server runs at most 8 at once. Results show the rows of the last statement that returned any, cut to 1000 rows, 100 columns, 500 characters per value, and a 10 MiB response; database errors show their SQLSTATE and the database's text with the caret under the failing position. Limitations: SQL runs as the database user postgres-meta connects with, not a separate restricted role; the run registry lives in one server process, so a cancel must reach the process that started the run; duplicate column names in a result collapse into one; there is no history of past runs. `SUPABASE_DASHBOARD_REQUEST_TIMEOUT_SECS` must stay above 26 for long queries to report their own timeout.)
- [ ] Store saved SQL snippets in the control plane with explicit ownership and sharing rules; do not assume self-hosted Studio provides cloud saved queries.
- [ ] Add schema/table editing, indexes, roles, extensions, RLS policy inspection/editing, and previews for destructive schema changes.
- [ ] Add project API documentation and connection guidance without disclosing privileged secrets.

Acceptance: table and SQL workflows run against the supported fixture stack. Unauthorized users cannot execute SQL or mutate schema. Long queries can be cancelled, results are bounded, and destructive actions identify the project and require confirmation.

### M4: project lifecycle and remote servers (P2)

- [ ] Define a deployment-provider interface and implement one documented provider first. Dokploy is the first provider (see "Dokploy integration" below); a separate Docker/SSH executor comes after it.
- [ ] Add enrolled remote servers with verified identity, connectivity checks, access restrictions, and resource inventory.
- [ ] Provision a new isolated stack through a durable background job with generated secrets, health checks, progress, and reconciliation after restart.
- [ ] Edit supported stack configuration with a preview, validation, restart requirements, and recovery instructions.
- [ ] Separate project unregister, stack removal, and data/volume destruction in both permissions and UI; document backup prerequisites.
- [ ] Document and test metadata backup/restore. Add provider-aware project backup/restore only after an isolated restore drill succeeds.

Acceptance: provision, reconfigure, and remove a disposable project through the chosen provider without touching another project's services or storage. Restarting the dashboard mid-job does not duplicate resources or lose the operation's status. Unknown outcomes require reconciliation rather than blind retries.

#### Dokploy integration (first M4 provider, P2)

Goal: when the dashboard is installed as a service on [Dokploy](https://dokploy.com), it finds that Dokploy instance and its own place in it. Every Supabase stack it creates then appears in Dokploy as a Compose service, in the same Dokploy project and environment as the dashboard unless the operator picks another one.

What the Dokploy documentation says (read through Context7 on 2026-11-08; check again against the version we pin):

- The API is served at `/api/<router>.<procedure>` and authenticated with an `x-api-key` header. A key belongs to one Dokploy user and one Dokploy organization (`metadata.organizationId`), has that user's permissions, and can have an expiry.
- Resources form a tree: organization, project, environment, service. Each project starts with a default environment, and services in different environments are isolated from each other. Members can be limited to specific projects and environments.
- `compose.create` takes a `name` and an `environmentId`, plus optional fields that include `serverId` (deploy on a remote server) and `composeType` (`docker-compose` or `stack` for Swarm). Older API versions took a `projectId` instead, so the supported version range matters.
- Other calls we need: `project.all`, `environment.byProjectId`, `environment.create`, `compose.one`, `compose.update`, `compose.deploy`, `compose.delete` (with a required `deleteVolumes` flag), and `domain.create` (with `composeId` and `serviceName`). `compose.deployTemplate` deploys the official templates.
- Environment variables set on a service are written to its `.env` file and reach containers only where the compose file references them. Project and environment shared variables are referenced as `${{project.NAME}}` and `${{environment.NAME}}`.
- "Isolated deployments" put each compose app on its own network named after its `appName` and attach Traefik to that network. Without isolation, two stacks with the same service names collide on the shared `dokploy-network`.
- The official Supabase template routes one domain to an Envoy `api-gw` service on port 8000. Our health check has only been verified against the Kong gateway.
- The docs describe no variable that tells a container its own Dokploy project, environment, or service. Detection has to be built (first item below).

Items:

- [ ] Record the supported Dokploy versions and the API calls we use, from Dokploy's OpenAPI document. Add a disposable Dokploy instance to the test fixtures. Read the version when connecting and refuse unsupported versions with a clear message.
- [ ] Detect the dashboard's Dokploy placement. An installation admin enters the Dokploy URL and an API key, or the deployment supplies them (the key from a file). The dashboard then looks for its own service by matching the host of `SUPABASE_DASHBOARD_PUBLIC_URL` against the Dokploy domains the key can see, which gives the service, environment, and project. One match is shown for the admin to confirm; zero or several matches ask the admin to choose. Nothing is used before confirmation, and startup reports when the dashboard's service has moved or disappeared. Optional extra signal, to verify first: whether Dokploy's own API answers on `dokploy-network`, so the setup page can suggest the internal URL.
- [ ] Treat the Dokploy key as an infrastructure credential: whoever holds it can deploy any compose file on Dokploy's servers. Encrypt it with the existing credential key, limit connecting, replacing, and removing it to installation admins, audit each change, and never send it to the browser. Recommend a dedicated Dokploy member limited to the target projects and environments, show the key's expiry, and warn before it lapses.
- [ ] Enroll the Dokploy URL as an explicit destination in the SSRF address policy, including a private address when Dokploy is on the same host or network. A Dokploy connection does not enroll any other destination.
- [ ] Choose where new stacks go. The create-project form defaults to the dashboard's own Dokploy project and environment. The operator can pick another project or environment the key can see, create a new environment, and pick a Dokploy server when Dokploy manages more than one. Dashboard organizations and Dokploy organizations are separate: an installation admin decides which Dokploy targets each dashboard organization may use, and by default only the dashboard's own environment is allowed.
- [ ] Provision a stack as a durable job. Generate the Postgres password, JWT secret, and signed anon and service role keys on the server, and store the keys the dashboard needs encrypted. Create the compose service from our pinned compose file rather than the moving official template, with isolated deployment on. Set its variables through the API, add the domain, deploy, poll the deployment until it finishes, run the health check, and register the project with its Dokploy `composeId`. Give each service a name derived from the job, and look the name up before creating it, so a restart does not create a duplicate. Document that Dokploy keeps these variables in its own database, so anyone with access to the service in Dokploy can read the stack's secrets.
- [ ] Link both sides. The Dokploy service gets a recognizable name and a description pointing to the dashboard project. The dashboard project shows the Dokploy project, environment, server, deployment status, and last deployment, with a link to the service in Dokploy. Reconciliation detects changes made in Dokploy (redeploys, variable edits, deletion) and shows them instead of overwriting them.
- [ ] Adopt existing Supabase services already running in Dokploy, for example ones made from the official template. List compose services that look like Supabase stacks, register one as a project with its `composeId`, and take the API URL from its domain. Copy the stack's keys from the service variables only after an admin confirms. Add a health check for the Envoy gateway.
- [ ] Keep three separate actions, each with its own permission, typed confirmation, and audit event: unregister (dashboard record only), remove from Dokploy (`compose.delete` with `deleteVolumes: false`, data volumes stay on the server), and destroy data (`deleteVolumes: true`). Add stop, start, and redeploy. Do not retry a delete without first reading the service's state.
- [ ] Change a stack's configuration through `compose.update`, with a preview listing the changed variable names (values hidden) and the restart required. Never edit the `.env` file as text.
- [ ] Document installing the dashboard on Dokploy (compose service, domain, metadata database, connecting the key). Then consider publishing a Dokploy template for the dashboard, and using Dokploy's volume backups for project backups once a restore drill has passed.

Acceptance: on a disposable Dokploy instance, install the dashboard as a Dokploy service, connect a key, and confirm the detected project and environment. Create two Supabase projects that appear in that environment without name or network collisions, and a third in another environment. Restarting the dashboard during provisioning creates no duplicate. Remove one stack while keeping its volumes, destroy another, and check that the dashboard and Dokploy agree on what is left. The Dokploy key never reaches the browser, logs, or audit records.

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
- [ ] Show the Dokploy connection and each organization's allowed Dokploy targets on `/org/:org_id/integrations` next to the other providers. The Dokploy provider itself is M4 work.
- [ ] Add a DNS-provider adapter for previewed record changes, ownership checks, propagation status, and safe rollback. Select the first provider before implementation.
- [ ] Add scoped/revocable dashboard API tokens, integration settings, and account/organization audit views.

Acceptance: each integration has documented credentials, scopes, version support, error handling, and disposable test coverage. Tokens stay server-side; webhook replay or a repository link alone cannot authorize arbitrary deployment commands.

### M7: advanced operations and documentation (P3)

- [ ] Define cluster support precisely: server grouping/scheduling, PostgreSQL HA, replication, failover, and backups are separate capabilities. Choose supported infrastructure before promising availability guarantees.
- [ ] Add capacity placement and multi-server operation only after failure/recovery tests for the selected architecture.
- [ ] Add organization security controls, supported application integrations, organization documents, and audit-log drains with delivery/retention guarantees.
- [ ] Publish installation, upgrade, migration, recovery, and troubleshooting documentation; publish a GitHub wiki when the core deployment flow is stable. (Started: `docs/deployment.md` covers Docker install, upgrade, backup, and restore for the dev releases; the restore steps were checked by hand once and have no automated test.)
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
- [Dokploy documentation](https://docs.dokploy.com) and [API reference](https://docs.dokploy.com/docs/api): the first deployment provider; its OpenAPI document is the source for the supported API surface.
- [Dokploy templates](https://github.com/Dokploy/templates): includes the official Supabase blueprint (Envoy gateway); check its license before reusing any of it.

## Revision history

- 2026-11-09: M3 SQL editor: owners, admins, and developers run SQL on a project through postgres-meta with a database-side timeout, bounded results, cancel, and audit. Started the second M3 item.
- 2026-11-08: M0 dialogs: confirmations open a modal dialog; marked the M0 shell item done. Tables in a scrolling wrapper no longer widen the page on phones through their visually hidden header text.
- 2026-11-08: M2 filters: the table editor's Data tab filters rows by column, operator, and value. Updated the fourth M2 item.
- 2026-11-08: M2 sorting: the table editor's Data tab sorts by a column from its header. Updated the fourth M2 item.
- 2026-11-08: M2 relation kinds: the table editor lists views, materialized views, and foreign tables, and reads view rows. Fixed the phone navigation widening every page at 390px. Updated the fourth M2 item.
- 2026-11-08: M2 foreign keys: the table editor's Definition tab lists foreign keys on the table and keys pointing at it. Updated the fourth M2 item.

- 2026-11-08: M2 schema browsing: a read-only table editor for schemas, tables, and columns through postgres-meta behind the gateway, and the fixture now routes `/pg/` and loads a synthetic sample schema. Updated the second and fourth M2 items. Released as `v0.1.0-dev.3`.
- 2026-11-08: M2 read-only table rows: the table editor's Data tab pages through rows, 50 at a time, with a generated read-only query through postgres-meta. Updated the fourth M2 item. Released as `v0.1.0-dev.4`.
- 2026-11-08: planned the Dokploy integration as the first M4 provider: detecting the dashboard's own Dokploy project and environment, creating stacks there by default, adopting existing Supabase services, and separate remove and destroy actions. The M6 Dokploy item now covers only the integrations page.

- 2026-11-08: M2 API keys and health checks: encrypted anon and service role key storage, a gateway health check for Auth and REST with an SSRF address policy, the Kong gateway in the fixture, and release `v0.1.0-dev.2`. Updated the first, second, third, and last M2 items.
- 2026-11-08: first development release `v0.1.0-dev.1`: a multi-arch container image on GHCR, a Docker Compose deploy bundle with optional Caddy TLS, and Linux tarballs, built by `.github/workflows/release.yml`. Started the M7 installation documentation item.
- 2026-11-07: owners and admins can change a project's API URL from its settings page. The M2 project item stays open.
- 2026-11-07: added the top-bar project switcher; the M0 shell item now only lacks dialogs.
- 2026-11-07: the administrator view now lists every organization and registered project, read-only. Marked the M1 administrator item done.
- 2026-11-07: M2 project registry: register an existing stack by API URL (plain HTTP needs explicit confirmation), list, rename, and unregister with typed confirmation. Marked the M2 unregister item done; connections, credentials, and health are still open.
- 2026-11-07: added the installation admin account list with disable and enable; the M1 administrator item stays open until projects exist.
- 2026-11-07: added the `reset-password` recovery command and marked the M1 security item done.
- 2026-11-07: M1 account settings: profile editing, password change, and session list and revocation. Marked the account item done. Earlier the same day: organizations, team management, and invitations.
- 2026-11-07: M1 sign-in slice: operator accounts, owner bootstrap command, sessions, sign-in/sign-out pages, Origin check, login throttle, and audit events. Updated M1 notes.
- 2026-11-07: relicensed the application from Apache-2.0 to `MIT OR Apache-2.0`.
- 2026-11-07: M0 scaffold landed: workspace, server, UI shell, metadata migrations, CI, and the Supabase fixture. Updated M0 checkboxes with what remains.
- 2026-11-05: reviewed the initial feature/page list, retained its requested areas, added missing project workflows, and organized implementation around security boundaries, adapter capabilities, milestone dependencies, and testable acceptance criteria.
