# ADR 0002: a project's pages are its own Supabase Studio

Status: accepted, 2026-11-10. Implementation is tracked in ROADMAP.md (M2 "Studio access"); this file describes the design, and sections say when something is not built yet.

## Context

On supabase.com you sign in to the dashboard, pick an organization and a project, and the project's pages (Table editor, SQL editor, Auth, Storage, and the rest) are Studio. Nobody reaches a project's Studio without signing in to the dashboard first.

Every self-hosted stack already runs Studio. Up to 2026-11-09 this repository rebuilt parts of it (a read-only table editor, a SQL editor, saved snippets). That duplicated a large, maintained application, and a copy of Studio would always lag behind it. Those pages were removed on 2026-11-10.

Facts about self-hosted Studio this design relies on (from the upstream `docker/` files and self-hosting docs, read through Context7 on 2026-11-10; check them again for each pinned Studio version):

- The gateway (Kong or Envoy) sends every path that no API route claims (`/`) to `http://studio:3000/`, behind HTTP basic auth with `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD`. The gateway removes the `Authorization` header before the request reaches Studio.
- Studio has no users or roles of its own. Whoever passes basic auth can do everything Studio can: run any SQL as the database owner, read the API keys and JWT secret on the settings pages, and change Auth users and Storage objects.
- Self-hosted Studio has one project, `default`, and sends `/` to `/project/default`. Its own server routes live under `/api/`, and its assets under `/_next/`, all at the root of its host. Studio keeps its own SQL snippets (`SNIPPETS_MANAGEMENT_FOLDER`).
- Not found: a supported way to serve the stock Studio image under a path prefix. Treat Studio as needing a host of its own.

## Decision

The dashboard is the only way into a project's Studio. It authenticates the person, checks their role in the project, and forwards their requests to that project's Studio through the stack's gateway, adding the gateway's basic-auth credentials on the server.

### Hosts

- The dashboard keeps its own host, `SUPABASE_DASHBOARD_PUBLIC_URL` (for example `https://dashboard.example.com`).
- Each project's Studio gets its own host under a base domain set by the deployment, `SUPABASE_DASHBOARD_STUDIO_DOMAIN` (for example `studio.example.com`). A project is served at `https://<label>.studio.example.com`, where `<label>` is the project's ID in 32-character hex form (a UUID without dashes, which fits in a 63-character DNS label). The ID is not a secret, and it stays the same when the project is renamed.
- Every Studio host points at the dashboard process (a wildcard DNS record and certificate, or one record and certificate per project). The dashboard looks at the `Host` header first: a known Studio host goes to the Studio gateway code, and any other host goes to the normal dashboard routes. An unknown host under the Studio domain gets a plain 404.
- Giving each project its own origin keeps one project's Studio from reading another project's cookies or pages. The dashboard's own `__Host-` session cookie is never sent to Studio hosts.

### Opening Studio

1. A member opens `/dashboard/project/:project_id`. The dashboard requires a signed-in session (the normal sign-in page otherwise) and checks `Permission::StudioOpen` for the member's role in the project's organization.
2. The dashboard creates a one-time code: 256 random bits, stored only as a SHA-256 hash, bound to the account, the dashboard session, and the project, valid for 60 seconds. It answers with a 303 redirect to `https://<label>.<studio domain>/__dashboard/handoff?code=…`, with `Referrer-Policy: no-referrer`. Opening Studio is audited as `studio.open`, and a refused attempt is audited too.
3. The Studio host redeems the code in one statement that deletes it, so it works once. It creates a Studio session (a random token, stored as a hash) that points at the dashboard session, then sets `__Host-sd-studio` (HttpOnly, Secure, `SameSite=Lax`, `Path=/`; `sd-studio` without `Secure` in local HTTP development) and redirects to `/project/default`, or to the Studio path the member started from.
4. Without a valid Studio cookie, a `GET` on a Studio host redirects to `/dashboard/project/:project_id` on the dashboard host, which signs the member in if needed and starts again at step 2. Other methods get 401.

Every request on a Studio host checks again, in one indexed query, that:

- the Studio session exists and has not expired;
- its dashboard session is not revoked or expired;
- the account is not disabled;
- the member's current role still allows `StudioOpen`;
- the project is still registered and has Studio credentials.

Signing out of the dashboard, signing out other sessions, disabling an account, removing a member, lowering their role, or unregistering the project therefore ends Studio access on the next request.

Unsafe methods (`POST`, `PUT`, `PATCH`, `DELETE`) on a Studio host must come from the same origin: `Sec-Fetch-Site: same-origin`, or a matching `Origin` header when that is missing. This is the same check the dashboard uses on its own host.

### Forwarding

- The upstream is the project's registered API URL, which already went through the outbound address policy (`crates/adapters/src/net.rs`), and only the gateway's catch-all Studio route. No request on a Studio host can choose the destination. This is a fixed, per-project route, not a general proxy.
- The dashboard adds `Authorization: Basic …` from the project's stored Studio credentials. It drops whatever `Authorization` header the browser sent, and removes its own cookie from the forwarded `Cookie` header. It also removes any `Set-Cookie` from Studio that uses its cookie name.
- Hop-by-hop headers are dropped, `X-Forwarded-Host` and `X-Forwarded-Proto` describe the Studio host, and redirects from Studio are passed to the browser, never followed by the dashboard.
- Request bodies are capped by their own limit, larger than the dashboard's because of Studio's Storage uploads, and responses are streamed rather than buffered. The upstream timeout is longer than the dashboard's, because Studio's SQL editor can run long queries.
- Studio's Realtime inspector connects from the browser to the stack's public API URL, not to the Studio host, so the gateway does not need to handle WebSockets at first. This needs checking in the browser for each pinned Studio version.

### Credentials and roles

- Studio credentials (the gateway's `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD`) are a new credential slot next to the anon and service role keys. They are encrypted the same way, never sent to the browser, and only owners and admins can replace them. Saving them is audited.
- `Permission::StudioOpen` is granted to owners, admins, and developers. Viewers cannot open Studio, because Studio cannot limit what they do there. A viewer sees the project's status in the dashboard and nothing inside it.
- Anyone who can open Studio can read the stack's API keys and JWT secret in Studio's settings. The role matrix has to say this plainly.
- The dashboard's audit log records who opened which Studio and when. It does not record what they did inside Studio, because Studio runs everything as one database user. A later, optional per-request access log (method and path, never bodies) can fill part of that gap.

### Closing the stack's own door

While the stack's gateway still serves Studio on its own public URL with a password someone knows, people can skip the dashboard. To make the dashboard the only way in:

- For an existing stack, set `DASHBOARD_PASSWORD` to a long random value, give it only to the dashboard, and restart the gateway. The project page warns until Studio credentials are saved, and the connection check reports when the gateway accepts no password or the default one.
- For a stack the dashboard provisions (M4), the dashboard generates that password and never shows it. If the gateway can be reached on a private network, the pinned compose can also keep the Studio route off the public entry point.

### Authentik

Authentik is the identity provider for the dashboard, through OIDC sign-in (M6). The chain is Authentik, then the dashboard session, then the Studio handoff, so a person signed in to Authentik reaches Studio with no extra prompt, the same as on supabase.com. Studio hosts need no Authentik configuration.

Authentik's proxy outpost (forward auth) should not decide who may open a Studio, because it does not know the dashboard's organizations and roles. Operators may still put it in front of the dashboard and Studio hosts as an extra layer. Group-to-role mapping from the OIDC `groups` claim is optional later work. It is off by default and never makes anyone an installation admin. OIDC back-channel logout from Authentik should revoke the matching dashboard sessions, which ends Studio access as described above.

### Dokploy

When the dashboard runs as a Dokploy service (M4), Traefik in front of it needs the dashboard host and the Studio hosts. Two ways are supported, and the operator picks one:

- One wildcard domain `*.studio.example.com` on the dashboard's service. This needs a DNS challenge for the wildcard certificate in Traefik. Whether Dokploy's domain settings accept a wildcard host has not been checked yet.
- One domain per project, which the dashboard adds to its own Dokploy service with `domain.create` when a project is registered or provisioned, and removes when the project is unregistered. Each gets its own HTTP-challenge certificate. This depends on the dashboard knowing its own Dokploy service, which is the first Dokploy detection item.

The stacks themselves keep their API domain in Dokploy. The dashboard reaches each stack's Studio through that domain, or through an internal address when both run on the same Dokploy network.

## Consequences

- The dashboard no longer builds table, SQL, database, Auth, Storage, Realtime, Functions, or logs pages for a project. It builds what Studio does not have when self-hosted: organizations and members, the project registry, access to Studio, health, provisioning, configuration, backups, and servers.
- A new HTTP path, the Studio gateway, carries all of Studio's traffic. It has to be fast, bounded, and covered by tests for isolation, revocation, header stripping, and CSRF.
- Deployments need a second DNS name and certificate (wildcard or per project).
- Studio's features and limits are upstream's. The compatibility baseline pins the Studio image and records what was checked in a browser.
