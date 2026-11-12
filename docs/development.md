# Local development

This describes what exists today (M0, M1, and the start of M2). See `docs/adr/0001-stack-and-workspace.md` for why the stack was chosen.

## Prerequisites

- Rust via rustup. `rust-toolchain.toml` pins 1.98.0 and the `wasm32-unknown-unknown` target; rustup installs them on first use.
- cargo-leptos 0.3.11: `cargo install cargo-leptos --version 0.3.11 --locked`. It downloads the matching `wasm-bindgen` CLI on first build.
- PostgreSQL 14 or newer for the metadata database. Docker is the easiest way to get a throwaway one.

## Start a disposable metadata database

```sh
docker run -d --rm --name supabase-dashboard-devdb \
  -e POSTGRES_USER=dashboard -e POSTGRES_PASSWORD=dashboard-dev-only -e POSTGRES_DB=dashboard \
  -p 127.0.0.1:55432:5432 postgres:17-alpine
cp .env.example .env
```

`--rm` deletes the container and its data when it stops.

## Run

```sh
cargo leptos watch      # rebuilds server and WASM on change, serves http://127.0.0.1:3000
cargo leptos build      # one-off debug build into target/site and target/debug
cargo leptos build --release
```

The server applies pending migrations at startup and exits with an error if the database is unreachable or contains a migration this binary does not know.

## Create the first operator

There is no default account and no public sign-up. On a fresh database, create the first owner, who becomes the installation administrator:

```sh
cargo run -p supabase-dashboard-server -- create-owner --email ops@example.test --name "Ops"
```

The command prompts for the password twice on a terminal, or reads one line from stdin when piped. There is no `--password` flag, so the password never appears in shell history or the process list. Passwords need at least 12 characters. The command refuses to run once any account exists.

## Reset a forgotten password

An operator who forgot their password, including the only owner, can be given a new one from the server:

```sh
cargo run -p supabase-dashboard-server -- reset-password --email ops@example.test
```

It reads the new password the same way as `create-owner`, signs the account out of every session, and records an `account.password_reset` audit event without an actor. It does not re-enable a disabled account. The sign-in throttle lives in the server's memory, so an address blocked after failed attempts stays blocked until the window ends (15 minutes by default) or the server restarts. Signed-in operators change their own password under Account, Security.

Running the binary directly (outside cargo-leptos) needs the Leptos site settings in the environment:

```sh
LEPTOS_OUTPUT_NAME=supabase-dashboard LEPTOS_SITE_ROOT=target/site LEPTOS_SITE_PKG_DIR=pkg \
LEPTOS_SITE_ADDR=127.0.0.1:3000 ./target/debug/supabase-dashboard-server
```

## Configuration

All settings are environment variables. Invalid values stop the server at startup with a message naming the variable.

| Variable | Default | Notes |
| --- | --- | --- |
| `SUPABASE_DASHBOARD_ENV` | `production` | `development` allows plain HTTP and pretty logs |
| `SUPABASE_DASHBOARD_PUBLIC_URL` | required in production | Must be `https://` outside development; no credentials, query, or fragment |
| `SUPABASE_DASHBOARD_DATABASE_URL` | required | `postgres://` URL of the metadata database. Treated as a secret and never logged |
| `SUPABASE_DASHBOARD_DB_MAX_CONNECTIONS` | 10 | 1 to 200 |
| `SUPABASE_DASHBOARD_DB_ACQUIRE_TIMEOUT_SECS` | 5 | 1 to 120 |
| `SUPABASE_DASHBOARD_DB_STATEMENT_TIMEOUT_SECS` | 30 | 1 to 3600; set as PostgreSQL `statement_timeout` |
| `SUPABASE_DASHBOARD_MAX_BODY_BYTES` | 1048576 | 1 KiB to 64 MiB; larger requests get 413 |
| `SUPABASE_DASHBOARD_REQUEST_TIMEOUT_SECS` | 30 | 1 to 600; slower requests get 408 |
| `SUPABASE_DASHBOARD_READINESS_TIMEOUT_SECS` | 2 | 1 to 30 |
| `SUPABASE_DASHBOARD_SESSION_LIFETIME_HOURS` | 12 | 1 to 720; absolute session lifetime from sign-in |
| `SUPABASE_DASHBOARD_SESSION_IDLE_TIMEOUT_MINS` | 60 | 5 to 1440; must not exceed the lifetime |
| `SUPABASE_DASHBOARD_LOG_FORMAT` | `json` (`pretty` in development) | |
| `SUPABASE_DASHBOARD_SECRET_KEY_FILE` | unset | Path to a file holding the key that encrypts stored project API keys: 32 random bytes, base64-encoded. Without a key the server starts, but it cannot store or use API keys |
| `SUPABASE_DASHBOARD_SECRET_KEY` | unset | The same key given directly. Set only one of the two; prefer the file, because environment variables show up in `docker inspect` and process listings |
| `SUPABASE_DASHBOARD_STUDIO_DOMAIN` | unset | Base domain for project Studio hosts, as `host` or `host:port`, for example `studio.example.com`. Each project's Studio is served at `<project id in hex>.<domain>`. Needs `SUPABASE_DASHBOARD_PUBLIC_URL`, whose host must not be this domain or a name under it; Studio hosts use the public URL's scheme. Unset turns Studio access off |
| `SUPABASE_DASHBOARD_STUDIO_MAX_BODY_BYTES` | 52428800 | 1 KiB to 1 GiB; request body limit on Studio hosts |
| `SUPABASE_DASHBOARD_STUDIO_REQUEST_TIMEOUT_SECS` | 300 | 10 to 3600; how long a Studio request may take, including Studio's own wait for long SQL queries. Slower requests get 504 |
| `SUPABASE_DASHBOARD_HEALTH_CHECK_INTERVAL_MINS` | 15 | 0, or 5 to 1440. The server checks a project again on its own once its last check is older than this; 0 turns the server's own checks off, leaving only "Check now" |
| `SUPABASE_DASHBOARD_ALLOW_LOOPBACK_TARGETS` | `false` | `true` lets service checks connect to `127.0.0.0/8` and `::1`, for a stack on the same machine. Logged as a warning at startup |
| `RUST_LOG` | `info,tower_http=info,sqlx=warn` | Standard `tracing` filter |
| `LEPTOS_SITE_ADDR` | `127.0.0.1:3000` | Listen address |

### The credential encryption key

Generate one and keep it outside the repository and outside the metadata database:

```sh
openssl rand -base64 32 > .secret.key && chmod 600 .secret.key
echo "SUPABASE_DASHBOARD_SECRET_KEY_FILE=$PWD/.secret.key" >> .env
```

The server logs a short key ID at startup, never the key. Each stored API key is sealed with AES-256-GCM and tied to its project and key slot, so a ciphertext copied to another project or slot does not decrypt. If the server starts with a different key, keys saved under the old one show as unreadable on the project's settings page and have to be entered again. There is no key rotation command yet.

### Service checks

The project overview's "Check now" button asks the stack's API gateway for `/auth/v1/health`, `/storage/v1/version`, and `/realtime/v1/api/ping` (with the anon key), `/rest/v1/` (with the service role key), and `/` (Studio's route, once without a login and once with the stored one). Only those paths under the registered API URL are requested. Saving a Studio login requests `/` the same way before storing it. The client refuses loopback (unless allowed above), link-local, multicast, and cloud metadata addresses, checks every address a host name resolves to, does not follow redirects, ignores proxy environment variables, and gives up after 5 seconds to connect or 10 seconds in total. HTTPS uses the Mozilla root store bundled with the binary; stacks behind a private certificate authority are not supported yet. A project can be checked once every 10 seconds. Besides the button, the server checks projects itself: once a minute it takes up to 20 projects that were never checked or whose last check is older than `SUPABASE_DASHBOARD_HEALTH_CHECK_INTERVAL_MINS`, oldest first, and checks up to 4 at a time with the same requests. Every saved result is also added to the project's history, which the overview summarizes under "Recent checks". Saving a result deletes that project's entries older than 7 days and any beyond its newest 1000; entries older than 7 days are hidden right away, even before the next save deletes them. Unregistering a project deletes its history. With several server processes on one database, each runs these checks, so a project may be checked more than once per interval.

## Endpoints

- `GET /healthz`: liveness. Does not touch the database.
- `GET /readyz`: readiness. 200 when the metadata database answers, 503 otherwise, with a JSON body listing component status. Error details go to the server log, not the response.
- Unknown paths under `/api/` return `404` with `{"error":{"code":"not_found","message":...}}`. API errors always use this envelope; messages never contain credentials or internal error text.
- `GET /dashboard/sign-in`: the sign-in page. Signed-in operators are redirected to the home page.
- `POST /auth/sign-in`: form fields `email`, `password`, and optionally `next`. Redirects with a session cookie to `next` when it is a dashboard page on this host (a path starting with `/dashboard/`, printable ASCII, no backslash, not the sign-in page), and home otherwise, or back to the sign-in page with a fixed `error` code. Five failures for one email within 15 minutes block further attempts for that email until the window passes.
- `POST /auth/sign-out`: revokes the session and clears the cookie.
- `/dashboard/organizations` and `/dashboard/status`: the UI shell. Organizations is an empty state for now.
- `GET /dashboard/project/:project_id[?path=/project/default/...]`: opens the project's Studio. Members whose role allows `StudioOpen` (owner, admin, developer) get a 303 redirect to the project's Studio host with a one-time code valid for 60 seconds. Others are sent to the project page with `?studio=forbidden`, `?studio=not_configured` (no Studio login saved), or `?studio=disabled` (no Studio domain configured).
- `GET /__dashboard/handoff?code=` on a Studio host: redeems the code, sets the Studio cookie, and redirects to the requested Studio path or `/project/default`. A used or expired code shows a page with a link to start again.

Everything except `/healthz`, `/readyz`, `/favicon.svg`, `/pkg/*`, the sign-in page, and the two `/auth/` form endpoints requires a session. Pages redirect to sign-in, with `?next=` naming the page when it is under `/dashboard/`, so the operator returns there afterwards; `/api/*` and other `/auth/*` paths answer `401` with the JSON error envelope. Signed-in responses are sent with `Cache-Control: no-store`.

The session cookie is `__Host-sd-session` with `Secure` when the public URL is HTTPS, and `sd-session` otherwise (local HTTP development). It is HttpOnly and SameSite=Lax. The database stores only a SHA-256 hash of the token.

Cross-site request protection: a POST, PUT, PATCH, or DELETE must carry `Sec-Fetch-Site: same-origin`, or, when that header is absent, an `Origin` equal to the public URL's origin (the request's `Host` in development without a public URL). Requests with neither header are refused with `403 cross_origin_request`. Scripts calling the API need to send a matching `Origin`.

The Studio cookie is `__Host-sd-studio` (`sd-studio` over plain HTTP), set on one project's Studio host only. It is HttpOnly and SameSite=Lax, and it works only while the dashboard session it came from is valid and the member's role still allows `StudioOpen`; every request on a Studio host checks this again. Without it, page loads on a Studio host go back through `/dashboard/project/:project_id` and other requests get 401. Unsafe methods on a Studio host need the same-origin check above, against the Studio host's own origin.

Every response carries an `x-request-id` header (a client-supplied one is kept), and request log lines include it. Logs record method and path only; query strings, headers, and bodies are not logged.

### Studio hosts

Opening a project's Studio needs `SUPABASE_DASHBOARD_STUDIO_DOMAIN`, a DNS name under it for every project (a wildcard record is simplest), and the project's Studio login saved on its settings page. For local development, browsers resolve every `*.localhost` name to the loopback address, so this works without DNS:

```sh
SUPABASE_DASHBOARD_PUBLIC_URL=http://dash.localhost:3000
SUPABASE_DASHBOARD_STUDIO_DOMAIN=studio.localhost:3000
```

Requests are routed by their `Host` header before anything else runs: a project's Studio host goes to the Studio gateway, an unknown name under the Studio domain gets a plain 404, and every other host gets the dashboard. On a Studio host only `/__dashboard/handoff` belongs to the dashboard; every other path is forwarded to the project's registered gateway with the stored Studio login added on the server. The browser's `Authorization` header, its forwarding headers, and the dashboard's Studio cookie are not forwarded. Responses are streamed, redirects are passed back to the browser, and the gateway's own address in a `Location` header is turned into a path. A gateway on the loopback address is reached only when `SUPABASE_DASHBOARD_ALLOW_LOOPBACK_TARGETS` is on.

## Checks

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p supabase-dashboard-web --target wasm32-unknown-unknown --features hydrate -- -D warnings
cargo test --workspace
SUPABASE_DASHBOARD_TEST_DATABASE_URL=postgres://... cargo test --workspace
SUPABASE_DASHBOARD_TEST_FIXTURE_URL=http://127.0.0.1:54321 cargo test -p supabase-dashboard-adapters
cargo leptos build
```

The database tests create and drop their own scratch databases, so the role in the URL needs `CREATEDB`. Without the variable they print a skip message and pass. The fixture URL points the adapter tests at the gateway of the disposable Supabase stack described in `docs/supabase-compatibility.md`; without it that test is skipped too.

The WASM clippy run also catches server-only crates leaking into the browser build: `cargo tree -p supabase-dashboard-web --target wasm32-unknown-unknown --features hydrate -e normal` must not list `sqlx`, `axum`, `tokio`, `argon2`, `reqwest`, `supabase-dashboard-persistence`, `supabase-dashboard-application`, or `supabase-dashboard-adapters`. CI checks this.
