# Deploying supabase-dashboard with Docker

This guide runs a released build on one Linux server from the prebuilt container image `ghcr.io/filipnone/supabase-dashboard`. Nothing is compiled on the server. To run the dashboard as a Dokploy service instead, see "Installing the dashboard on Dokploy" in [docs/dokploy.md](https://github.com/FilipNone/supabase-dashboard/blob/main/docs/dokploy.md#installing-the-dashboard-on-dokploy). To build from source, see [docs/development.md](https://github.com/FilipNone/supabase-dashboard/blob/main/docs/development.md).

Development releases (`0.N.0-dev.N`) are previews. The dashboard can manage operator accounts, organizations, members, invitations, and a registry of self-hosted stacks. It can store a stack's API keys and Studio login, check whether its Auth, REST, and Studio routes answer, and open the stack's own Studio for members whose role allows it (see "Studio access" below). With a Dokploy instance connected, it can also create new stacks, adopt existing ones, stop, start, redeploy, reconfigure, and remove them (see `docs/dokploy.md`). Expect breaking changes between dev releases.

## What you need

- A Linux server, x86_64 or arm64, with Docker Engine and the Compose plugin (`docker compose version` prints v2 or newer).
- A DNS name for the dashboard, for example `dashboard.example.com`, pointing at the server.
- HTTPS. In production the dashboard refuses to start without an `https://` public URL. Use the bundled Caddy proxy, or your own reverse proxy that terminates TLS and forwards to `127.0.0.1:3000`.

The bundle contains:

| File | Purpose |
| --- | --- |
| `compose.yaml` | The dashboard, its PostgreSQL metadata database, and an optional Caddy proxy |
| `.env.example` | Settings template |
| `Caddyfile` | Caddy configuration for the `caddy` profile |

The metadata database belongs to the dashboard. It is separate from the databases of the Supabase stacks you manage.

## Install

1. Download and unpack the bundle from the release page:

   ```sh
   curl -fLO https://github.com/FilipNone/supabase-dashboard/releases/download/v0.3.0-dev.6/supabase-dashboard-0.3.0-dev.6-docker.tar.gz
   tar -xzf supabase-dashboard-0.3.0-dev.6-docker.tar.gz
   cd supabase-dashboard-0.3.0-dev.6-docker
   ```

   `SHA256SUMS` on the release page lists the checksum of each file.

2. Create the settings file:

   ```sh
   cp .env.example .env
   chmod 600 .env
   sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" .env
   ```

   Then edit `.env` and set `SUPABASE_DASHBOARD_PUBLIC_URL` (and `SUPABASE_DASHBOARD_DOMAIN` if you use Caddy) to your DNS name.

3. Create the key that encrypts the API keys of the stacks you register. The container runs as user 10001, so that user has to be able to read the file:

   ```sh
   openssl rand -base64 32 > secret.key
   sudo chown 10001:10001 secret.key
   sudo chmod 400 secret.key
   ```

   Copy `secret.key` somewhere safe, away from the database backups. Anyone with both can decrypt the stored keys, and without the file nobody can: if it is lost, every stack's keys have to be entered again. The dashboard logs a short key ID at startup so you can tell which key is in use.

4. Start it. With the bundled Caddy, which gets a Let's Encrypt certificate and needs ports 80 and 443 open:

   ```sh
   docker compose --profile caddy up -d
   ```

   Behind your own reverse proxy instead:

   ```sh
   docker compose up -d
   ```

   The dashboard listens on `127.0.0.1:3000` on the host. Point the proxy there and keep the original `Host` header. The server checks the `Origin` of every form submission against `SUPABASE_DASHBOARD_PUBLIC_URL`, so the URL in the browser must match it exactly.

5. Check that it is up:

   ```sh
   docker compose ps                     # dashboard shows "healthy"
   curl -fsS http://127.0.0.1:3000/readyz
   ```

   The server applies database migrations at startup. If it keeps restarting, `docker compose logs dashboard` names the setting or problem.

6. Create the first operator. There is no default account and no public sign-up:

   ```sh
   docker compose exec dashboard supabase-dashboard-server create-owner --email you@example.com --name "Your Name"
   ```

   It asks for the password twice (at least 12 characters). This account is the installation administrator. Sign in at `https://<your domain>/dashboard/sign-in`.

### Trying it without TLS

On a private network only, you can skip HTTPS: in `.env`, set `SUPABASE_DASHBOARD_ENV=development`, `SUPABASE_DASHBOARD_BIND=0.0.0.0`, and `SUPABASE_DASHBOARD_PUBLIC_URL=http://<server address>:3000`, then `docker compose up -d`. Session cookies then lack the `Secure` flag. Do not expose this setup to the internet.

## Settings

Everything is set in `.env`. `compose.yaml` passes it to the dashboard container and builds `SUPABASE_DASHBOARD_DATABASE_URL` from `POSTGRES_PASSWORD`. Only use letters and digits in that password, because it goes into the URL unescaped. Session lifetime, request limits, and logging are documented under Configuration in [docs/development.md](https://github.com/FilipNone/supabase-dashboard/blob/main/docs/development.md#configuration). Restart after a change with `docker compose up -d`.

The encryption key is not in `.env`. `compose.yaml` mounts `secret.key` as a Compose secret at `/run/secrets/secret_key` and points `SUPABASE_DASHBOARD_SECRET_KEY_FILE` at it, so the key does not appear in `docker inspect`.

To check a stack that runs on the same server, register it by an address the container can reach, such as the host's private network address. Loopback addresses are refused unless `SUPABASE_DASHBOARD_ALLOW_LOOPBACK_TARGETS=true`, and inside the container `127.0.0.1` is the container itself.

If a stack's gateway uses a certificate from a private certificate authority, mount the authority's certificate into the container read-only and point `SUPABASE_DASHBOARD_EXTRA_CA_FILE` at it, for example `/run/secrets/stacks-ca.pem`. Only the public certificate belongs there, never the authority's key. Restart the dashboard after changing the file; it is read once at startup.

That file is trusted for every project. To trust an authority for one project only, an owner or admin pastes its certificate into the Certificate authorities section of that project's settings page instead. The dashboard stores it with the project (public certificates only, at most 8 and 64 KiB), lists each certificate's subject, expiry, and SHA-256 fingerprint, and uses it for that project's health checks, the Studio login check, and Studio traffic. Saving and removing it are audited. A change applies to the next request without a restart.

### Invitation email

By default the dashboard sends no email: an owner or admin who invites someone copies the invitation link and sends it themselves. To have the dashboard email the link as well, give it a mail server in `.env`:

```sh
SUPABASE_DASHBOARD_SMTP_URL=smtps://smtp.example.com      # or smtp://smtp.example.com:587 for STARTTLS
SUPABASE_DASHBOARD_MAIL_FROM=Dashboard <dashboard@example.com>
SUPABASE_DASHBOARD_SMTP_USERNAME=dashboard@example.com
SUPABASE_DASHBOARD_SMTP_PASSWORD_FILE=/run/secrets/smtp_password
```

The URL holds no credentials. Keep the password in a file mounted as a Compose secret, as for the encryption key: add `smtp_password` under `secrets:` in `compose.yaml` (`file: ./smtp-password`) and list it under the dashboard's `secrets`. `SUPABASE_DASHBOARD_SMTP_PASSWORD` also works, but then the password appears in `docker inspect`. The connection always uses TLS: `smtp://` requires the server to offer STARTTLS, and the certificate must chain to a public authority or to `SUPABASE_DASHBOARD_EXTRA_CA_FILE`. `SUPABASE_DASHBOARD_PUBLIC_URL` must be set, because the emailed link starts with it.

To send through [Resend](https://resend.com)'s HTTP API instead of SMTP, set an API key in place of the `SMTP_*` settings:

```sh
SUPABASE_DASHBOARD_RESEND_API_KEY_FILE=/run/secrets/resend_api_key
SUPABASE_DASHBOARD_MAIL_FROM=Dashboard <dashboard@example.com>
```

The From address must be on a domain verified in Resend, and a key limited to sending is enough. Mount the key as a Compose secret like the SMTP password; `SUPABASE_DASHBOARD_RESEND_API_KEY` also works, with the same `docker inspect` caveat. The dashboard sends only to `https://api.resend.com`, directly (no proxy). Set SMTP or Resend, not both.

After an invitation is created, the page says whether the email went out. If the mail server or Resend could not be reached or refused the message, the invitation still works and the link is still shown once to send by hand; the dashboard does not retry. To send it again later, use Resend next to the invitation under Open invitations: it makes a new link, emails it, and the old link stops working. Each send is recorded in the audit log as `organization.invitation_email`, without the message or the link. The settings and their limits are in [Configuration](https://github.com/FilipNone/supabase-dashboard/blob/main/docs/development.md#configuration). With mail set up, the sign-in page's "Forgot your password?" link also emails operators a one-hour link to choose a new password; without it, a forgotten password is reset with `supabase-dashboard-server reset-password` on the server. Mail also lets operators change their sign-in email under Account settings > Profile: the dashboard emails a one-hour confirmation link to the new address, changes nothing until it is opened, and then sends a notice to the old address. Without mail, the sign-in email cannot be changed.

### Signing in with OIDC

Operators can also sign in through an OpenID Connect provider, such as Authentik. It is off by default, and passwords keep working with it on. A provider identity signs in only to the dashboard account it was linked to: the dashboard never finds, links, or creates accounts by email, and the provider cannot sign anyone up.

1. In Authentik, create an OAuth2/OpenID provider (Applications > Providers): client type Confidential, authorization flow of your choice, grant types including Authorization Code, and one strict redirect URI, `https://<dashboard host>/auth/oidc/callback` (the dashboard's `SUPABASE_DASHBOARD_PUBLIC_URL` followed by `/auth/oidc/callback`). Keep the default scope mappings for `openid`, `email`, and `profile`, and the signing key (an RS256 or ES256 certificate; the dashboard refuses HMAC-signed ID and logout tokens). Under Logout, set the Logout URI to `https://<dashboard host>/auth/oidc/backchannel-logout` and the Logout Method to Back-channel. Then create an application that uses the provider and note its slug.
2. Put the client secret in a file next to `compose.yaml`, add it as a Compose secret like the encryption key (`oidc_client_secret` under `secrets:` with `file: ./oidc-client-secret`, and listed under the dashboard's `secrets`), and set in `.env`:

   ```sh
   SUPABASE_DASHBOARD_OIDC_ISSUER_URL=https://authentik.example.com/application/o/<slug>/
   SUPABASE_DASHBOARD_OIDC_CLIENT_ID=<client id>
   SUPABASE_DASHBOARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
   SUPABASE_DASHBOARD_OIDC_NAME=Authentik
   ```

   The issuer must be written exactly as the provider names itself, trailing slash included. `SUPABASE_DASHBOARD_OIDC_CLIENT_SECRET` also works, but then the secret appears in `docker inspect`.
3. Restart. The log line `single sign-on is enabled` shows the issuer, the redirect URI, and the back-channel logout URL to register. The sign-in page now offers "Sign in with Authentik".
4. Each operator signs in with their password once, opens Account settings > Security, and chooses Link under Single sign-on. After they sign in at the provider, the identity is linked to that account, and from then on "Sign in with Authentik" signs them in. They can unlink it there; their password still works. An installation administrator can also unlink another operator's identity from Administration > Accounts, after a confirmation naming the account: that ends the operator's dashboard sessions started with the identity (and the Studio sessions opened from them), keeps their password and other sessions, and is recorded as `admin.account_oidc_unlink`. Administrators unlink their own identity under Account settings, like everyone else.

The dashboard talks to the provider only at the issuer's origin: discovery, the key set, and the token endpoint must be there, redirects are not followed, no proxy is used, and answers are size- and time-limited. Cloud metadata addresses are always refused. A provider on the same host is allowed, because the issuer is configured by the deployment. If the provider's certificate is from a private authority, add it to `SUPABASE_DASHBOARD_EXTRA_CA_FILE`. Sign-ins, refusals, links, and unlinks are in the audit log, without codes, tokens, or ID token contents. A disabled account cannot sign in this way either.

The sign-in uses the authorization code flow with PKCE, `state`, and `nonce`, and checks the ID token's issuer, audience, signature, and expiry. A started sign-in waits at most 10 minutes, only in the browser that started it, and in the dashboard's memory: restarting the dashboard cancels sign-ins in progress. Authentik groups are not mapped to roles.

Signing out of Authentik signs out of the dashboard through OpenID Connect Back-Channel Logout 1.0. Authentik posts a signed logout token to `/auth/oidc/backchannel-logout`. The dashboard checks its signature against the provider's key set (cached for 5 minutes), the issuer, that the client ID is its only audience, that it was issued within the last 5 minutes (1 minute of clock skew allowed), the back-channel logout event, and that it names `sub` or `sid` and has no `nonce`. It then ends the dashboard sessions that were started by signing in through Authentik: those of that Authentik session when the token names a `sid`, otherwise every one of that identity. Password sessions of the same account stay signed in. Ending a dashboard session also ends the Studio sessions opened from it. Each ended session is recorded as `session.oidc_backchannel_logout`; refused tokens are only logged, and neither keeps token contents. A token is used once: its `jti` is remembered in the dashboard's memory for the 7 minutes it could still be accepted, so a restart forgets them, and with several dashboard instances each keeps its own list. The provider must be able to reach the dashboard's public URL for this. The endpoint takes no cookie and is exempt from the dashboard's same-origin check on posts, for `POST` to that path only; it accepts a form body of at most 16 KiB, works on at most 8 logouts at a time, and answers 200, 400 for a token it refuses, or 503 when it cannot check one now (busy, or the key set unreachable). Without it, a dashboard session ends on its own timeouts.

The flow was checked on 2026-11-15 in Chromium against Authentik 2026.8.5 from `tests/fixtures/authentik/` (see its `setup.sh`): link from Account settings > Security, sign out, sign in through Authentik and land on the `next` page, unlink, and be refused after unlinking. Back-channel logout was checked the same way: signing out of Authentik ended the dashboard session started through it, and a password session of the same account in another browser stayed signed in.

## Studio access

Members open a project's Studio through the dashboard, which serves each project's Studio on its own host under `SUPABASE_DASHBOARD_STUDIO_DOMAIN` (see `docs/adr/0002-studio-access.md`). To turn it on:

1. Pick a domain that is not the dashboard's own host and not a parent of it, for example `studio.example.com` next to `dashboard.example.com`, and set `SUPABASE_DASHBOARD_STUDIO_DOMAIN=studio.example.com` in `.env`.

   If your certificate or CDN covers only one level of names under your domain (a `*.example.com` wildcard, or Cloudflare's free Universal SSL, which does not cover `*.studio.example.com`), use a flat pattern instead: `SUPABASE_DASHBOARD_STUDIO_DOMAIN=*-studio.example.com` serves each project at `<project id in hex>-studio.example.com`. The dashboard's own host must not match the pattern. In the steps below, the wildcard record and certificate are then the ones for `*.example.com`, which may already exist. The bundled Caddyfile's Studio site is written for the nested form: for a flat pattern, change its address from `*.{$SUPABASE_DASHBOARD_STUDIO_DOMAIN:studio.invalid}` to `*.example.com`. On-demand certificates still go only to names `/tls/ask` accepts.
2. Point `*.studio.example.com` at the dashboard server (a wildcard DNS record). The reverse proxy needs certificates for the Studio hosts, and it must pass the original `Host` header through, because the dashboard picks the project from it. There are two ways to get the certificates:
   - The bundled Caddy (`--profile caddy`) reads `SUPABASE_DASHBOARD_STUDIO_DOMAIN` from `.env` and obtains a certificate for a project's Studio host the first time someone opens it (on-demand TLS). Before each new certificate it asks the dashboard at `http://dashboard:3000/tls/ask?domain=<name>`, which answers 200 only for the Studio host of a registered project, so other names under the domain get no certificate. No DNS provider plugin is needed; ports 80 and 443 must be reachable, as for the dashboard's own certificate. The first visit to a project's Studio waits while Caddy obtains the certificate. Each project gets its own certificate, which counts toward the certificate authority's rate limits (Let's Encrypt allows 50 per registered domain per week), and its Studio host name appears in public certificate transparency logs.
   - A wildcard certificate for `*.studio.example.com` covers every project with one certificate. Obtaining it needs the ACME DNS challenge, so the proxy needs a plugin for your DNS provider (for Caddy, a custom build).

   With your own proxy, keep `/tls/ask` off the dashboard's public site, as the bundled Caddyfile does: it answers without a session, and it tells whether a project ID is registered.

   Both were checked on 2026-11-12 with Caddy 2.10 in front of the dashboard, using Caddy's internal certificate authority in place of ACME: a member signed in at `https://dash.localhost`, opened a project's Studio on its own host, ran a query through Studio, and lost access on signing out. The on-demand setup gave the registered project's host a certificate and refused the TLS handshake for an unregistered one.
3. For each project, save the stack gateway's Studio login on the project's Settings page.

Some Studio pages do not go through the dashboard. The Realtime inspector opens a WebSocket from the browser straight to the stack's public API URL (the stack's `SUPABASE_PUBLIC_URL`), with the service role key in the query string. Members' browsers must be able to reach that URL for those pages to work, and anyone who can open Studio can read the key from there, as they can on Studio's API settings page. File uploads on the Storage page also go straight to that URL: Studio sends them as resumable uploads to `/storage/v1/upload/resumable` on the stack's public API URL. Seen with Studio 2026.11.02 against the test stack; other pages may do the same.

Requests on a Studio host are limited by `SUPABASE_DASHBOARD_STUDIO_MAX_BODY_BYTES` (50 MiB by default) and `SUPABASE_DASHBOARD_STUDIO_REQUEST_TIMEOUT_SECS` (300 seconds). If the reverse proxy has its own body limit or timeout, raise it to match, or Storage uploads and long SQL queries in Studio fail at the proxy. Caddy's `reverse_proxy` sets neither by default.

### Closing the stack's own Studio entrance

A self-hosted stack serves Studio itself, behind HTTP basic auth on the gateway's catch-all `/` route, using `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` from the stack's `.env`. Anyone who knows that password can open Studio directly, without the dashboard's sign-in, roles, or audit log. Make the dashboard the only holder of it:

1. Generate a long random password. Upstream requires at least one letter and no special characters; hex output fits:

   ```sh
   openssl rand -hex 32
   ```

2. Set it as `DASHBOARD_PASSWORD` in the stack's `.env`, and restart the stack's API gateway so it reads the new value.
3. Save the same username and password on the project's Settings page in the dashboard. The dashboard tries the login against the gateway before storing it: if the gateway refuses it, nothing is saved and the page says so. If the gateway cannot be reached, or still opens Studio without a password, the login is saved with a warning; restart the gateway and run "Check now" on the project page until the Studio row reports the stored login as accepted.
4. Do not keep the password anywhere else. If someone needs Studio, give them a dashboard role that allows it.

Where the network allows it, also keep the gateway's Studio route away from the internet: for example, let only the dashboard server reach the stack's gateway port, or put the stack's public API behind a separate proxy that serves only the API paths (`/auth/v1/`, `/rest/v1/`, `/storage/v1/`, `/realtime/v1/`, `/functions/v1/`, and the others your apps use). Closing the API paths themselves to members' browsers breaks the Studio pages that call them directly. These setups depend on the stack's gateway and network and have not been tested with this dashboard yet.

The project page warns every member until a Studio login is saved.

## Operations

| Task | Command |
| --- | --- |
| Logs | `docker compose logs -f dashboard` |
| Stop (keeps data) | `docker compose down` |
| Reset a forgotten password | `docker compose exec dashboard supabase-dashboard-server reset-password --email you@example.com` |
| Move stored keys to a new encryption key | `docker compose exec dashboard supabase-dashboard-server rotate-secret-key` (see below) |
| Back up the metadata database | `docker compose exec -T db pg_dump -U dashboard -Fc dashboard > dashboard-$(date +%F).dump` |

`reset-password` signs the account out everywhere. Keep backups outside the server and treat them as secrets: they contain session hashes, password hashes, audit records, and the encrypted API keys of registered stacks. Keep `secret.key` in a different place from the dumps.

The audit log records sign-ins, membership and role changes, project and stack changes, and refused attempts, without passwords, keys, or project data. Owners and admins read their organization's events on its Audit log tab, and every operator reads their own under Account, Audit log. Events are kept until the metadata database is cleaned by hand; there is no retention limit yet.

### Replacing the encryption key

The dashboard can read stored keys under an old encryption key while it moves them to a new one, so the stacks stay reachable during the change. Run these steps in the directory that holds `compose.yaml`:

1. Keep the old key as a previous key, then write a new one:

   ```sh
   sudo cp -p secret.key previous.keys
   openssl rand -base64 32 | sudo tee secret.key > /dev/null
   ```

   `cp -p` keeps the owner and mode that step 3 of Install set, and `tee` writes into the existing file, so `secret.key` keeps them too.

2. In `compose.yaml`, give the dashboard the previous keys. Add `SUPABASE_DASHBOARD_PREVIOUS_SECRET_KEYS_FILE: /run/secrets/previous_secret_keys` to its `environment`, `- previous_secret_keys` to its `secrets`, and at the end of the file, under the top-level `secrets`:

   ```yaml
     previous_secret_keys:
       file: ./previous.keys
   ```

3. Restart with `docker compose up -d`. The log names the new key's ID and warns that stored keys are still under a previous key.
4. Run `docker compose exec dashboard supabase-dashboard-server rotate-secret-key`. It reseals every stored key under the new key, including the Dokploy API key, the secrets of provisioning jobs that have not succeeded, and the records of the variables written to provisioned stacks, without changing who set each one or when, and is audited as `credentials.reseal`. It can run while people use the dashboard, and running it again is harmless.
5. When it prints that no stored credential needs a previous key, remove the lines from step 2, delete `previous.keys`, and restart.

Backups taken before the change still need the old key. Store a copy of it with those backups until they expire. A key listed in neither setting cannot be recovered: the command reports how many stored keys it could not read, and those have to be entered again on each project's settings page, or for the Dokploy key, replaced on the administrator page.

To restore a backup into an empty database:

```sh
docker compose stop dashboard
docker compose exec -T db pg_restore -U dashboard -d dashboard --clean --if-exists < dashboard-2026-11-08.dump
docker compose start dashboard
```

These steps were checked once with 0.1.0-dev.1 (backup, wipe the volume, start fresh, restore, sign in), and there is no automated restore test yet. Try a restore on a disposable copy before you rely on it.

## Upgrade

1. Read the release notes.
2. Back up the metadata database (see above).
3. Set `SUPABASE_DASHBOARD_VERSION` in `.env` to the new version, and replace `compose.yaml` and `Caddyfile` with the files from the new bundle if they changed. Upgrading from 0.1.0-dev.1: the new `compose.yaml` expects `secret.key`, so create it first (Install, step 3).
4. `docker compose pull && docker compose up -d`

Migrations only move forward. To go back to an older version, restore the backup taken before the upgrade.

## Uninstall

`docker compose down` stops the containers and keeps the data. `docker compose down -v` also deletes the metadata database and Caddy's certificates; this cannot be undone. Neither command touches the Supabase stacks registered in the dashboard.

## Without Docker

Each release also has `supabase-dashboard-<version>-<arch>-linux-gnu.tar.gz` with the server binary and web assets. It needs glibc 2.36 or newer and a PostgreSQL 14+ database. Unpack it and run from that directory:

```sh
export LEPTOS_OUTPUT_NAME=supabase-dashboard LEPTOS_SITE_ROOT=site LEPTOS_SITE_PKG_DIR=pkg \
  LEPTOS_SITE_ADDR=127.0.0.1:3000 LEPTOS_ENV=PROD
export SUPABASE_DASHBOARD_PUBLIC_URL=https://dashboard.example.com
export SUPABASE_DASHBOARD_DATABASE_URL=postgres://dashboard:<password>@127.0.0.1:5432/dashboard
export SUPABASE_DASHBOARD_SECRET_KEY_FILE=/etc/supabase-dashboard/secret.key
./supabase-dashboard-server
```

Keep the database URL out of shell history and process listings, for example with a systemd unit and an `EnvironmentFile=` readable only by the service user.
