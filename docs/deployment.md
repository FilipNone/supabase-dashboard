# Deploying supabase-dashboard with Docker

This guide runs a released build on one Linux server from the prebuilt container image `ghcr.io/filipnone/supabase-dashboard`. Nothing is compiled on the server. To build from source, see [docs/development.md](https://github.com/FilipNone/supabase-dashboard/blob/main/docs/development.md).

Development releases (`0.1.0-dev.N`) are previews. The dashboard can manage operator accounts, organizations, members, invitations, and a registry of self-hosted stacks. It can store a stack's API keys and Studio login, check whether its Auth, REST, and Studio routes answer, and open the stack's own Studio for members whose role allows it (see "Studio access" below). Expect breaking changes between dev releases.

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
   curl -fLO https://github.com/FilipNone/supabase-dashboard/releases/download/v0.1.0-dev.4/supabase-dashboard-0.1.0-dev.4-docker.tar.gz
   tar -xzf supabase-dashboard-0.1.0-dev.4-docker.tar.gz
   cd supabase-dashboard-0.1.0-dev.4-docker
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

## Studio access

Members open a project's Studio through the dashboard, which serves each project's Studio on its own host under `SUPABASE_DASHBOARD_STUDIO_DOMAIN` (see `docs/adr/0002-studio-access.md`). To turn it on:

1. Pick a domain that is not the dashboard's own host and not a parent of it, for example `studio.example.com` next to `dashboard.example.com`, and set `SUPABASE_DASHBOARD_STUDIO_DOMAIN=studio.example.com` in `.env`.
2. Point `*.studio.example.com` at the dashboard server (a wildcard DNS record), and give the reverse proxy a certificate for it. A wildcard certificate needs the ACME DNS challenge. The proxy must pass the original `Host` header through, because the dashboard picks the project from it.
3. For each project, save the stack gateway's Studio login on the project's Settings page.

Some Studio pages do not go through the dashboard. The Realtime inspector opens a WebSocket from the browser straight to the stack's public API URL (the stack's `SUPABASE_PUBLIC_URL`), with the service role key in the query string. Members' browsers must be able to reach that URL for those pages to work, and anyone who can open Studio can read the key from there, as they can on Studio's API settings page. Seen with Studio 2026.11.02 against the test stack; other pages may do the same.

Requests on a Studio host are limited by `SUPABASE_DASHBOARD_STUDIO_MAX_BODY_BYTES` (50 MiB by default) and `SUPABASE_DASHBOARD_STUDIO_REQUEST_TIMEOUT_SECS` (300 seconds). If the reverse proxy has its own body limit or timeout, raise it to match, or Storage uploads and long SQL queries in Studio fail at the proxy.

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
4. Run `docker compose exec dashboard supabase-dashboard-server rotate-secret-key`. It reseals every stored key under the new key, without changing who set each one or when, and is audited as `credentials.reseal`. It can run while people use the dashboard, and running it again is harmless.
5. When it prints that no stored credential needs a previous key, remove the lines from step 2, delete `previous.keys`, and restart.

Backups taken before the change still need the old key. Store a copy of it with those backups until they expire. A key listed in neither setting cannot be recovered: the command reports how many stored keys it could not read, and those have to be entered again on each project's settings page.

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
