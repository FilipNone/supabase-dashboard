# Deploying supabase-dashboard with Docker

This guide runs a released build on one Linux server from the prebuilt container image `ghcr.io/filipnone/supabase-dashboard`. Nothing is compiled on the server. To build from source, see [docs/development.md](https://github.com/FilipNone/supabase-dashboard/blob/main/docs/development.md).

Development releases (`0.1.0-dev.N`) are previews. The dashboard can manage operator accounts, organizations, members, invitations, and a registry of self-hosted stacks. It does not connect to registered stacks yet. Expect breaking changes between dev releases.

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
   curl -fLO https://github.com/FilipNone/supabase-dashboard/releases/download/v0.1.0-dev.1/supabase-dashboard-0.1.0-dev.1-docker.tar.gz
   tar -xzf supabase-dashboard-0.1.0-dev.1-docker.tar.gz
   cd supabase-dashboard-0.1.0-dev.1-docker
   ```

   `SHA256SUMS` on the release page lists the checksum of each file.

2. Create the settings file:

   ```sh
   cp .env.example .env
   chmod 600 .env
   sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" .env
   ```

   Then edit `.env` and set `SUPABASE_DASHBOARD_PUBLIC_URL` (and `SUPABASE_DASHBOARD_DOMAIN` if you use Caddy) to your DNS name.

3. Start it. With the bundled Caddy, which gets a Let's Encrypt certificate and needs ports 80 and 443 open:

   ```sh
   docker compose --profile caddy up -d
   ```

   Behind your own reverse proxy instead:

   ```sh
   docker compose up -d
   ```

   The dashboard listens on `127.0.0.1:3000` on the host. Point the proxy there and keep the original `Host` header. The server checks the `Origin` of every form submission against `SUPABASE_DASHBOARD_PUBLIC_URL`, so the URL in the browser must match it exactly.

4. Check that it is up:

   ```sh
   docker compose ps                     # dashboard shows "healthy"
   curl -fsS http://127.0.0.1:3000/readyz
   ```

   The server applies database migrations at startup. If it keeps restarting, `docker compose logs dashboard` names the setting or problem.

5. Create the first operator. There is no default account and no public sign-up:

   ```sh
   docker compose exec dashboard supabase-dashboard-server create-owner --email you@example.com --name "Your Name"
   ```

   It asks for the password twice (at least 12 characters). This account is the installation administrator. Sign in at `https://<your domain>/dashboard/sign-in`.

### Trying it without TLS

On a private network only, you can skip HTTPS: in `.env`, set `SUPABASE_DASHBOARD_ENV=development`, `SUPABASE_DASHBOARD_BIND=0.0.0.0`, and `SUPABASE_DASHBOARD_PUBLIC_URL=http://<server address>:3000`, then `docker compose up -d`. Session cookies then lack the `Secure` flag. Do not expose this setup to the internet.

## Settings

Everything is set in `.env`. `compose.yaml` passes it to the dashboard container and builds `SUPABASE_DASHBOARD_DATABASE_URL` from `POSTGRES_PASSWORD`. Only use letters and digits in that password, because it goes into the URL unescaped. Session lifetime, request limits, and logging are documented under Configuration in [docs/development.md](https://github.com/FilipNone/supabase-dashboard/blob/main/docs/development.md#configuration). Restart after a change with `docker compose up -d`.

## Operations

| Task | Command |
| --- | --- |
| Logs | `docker compose logs -f dashboard` |
| Stop (keeps data) | `docker compose down` |
| Reset a forgotten password | `docker compose exec dashboard supabase-dashboard-server reset-password --email you@example.com` |
| Back up the metadata database | `docker compose exec -T db pg_dump -U dashboard -Fc dashboard > dashboard-$(date +%F).dump` |

`reset-password` signs the account out everywhere. Keep backups outside the server and treat them as secrets: they contain session hashes, password hashes, and audit records.

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
3. Set `SUPABASE_DASHBOARD_VERSION` in `.env` to the new version, and replace `compose.yaml` and `Caddyfile` with the files from the new bundle if they changed.
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
./supabase-dashboard-server
```

Keep the database URL out of shell history and process listings, for example with a systemd unit and an `EnvironmentFile=` readable only by the service user.
