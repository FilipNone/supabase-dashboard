# Supabase compatibility baseline

This file records which self-hosted Supabase component versions the dashboard is tested against, and what that testing covers. Nothing here is a promise that a dashboard feature works; a capability is only listed as supported once an integration test exercises it.

## Baseline (2026-11-07)

Versions match the upstream `docker/docker-compose.yml` in supabase/supabase on that date.

| Component | Image | Fixture service | Host port (loopback) |
| --- | --- | --- | --- |
| PostgreSQL | `supabase/postgres:17.6.1.136` | `db` | 54322 |
| Auth (GoTrue) | `supabase/gotrue:v2.197.0` | `auth` | 54399 |
| PostgREST | `postgrest/postgrest:v14.18` | `rest` | 54330 |
| postgres-meta | `supabase/postgres-meta:v0.100.0` | `meta` | 54380 |

Not in the fixture yet: Studio, the API gateway, Realtime, Storage, imgproxy, Edge Functions, Supavisor, analytics. They will be added when the milestone that uses them starts (Storage, Realtime, and Functions are M5).

## Fixture

`tests/fixtures/supabase/` holds a reduced compose file adapted from upstream (Apache-2.0) with synthetic, test-only credentials in `fixture.env`. Every port binds to `127.0.0.1` and no volume persists data.

```sh
docker compose -f tests/fixtures/supabase/docker-compose.yml \
  --env-file tests/fixtures/supabase/fixture.env -p sd-fixture up -d --wait
docker compose -p sd-fixture down -v
```

## Capability evidence

| Capability | Status | Evidence |
| --- | --- | --- |
| Fixture services start and report healthy | Verified | CI job `fixture` (`up --wait`) |
| Any dashboard adapter operation | Not implemented | Adapters start in M2 |

Update the baseline only together with a fixture change and a passing CI run.
