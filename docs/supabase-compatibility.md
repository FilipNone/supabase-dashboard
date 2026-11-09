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
| API gateway (Kong) | `kong/kong:3.9.3` | `gateway` | 54321 |

Upstream now defaults to an Envoy gateway and keeps Kong as an alternative. The fixture uses Kong with a reduced `api/kong.yml` (Auth and REST routes only, legacy JWT API keys) because its configuration is much smaller; the routes and key checks match upstream's. An Envoy fixture is still to do.

Not in the fixture yet: Studio, Realtime, Storage, imgproxy, Edge Functions, Supavisor, analytics. Studio and the gateway's Studio route come with M3 (Studio access); the services behind Studio's other pages are added as those pages are checked through the dashboard.

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
| Auth health and version through the gateway (anon key) | Verified against GoTrue v2.197.0 via Kong 3.9.3 | `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture` |
| PostgREST reachability through the gateway (service role key; the gateway refuses the anon key on the root path with 403) | Verified against PostgREST v14.18 via Kong 3.9.3 | same test |
| Wrong key reported as rejected (401) | Verified | same test |
| Studio route: refuses requests without the login, accepts the stored login, reports a gateway that needs no password | Mock gateway only | `crates/adapters/tests/gateway_mock.rs`; the fixture has no Studio yet |
| Envoy gateway, new-style `sb_publishable_`/`sb_secret_` keys | Not tested | No fixture yet |
| Studio through the dashboard (Table editor, SQL editor, Auth, Storage, and the rest) | Not implemented | M3, see `docs/adr/0002-studio-access.md` |

Update the baseline only together with a fixture change and a passing CI run.
