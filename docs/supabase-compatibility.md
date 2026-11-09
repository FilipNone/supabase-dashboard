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
| Studio | `supabase/studio:2026.11.02-sha-a05e7ec` (pinned 2026-11-09) | `studio` | none: only through the gateway |

Upstream now defaults to an Envoy gateway and keeps Kong as an alternative. The fixture uses Kong with a reduced `api/kong.yml` (Auth and REST routes, legacy JWT API keys, and the basic-auth catch-all route to Studio) because its configuration is much smaller; the routes, key checks, and Studio login match upstream's. The Studio login is `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` in `fixture.env`. An Envoy fixture is still to do.

Not in the fixture yet: Realtime, Storage, imgproxy, Edge Functions, Supavisor, analytics. The Studio pages that need them are added as those pages are checked through the dashboard.

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
| Studio route: refuses requests without the login or with a wrong one, accepts the stored login | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 | `fixture_studio_route_needs_the_login` in `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture` |
| Studio route: reports a gateway that opens Studio without a login | Mock gateway only | `crates/adapters/tests/gateway_mock.rs` |
| Studio forwarding: the stored login replaces the browser's, Studio's redirect comes back as a path, pages and Studio's own API answer | Verified against the same Studio and gateway | `fixture_studio_is_reached_through_the_proxy` in `crates/adapters/tests/gateway_fixture.rs` |
| Envoy gateway, new-style `sb_publishable_`/`sb_secret_` keys | Not tested | No fixture yet |
| Studio through the dashboard (Table editor, SQL editor, Auth, Storage, and the rest) | Not implemented | M3, see `docs/adr/0002-studio-access.md` |

Update the baseline only together with a fixture change and a passing CI run.
