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
| Storage | `supabase/storage-api:v1.89.12` (pinned 2026-11-09; file backend, no image transformations) | `storage` | none: only through the gateway |
| Realtime | `supabase/realtime:v2.148.3` (pinned 2026-11-09) | `realtime` | none: only through the gateway |
| Edge Functions | `supabase/edge-runtime:v1.77.9` (pinned 2026-11-12; upstream's `main` router with `VERIFY_JWT` on, no user functions) | `functions` | none: only through the gateway |

Upstream now defaults to an Envoy gateway and keeps Kong as an alternative. The fixture uses Kong with a reduced `api/kong.yml` (Auth, REST, Storage, Realtime, and Edge Functions routes, legacy JWT API keys, and the basic-auth catch-all route to Studio) because its configuration is much smaller; the routes, key checks, and Studio login match upstream's. The Studio login is `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` in `fixture.env`. An Envoy fixture is still to do.

Not in the fixture yet: imgproxy, Supavisor, analytics. The `functions` service's router imports `jsr:@panva/jose` when it starts, so the fixture needs access to the JSR registry. The Studio pages that need them are added as those pages are checked through the dashboard.

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
| PostgREST reachability through the gateway (service role key; the gateway refuses the anon key on the root path with 403), and its version from the `Server` header (`postgrest/14.18`), which Kong passes through | Verified against PostgREST v14.18 via Kong 3.9.3 | same test |
| Wrong key reported as rejected (401) | Verified | same test |
| Storage reachability and version through the gateway (`/storage/v1/version`, anon key) | Verified against Storage v1.89.12 via Kong 3.9.3 | `fixture_gateway_reports_storage_and_realtime` in `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture` |
| Realtime reachability through the gateway (`/realtime/v1/api/ping`, anon key; no WebSocket and no tenant database check) | Verified against Realtime v2.148.3 via Kong 3.9.3 | same test |
| Edge Functions reachability through the gateway (`/functions/v1/` with no function name, anon key in `apikey` and `Authorization`): the router's own 404 with `sb-error-code: NOT_FOUND` counts as healthy, and so does the 400 "missing function name in request" of routers from before 2025. The router, not the gateway, checks the key | Verified against edge-runtime v1.77.9 via Kong 3.9.3; the older router's answer against the mock gateway only | `fixture_gateway_reports_edge_functions` in `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture`; `an_older_functions_router_counts_as_healthy` in `crates/adapters/tests/gateway_mock.rs` |
| A service the gateway has no route for is reported as not found (404) | Mock gateway only | `services_without_a_route_are_reported_as_not_found` in `crates/adapters/tests/gateway_mock.rs` |
| A service request that lands on the gateway's Studio route is reported as having no route, not as a rejected key: a 401 with a `Basic` challenge comes from Studio's basic-auth catch-all, while Kong's key check answers `WWW-Authenticate: Key` | Mock gateway; the two challenges were read from the fixture's Kong 3.9.3 by hand on 2026-11-12 | `services_that_reach_the_studio_login_have_no_route` in `crates/adapters/tests/gateway_mock.rs`. Envoy's challenge is not checked |
| Studio route: refuses requests without the login or with a wrong one, accepts the stored login | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 | `fixture_studio_route_needs_the_login` in `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture` |
| Saving a Studio login tries it against the Studio route first and refuses a login the gateway rejects | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 | `studio_opens_the_fixture_studio` in `apps/server/src/app.rs` (saves the fixture's login through the settings form); refusal covered by application tests |
| Studio route: reports a gateway that opens Studio without a login | Mock gateway only | `crates/adapters/tests/gateway_mock.rs` |
| Studio forwarding: the stored login replaces the browser's, Studio's redirect comes back as a path, pages and Studio's own API answer | Verified against the same Studio and gateway | `fixture_studio_is_reached_through_the_proxy` in `crates/adapters/tests/gateway_fixture.rs` |
| Reported Auth, PostgREST, and Storage versions compared with this baseline: the service health table marks each as tested, older, newer, or not comparable | Comparison unit-tested; a test fails if the fixture images and this table stop matching the versions in code | `reported_versions_are_compared_with_the_tested_ones` and `tested_versions_match_the_fixture_and_the_baseline` in `crates/domain/src/connection.rs`; table checked in Chromium on 2026-11-12 with a synthetic report |
| Expiry date of the gateway's TLS certificate, read from the leaf certificate after the handshake; the project overview, project cards, and the administrator's project table flag it 30 days ahead and when it has passed | Self-signed test authority only (the fixture gateway is plain HTTP) | `crates/adapters/tests/gateway_tls.rs` |
| Realtime and Studio versions | Not reported | Checked by hand on 2026-11-12: Realtime v2.148.3's ping answers `{"message":"Success"}` with `server: Cowboy` and no version, and Studio 2026.11.02-sha-a05e7ec answers `/api/get-deployment-commit` with `{"commitSha":"development","commitTime":"unknown"}`. Neither can be compared with this baseline, so the health table shows them as not reported |
| Envoy gateway, new-style `sb_publishable_`/`sb_secret_` keys | Not tested | No fixture yet |
| Studio through the dashboard: launcher, one-time code, Studio host cookie, Studio's redirect and project page, a same-origin SQL query through Studio's API, a cross-site write refused, a viewer refused, sign-out ending access | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 | `studio_opens_the_fixture_studio` in `apps/server/src/app.rs`, CI job `fixture` |
| Studio pages in a browser through the dashboard: Home, Table editor (a table and row created through the SQL API are listed), SQL editor, Auth users | Checked by hand in headless Chromium on 2026-11-09, light and dark themes, at 1280×720; no page errors | Not automated |
| Studio's Storage buckets page through the dashboard (bucket list loads through Studio's API), and a file upload into a bucket | Bucket list checked by hand in Chromium on 2026-11-09; upload checked in headless Chromium on 2026-11-12 with a synthetic 23-byte file, which the Storage API then listed | Not automated. Studio lists objects through its own API on the Studio host, but sends the upload from the browser straight to the stack's public API URL (`/storage/v1/upload/resumable`, answered 201), not through the dashboard |
| Studio's Realtime inspector: joins a channel and receives presence | Checked by hand in Chromium on 2026-11-09 | Not automated. The inspector's WebSocket goes from the browser straight to the stack's public API URL with the service role key, not through the dashboard |
| Studio's Edge Functions page, and logs | Not checked | The fixture runs Edge Functions but does not give Studio the functions folder; it has no analytics service |

Update the baseline only together with a fixture change and a passing CI run. For Auth, PostgREST, and Storage, also change `StackService::tested_version` in `crates/domain/src/connection.rs`.
