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
| API gateway (Envoy) | `envoyproxy/envoy:v1.39.6` (pinned 2026-11-12) | `envoy` | 54323 |
| Studio | `supabase/studio:2026.11.02-sha-a05e7ec` (pinned 2026-11-09) | `studio` | none: only through the gateway |
| Storage | `supabase/storage-api:v1.89.12` (pinned 2026-11-09; file backend, no image transformations) | `storage` | none: only through the gateway |
| Realtime | `supabase/realtime:v2.148.3` (pinned 2026-11-09) | `realtime` | none: only through the gateway |
| Edge Functions | `supabase/edge-runtime:v1.77.9` (pinned 2026-11-12; upstream's `main` router with `VERIFY_JWT` on, and one synthetic function, `hello`, that returns a fixed body; Studio reads the same folder read-only) | `functions` | none: only through the gateway |

Upstream defaults to an Envoy gateway and keeps Kong as a deprecated override, so the fixture runs both in front of the same services. Kong uses a reduced `api/kong.yml` (Auth, REST, Storage, Realtime, and Edge Functions routes, legacy JWT API keys, and the basic-auth catch-all route to Studio); its routes, key checks, and Studio login match upstream's. Envoy uses upstream's own files in `api/envoy/` (from commit 5583c2bd6f7e), unchanged. The fixture also turns on upstream's new API keys the way `utils/add-new-auth-keys.sh` does: synthetic `sb_publishable_` and `sb_secret_` keys (fixed strings outside the real key format, so secret scanners ignore them; Envoy compares them exactly) and an ES256 key pair are in `fixture.env`, Auth signs with the ES256 key, and every service verifies a JWKS that holds both it and `JWT_SECRET`. Envoy translates the opaque keys to the ES256 JWTs; Kong stays in legacy key mode, and the HS256 keys keep working through both. The Studio login is `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` in `fixture.env`. CI runs the gateway tests and the Studio end-to-end test once through each gateway, and the opaque key tests through Envoy.

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
| Auth health and version through the gateway (anon key) | Verified against GoTrue v2.197.0 via Kong 3.9.3 and Envoy 1.39.6 | `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture` |
| PostgREST reachability through the gateway (service role key; the gateway refuses the anon key on the root path with 403), and its version: from the `Server` header (`postgrest/14.18`) when the gateway passes it on, as Kong does, or else from `info.version` near the start of the OpenAPI description, since Envoy replaces the header with `server: envoy`. At most 16 KiB of the description is read | Verified against PostgREST v14.18 via Kong 3.9.3 and Envoy 1.39.6 | same test |
| Wrong key reported as rejected (401) | Verified | same test |
| Storage reachability and version through the gateway (`/storage/v1/version`, anon key) | Verified against Storage v1.89.12 via Kong 3.9.3 and Envoy 1.39.6 | `fixture_gateway_reports_storage_and_realtime` in `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture` |
| Realtime reachability through the gateway (`/realtime/v1/api/ping`, anon key; no WebSocket and no tenant database check) | Verified against Realtime v2.148.3 via Kong 3.9.3 and Envoy 1.39.6 | same test |
| Edge Functions reachability through the gateway (`/functions/v1/` with no function name, anon key in `apikey` and `Authorization`): the router's own 404 with `sb-error-code: NOT_FOUND` counts as healthy, and so does the 400 "missing function name in request" of routers from before 2025. The router, not the gateway, checks the key | Verified against edge-runtime v1.77.9 via Kong 3.9.3 and Envoy 1.39.6; the older router's answer against the mock gateway only | `fixture_gateway_reports_edge_functions` in `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture`; `an_older_functions_router_counts_as_healthy` in `crates/adapters/tests/gateway_mock.rs` |
| A service the gateway has no route for is reported as not found (404) | Mock gateway only | `services_without_a_route_are_reported_as_not_found` in `crates/adapters/tests/gateway_mock.rs` |
| A service request that lands on the gateway's Studio route is reported as having no route, not as a rejected key: a 401 with a `Basic` challenge comes from Studio's basic-auth catch-all, while Kong's key check answers `WWW-Authenticate: Key` | Mock gateway; the two challenges were read from the fixture's Kong 3.9.3 by hand on 2026-11-12 | `services_that_reach_the_studio_login_have_no_route` in `crates/adapters/tests/gateway_mock.rs`. Envoy 1.39.6, read from the fixture by hand on 2026-11-12, answers a rejected key with a 401 and no challenge, and a path without a route with a 401 and `Basic realm="<request URL>"`, so the same rule holds |
| Studio route: refuses requests without the login or with a wrong one, accepts the stored login | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 and Envoy 1.39.6 | `fixture_studio_route_needs_the_login` in `crates/adapters/tests/gateway_fixture.rs`, CI job `fixture` |
| Saving a Studio login tries it against the Studio route first and refuses a login the gateway rejects | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 and Envoy 1.39.6 | `studio_opens_the_fixture_studio` in `apps/server/src/app.rs` (saves the fixture's login through the settings form); refusal covered by application tests |
| Studio route: reports a gateway that opens Studio without a login | Mock gateway only | `crates/adapters/tests/gateway_mock.rs` |
| Studio forwarding: the stored login replaces the browser's, Studio's redirect comes back as a path, pages and Studio's own API answer | Verified against the same Studio and gateway | `fixture_studio_is_reached_through_the_proxy` in `crates/adapters/tests/gateway_fixture.rs` |
| Reported Auth, PostgREST, and Storage versions compared with this baseline: the service health table marks each as tested, older, newer, or not comparable | Comparison unit-tested; a test fails if the fixture images and this table stop matching the versions in code | `reported_versions_are_compared_with_the_tested_ones` and `tested_versions_match_the_fixture_and_the_baseline` in `crates/domain/src/connection.rs`; table checked in Chromium on 2026-11-12 with a synthetic report |
| Expiry date of the gateway's TLS certificate, read from the leaf certificate after the handshake; the project overview, project cards, and the administrator's project table flag it 30 days ahead and when it has passed | Self-signed test authority only (the fixture gateway is plain HTTP) | `crates/adapters/tests/gateway_tls.rs` |
| Realtime and Studio versions | Not reported | Checked by hand on 2026-11-12: Realtime v2.148.3's ping answers `{"message":"Success"}` with `server: Cowboy` and no version, and Studio 2026.11.02-sha-a05e7ec answers `/api/get-deployment-commit` with `{"commitSha":"development","commitTime":"unknown"}`. Neither can be compared with this baseline, so the health table shows them as not reported |
| Envoy gateway with the legacy HS256 keys | Verified against Envoy 1.39.6 with upstream's config | Every `gateway_fixture.rs` test and `studio_opens_the_fixture_studio` run through it in CI job `fixture` |
| Opaque `sb_publishable_`/`sb_secret_` keys in the anon and service role fields: Envoy translates them to ES256 JWTs, and the checks give the same results as with the HS256 keys (only the secret key opens the PostgREST root); a key the stack never issued is refused with 401. The keys have no expiry to show | Verified against Envoy 1.39.6 with every service on the fixture's JWKS | `fixture_gateway_accepts_the_new_api_keys` in `crates/adapters/tests/gateway_fixture.rs` and `the_new_api_keys_pass_a_fixture_check` in `apps/server/src/app.rs` (keys stored through the settings forms, then a full check), CI job `fixture`. Kong refuses them, as upstream's Kong setup in legacy mode does |
| Studio through the dashboard: launcher, one-time code, Studio host cookie, Studio's redirect and project page for an owner, an admin, and a developer, a same-origin SQL query through Studio's API, a cross-site write refused, a viewer and a non-member refused, sign-out ending access | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 and Envoy 1.39.6 | `studio_opens_the_fixture_studio` in `apps/server/src/app.rs`, CI job `fixture` |
| Studio pages in a browser through the dashboard: Home, Table editor (a table and row created through the SQL API are listed), SQL editor, Auth users | Checked by hand in headless Chromium on 2026-11-09, light and dark themes, at 1280×720; no page errors | Not automated |
| Studio's Storage buckets page through the dashboard (bucket list loads through Studio's API), and a file upload into a bucket | Bucket list checked by hand in Chromium on 2026-11-09; upload checked in headless Chromium on 2026-11-12 with a synthetic 23-byte file, which the Storage API then listed | Not automated. Studio lists objects through its own API on the Studio host, but sends the upload from the browser straight to the stack's public API URL (`/storage/v1/upload/resumable`, answered 201), not through the dashboard |
| Studio's Realtime inspector: joins a channel and receives presence | Checked by hand in Chromium on 2026-11-09 | Not automated. The inspector's WebSocket goes from the browser straight to the stack's public API URL with the service role key, not through the dashboard |
| Studio's Edge Functions page: lists the functions in its mounted folder (`hello`, not the router) | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 and Envoy 1.39.6; page checked in headless Chromium through the dashboard on 2026-11-12 at 1280 and 390 wide in both themes | `fixture_studio_is_reached_through_the_proxy` in `crates/adapters/tests/gateway_fixture.rs` reads the list through the Studio proxy, CI job `fixture`. Deploying or editing functions from Studio is not checked |
| Studio's SQL editor saving a snippet (Studio keeps snippets in `SNIPPETS_MANAGEMENT_FOLDER`, which the fixture sets as upstream does) | Verified against Studio 2026.11.02-sha-a05e7ec via Kong 3.9.3 and Envoy 1.39.6; a query run and saved as a snippet in headless Chromium through the dashboard on 2026-11-12, listed again after a reload | `fixture_studio_is_reached_through_the_proxy` reads the snippet count through the Studio proxy, CI job `fixture`. Without the folder Studio answers 500 on its snippet routes and the editor's list stays empty |
| Studio through a TLS reverse proxy: Caddy 2.10 in front of the dashboard, with per-host on-demand certificates and with a wildcard certificate | Checked by hand on 2026-11-12 with Caddy's internal certificate authority: sign-in, opening Studio, a query through Studio, and sign-out ending access | `/tls/ask` is covered by `studio_opens_only_through_the_dashboard` in `apps/server/src/app.rs`. Certificates from a public ACME authority were not tried |
| Studio's logs pages | Not checked | The fixture has no analytics service |

Update the baseline only together with a fixture change and a passing CI run. For Auth, PostgREST, and Storage, also change `StackService::tested_version` in `crates/domain/src/connection.rs`.
