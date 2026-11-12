# Dokploy provider

Dokploy is the dashboard's first deployment provider (ROADMAP.md, M4). This page records which Dokploy versions the dashboard works with, the API calls it makes, and how the test fixture runs Dokploy.

## Supported versions

| Dokploy | Status |
| --- | --- |
| v0.31.1 | Tested: the fixture runs `dokploy/dokploy:v0.31.1` |
| Other v0.31.x patch releases | Accepted, not tested |
| Any other release, `canary`, `latest`, or a pre-release | Refused when connecting |

Dokploy is on 0.x and generates its HTTP API from its tRPC routers, so a minor release can rename or reshape a call. The dashboard reads the version first and refuses a minor release it has not been tested with. The message names the version found and the supported range, for example "Dokploy v0.32.0 is not supported. This dashboard works with Dokploy v0.31.x, tested with v0.31.1." Supporting a new minor release means running the provider tests against it, then changing `TESTED_DOKPLOY_VERSION` in `crates/domain/src/dokploy.rs`, `DOKPLOY_VERSION` in `tests/fixtures/dokploy/fixture.env`, and this table together. A unit test fails if they disagree.

## How the dashboard calls Dokploy

Every call goes to `<Dokploy URL>/api/<procedure>` with the API key in the `x-api-key` header. Dokploy answers 401 without a valid key. Queries are `GET` with their input in the query string, and mutations are `POST` with a JSON body. Dokploy v0.31.1 serves its OpenAPI 3.1 document at `settings.getOpenApiDocument` (also behind the key); the calls below were read from that document on 2026-11-12.

The client in `crates/adapters/src/dokploy.rs` uses the same connection rules as the gateway checks: resolved addresses are checked against the address policy at connection time, redirects are not followed, proxies from the environment are ignored, and every request has a connect timeout, a total timeout, and a bound on the body it reads. Its error messages name no address, key, or response text.

### Implemented

| Call | Method | Input | Used for |
| --- | --- | --- | --- |
| `settings.getDokployVersion` | GET | none | Read the version before anything else; the answer is a JSON string such as `"v0.31.1"` |

### Planned

These are the calls the M4 roadmap items need, with their required inputs in v0.31.1. None is called yet.

| Call | Method | Required input | Roadmap use |
| --- | --- | --- | --- |
| `project.all` | GET | none | Projects and environments the key can see |
| `project.one` | GET | `projectId` | One project's environments and services |
| `environment.create` | POST | `name`, `projectId` | New environment for stacks |
| `environment.one` | GET | `environmentId` | Environment details |
| `server.all` | GET | none | Servers Dokploy manages |
| `compose.search` | GET | none (`q`, `name`, `appName`, `projectId`, `environmentId`, `limit`, `offset`) | Find the dashboard's own service and existing Supabase stacks; look up a job's service before creating it |
| `compose.create` | POST | `name`, `environmentId` | Create a stack's compose service |
| `compose.one` | GET | `composeId` | Read a stack's service, variables, and status |
| `compose.update` | POST | `composeId` | Set the compose file and variables |
| `compose.deploy` | POST | `composeId` | First deployment |
| `compose.redeploy` | POST | `composeId` | Redeploy |
| `compose.stop`, `compose.start` | POST | `composeId` | Stop and start |
| `compose.delete` | POST | `composeId`, `deleteVolumes` | Remove a stack, keeping or destroying its volumes |
| `deployment.allByCompose` | GET | `composeId` | Poll deployments |
| `domain.create` | POST | `host` (with `composeId`, `serviceName`, `port`) | Stack and Studio domains |
| `domain.byComposeId` | GET | `composeId` | A service's domains |
| `domain.delete` | POST | `domainId` | Remove a domain |
| `user.get` | GET | none | The key's user |

## Connecting

An installation administrator connects the dashboard to Dokploy in the Dokploy section of the administrator page (`/dashboard/admin`), with Dokploy's URL and an API key. One Dokploy connection exists per installation.

- **Connect.** The server parses the URL with the same rules as a project's API URL, calls `settings.getDokployVersion` with the key, and stores the connection only when Dokploy accepts the key and reports a supported version. It stores the URL, the key encrypted with the credential encryption key (`SUPABASE_DASHBOARD_SECRET_KEY_FILE`, AES-256-GCM, bound to the URL so a stored key cannot be moved to another URL), the version, who connected it, and when. Without an encryption key nothing can be connected. A second connection is refused before any key is sent.
- **Replace the key.** The new key is checked against the stored URL first; a key Dokploy refuses leaves the stored one in place. The page then shows who replaced it and when, next to who connected it.
- **Remove.** Deletes the dashboard's record and its stored key, after a confirmation dialog. Nothing in Dokploy changes, and the key stays valid in Dokploy until it is revoked there. It works on a server without the encryption key.

The key never goes back to the browser. The page shows the URL, whether a key is stored (or stored under an encryption key this server does not have), the version Dokploy reported, and who connected or replaced it and when. Every server function behind the page refuses anyone who is not an installation administrator. `supabase-dashboard-server rotate-secret-key` reseals the Dokploy key with the project keys, and the startup warning about keys under a previous encryption key counts it.

Audit events, with target type `dokploy` and Dokploy's host name as the target (never the key or the full URL):

| Action | Recorded |
| --- | --- |
| `dokploy.connect` | Success, failure (Dokploy refused the key, was unreachable, or runs an unsupported version), or denied |
| `dokploy.key_replace` | Success, failure, or denied |
| `dokploy.disconnect` | Success or denied |
| `dokploy.view` | Denied only |

Denied attempts have no target, since nothing is read before the role check.

### The API key

A Dokploy key has the permissions of the Dokploy user who created it, in the organization it was created for. Whoever holds it can deploy any compose file on Dokploy's servers. The page recommends creating it as a Dokploy member made for the dashboard, so it can be revoked without touching anyone's own access.

Create the key without a rate limit. Dokploy's "Add API key" form leaves the rate limit off by default, but a key created through `user.createApiKey` without `rateLimitEnabled: false` gets better-auth's default of 10 requests a day, after which Dokploy answers 401 as if the key were invalid. The dashboard cannot tell the two apart, so its message mentions both.

The dashboard cannot show when the key in use expires. In v0.31.1, `user.get` returns every key of the key's user, with `expiresAt`, but no call identifies which of them made the request: the session Dokploy builds from a key carries no key ID, and better-auth's own key endpoints need a browser session. The expiry could be inferred only when the user has exactly one key.

### Destinations

The Dokploy URL is the only destination the connection adds, and it is enrolled by an administrator entering it. Nothing in Dokploy's answers adds another: the client builds every request URL from the stored URL, does not follow redirects, and checks each resolved address against the same address policy as project checks. Private addresses are allowed, such as Dokploy's address on a shared Docker network. Loopback is refused unless `SUPABASE_DASHBOARD_ALLOW_LOOPBACK_TARGETS=true`, which applies to project checks as well. The extra certificate authorities in `SUPABASE_DASHBOARD_EXTRA_CA_FILE` are trusted for Dokploy too.

## Test fixture

`tests/fixtures/dokploy` runs Dokploy for the provider tests. Dokploy needs Docker Swarm, and its installer turns the host's Docker into a swarm manager. The fixture avoids that by running Docker-in-Docker: a privileged `docker:28.5.0-dind` container holds the swarm, Dokploy's Postgres (`postgres:16`), and Dokploy itself, created by `setup.sh` with the service definitions of Dokploy's installer as of 2026-11-12. Dokploy's Traefik is not started yet, because nothing is deployed through it so far. `docker compose ... down -v` removes everything, including the inner volumes.

```sh
docker compose -f tests/fixtures/dokploy/docker-compose.yml up -d --wait
tests/fixtures/dokploy/setup.sh
SUPABASE_DASHBOARD_TEST_DOKPLOY_URL=http://127.0.0.1:54340 \
  cargo test -p supabase-dashboard-adapters --test dokploy_fixture
# The connect, replace, and remove test also needs the metadata database:
SUPABASE_DASHBOARD_TEST_DOKPLOY_URL=http://127.0.0.1:54340 \
SUPABASE_DASHBOARD_TEST_DATABASE_URL=postgres://... \
  cargo test -p supabase-dashboard-server dokploy
docker compose -f tests/fixtures/dokploy/docker-compose.yml down -v
```

`setup.sh` signs up the fixture's admin with the synthetic login in `fixture.env` (the first account becomes Dokploy's owner), creates an API key without a rate limit through `user.createApiKey`, and writes it to `tests/fixtures/dokploy/api-key`, which git ignores. Running it again reuses a key that still works. The first run pulls about 1 GB of images inside the container. Dokploy's UI and API listen on `127.0.0.1:54340`.
