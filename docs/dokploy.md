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

## Test fixture

`tests/fixtures/dokploy` runs Dokploy for the provider tests. Dokploy needs Docker Swarm, and its installer turns the host's Docker into a swarm manager. The fixture avoids that by running Docker-in-Docker: a privileged `docker:28.5.0-dind` container holds the swarm, Dokploy's Postgres (`postgres:16`), and Dokploy itself, created by `setup.sh` with the service definitions of Dokploy's installer as of 2026-11-12. Dokploy's Traefik is not started yet, because nothing is deployed through it so far. `docker compose ... down -v` removes everything, including the inner volumes.

```sh
docker compose -f tests/fixtures/dokploy/docker-compose.yml up -d --wait
tests/fixtures/dokploy/setup.sh
SUPABASE_DASHBOARD_TEST_DOKPLOY_URL=http://127.0.0.1:54340 \
  cargo test -p supabase-dashboard-adapters --test dokploy_fixture
docker compose -f tests/fixtures/dokploy/docker-compose.yml down -v
```

`setup.sh` signs up the fixture's admin with the synthetic login in `fixture.env` (the first account becomes Dokploy's owner), creates an API key through `user.createApiKey`, and writes it to `tests/fixtures/dokploy/api-key`, which git ignores. Running it again reuses a key that still works. The first run pulls about 1 GB of images inside the container. Dokploy's UI and API listen on `127.0.0.1:54340`.
