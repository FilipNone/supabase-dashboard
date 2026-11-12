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
| `overview.services` | GET | none | Every service the key can see, with its type, project, environment, and server |
| `overview.domains` | GET | none | Every domain the key can see, with its host, whether it is enabled, whether it is a preview domain, and the service it routes to |

Both lists are read with a 4 MiB body bound and at most 10,000 entries. An entry that does not parse, a service type other than application or compose, an ID outside `[A-Za-z0-9_-]{1,64}`, and an empty or overlong host are skipped one at a time, so one odd entry does not hide the rest.

### Planned

These are the calls the M4 roadmap items need, with their required inputs in v0.31.1. None is called yet.

| Call | Method | Required input | Roadmap use |
| --- | --- | --- | --- |
| `project.all` | GET | none | Projects and environments the key can see |
| `project.one` | GET | `projectId` | One project's environments and services |
| `environment.create` | POST | `name`, `projectId` | New environment for stacks |
| `environment.one` | GET | `environmentId` | Environment details |
| `server.all` | GET | none | Servers Dokploy manages |
| `compose.search` | GET | none (`q`, `name`, `appName`, `projectId`, `environmentId`, `limit`, `offset`) | Find existing Supabase stacks; look up a job's service before creating it |
| `compose.move` | POST | `composeId`, `targetEnvironmentId` | Not planned for the dashboard; the browser check uses it to move a service and show the Moved state |
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

### Supplied by the deployment

The deployment can supply the connection instead, with `SUPABASE_DASHBOARD_DOKPLOY_URL` and `SUPABASE_DASHBOARD_DOKPLOY_API_KEY_FILE`, a file holding the key alone such as a Docker secret. Both are needed, and so is an encryption key; otherwise the server refuses to start. The file is read once at startup.

After starting, the server copies the connection into its stored one, in the background so an unreachable Dokploy does not delay startup:

- Nothing stored: the key is checked with Dokploy as on the page, then stored encrypted.
- The same URL stored: a different key is checked and replaces the stored one; the same key changes nothing and calls nobody. A connection an administrator made at that URL is taken over, and who connected it stays on record.
- Another URL, supplied by the deployment before: the new URL and key are checked and replace the connection. The dashboard's confirmed placement goes with it, since it belonged to the other Dokploy.
- Another URL that an administrator connected: nothing changes, and the server logs an error asking for that connection to be removed on the page. The next start applies the deployment's connection.

When Dokploy cannot be reached, or answers with a server error, the server tries again with growing pauses of up to five minutes. A refused key or an unsupported version is logged as an error and not retried.

While the deployment supplies the connection, the page shows it as managed by the server configuration and offers no way to replace or remove it, and the server refuses both. Changes the server makes this way are audited as `dokploy.connect` and `dokploy.key_replace` without an actor, and so are a refused key and an unsupported version; an unreachable Dokploy is not audited, since it is retried. When the deployment stops supplying a connection, the stored one stays and administrators can replace or remove it again.

The URL the deployment supplies is an enrolled destination: calls to exactly that URL may reach a loopback address, such as a Dokploy published on `127.0.0.1` of the same host, without `SUPABASE_DASHBOARD_ALLOW_LOOPBACK_TARGETS`. The other address rules still apply to it, and project checks and any URL an administrator enters keep the general policy.

### Where the dashboard runs

Once Dokploy is connected, the Dokploy section also shows which Dokploy service the dashboard itself runs as. New stacks will go into that service's project and environment by default, so the placement is chosen once by an installation administrator and then stored.

- **Detection.** Each time the section loads, the server reads `overview.services` and `overview.domains` and looks for enabled, non-preview domains whose host is the host of `SUPABASE_DASHBOARD_PUBLIC_URL` (compared without case or a trailing dot). A domain counts only when the key can also see the service it routes to. One match is offered with a "Confirm this service" button, and the full list stays one step away behind "Choose another service". With no match or several, the admin picks from every application and compose service the key can see, with the matches listed first. Without `SUPABASE_DASHBOARD_PUBLIC_URL` there is nothing to match, and the page says so.
- **Confirmation.** Nothing is used until an admin confirms a service. Confirming reads the services again and refuses one the key cannot see. The dashboard stores the service's type and ID, its project and environment IDs and names, who confirmed it, and when. "Forget this placement" deletes that record. Removing the Dokploy connection removes the placement with it; replacing the key does not.
- **Status.** A stored placement is checked against Dokploy's current lists and shown as Current, Domain differs (the service is where it was, but no longer has the public host as a domain), Moved (the service is now in another project or environment, with a button to confirm it there), or Not found (the key cannot see it any more). When Dokploy cannot be reached, the page says that instead and keeps the stored placement.
- **Startup.** After it starts, the server checks a stored placement once and logs a warning when it is anything but Current, for example `The service has moved in Dokploy: it is now in project "Infra", environment "staging". Confirm the new placement to use it.`

The key's Dokploy member needs access to the dashboard's own service and permission to read services and domains. With fewer rights, the dashboard's domain does not show and the page explains why.

Audit events for the placement have target type `dokploy_service` and the target `compose:<id>` or `application:<id>`:

| Action | Recorded |
| --- | --- |
| `dokploy.placement_confirm` | Success, failure (Dokploy was unreachable or did not show the service), or denied |
| `dokploy.placement_clear` | Success or denied |

Denied attempts are recorded with target type `dokploy` and no target, like the connection's.

### The API key

A Dokploy key has the permissions of the Dokploy user who created it, in the organization it was created for. Whoever holds it can deploy any compose file on Dokploy's servers. The page recommends creating it as a Dokploy member made for the dashboard, so it can be revoked without touching anyone's own access.

Create the key without a rate limit. Dokploy's "Add API key" form leaves the rate limit off by default, but a key created through `user.createApiKey` without `rateLimitEnabled: false` gets better-auth's default of 10 requests a day, after which Dokploy answers 401 as if the key were invalid. The dashboard cannot tell the two apart, so its message mentions both.

The dashboard cannot show when the key in use expires. In v0.31.1, `user.get` returns every key of the key's user, with `expiresAt`, but no call identifies which of them made the request: the session Dokploy builds from a key carries no key ID, and better-auth's own key endpoints need a browser session. The expiry could be inferred only when the user has exactly one key.

### Destinations

The Dokploy URL is the only destination the connection adds, and it is enrolled by an administrator entering it. Nothing in Dokploy's answers adds another: the client builds every request URL from the stored URL, does not follow redirects, and checks each resolved address against the same address policy as project checks. Private addresses are allowed, such as Dokploy's address on a shared Docker network. Loopback is refused unless `SUPABASE_DASHBOARD_ALLOW_LOOPBACK_TARGETS=true`, which applies to project checks as well, or the URL is the one the deployment supplies (see "Supplied by the deployment"). The extra certificate authorities in `SUPABASE_DASHBOARD_EXTRA_CA_FILE` are trusted for Dokploy too.

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
