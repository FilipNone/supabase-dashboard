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
| `project.all` | GET | none | Every project and environment the key can see, for choosing where stacks go; the services nested in each environment are ignored |
| `server.all` | GET | none | Dokploy's remote servers; only active deploy servers are kept, and only their ID and name are read |
| `environment.create` | POST | `name`, `projectId` | Create an environment for stacks, sent once and never retried |
| `compose.search` | GET | `name`, `environmentId`, `limit` | Find a provisioning job's service by its exact name before creating it |
| `compose.search` | GET | `environmentId`, `limit: 100` | List the compose services in an allowed environment for adopting; each item has the ID, name, `appName`, status, and environment, never the compose file or variables |
| `compose.create` | POST | `name`, `appName`, `environmentId`, `serverId` (remote server only), `sourceType: raw`, `composeFile` | Create a stack's compose service |
| `compose.update` | POST | `composeId`, `sourceType: raw`, `composeFile`, `env`, `isolatedDeployment: true` | Set a stack's compose file and variables |
| `compose.update` | POST | `composeId`, `env` | Replace a stack's variables when its settings change; the fixture test checks that the compose file is kept |
| `mounts.listByServiceId` | GET | `serviceId`, `serviceType: compose` | A service's file mounts |
| `mounts.create` | POST | `type: file`, `serviceType: compose`, `serviceId`, `filePath`, `mountPath`, `content` | Write a file the compose file mounts |
| `mounts.update` | POST | `mountId`, `content` | Replace a mounted file |
| `compose.deploy` | POST | `composeId`, `title` | Queue a deployment |
| `deployment.allByCompose` | GET | `composeId` | Poll a service's deployments |
| `domain.create` | POST | `host`, `composeId`, `domainType: compose`, `serviceName`, `port`, `https`, `certificateType`, `path` | Route a host to one service of a stack |
| `compose.one` | GET | `composeId` | A provisioned stack's service for its project overview: name, status, project, environment, server, and deployments; 404 means Dokploy has no such service. Read separately for a stack's settings and for adopting, keeping only `env` and `composeFile` on the server |
| `domain.byComposeId` | GET | `composeId` | A service's domains, with host, service name, port, and HTTPS; read for adopting and for routing Studio hosts |
| `compose.stop` | POST | `composeId` | Stop a provisioned stack's containers; answers `true` once they are down, and sets the status to `idle` |
| `compose.start` | POST | `composeId` | Start them again; answers `true` |
| `compose.delete` | POST | `composeId`, `deleteVolumes` | Remove a provisioned stack's service, keeping (`false`) or deleting (`true`) its named volumes; answers with the deleted service, of which only `composeId` is read, and 404 once it is gone |
| `compose.redeploy` | POST | `composeId`, `title` | Queue a redeployment from the stored compose file and variables; answers `{"success":true,"message":"Redeployment queued","composeId":…}` |

Every list is read with a 4 MiB body bound and at most 10,000 entries. An entry that does not parse, a service type other than application or compose, an ID outside `[A-Za-z0-9_-]{1,64}`, and an empty or overlong host are skipped one at a time, so one odd entry does not hide the rest.

The compose calls are in `crates/adapters/src/dokploy/compose.rs`, used by the provisioning job and the project overview. What they rely on, checked on the fixture with Dokploy v0.31.1:

- Creating a service, a mount, a domain, or a deployment is not idempotent: each repeated request makes another one, and Dokploy has no idempotency key. These requests are sent once and never retried, and a job looks the object up first.
- Dokploy appends `-` and six random characters to the requested `appName`, so the name on disk is known only from the answer. A job finds its service again by its exact `name` in its environment. `compose.search` matches names as case-insensitive substrings and treats `%` and `_` as wildcards, so the dashboard's names use only lowercase letters, digits, and `-`, and the comparison is repeated on the dashboard's side. The search lists only services the key's member can access.
- `compose.one`, `compose.update`, `compose.delete`, and the mount calls answer with the service's variables, compose file, or file contents in plain text. The adapter reads only the IDs and names it needs from those answers, except when reading a stack's settings, where it reads the variables and compose file and keeps them on the server. Anyone with a Dokploy key that can see a stack's service can read its secrets this way.
- Dokploy writes the variables to a `.env` file next to the compose file, each value in double quotes, and escapes every `$` except at the start of `${`, so a value containing `${` would be expanded by Docker Compose. The adapter refuses such variables before sending them. The variables only fill `${…}` references in the compose file; a container receives nothing the compose file does not pass to it.
- A file mount is written to the server at once, at `/etc/dokploy/compose/<appName>/files/<filePath>`, and the compose file refers to it as `../files/<filePath>`. Dokploy requires `mountPath` even though compose services ignore it. Paths outside the files folder are refused by both Dokploy and the adapter.
- `compose.stop` waits for the containers to stop before it answers (about 10 seconds for a stack on the fixture; the client's 15-second timeout can cut a larger one short). Stopping a stopped service and starting a running one change nothing, so a stop or start whose answer was lost is sent again. `compose.redeploy` is like `compose.deploy`: it is not idempotent and returns no deployment ID. Both keep the named volumes.
- `compose.delete` also waits until it is done (about 10 seconds on the fixture) and removes the containers, the service's folder on the server with its mounted files, and its domains. Named volumes are called `<appName>_<volume>`; with `deleteVolumes: false` they stay on the server, with `true` they are deleted. Both were checked on the fixture with a deployed service that had a named volume. The stack template keeps all of its data in named volumes (`db-data`, `db-config`, `storage-data`, `snippets`), so removing keeps the data and destroying deletes it.
- `compose.deploy` queues the deployment and returns no ID. Its row in `deployment.allByCompose` appears only once a worker starts it (status `running`, then `done`, `error`, or `cancelled`), and deployments run one at a time. The adapter therefore sends a title unique to the job and finds the deployment by it. `errorMessage` stayed empty on failed compose deployments; the reason is only in the deployment log.
- Domains become proxy labels when Dokploy deploys, so a domain added or removed after a deployment takes effect at the next one. `domain.create` answers every error with 400, including an unknown service, and checks neither `serviceName` nor the certificate type, so the adapter always sends both.
- Dokploy answers 401 for a server ID the key may not use, not only for a refused key. The adapter reports both as a refused key; the job checks the target against `server.all` first.
- With `isolatedDeployment`, Dokploy puts the stack's services on their own network named after the `appName`. `compose.delete` leaves that network behind.

### Planned

These are the calls the M4 roadmap items need, with their required inputs in v0.31.1. None is called yet.

| Call | Method | Required input | Roadmap use |
| --- | --- | --- | --- |
| `project.one` | GET | `projectId` | One project's environments and services |
| `environment.one` | GET | `environmentId` | Environment details |
| `compose.move` | POST | `composeId`, `targetEnvironmentId` | Not planned for the dashboard; the browser check uses it to move a service and show the Moved state |
| `domain.delete` | POST | `domainId` | Remove a domain |
| `user.get` | GET | none | The key's user |

## The provisioned stack

The stack the dashboard provisions is pinned in `crates/application/stack`: a compose file adapted from upstream's `docker/docker-compose.yml` and the files it mounts, built into the server by `crates/application/src/stack_template.rs`. Image tags are the ones the Supabase fixture runs against. Compared with upstream:

- No service publishes a port or sets a container name. Dokploy routes the stack's domain to the Envoy gateway on port 8000, and two stacks can run on one server.
- Postgres data, Postgres's custom config, Storage files, and Studio's saved snippets live in named volumes, which Docker prefixes with the service's `appName`.
- Kong, the logs pipeline (vector and analytics), the pooler, and image transformations are left out, so the database is reached only from inside the stack and Studio's log pages are off.
- Only the legacy anon and service role keys are set up. Upstream leaves Envoy's asymmetric key variables empty in that mode, which turns two RBAC rules (Realtime and GraphQL) into a match on an empty `apikey` header; the pinned stack sets them to the legacy keys instead, so those rules match only real keys and sb_ key translation stays off.
- Sign-ups are closed and new users are confirmed without an email, because a new stack has no mail server. Users are added from Studio until the stack's Auth settings change.

The variables are `POSTGRES_PASSWORD`, `JWT_SECRET`, `ANON_KEY`, `SERVICE_ROLE_KEY`, `DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD`, `REALTIME_DB_ENC_KEY`, `SECRET_KEY_BASE`, `PG_META_CRYPTO_KEY`, `SUPABASE_PUBLIC_URL`, and `SITE_URL`. Unit tests check that the compose file reads exactly these, that every mounted file is shipped and every shipped file mounted, that no service has a port or container name, and that the upstream files are byte for byte the fixture's copies. An opt-in fixture test deploys the stack through Dokploy; on 2026-11-13 every service came up healthy, and from inside the stack's network the gateway answered Auth's health check with the anon key, REST and Storage with the service role key, and Studio with the login, and refused requests without a key, as the Supabase fixture's Envoy does.

### The provisioning job

`crates/application/src/provisioning` holds the job that creates stacks. The server runs it in its own process, and a job left by a stopped server resumes once its lease runs out. An owner or admin starts one with **Create a new stack** on the organization's Projects page (`/dashboard/new/<organization>/stack`), picking a name, a host, and one of the organization's targets, and choosing whether the stack is served over HTTPS (checked by default; the form warns that without it keys travel in plain text). When Dokploy is not connected, no target is allowed, or the default target cannot be read, the page says so and points to an installation administrator instead of showing the form. The form also says that the host's DNS must point at the Dokploy server, and that Dokploy keeps the stack's variables, so anyone with access to the service in Dokploy can read its secrets. The server checks the role, the host (a lowercase name of two or more labels, not an IP address), and the target, generates the stack's secrets, and queues a job with the secrets encrypted apart from its data. The job then runs these steps, saving after each:

1. Check that the account that asked may still register projects in the organization, and that the target is still allowed.
2. Look up the compose service by its name, `sd-` and the job ID, and create it only if there is none.
3. Set the compose file and the variables.
4. Create or update the file mounts.
5. Add the host as a domain on the Envoy service, port 8000, unless it is there.
6. Start a deployment titled `supabase-dashboard provision <job ID>`, unless one with that title exists.
7. Poll the deployment until it is done, failed, or cancelled.
8. Check the role again, then register the project with its anon key, service role key, Studio login, and Dokploy service in one transaction.
9. Check Auth at the public URL with the anon key, for about five minutes. If it does not answer, the job still succeeds and says to check the host's DNS.

When Dokploy does not answer, the step runs again after 30 seconds, up to ten times in a row. A deployment request whose answer was lost is not sent again; the job waits for its title to appear. Any other refusal fails the job, and what it made stays in Dokploy, with the job's secrets kept.

After queuing, the browser goes to the job's page (`/dashboard/org/<organization>/provisioning/<job>`), which any member of the organization can open. It shows the name, the address, the state, each step above as done, in progress, pending, failed, or not run, the job's message, and a link to the project once it is registered. While the job is unfinished the page reloads it every five seconds, and stops when it finishes or the job turns out to be missing or not allowed; a failed reload is tried again. The Projects page lists the organization's 20 latest jobs with their state. None of these show the job's saved data or secrets.

Tests with a fake Dokploy cover a full run, lost answers to the create and deploy requests, a failed deployment, a stack that never answers, and an account that loses its role while the job waits.

### The service on the project overview

A provisioned project's overview has a **Dokploy service** section. Each time the page loads, the server reads the service with `compose.one`, by the `composeId` the job recorded, and shows:

- the service name and its status in Dokploy (not deployed, deploying, deployed, or last deployment failed);
- the five newest deployments, with their title, status, start and finish times in UTC, and whether this dashboard started them or someone started them in Dokploy (the dashboard's deployment titles start with `supabase-dashboard `);
- a notice when the service is in another environment or on another server than the job created it in, which means it was moved in Dokploy;
- for owners and admins, who choose where stacks go: the Dokploy project, environment, server, the service's name on the server, and a link to the service's page in Dokploy (`/dashboard/project/<project>/environment/<environment>/services/compose/<compose>`, checked on v0.31.1). The link is left out when the dashboard reaches Dokploy at a single-label host such as `http://dokploy:3000`, which a browser cannot open.

When Dokploy has no service with the recorded ID, the section says it was deleted or moved out of the key's reach, and gives owners and admins the name the job gave it. When Dokploy does not answer or refuses the key, the section says so and points to the health check, which asks the stack directly. When Dokploy is no longer connected, it says that. The section is left out for registered projects. Nothing is changed in Dokploy or in the dashboard by reading it: the dashboard shows what changed instead of putting it back. Variable edits made in Dokploy are not detected yet.

### Stop, start, and redeploy

Owners and admins (the `StackOperate` permission) see **Stop**, **Start**, and **Redeploy** buttons in the section. Stopping asks for a confirmation naming the stack, because its API, Auth, Storage, and Studio stop answering until it is started again; the server refuses an unconfirmed stop after checking the role, and the checkbox is cleared after each request. Each button queues a `stack_action` job and records `stack.stop`, `stack.start`, or `stack.redeploy` in the audit log; an attempt the role does not allow is recorded as denied. A project has at most one unfinished action, enforced by a unique index, so a second request while one runs is refused and recorded as a failure. The buttons stay focusable while an action runs (`aria-disabled`), and a live region announces the action's progress and outcome. A service that Dokploy reports as not deployed after a stop the dashboard ran shows as Stopped. Developers and viewers see the last action and its outcome but no buttons. Only projects the dashboard provisioned can be operated.

The job runs these steps:

1. `check`: the account that asked is still active and may still operate the project, and the project still has the Dokploy service the job was queued for.
2. `act`: reads the service with `compose.one` and fails if Dokploy no longer has it. Then it calls `compose.stop` or `compose.start`, sent again if Dokploy did not answer, or queues a redeployment titled `supabase-dashboard redeploy <job ID>`. Before a redeployment it looks for that title, and it records when it asked before asking, so a redeployment whose answer was lost is never asked for twice.
3. `wait`: for a redeployment, polls the deployments until the titled one finishes, fails, or is cancelled, for at most 30 minutes.

While an action runs, the section asks the server again every four seconds. None of these actions removes the service, its volumes, or the project.

### Remove and destroy

Below the deployments, a **Remove the stack** area offers two separate actions, each confirmed by typing the project's name, which the server compares again:

- **Remove from Dokploy** (`StackRemove`: owners and admins) sends `compose.delete` with `deleteVolumes: false`. The database, stored files, and Studio snippets stay on the server in the Docker volumes.
- **Destroy stack and data** (`StackDestroy`: owners only) sends `deleteVolumes: true`, which deletes those volumes. It cannot be undone.

Both are `stack_action` jobs, audited as `stack.remove` and `stack.destroy`, and share the one-unfinished-action rule. After `check`, the job reads the service; if Dokploy no longer has it, the job fails and changes nothing. Otherwise it saves the time it asks before asking, then in `remove` reads the service again and sends the delete only while Dokploy still lists it. If the answer is lost, `confirm_removed` polls `compose.one` until the service is gone, for at most 30 minutes, and never asks again. The removal is then recorded on the project (`removed_at`, and `volumes_deleted` for destroy). For the moment between Dokploy deleting the service and the job recording it, the section says the service is being removed and keeps following the job rather than reporting a missing service.

### Stack settings

Owners and admins see a **Stack settings** section on a provisioned project's overview. It lists the variables the dashboard may change (`STACK_SETTINGS` in `crates/domain/src/stack_settings.rs`): the site URL, additional redirect URLs, whether sign-ups are disabled, automatic email confirmation, anonymous sign-ins, the access token lifetime, and the schemas the REST API serves. None holds a secret. The pinned compose file reads each as `${NAME:-default}` with the value earlier stacks had built in, so a stack without the variable behaves as before. The access token lifetime reaches Auth only; the database's own `JWT_EXP`, used when it is first initialized, stays fixed, so changing it never restarts the database.

The section reads the variables and compose file with `compose.one` each time the page loads. A setting whose variable the compose file does not read (stacks created before this) or whose value is set more than once, quoted with escapes, or uses `$` is shown but cannot be changed. Values are checked on the server and are written unquoted, without spaces, quotes, `$`, `#`, or `\`. The dashboard has no connection to the stack's database, so it does not check that the exposed schemas exist. PostgREST does not start with a schema that does not exist: Docker Compose marks `rest` unhealthy after its health check gives up, about 100 seconds, and the redeployment fails with the REST API down until the list is fixed. The field's help and the review say so.

"Review changes" lists the variables that would change and the compose services Docker Compose recreates; values are not repeated. The review also carries a digest of every setting's state and value as the server read them. "Apply and redeploy" sends the values with that digest; the server reads the service again and refuses, asking for a new review, if any setting changed since, then queues a `stack_action` job audited as `stack.configure`. The job saves the variables' previous values, never secrets. After `check` it runs:

1. `update`: reads the variables. If every changed variable still has its previous value, the job sets them and sends the whole variable text back with `compose.update` (only `composeId` and `env`). Every other line is kept as it was. If they already have the new values, an earlier answer was lost and nothing is sent. Anything else means they were edited in Dokploy meanwhile: the job fails, naming them, and writes nothing.
2. `act` and `wait`: a redeployment, as for Redeploy.

In the browser, changing a field withdraws the review, and the section reads the settings again only when the job finishes, so focus stays on the Apply button while it runs. A refused apply also withdraws the review and reads the settings again, so a second review starts from what Dokploy has now rather than from the values loaded with the page. Each time the settings are read again the form is reset to them, discarding anything typed meanwhile, and focus moves to the section's heading if it was on the removed Apply button. A locked setting shows no value, because the one Dokploy holds may not be the one in effect.

### Variables edited in Dokploy

The dashboard keeps a record of the variables it wrote to each provisioned service: the provisioning job records every variable it set when it registers the project, and a settings job updates the entries for the variables it wrote. The record holds a SHA-256 digest of each variable's value by name, never the value, and is stored in `project_dokploy_env_records`, sealed with the credential key and bound to the project. `rotate-secret-key` reseals it with the other stored keys.

When the Stack settings section loads, the server compares the variables Dokploy has with the record and lists, by name only, the variables changed, added, or removed in Dokploy since. The dashboard keeps such edits and does not write them back. The section says so when a stack has no record (stacks provisioned before the record existed) or when the record is sealed under a key the server does not have. A settings job only refreshes the entries for the variables it wrote, so an edit to another variable stays listed.

Owners and admins can accept the listed edits with "Accept these edits". The server reads the variables from Dokploy again and replaces the record with a digest of each one as Dokploy has it now, so the edits stop being listed until a variable is edited again. Nothing is written to Dokploy and the stack is not redeployed. The page sends back the names it listed (never a value or digest), and the server refuses when its own comparison lists something else, so an edit made in Dokploy after the page was read is never accepted unseen. Accepting is also refused while an action on the stack runs, and when another accept, a settings job, or a key rotation replaced the record meanwhile. For a stack with no record, or with one sealed under a key the server does not have, the same button records the current variables with this server's key. An accepted change is audited as `stack.variables_accept` on the project, and so is a refusal for a member without the role.

A removed project stays registered. Its section says when the service was removed and whether the volumes went with it; owners and admins get the volumes' name prefix to delete them on the server later. No further action can be asked for, and unregistering under Settings stays a separate step.

The job gives each service the description `Supabase stack <name>, project <project ID> in supabase-dashboard`, so the service in Dokploy points to its dashboard project.

### Adopting a stack from Dokploy

Owners and admins can register a Supabase stack that already runs in Dokploy, for example one made from Dokploy's Supabase template, with "Adopt from Dokploy" on the organization page (`/dashboard/new/:org_id/adopt`). Adopting writes nothing to Dokploy.

The page lists the compose services in the Dokploy environments an installation administrator allowed for the organization on the administrator page, read with `compose.search` by environment, at most 200 in all, without the services a project already runs as. The default target is shared by every organization without targets of its own, so an organization with no allowed environment gets nothing listed. Allowing an environment for an organization therefore also lets its owners and admins adopt the unregistered Supabase services in it. Listing reads no compose file or variables.

Choosing a service reads it with `compose.one`. A service outside the allowed environments, one a project already runs as, and an unknown ID get the same refusal, before the server reads the compose file or variables. The preview then shows:

- whether it runs Supabase: its compose file needs `image:` lines for `supabase/studio` and for `supabase/gotrue` or `supabase/auth`, with any registry and tag;
- the URLs of its Dokploy domains routed to the API gateway (a service named `kong`, `envoy`, `api-gw`, or `supabase-kong`, or port 8000), read with `domain.byComposeId`; a host the dashboard would not provision, such as an IP address, is left out. One of them becomes the project's API URL;
- for `ANON_KEY`, `SERVICE_ROLE_KEY`, and `DASHBOARD_USERNAME` with `DASHBOARD_PASSWORD`, whether each is set and passes the checks the setup page applies, by name only. A JWT signed for the wrong role is refused.

"Adopt stack" sends the name, the chosen URL, and whether to copy the keys. The server reads the service again, repeats every check, and refuses a URL that is not one of the offered ones. The keys and the Studio login are copied into the dashboard's sealed credentials only when that box is ticked; otherwise they can be added later on the project's setup page. The variables record described above is always written, so later edits in Dokploy are listed under Stack settings. The project is registered with the service's `composeId` and no provisioning job (`adopted_at` is set instead), and gets the same overview section, actions, and settings as a provisioned stack. Adopting is audited as `project.adopt`, copying keys as `project.adopt_keys`, and a refusal for a member without the role as a denied `project.adopt`.

Stack settings check the adopted service's own compose file, so a setting whose variable that file does not read is locked, as for stacks created before settings existed. A setting whose variable it reads but which is not set is shown with the pinned compose file's default, which may not be the one the adopted file uses.

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

### Dokploy's internal address

When the dashboard runs as a Dokploy service attached to `dokploy-network`, Dokploy's API answers inside that network at `http://dokploy:3000`. This was checked against the fixture's Dokploy v0.31.1: `dokploy-network` is an attachable overlay network, and a container on it got `"v0.31.1"` from `settings.getDokployVersion` with the key. The address is private, so the address policy allows it without extra settings. The page marks it as plain HTTP: the key crosses Dokploy's overlay network unencrypted, since Docker encrypts overlay traffic only for networks created with the `encrypted` option. The connect form mentions this address; the dashboard does not try it on its own, because it contacts only URLs an administrator or the deployment gave it.

Dokploy's documentation describes compose services without "isolated deployment" as sharing `dokploy-network`; with isolated deployment, a service gets its own network, so use Dokploy's public URL or attach the dashboard to `dokploy-network` as well.

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

### Studio hosts on Dokploy

When the dashboard runs as a Dokploy service, the Studio hosts under `SUPABASE_DASHBOARD_STUDIO_DOMAIN` must reach it too. The dashboard does not set this up; it is a one-time step for whoever runs Dokploy.

Dokploy cannot do it with a domain. In v0.31.1, `domain.create` refuses a wildcard host such as `*.studio.example.com` ("Invalid domain name. Use only letters, numbers, hyphens and dots"), which was checked against the fixture on 2026-11-13. A domain for each project would work, but a compose service's domains become Traefik labels only when it is deployed, so every new project would mean redeploying the dashboard itself. The dashboard also would need a Dokploy key that may change its own service.

Instead, add a file under `dynamic/` in Traefik's configuration, which Dokploy can edit on its Traefik file system page (or `/etc/dokploy/traefik/dynamic/` on the Dokploy server). Traefik reads it without a restart. Studio hosts are the project ID in hex, 32 characters, so the rule can be exact:

```yaml
http:
  routers:
    supabase-dashboard-studio:
      rule: "HostRegexp(`^[0-9a-f]{32}\\.studio\\.example\\.com$`)"
      entryPoints: [websecure]
      service: <the dashboard's Traefik service>@docker
      tls: {}
```

The service name is the one in the `traefik.http.services.<name>` label Dokploy writes for the dashboard's own domain; the compose file Dokploy converts for the service (`compose.getConvertedCompose`) shows it. Routing to that service keeps the container's address out of the file.

Traefik cannot obtain a certificate for every name a regular expression matches, so HTTPS needs a wildcard certificate for `*.studio.example.com`: either uploaded under Certificates in Dokploy, or obtained by a certificate resolver that uses the DNS challenge, configured in Dokploy's Traefik settings with the DNS provider's credentials. The tls block then names that resolver and the domain.

This has not been tried end to end: the Dokploy fixture runs no Traefik. Doing it once, with a real wildcard certificate, is open in the roadmap.

### Where stacks go

A new stack goes into a Dokploy environment, on Dokploy's own server or on one of its remote servers. Dashboard organizations and Dokploy organizations are separate, so an installation administrator chooses in the Dokploy section which of these targets each dashboard organization may use. Creating stacks is not built yet; the next roadmap item uses these targets.

- **Default.** An organization with no targets of its own may use only the dashboard's own environment, on the server the dashboard's service runs on. That default exists only while the confirmed placement is Current or Domain differs. With no placement confirmed, or one that has moved or disappeared, there is no default, and an organization without targets of its own cannot create stacks.
- **Allowing a target.** The admin picks an organization, an environment the key can see, and a server: Dokploy's own server or an active deploy server from `server.all`. The server reads `project.all` and `server.all` again and refuses an environment or server the key cannot see, then stores the environment and server IDs with their names. An organization may have up to 50 targets. When the key's member may not list servers (Dokploy answers 401 or 403 to `server.all` after accepting the key for `project.all`), only Dokploy's own server can be chosen.
- **Status.** The page compares each stored target with Dokploy's lists and shows it as Available, Environment not found, Server not found, or Not checked (when the key may not list servers, or Dokploy cannot be reached).
- **Removing a target** changes nothing in Dokploy. An organization whose last target is removed falls back to the default.
- **Creating an environment.** The admin can create an empty environment in a project the key can see. Dokploy accepts a name that is already taken, so the dashboard refuses a name the project already has (compared without case) before calling `environment.create`. Names are 1 to 64 letters, digits, spaces, `.`, `_`, and `-`, starting with a letter or digit. The request is sent once; when Dokploy does not answer, the page says the environment may or may not exist and asks the admin to reload before trying again.

The stored targets belong to the connected Dokploy: removing the connection, or replacing a deployment-supplied connection with one at another URL, removes them. Replacing the key keeps them. Deleting an organization removes its targets.

Audit events:

| Action | Target | Recorded |
| --- | --- | --- |
| `dokploy.target_allow` | `organization`, the organization's ID | Success, failure (Dokploy was unreachable or did not show the environment or server, the target was already allowed, or the limit was reached), or denied |
| `dokploy.target_remove` | `organization`, the organization's ID | Success or denied |
| `dokploy.environment_create` | `dokploy_project`, `<project ID>/<environment ID>` on success, the project ID otherwise | Success, failure, or denied |

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
# Deploy the pinned Supabase stack (pulls about ten images; opt-in):
SUPABASE_DASHBOARD_TEST_DOKPLOY_URL=http://127.0.0.1:54340 \
  cargo test -p supabase-dashboard-adapters --test dokploy_fixture -- --ignored
docker compose -f tests/fixtures/dokploy/docker-compose.yml down -v
```

The stack test deletes the stack and its volumes afterwards unless `SUPABASE_DASHBOARD_TEST_KEEP_STACK` is set. Dokploy leaves the stack's network behind either way.

`setup.sh` signs up the fixture's admin with the synthetic login in `fixture.env` (the first account becomes Dokploy's owner), creates an API key without a rate limit through `user.createApiKey`, and writes it to `tests/fixtures/dokploy/api-key`, which git ignores. Running it again reuses a key that still works. The first run pulls about 1 GB of images inside the container. Dokploy's UI and API listen on `127.0.0.1:54340`.
