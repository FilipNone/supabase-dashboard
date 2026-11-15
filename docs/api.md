# Dashboard API

The dashboard has a small read-only JSON API under `/api/v1/` for scripts and monitoring. It answers only to dashboard API tokens. A browser session cookie does not work there, and a token does not work on the dashboard's pages or on any other path.

## Tokens

Each operator manages their own tokens under Account, API tokens (`/dashboard/account/tokens`).

- A token is `sbd_` followed by 64 lowercase hex characters (256 random bits). It is shown once, right after it is created. The dashboard stores only a SHA-256 hash of it and the first 8 characters after `sbd_`, which the token list shows to tell tokens apart.
- Every token has a name (1 to 64 characters, not unique) and expires after 7, 30, 90, or 365 days. There are no tokens that never expire.
- An account can hold at most 25 tokens that are neither revoked nor expired. Revoked and expired tokens stay listed for 30 days after they stop working and are deleted the next time the account creates a token.
- Revoking a token takes effect on the next request. Revocation cannot be undone.
- A token stops working when its account is disabled. Resetting an account's password with `reset-password` revokes all of its tokens.
- Creating and revoking a token are recorded in the account's audit log as `api_token.create` and `api_token.revoke`, with the token's ID as the target. Requests with a bad token are refused without an audit event, and there is no rate limit on them yet.

## Scopes

A token acts as the account that created it, with that account's roles at the time of each request, limited to the scopes ticked when it was created. Removing the account from an organization removes the token's access to it as well.

| Scope | Allows |
| --- | --- |
| `organizations:read` | `GET /api/v1/organizations` |
| `projects:read` | `GET /api/v1/organizations/{org_id}/projects` and `GET /api/v1/projects/{project_id}` |

Both scopes only read. No token can change anything, open a project's Studio, or read a project's API keys or Studio credentials.

## Requests

Send the token in the `Authorization` header:

```sh
curl -H "Authorization: Bearer sbd_..." https://dashboard.example.test/api/v1/organizations
```

Successful responses are JSON with `Cache-Control: no-store`. Timestamps are RFC 3339 in UTC.

### `GET /api/v1/organizations`

The organizations the account belongs to, with its role in each (`owner`, `admin`, `developer`, or `viewer`). At most 100, the most an account can join.

```json
{"organizations": [{"id": "…", "name": "Shop", "role": "owner"}]}
```

### `GET /api/v1/organizations/{org_id}/projects`

The organization's projects, at most 100 (the most an organization can hold).

```json
{"projects": [{
  "id": "…",
  "organization_id": "…",
  "name": "Storefront",
  "api_url": "https://shop.example.test",
  "created_at": "2026-11-15T10:51:00Z",
  "role": "owner",
  "last_check": {
    "checked_at": "2026-11-15T10:45:00Z",
    "stale": false,
    "failing": ["realtime"],
    "not_checked": []
  }
}]}
```

`last_check` is the project's last saved health check, or `null` if it has never been checked. `stale` is true when that check is more than a day old. `failing` and `not_checked` name services: `auth`, `rest`, `storage`, `realtime`, `functions`, `studio`. The API does not run a new check.

### `GET /api/v1/projects/{project_id}`

One project, in the same shape, as `{"project": {...}}`.

## Errors

Errors use the dashboard's JSON envelope, `{"error": {"code": "...", "message": "..."}}`.

| Status | Code | When |
| --- | --- | --- |
| 401 | `invalid_token` | No `Authorization: Bearer` header, or a token that is malformed, unknown, revoked, expired, or belongs to a disabled account. All of these get the same answer, with `WWW-Authenticate: Bearer realm="supabase-dashboard"`. |
| 403 | `insufficient_scope` | The token lacks the scope the endpoint needs. `WWW-Authenticate` names it. |
| 403 | `forbidden` | The account's role does not allow the read. |
| 404 | `not_found` | Unknown path, an ID that is not a UUID, or an organization or project the account does not belong to. |
| 503 | `unavailable` | The metadata database did not answer. The cause goes to the server log only. |

## Logging

The `Authorization` header is marked sensitive and is not logged. Request logs record method, path, and request ID, as for every other request.
