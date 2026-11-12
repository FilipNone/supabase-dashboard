#!/bin/sh
# Starts Dokploy inside the fixture's Docker-in-Docker container, with the
# service definitions from Dokploy's installer and the pinned versions in
# fixture.env. Safe to run again: existing services are left alone.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$here/fixture.env"

inner() {
    docker compose -f "$here/docker-compose.yml" exec -T docker "$@"
}

if [ "$(inner docker info --format '{{.Swarm.LocalNodeState}}')" != active ]; then
    inner docker swarm init --advertise-addr 127.0.0.1
fi
inner docker network inspect dokploy-network >/dev/null 2>&1 ||
    inner docker network create --driver overlay --attachable dokploy-network
inner mkdir -p /etc/dokploy
inner chmod 777 /etc/dokploy

inner docker secret inspect dokploy_postgres_password >/dev/null 2>&1 ||
    printf '%s' "$DOKPLOY_POSTGRES_PASSWORD" | inner docker secret create dokploy_postgres_password -
inner docker secret inspect dokploy_auth_secret >/dev/null 2>&1 ||
    printf '%s' "$DOKPLOY_AUTH_SECRET" | inner docker secret create dokploy_auth_secret -

inner docker service inspect dokploy-postgres >/dev/null 2>&1 ||
    inner docker service create \
        --name dokploy-postgres \
        --constraint 'node.role==manager' \
        --network dokploy-network \
        --env POSTGRES_USER=dokploy \
        --env POSTGRES_DB=dokploy \
        --secret source=dokploy_postgres_password,target=/run/secrets/postgres_password \
        --env POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password \
        --mount type=volume,source=dokploy-postgres,target=/var/lib/postgresql/data \
        postgres:16

inner docker service inspect dokploy >/dev/null 2>&1 ||
    inner docker service create \
        --name dokploy \
        --replicas 1 \
        --network dokploy-network \
        --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
        --mount type=bind,source=/etc/dokploy,target=/etc/dokploy \
        --mount type=volume,source=dokploy,target=/root/.docker \
        --secret source=dokploy_postgres_password,target=/run/secrets/postgres_password \
        --secret source=dokploy_auth_secret,target=/run/secrets/dokploy_auth_secret \
        --publish published=3000,target=3000,mode=host \
        --update-parallelism 1 \
        --update-order stop-first \
        --constraint 'node.role == manager' \
        -e RELEASE_TAG=latest \
        -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password \
        -e BETTER_AUTH_SECRET_FILE=/run/secrets/dokploy_auth_secret \
        "dokploy/dokploy:$DOKPLOY_VERSION"

# Wait for Dokploy's API, then create the fixture's admin (the first
# account becomes the owner) and an API key for the tests. The key is
# written to `api-key` next to this script, which git ignores.
url=http://127.0.0.1:54340
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/api/health")" = 200 ]; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then
        echo "Dokploy did not answer at $url" >&2
        exit 1
    fi
    sleep 2
done

if [ -s "$here/api-key" ] &&
    [ "$(curl -s -o /dev/null -w '%{http_code}' -H "x-api-key: $(cat "$here/api-key")" \
        "$url/api/settings.getDokployVersion")" = 200 ]; then
    echo "Dokploy is ready at $url"
    exit 0
fi

jar=$(mktemp)
trap 'rm -f "$jar"' EXIT
credentials=$(printf '{"email":"%s","password":"%s","name":"Fixture","lastName":"Admin"}' \
    "$DOKPLOY_ADMIN_EMAIL" "$DOKPLOY_ADMIN_PASSWORD")
curl -sf -c "$jar" -H 'Content-Type: application/json' -H "Origin: $url" \
    -d "$credentials" "$url/api/auth/sign-up/email" >/dev/null ||
    curl -sf -c "$jar" -H 'Content-Type: application/json' -H "Origin: $url" \
        -d "$credentials" "$url/api/auth/sign-in/email" >/dev/null
organization=$(curl -sf -b "$jar" -H "Origin: $url" "$url/api/auth/organization/list" |
    python3 -I -c 'import json, sys; print(json.load(sys.stdin)[0]["id"])')
curl -sf -b "$jar" -H 'Content-Type: application/json' -H "Origin: $url" \
    -d "{\"json\":{\"name\":\"fixture\",\"metadata\":{\"organizationId\":\"$organization\"}}}" \
    "$url/api/trpc/user.createApiKey" |
    python3 -I -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["result"]["data"]["json"]["key"])' \
        >"$here/api-key"
echo "Dokploy is ready at $url"
