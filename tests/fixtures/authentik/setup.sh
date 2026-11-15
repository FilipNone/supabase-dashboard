#!/bin/sh
# Starts the disposable Authentik and applies the dashboard's client and the
# synthetic operator from blueprints/dashboard.yaml. Safe to run again.
#
# Then run the dashboard with:
#   SUPABASE_DASHBOARD_ENV=development
#   SUPABASE_DASHBOARD_PUBLIC_URL=http://dash.localhost:3000
#   SUPABASE_DASHBOARD_OIDC_ISSUER_URL=http://localhost:54390/application/o/supabase-dashboard/
#   SUPABASE_DASHBOARD_OIDC_CLIENT_ID=supabase-dashboard-fixture
#   SUPABASE_DASHBOARD_OIDC_CLIENT_SECRET=fixture-only-client-secret
#   SUPABASE_DASHBOARD_OIDC_NAME=Authentik
# and sign in at Authentik as `operator` / `fixture-only-operator-password`.
#
# Remove it with: docker compose -f tests/fixtures/authentik/docker-compose.yml down
set -eu

here=$(cd "$(dirname "$0")" && pwd)
compose() {
    docker compose -f "$here/docker-compose.yml" "$@"
}

compose up -d --wait --wait-timeout 300
# The default flows and certificate come from Authentik's own blueprints,
# which the worker applies on startup; retry until they exist.
tries=0
until compose exec -T worker ak apply_blueprint /blueprints/custom/dashboard.yaml >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -ge 60 ]; then
        echo "the dashboard blueprint did not apply" >&2
        compose exec -T worker ak apply_blueprint /blueprints/custom/dashboard.yaml >&2 || true
        exit 1
    fi
    sleep 5
done
# Discovery answers once the provider and application exist.
until curl -fsS http://localhost:54390/application/o/supabase-dashboard/.well-known/openid-configuration >/dev/null; do
    sleep 2
done
echo "Authentik is ready at http://localhost:54390"
