#!/bin/sh
# Fixture gateway entrypoint. Adapted from supabase/supabase
# docker/volumes/api/kong-entrypoint.sh (Apache-2.0); reduced to the legacy
# key substitution. The fixture keys are JWTs, which contain no `|`.
set -eu
sed -e "s|\$SUPABASE_ANON_KEY|${SUPABASE_ANON_KEY}|g" \
    -e "s|\$SUPABASE_SERVICE_KEY|${SUPABASE_SERVICE_KEY}|g" \
    /home/kong/temp.yml > "$KONG_DECLARATIVE_CONFIG"
exec /entrypoint.sh kong docker-start
