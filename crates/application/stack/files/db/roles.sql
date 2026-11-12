-- From supabase/supabase docker/volumes/db/roles.sql (Apache-2.0, see
-- LICENSE-APACHE): gives the service roles the stack's Postgres password.
\set pgpass `echo "$POSTGRES_PASSWORD"`

ALTER USER authenticator WITH PASSWORD :'pgpass';
ALTER USER pgbouncer WITH PASSWORD :'pgpass';
ALTER USER supabase_auth_admin WITH PASSWORD :'pgpass';
ALTER USER supabase_storage_admin WITH PASSWORD :'pgpass';
