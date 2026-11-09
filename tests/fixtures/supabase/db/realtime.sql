-- Schema for Realtime's own tables. From supabase/supabase
-- docker/volumes/db/realtime.sql (Apache-2.0, see LICENSE-APACHE); this file
-- stays under Apache-2.0.
\set pguser `echo "$POSTGRES_USER"`

create schema if not exists _realtime;
alter schema _realtime owner to :pguser;
