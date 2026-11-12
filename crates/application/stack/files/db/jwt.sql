-- Adapted from supabase/supabase docker/volumes/db/jwt.sql (Apache-2.0).
\set jwt_exp `echo "$JWT_EXP"`

ALTER DATABASE postgres SET "app.settings.jwt_exp" TO :'jwt_exp';
