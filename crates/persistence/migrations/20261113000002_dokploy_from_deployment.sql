-- A Dokploy connection the deployment supplies through
-- SUPABASE_DASHBOARD_DOKPLOY_URL and SUPABASE_DASHBOARD_DOKPLOY_API_KEY_FILE.
--
-- The server copies it into this row at startup, so the key is stored
-- encrypted like one an administrator entered. While `from_deployment` is
-- set, the administrator page cannot replace or remove the connection; the
-- server clears the flag when the deployment stops supplying one. The two
-- `*_by_deployment` flags say that the server, not an account, connected or
-- replaced the key, since `connected_by` and `key_replaced_by` are also NULL
-- once the account that made the change is deleted.

ALTER TABLE dokploy_connection
    ADD COLUMN from_deployment BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN connected_by_deployment BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN key_replaced_by_deployment BOOLEAN NOT NULL DEFAULT FALSE;
