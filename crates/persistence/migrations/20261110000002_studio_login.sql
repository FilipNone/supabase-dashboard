-- A third credential slot: the gateway's basic-auth login for Studio
-- (DASHBOARD_USERNAME and DASHBOARD_PASSWORD), encrypted like the API keys.
-- The dashboard adds it on the server when it forwards a member's requests
-- to the project's Studio; it is never sent to a browser.

ALTER TABLE project_credentials DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials ADD CONSTRAINT project_credentials_kind_check
    CHECK (kind IN ('anon_key', 'service_role_key', 'studio_login'));
