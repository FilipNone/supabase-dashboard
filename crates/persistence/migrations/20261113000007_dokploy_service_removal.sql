-- When the dashboard removed a provisioned project's service from Dokploy,
-- and whether its data volumes went with it. The row is kept so the
-- project shows what happened until it is unregistered.
ALTER TABLE project_dokploy_services
    ADD COLUMN removed_at TIMESTAMPTZ,
    ADD COLUMN volumes_deleted BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT project_dokploy_services_volumes_removed
        CHECK (NOT volumes_deleted OR removed_at IS NOT NULL);
