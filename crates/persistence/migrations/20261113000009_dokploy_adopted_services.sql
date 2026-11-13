-- A project can also run as a Dokploy compose service the dashboard did
-- not create but adopted: one that already ran a Supabase stack, such as
-- one made from Dokploy's template. An adopted service has no job.
ALTER TABLE project_dokploy_services
    ALTER COLUMN job_id DROP NOT NULL,
    ADD COLUMN adopted_at TIMESTAMPTZ,
    ADD CONSTRAINT project_dokploy_services_origin
        CHECK ((job_id IS NULL) = (adopted_at IS NOT NULL));
