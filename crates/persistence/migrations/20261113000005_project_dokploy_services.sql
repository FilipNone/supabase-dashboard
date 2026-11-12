-- The Dokploy compose service behind a project the dashboard provisioned.
-- Registered projects have no row. Unregistering a project deletes its row
-- here; the service and its data stay in Dokploy.
CREATE TABLE project_dokploy_services (
    project_id UUID PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    compose_id TEXT NOT NULL UNIQUE CHECK (compose_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    -- Dokploy's name for the service on disk and in Docker.
    app_name TEXT NOT NULL CHECK (char_length(app_name) BETWEEN 1 AND 128),
    environment_id TEXT NOT NULL CHECK (environment_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    -- NULL for Dokploy's own server.
    server_id TEXT CHECK (server_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    -- The job that created it. Kept after the job row is gone.
    job_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
