-- The Dokploy targets an installation admin allowed each dashboard
-- organization for new stacks: an environment, and the server the stack
-- runs on (NULL for Dokploy's own server). An organization with no rows
-- may use only the dashboard's own environment.
--
-- The IDs belong to the connected Dokploy, so the rows go when the
-- connection is removed or replaced by one at another URL. The names are
-- kept for display while Dokploy cannot be reached.

CREATE TABLE dokploy_stack_targets (
    id UUID PRIMARY KEY,
    connection BOOLEAN NOT NULL DEFAULT TRUE CHECK (connection)
        REFERENCES dokploy_connection (singleton) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    project_id TEXT NOT NULL CHECK (project_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    project_name TEXT NOT NULL CHECK (char_length(project_name) <= 128),
    environment_id TEXT NOT NULL CHECK (environment_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    environment_name TEXT NOT NULL CHECK (char_length(environment_name) <= 128),
    server_id TEXT CHECK (server_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    server_name TEXT CHECK (char_length(server_name) <= 128),
    added_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((server_id IS NULL) = (server_name IS NULL))
);

-- One row per environment and server. PostgreSQL 14 has no
-- NULLS NOT DISTINCT, so Dokploy's own server gets its own index.
CREATE UNIQUE INDEX dokploy_stack_targets_remote
    ON dokploy_stack_targets (organization_id, environment_id, server_id)
    WHERE server_id IS NOT NULL;
CREATE UNIQUE INDEX dokploy_stack_targets_own
    ON dokploy_stack_targets (organization_id, environment_id)
    WHERE server_id IS NULL;
