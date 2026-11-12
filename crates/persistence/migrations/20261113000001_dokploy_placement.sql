-- Where the dashboard itself runs in Dokploy, as an installation admin
-- confirmed it: the service, and the project and environment it was in at
-- the time. At most one row, and only while Dokploy is connected:
-- removing the connection removes the placement with it.
--
-- The names are kept for display while Dokploy cannot be reached; the IDs
-- are what later reads compare against Dokploy.

CREATE TABLE dokploy_placement (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton)
        REFERENCES dokploy_connection (singleton) ON DELETE CASCADE,
    service_kind TEXT NOT NULL CHECK (service_kind IN ('application', 'compose')),
    service_id TEXT NOT NULL CHECK (service_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    service_name TEXT NOT NULL CHECK (char_length(service_name) <= 128),
    project_id TEXT NOT NULL CHECK (project_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    project_name TEXT NOT NULL CHECK (char_length(project_name) <= 128),
    environment_id TEXT NOT NULL CHECK (environment_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    environment_name TEXT NOT NULL CHECK (char_length(environment_name) <= 128),
    confirmed_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
