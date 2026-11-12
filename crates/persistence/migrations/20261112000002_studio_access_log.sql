-- Optional record of requests members send through a project's Studio
-- host. Method, path without query, status, member, and time only: never
-- bodies, query values, or headers. The application deletes entries past
-- the configured retention.
CREATE TABLE studio_access_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    account_id UUID REFERENCES accounts (id) ON DELETE SET NULL,
    at TIMESTAMPTZ NOT NULL,
    method TEXT NOT NULL CHECK (char_length(method) BETWEEN 1 AND 16),
    path TEXT NOT NULL CHECK (octet_length(path) <= 512),
    status SMALLINT NOT NULL CHECK (status BETWEEN 100 AND 599)
);

CREATE INDEX studio_access_log_project_at ON studio_access_log (project_id, at DESC);
CREATE INDEX studio_access_log_at ON studio_access_log (at);
