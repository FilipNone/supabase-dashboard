-- Access to a project's Studio through the dashboard (docs/adr/0002).
--
-- A handoff code moves a signed-in member from the dashboard host to the
-- project's Studio host once. A Studio session is the cookie on that host.
-- Both hang off the dashboard session that created them, so revoking or
-- expiring it ends Studio access. Only SHA-256 hashes of the random values
-- are stored.

CREATE TABLE studio_handoffs (
    code_hash BYTEA PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    -- A Studio path to land on, already validated by the application.
    return_path TEXT NOT NULL CHECK (char_length(return_path) BETWEEN 1 AND 2048),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX studio_handoffs_session_idx ON studio_handoffs (session_id);

CREATE TABLE studio_sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX studio_sessions_session_idx ON studio_sessions (session_id);
CREATE INDEX studio_sessions_project_idx ON studio_sessions (project_id);
