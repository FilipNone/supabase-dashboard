-- What the dashboard last wrote to a provisioned project's Dokploy
-- variables: a digest of each variable's value, by name, sealed with the
-- credential key and bound to the project. Comparing it with the variables
-- Dokploy has shows which ones were edited in Dokploy. Stacks provisioned
-- before this table existed have no row.
CREATE TABLE project_dokploy_env_records (
    project_id UUID PRIMARY KEY
        REFERENCES project_dokploy_services (project_id) ON DELETE CASCADE,
    key_id TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 16400),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
