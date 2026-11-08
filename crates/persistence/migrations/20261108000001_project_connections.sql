-- API keys the dashboard holds for a registered project, and the result of
-- the last service check.
--
-- Key values are encrypted by the application with AES-256-GCM under a key
-- supplied by the deployment; this database never sees the plaintext or the
-- encryption key. `key_id` names the encryption key a row was written with,
-- so rows written under another key can be reported instead of failing.
-- Unregistering a project deletes its rows here; nothing on the stack is
-- touched.

CREATE TABLE project_credentials (
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('anon_key', 'service_role_key')),
    key_id TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    -- The longest accepted key is 4096 bytes plus the 16-byte tag.
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 4112),
    updated_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, kind)
);

-- One row per project: the latest check only. History comes later with an
-- explicit retention policy.
CREATE TABLE project_health_reports (
    project_id UUID PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL,
    -- Serialized list of service checks. Holds statuses, versions, and
    -- timings only, never key values or raw error text.
    checks JSONB NOT NULL CHECK (jsonb_typeof(checks) = 'array')
);
