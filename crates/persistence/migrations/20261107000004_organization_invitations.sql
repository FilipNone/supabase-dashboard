-- Invitations to join a dashboard organization. Only the SHA-256 of each
-- invitation code is stored; the code itself is shown once to the inviter.

CREATE TABLE organization_invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- Normalized by the application (trimmed, lowercased), like accounts.email.
    email TEXT NOT NULL CHECK (email = lower(email) AND char_length(email) BETWEEN 3 AND 254),
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    invited_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- An invitation is closed by being accepted or withdrawn, never both,
    -- and is never reopened.
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

CREATE UNIQUE INDEX organization_invitations_token_hash_key
    ON organization_invitations (token_hash);

-- At most one open invitation per email in an organization. Inviting the
-- same address again withdraws the earlier invitation first.
CREATE UNIQUE INDEX organization_invitations_open_email_key
    ON organization_invitations (organization_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
