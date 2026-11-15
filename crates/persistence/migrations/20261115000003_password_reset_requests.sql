-- Password reset links sent by email. Only a SHA-256 hash of each code is
-- stored; the code itself is in the email. A link works once, for a short
-- time, and only while the account's password has not changed since it was
-- requested.

CREATE TABLE password_reset_requests (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    -- SHA-256 of the code's 32 random bytes.
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at),
    used_at TIMESTAMPTZ,
    -- Set when a newer request for the same account replaces this one.
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX password_reset_requests_token_hash_key
    ON password_reset_requests (token_hash);
CREATE INDEX password_reset_requests_account_idx
    ON password_reset_requests (account_id, created_at DESC);
