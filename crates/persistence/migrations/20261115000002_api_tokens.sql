-- Dashboard API tokens. A token acts as its account, limited to read-only
-- scopes. Only a SHA-256 hash of each token is stored; the token itself is
-- shown once to the operator who created it.

CREATE TABLE api_tokens (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    -- SHA-256 of the token's 32 random bytes.
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    -- `sbd_` and the first 8 characters, to tell tokens apart. Not enough
    -- of the token to use it.
    display_prefix TEXT NOT NULL CHECK (display_prefix ~ '^sbd_[0-9a-f]{8}$'),
    scopes TEXT[] NOT NULL CHECK (
        cardinality(scopes) >= 1
        AND scopes <@ ARRAY['organizations:read', 'projects:read']::TEXT[]
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX api_tokens_token_hash_key ON api_tokens (token_hash);
CREATE INDEX api_tokens_account_idx ON api_tokens (account_id, created_at DESC);
