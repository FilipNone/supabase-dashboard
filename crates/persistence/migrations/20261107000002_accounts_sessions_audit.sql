-- Dashboard operator accounts, browser sessions, and the security audit log.
-- Operator accounts are unrelated to any managed project's Supabase Auth users.

CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    -- Normalized by the application (trimmed, lowercased).
    email TEXT NOT NULL CHECK (email = lower(email) AND char_length(email) BETWEEN 3 AND 254),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 100),
    -- PHC-format Argon2id string. Never selected into anything sent to a browser.
    password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    is_installation_admin BOOLEAN NOT NULL DEFAULT FALSE,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX accounts_email_key ON accounts (email);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    -- SHA-256 of the random cookie value. The cookie value itself is never stored.
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Absolute lifetime; idle expiry is computed from last_seen_at.
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    -- Truncated, informational only; shown on the account security page.
    user_agent TEXT CHECK (char_length(user_agent) <= 256)
);

CREATE UNIQUE INDEX sessions_token_hash_key ON sessions (token_hash);
CREATE INDEX sessions_account_id_idx ON sessions (account_id);

-- Append-only record of security-relevant actions. Never stores credentials,
-- tokens, passwords, or managed project data.
CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_account_id UUID REFERENCES accounts (id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (action ~ '^[a-z_]+(\.[a-z_]+)+$'),
    target_type TEXT CHECK (char_length(target_type) <= 64),
    target_id TEXT CHECK (char_length(target_id) <= 128),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    request_id TEXT CHECK (char_length(request_id) <= 128)
);

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_account_id, occurred_at DESC);
