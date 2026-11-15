-- Requests to change an account's sign-in email, confirmed by a link sent
-- to the new address. Only a SHA-256 hash of each code is stored; the code
-- itself is in the email. A link works once, for a short time, only while
-- the account still has the address it had when the request was made, and
-- only while its password has not changed since.

CREATE TABLE email_change_requests (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    -- The sign-in email when the request was made, and the one asked for,
    -- normalized like accounts.email.
    old_email TEXT NOT NULL CHECK (old_email = lower(old_email) AND char_length(old_email) BETWEEN 3 AND 254),
    new_email TEXT NOT NULL CHECK (new_email = lower(new_email) AND char_length(new_email) BETWEEN 3 AND 254),
    -- SHA-256 of the code's 32 random bytes.
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at),
    used_at TIMESTAMPTZ,
    -- Set when a newer request for the same account, or a confirmed change,
    -- replaces this one.
    revoked_at TIMESTAMPTZ,
    CHECK (new_email <> old_email)
);

CREATE UNIQUE INDEX email_change_requests_token_hash_key
    ON email_change_requests (token_hash);
CREATE INDEX email_change_requests_account_idx
    ON email_change_requests (account_id, created_at DESC);
