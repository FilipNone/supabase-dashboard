-- The installation's connection to Dokploy, its first deployment provider:
-- at most one per installation.
--
-- The API key is encrypted by the application with AES-256-GCM under the
-- deployment's credential key, like project keys, and bound to `url`; this
-- database never sees the plaintext or the encryption key. A row is written
-- only after Dokploy accepted the key and reported a supported version.
-- Deleting the row removes the dashboard's record only; nothing is sent to
-- Dokploy.

CREATE TABLE dokploy_connection (
    -- Exactly one row at most; the check constraint enforces the singleton.
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    url TEXT NOT NULL CHECK (char_length(url) BETWEEN 1 AND 2048),
    key_id TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    -- The longest accepted key is 512 bytes plus the 16-byte tag.
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 528),
    -- As Dokploy reported it when the key last connected, e.g. v0.31.1.
    version TEXT NOT NULL CHECK (char_length(version) BETWEEN 1 AND 32),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    connected_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    key_replaced_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    key_replaced_at TIMESTAMPTZ
);
