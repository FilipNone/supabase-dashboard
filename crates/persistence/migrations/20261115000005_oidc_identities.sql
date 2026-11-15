-- Identities at the deployment's OpenID Connect provider that an operator
-- linked to their dashboard account. An identity is the pair (issuer,
-- subject); it signs in to the account it is linked to and to no other.
-- Accounts are never found or created by the provider's email address.

CREATE TABLE oidc_identities (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    issuer TEXT NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    -- `sub`: at most 255 ASCII characters (OpenID Connect Core 1.0, 2).
    subject TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    -- What the provider called the identity when it was linked, such as an
    -- email address. Shown to the operator; never used for matching.
    label TEXT CHECK (char_length(label) BETWEEN 1 AND 254),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

-- One account per identity.
CREATE UNIQUE INDEX oidc_identities_issuer_subject_key
    ON oidc_identities (issuer, subject);
-- One identity per provider per account.
CREATE UNIQUE INDEX oidc_identities_account_issuer_key
    ON oidc_identities (account_id, issuer);
