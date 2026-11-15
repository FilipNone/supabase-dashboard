-- Where a session came from when it was started by signing in through the
-- deployment's OpenID Connect provider: the identity (issuer and subject)
-- and the provider's session ID (`sid`), when its ID token named one. The
-- provider's back-channel logout names one of these, and the dashboard
-- revokes the matching sessions. Password sessions leave all three empty.
--
-- The identity is copied rather than referenced, so a logout from the
-- provider still finds the session after the identity is unlinked.

ALTER TABLE sessions
    ADD COLUMN oidc_issuer TEXT CHECK (char_length(oidc_issuer) BETWEEN 1 AND 2048),
    ADD COLUMN oidc_subject TEXT CHECK (char_length(oidc_subject) BETWEEN 1 AND 255),
    ADD COLUMN oidc_sid TEXT CHECK (char_length(oidc_sid) BETWEEN 1 AND 255),
    ADD CONSTRAINT sessions_oidc_identity_pair_check
        CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL)),
    ADD CONSTRAINT sessions_oidc_sid_needs_identity_check
        CHECK (oidc_sid IS NULL OR oidc_issuer IS NOT NULL);

CREATE INDEX sessions_oidc_identity_idx ON sessions (oidc_issuer, oidc_subject)
    WHERE oidc_issuer IS NOT NULL;
CREATE INDEX sessions_oidc_sid_idx ON sessions (oidc_issuer, oidc_sid)
    WHERE oidc_sid IS NOT NULL;
