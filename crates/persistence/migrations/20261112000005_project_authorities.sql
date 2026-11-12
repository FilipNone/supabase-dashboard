-- Private certificate authorities trusted for one project's gateway, in
-- addition to the bundled public roots and the deployment-wide CA file.
--
-- Certificates are public, so the bundle is stored as PEM text. The
-- application checks that it holds only usable CA certificates before it
-- writes a row. Unregistering a project deletes its row; nothing on the
-- stack is touched.

CREATE TABLE project_authorities (
    project_id UUID PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    pem TEXT NOT NULL CHECK (octet_length(pem) BETWEEN 1 AND 65536),
    updated_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
