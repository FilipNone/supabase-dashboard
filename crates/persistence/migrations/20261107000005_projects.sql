-- Registry entries for existing self-hosted Supabase stacks. A row records
-- where a stack is; removing it never touches the stack or its data.
-- Credentials for the stack are stored separately once they are supported.

CREATE TABLE projects (
    id UUID PRIMARY KEY,
    -- Organizations are never deleted while they still have projects.
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    api_url TEXT NOT NULL
        CHECK (char_length(api_url) <= 2048 AND api_url ~ '^https?://[^/?#@]+'),
    created_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX projects_organization_idx ON projects (organization_id);
