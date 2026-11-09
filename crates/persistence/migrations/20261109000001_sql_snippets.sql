-- SQL snippets saved in the dashboard for one project. The rules for who
-- sees and changes them live in the application (see the domain `snippet`
-- module); this table only records author, project, and visibility.
--
-- Unregistering a project deletes its snippets. Nothing on the stack is
-- touched. Snippet text is never copied into the audit log.

CREATE TABLE sql_snippets (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    visibility TEXT NOT NULL CHECK (visibility IN ('private', 'project')),
    -- Same limit as SQL sent from the editor: 256 KiB.
    content TEXT NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 262144),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sql_snippets_project_author ON sql_snippets (project_id, author_id);
CREATE INDEX sql_snippets_project_shared ON sql_snippets (project_id) WHERE visibility = 'project';
