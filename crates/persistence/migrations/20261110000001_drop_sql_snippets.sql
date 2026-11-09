-- The dashboard no longer has its own SQL editor: a project's pages are its
-- own Supabase Studio (see docs/adr/0002-studio-access.md), and Studio keeps
-- its own snippets. The earlier migration stays in place so databases that
-- applied it still match the migration history.

DROP TABLE IF EXISTS sql_snippets;
