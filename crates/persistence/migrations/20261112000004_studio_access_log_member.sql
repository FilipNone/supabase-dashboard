-- Filtering a project's Studio access log by member, and listing the
-- members who have entries.
CREATE INDEX studio_access_log_project_account_at
    ON studio_access_log (project_id, account_id, at DESC);
