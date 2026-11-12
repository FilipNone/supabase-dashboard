-- Past service checks of each project. The application deletes entries
-- older than its retention period, and beyond a per-project cap, whenever
-- it saves a new check; project_health_reports keeps holding the latest.
CREATE TABLE project_health_history (
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL,
    -- Whether any service failed, so counts need not read the checks.
    failing BOOLEAN NOT NULL,
    -- Same shape as project_health_reports.checks: statuses, versions, and
    -- timings only, never key values or raw error text.
    checks JSONB NOT NULL CHECK (jsonb_typeof(checks) = 'array'),
    PRIMARY KEY (project_id, checked_at)
);
