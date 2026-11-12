-- Which server process is running the scheduled check of a project, so
-- several processes sharing this database do not check the same stack at
-- the same time. A claim lapses at claimed_until; a process that stops
-- halfway through leaves nothing to clean up by hand.
CREATE TABLE project_check_claims (
    project_id UUID PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    claimed_until TIMESTAMPTZ NOT NULL
);
