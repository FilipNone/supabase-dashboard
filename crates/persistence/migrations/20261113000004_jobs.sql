-- Durable background jobs, such as provisioning a stack.
--
-- A job runs one step at a time and is saved after each one, so a dashboard
-- that stops partway resumes from the last saved step. A worker holds a
-- job through a lease: `lease_until` is pushed forward while it works, and
-- a job whose lease ran out, because its worker stopped, is claimed again.
-- `interruptions` counts claims of a job whose lease ran out and steps that
-- took too long, so a job that keeps being interrupted fails instead of
-- running forever. Waiting, for example between polls, is not counted.
--
-- `data` holds the job's inputs and what it has learned, such as IDs from
-- the deployment provider. It never holds secrets: those go in
-- `job_secrets`, encrypted with the credential key and bound to the job.

CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('provision_stack')),
    -- Organizations are never deleted while they still have jobs.
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    state TEXT NOT NULL
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    step TEXT NOT NULL CHECK (step ~ '^[a-z][a-z_]{0,63}$'),
    data JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(data) = 'object' AND octet_length(data::text) <= 65536),
    interruptions INTEGER NOT NULL DEFAULT 0 CHECK (interruptions >= 0),
    run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner UUID,
    lease_until TIMESTAMPTZ,
    -- Why the job failed, or why its last step is waiting, for the
    -- operator. Never credentials or provider responses.
    message TEXT CHECK (char_length(message) <= 1000),
    created_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
    CHECK ((state IN ('succeeded', 'failed')) = (finished_at IS NOT NULL)),
    CHECK (state = 'running' OR lease_owner IS NULL)
);

-- Workers look for queued jobs that are due and running jobs whose lease
-- has run out.
CREATE INDEX jobs_due_idx ON jobs (run_after) WHERE state = 'queued';
CREATE INDEX jobs_lease_idx ON jobs (lease_until) WHERE state = 'running';
CREATE INDEX jobs_organization_idx ON jobs (organization_id, created_at DESC);

CREATE TABLE job_secrets (
    job_id UUID PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    key_id TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 16400)
);
