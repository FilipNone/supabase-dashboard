-- Control-plane metadata schema. This database belongs to the dashboard and
-- never stores managed project data.
CREATE TABLE installation (
    -- Exactly one row; the check constraint enforces the singleton.
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    installation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO installation (installation_id) VALUES (gen_random_uuid());
