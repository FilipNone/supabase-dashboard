-- Stop, start, and redeploy of a provisioned stack's Dokploy service run
-- as durable jobs too. Their `data` names the project and the action.
ALTER TABLE jobs DROP CONSTRAINT jobs_kind_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check
    CHECK (kind IN ('provision_stack', 'stack_action'));

-- The panel reads a project's newest action, and a new action is refused
-- while one is unfinished.
CREATE INDEX jobs_stack_action_project_idx ON jobs ((data ->> 'project_id'), created_at DESC)
    WHERE kind = 'stack_action';

-- At most one unfinished action per project, even when two are asked for
-- at once.
CREATE UNIQUE INDEX jobs_stack_action_unfinished_idx ON jobs ((data ->> 'project_id'))
    WHERE kind = 'stack_action' AND state IN ('queued', 'running');
