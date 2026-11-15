-- The organization an audit event belongs to, so owners and admins can read
-- their organization's audit log. Events about an installation (accounts,
-- sessions, the Dokploy connection, the encryption key) have none.
--
-- There is no foreign key: an organization's events stay readable for an
-- installation admin after the organization is gone.

ALTER TABLE audit_events ADD COLUMN organization_id UUID;

CREATE INDEX audit_events_organization_idx
    ON audit_events (organization_id, occurred_at DESC, id DESC)
    WHERE organization_id IS NOT NULL;

-- An account's own log also lists events about the account by others.
CREATE INDEX audit_events_account_target_idx
    ON audit_events (target_id, occurred_at DESC)
    WHERE target_type = 'account';

-- The organization of an event's target, for events whose writer did not
-- name one. Targets that do not name a row in this database give NULL,
-- never an error, so a malformed target cannot fail the event's insert.
CREATE FUNCTION audit_target_organization(target_type TEXT, target_id TEXT)
RETURNS UUID
LANGUAGE sql STABLE
AS $$
    SELECT CASE
        WHEN target_id IS NULL THEN NULL
        WHEN target_type = 'organization'
             AND target_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN (SELECT o.id FROM organizations o WHERE o.id = target_id::uuid)
        -- `<organization>:<account>`
        WHEN target_type = 'organization_member'
             AND target_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:'
            THEN (SELECT o.id FROM organizations o WHERE o.id = left(target_id, 36)::uuid)
        WHEN target_type = 'project'
             AND target_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN (SELECT p.organization_id FROM projects p WHERE p.id = target_id::uuid)
        WHEN target_type = 'organization_invitation'
             AND target_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN (SELECT i.organization_id FROM organization_invitations i
                  WHERE i.id = target_id::uuid)
        WHEN target_type = 'job'
             AND target_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN (SELECT j.organization_id FROM jobs j WHERE j.id = target_id::uuid)
    END
$$;

-- Earlier events. Those about projects unregistered since cannot be placed
-- and stay without an organization.
UPDATE audit_events
SET organization_id = audit_target_organization(target_type, target_id)
WHERE organization_id IS NULL;
