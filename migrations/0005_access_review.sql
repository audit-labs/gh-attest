-- Access-review facts are org-scoped and about a person or team, not a
-- repository, so the repo column can't identify them. `subject` holds the
-- entity the fact is about: a member login, or "team-slug:login" for team
-- membership.
ALTER TABLE snapshots ADD COLUMN subject TEXT;

-- Polled access state uses its own resource names so it doesn't collide with
-- the webhook event trail (`member_access`, `team`), which records changes
-- rather than current state. These are inventory for access review, so they
-- are informational rather than pass/fail.
INSERT INTO control_mappings (resource, status, framework, control_id, posture, rationale) VALUES
  ('org_member', NULL, 'soc2', 'CC6.2', 'informational', 'Organization access inventory — subject to periodic access review'),
  ('org_member', NULL, 'iso27001', 'A.5.18', 'informational', 'Access rights inventory'),
  ('team_member', NULL, 'soc2', 'CC6.3', 'informational', 'Team-based access inventory'),
  ('team_member', NULL, 'iso27001', 'A.5.18', 'informational', 'Access rights inventory');
