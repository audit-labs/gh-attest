-- snapshots.control_id was a placeholder for a mapping approach we didn't
-- end up using — mapping happens via a join against control_mappings at
-- query/export time instead, so re-mapping doesn't require re-ingesting
-- webhook history.
DROP INDEX IF EXISTS idx_snapshots_control;
ALTER TABLE snapshots DROP COLUMN control_id;

CREATE TABLE control_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  resource TEXT NOT NULL,
  status TEXT,               -- NULL matches any status for this resource
  framework TEXT NOT NULL,   -- 'soc2' | 'iso27001'
  control_id TEXT NOT NULL,  -- e.g. 'CC8.1', 'A.8.32'
  posture TEXT NOT NULL,     -- 'positive' | 'negative' | 'informational'
  rationale TEXT NOT NULL
);

CREATE INDEX idx_control_mappings_resource ON control_mappings(resource);

INSERT INTO control_mappings (resource, status, framework, control_id, posture, rationale) VALUES
  -- branch protection / ruleset present
  ('branch_protection', 'created', 'soc2', 'CC8.1', 'positive', 'Change management — code changes require review before merge'),
  ('branch_protection', 'edited', 'soc2', 'CC8.1', 'positive', 'Change management — code changes require review before merge'),
  ('branch_protection', 'created', 'iso27001', 'A.8.32', 'positive', 'Change management'),
  ('branch_protection', 'edited', 'iso27001', 'A.8.32', 'positive', 'Change management'),
  ('repository_ruleset', 'created', 'soc2', 'CC8.1', 'positive', 'Change management — code changes require review before merge'),
  ('repository_ruleset', 'edited', 'soc2', 'CC8.1', 'positive', 'Change management — code changes require review before merge'),
  ('repository_ruleset', 'created', 'iso27001', 'A.8.32', 'positive', 'Change management'),
  ('repository_ruleset', 'edited', 'iso27001', 'A.8.32', 'positive', 'Change management'),

  -- branch protection / ruleset removed
  ('branch_protection', 'deleted', 'soc2', 'CC8.1', 'negative', 'Change control gap — direct pushes now possible'),
  ('branch_protection', 'deleted', 'iso27001', 'A.8.32', 'negative', 'Change control gap — direct pushes now possible'),
  ('repository_ruleset', 'deleted', 'soc2', 'CC8.1', 'negative', 'Change control gap — direct pushes now possible'),
  ('repository_ruleset', 'deleted', 'iso27001', 'A.8.32', 'negative', 'Change control gap — direct pushes now possible'),

  -- dependabot_alert
  ('dependabot_alert', NULL, 'soc2', 'CC7.1', 'positive', 'Detection tooling is active'),
  ('dependabot_alert', 'open', 'soc2', 'CC7.2', 'negative', 'Unremediated known vulnerability'),
  ('dependabot_alert', 'fixed', 'soc2', 'CC7.2', 'positive', 'Remediated'),
  ('dependabot_alert', 'dismissed', 'soc2', 'CC7.2', 'positive', 'Remediated (risk accepted)'),
  ('dependabot_alert', 'auto_dismissed', 'soc2', 'CC7.2', 'positive', 'Remediated (e.g. dependency removed)'),

  -- code_scanning_alert
  ('code_scanning_alert', NULL, 'iso27001', 'A.8.29', 'positive', 'Security testing in development is active'),
  ('code_scanning_alert', 'open', 'iso27001', 'A.8.28', 'negative', 'Unremediated finding'),
  ('code_scanning_alert', 'fixed', 'iso27001', 'A.8.28', 'positive', 'Remediated'),
  ('code_scanning_alert', 'dismissed', 'iso27001', 'A.8.28', 'positive', 'Remediated (risk accepted)'),

  -- secret_scanning_alert
  ('secret_scanning_alert', NULL, 'soc2', 'CC6.6', 'positive', 'Leaked-credential detection is active'),
  ('secret_scanning_alert', 'open', 'soc2', 'CC6.6', 'negative', 'Live credential exposure'),
  ('secret_scanning_alert', 'resolved', 'soc2', 'CC6.6', 'positive', 'Exposure remediated'),

  -- member_access
  ('member_access', 'added', 'soc2', 'CC6.2', 'informational', 'Access grant — logged for review'),
  ('member_access', 'removed', 'soc2', 'CC6.3', 'positive', 'Timely access removal'),
  ('member_access', 'edited', 'soc2', 'CC6.3', 'informational', 'Access-level change — logged for review'),

  -- team and repository metadata — audit trail, not itself pass/fail
  ('team', NULL, 'iso27001', 'A.5.18', 'informational', 'Access-rights change, audit trail'),
  ('repository', NULL, 'iso27001', 'A.5.9', 'informational', 'Asset inventory trail');
