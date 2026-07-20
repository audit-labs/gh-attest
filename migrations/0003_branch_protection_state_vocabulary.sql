-- branch_protection / repository_ruleset now report current-state status
-- (enabled/disabled) instead of the raw webhook action (created/edited/
-- deleted), so the cron poller can report the same facts for pre-existing
-- state that the webhook never delivered an event for.
DELETE FROM control_mappings WHERE resource IN ('branch_protection', 'repository_ruleset');

INSERT INTO control_mappings (resource, status, framework, control_id, posture, rationale) VALUES
  ('branch_protection', 'enabled', 'soc2', 'CC8.1', 'positive', 'Change management — code changes require review before merge'),
  ('branch_protection', 'disabled', 'soc2', 'CC8.1', 'negative', 'Change control gap — direct pushes possible'),
  ('branch_protection', 'enabled', 'iso27001', 'A.8.32', 'positive', 'Change management'),
  ('branch_protection', 'disabled', 'iso27001', 'A.8.32', 'negative', 'Change control gap — direct pushes possible'),
  ('repository_ruleset', 'enabled', 'soc2', 'CC8.1', 'positive', 'Change management — code changes require review before merge'),
  ('repository_ruleset', 'disabled', 'soc2', 'CC8.1', 'negative', 'Change control gap — direct pushes possible'),
  ('repository_ruleset', 'enabled', 'iso27001', 'A.8.32', 'positive', 'Change management'),
  ('repository_ruleset', 'disabled', 'iso27001', 'A.8.32', 'negative', 'Change control gap — direct pushes possible');
