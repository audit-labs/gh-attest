-- Migration 0008: fixes from the evidence-to-control mapping review.
--
-- 1. Secret-scanning status vocabulary. The secret_scanning_alert webhook
--    payload has no alert.state field (unlike Dependabot / code scanning), so
--    ingest recorded the webhook action (created/reopened/...) and the 'open'
--    mappings never matched — an open leak exported only positive rows.
--    Ingest now derives open/resolved from alert.resolution; historical rows
--    are backfilled the same way below.
-- 2. Per-entity subjects. Alert/member/team snapshots had a NULL subject, so
--    "latest row wins per (repo, subject, resource)" collapsed every alert of
--    a type in a repo into one evidence row — one fixed alert masked any
--    number of still-open ones. Ingest now stores the alert number / login /
--    slug in subject; historical rows are backfilled from raw_payload.
-- 3. Tooling-active re-homed. "Detection tooling is active" was inferred from
--    the latest alert event, which keeps attesting after the scanner is
--    disabled and never fires for a clean repo. The poller now reports the
--    feature state directly (resources dependabot / code_scanning /
--    secret_scanning, status enabled|disabled|unavailable); the status-NULL
--    alert mappings are replaced by 'enabled' mappings on those resources.
--    disabled/unavailable stay unmapped — missing tooling is recorded but not
--    claimed either way, matching the branch-protection precedent.
-- 4. SOC 2 vulnerability lifecycle consolidated under CC7.1, resolving the
--    CC7.1-vs-CC7.2 question left open in docs/framework-mapping.md: a known
--    vulnerability sits in CC7.1's "susceptibility to newly discovered
--    vulnerabilities" language, not CC7.2's runtime anomaly monitoring. Code
--    scanning gains the finding-level SOC 2 rows deferred on that decision.
-- 5. Human dismissals downgraded to informational. A dismissal (or a secret
--    "resolved" that may be wont_fix) is a recorded human decision, not a
--    verified remediation — the justification is what an auditor samples.
--    Machine-verified outcomes (fixed, auto_dismissed) stay positive.
-- 6. Branch-protection rationales reworded to what is actually verified: a
--    protection rule / active ruleset covers the default branch; the rule
--    contents are not checked.
-- 7. The `member` webhook is repository-collaborator scoped: rationales now
--    say so, "removed" no longer claims timeliness the event can't prove, and
--    org-level membership events (`organization` webhook -> org_membership)
--    are mapped. member_access gains the ISO A.5.18 rows it was missing.
-- 8. repository 'publicized' additionally flagged to SOC 2 CC6.1 — a repo
--    going public is a visibility change worth surfacing, not just an
--    inventory tick.

-- (1) Backfill secret-scanning statuses recorded from the raw webhook action.
UPDATE snapshots
SET status = CASE
  WHEN json_extract(raw_payload, '$.alert.resolution') IS NULL THEN 'open'
  ELSE 'resolved'
END
WHERE resource = 'secret_scanning_alert'
  AND status NOT IN ('open', 'resolved')
  AND raw_payload IS NOT NULL;

-- (2) Backfill per-entity subjects from the retained webhook payloads.
UPDATE snapshots
SET subject = CAST(json_extract(raw_payload, '$.alert.number') AS TEXT)
WHERE resource IN ('dependabot_alert', 'code_scanning_alert', 'secret_scanning_alert')
  AND subject IS NULL
  AND json_extract(raw_payload, '$.alert.number') IS NOT NULL;

UPDATE snapshots
SET subject = json_extract(raw_payload, '$.member.login')
WHERE resource = 'member_access'
  AND subject IS NULL
  AND json_extract(raw_payload, '$.member.login') IS NOT NULL;

UPDATE snapshots
SET subject = json_extract(raw_payload, '$.team.slug')
WHERE resource = 'team'
  AND subject IS NULL
  AND json_extract(raw_payload, '$.team.slug') IS NOT NULL;

-- (3)-(8) Replace the mappings for every affected resource wholesale (same
-- pattern as migration 0003).
DELETE FROM control_mappings WHERE resource IN
  ('dependabot_alert', 'code_scanning_alert', 'secret_scanning_alert',
   'branch_protection', 'repository_ruleset', 'member_access');

INSERT INTO control_mappings (resource, status, framework, control_id, posture, rationale) VALUES
  -- Branch protection / rulesets: state of the default branch's merge gate.
  ('branch_protection', 'enabled', 'soc2', 'CC8.1', 'positive', 'Change management — a protection rule is enforced on the default branch (rule contents not verified)'),
  ('branch_protection', 'disabled', 'soc2', 'CC8.1', 'negative', 'Change-control gap — no protection on the default branch; direct pushes possible'),
  ('branch_protection', 'enabled', 'iso27001', 'A.8.32', 'positive', 'Change management — a protection rule is enforced on the default branch (rule contents not verified)'),
  ('branch_protection', 'disabled', 'iso27001', 'A.8.32', 'negative', 'Change-control gap — no protection on the default branch; direct pushes possible'),
  ('repository_ruleset', 'enabled', 'soc2', 'CC8.1', 'positive', 'Change management — an active ruleset covers the default branch (rule contents not verified)'),
  ('repository_ruleset', 'disabled', 'soc2', 'CC8.1', 'negative', 'Change-control gap — no active ruleset covers the default branch'),
  ('repository_ruleset', 'enabled', 'iso27001', 'A.8.32', 'positive', 'Change management — an active ruleset covers the default branch (rule contents not verified)'),
  ('repository_ruleset', 'disabled', 'iso27001', 'A.8.32', 'negative', 'Change-control gap — no active ruleset covers the default branch'),

  -- Detection tooling state (polled; disabled/unavailable deliberately unmapped).
  ('dependabot', 'enabled', 'soc2', 'CC7.1', 'positive', 'Detection tooling — Dependabot alerts are enabled on the repository'),
  ('dependabot', 'enabled', 'iso27001', 'A.8.8', 'positive', 'Technical vulnerability management — Dependabot alerts are enabled on the repository'),
  ('code_scanning', 'enabled', 'soc2', 'CC7.1', 'positive', 'Detection tooling — code scanning is enabled on the repository'),
  ('code_scanning', 'enabled', 'iso27001', 'A.8.29', 'positive', 'Security testing in development — code scanning is enabled on the repository'),
  ('secret_scanning', 'enabled', 'soc2', 'CC6.6', 'positive', 'Leaked-credential detection — secret scanning is enabled on the repository'),
  ('secret_scanning', 'enabled', 'soc2', 'CC6.1', 'positive', 'Logical-access credential protection — secret scanning is enabled on the repository'),
  ('secret_scanning', 'enabled', 'iso27001', 'A.5.17', 'positive', 'Authentication-information protection — secret scanning is enabled on the repository'),

  -- Dependabot findings.
  ('dependabot_alert', 'open', 'soc2', 'CC7.1', 'negative', 'Unremediated known vulnerability'),
  ('dependabot_alert', 'fixed', 'soc2', 'CC7.1', 'positive', 'Vulnerability remediated'),
  ('dependabot_alert', 'dismissed', 'soc2', 'CC7.1', 'informational', 'Dismissed by a user — risk-acceptance justification subject to review'),
  ('dependabot_alert', 'auto_dismissed', 'soc2', 'CC7.1', 'positive', 'Auto-dismissed by GitHub (e.g. dependency removed)'),
  ('dependabot_alert', 'open', 'iso27001', 'A.8.8', 'negative', 'Unremediated known technical vulnerability'),
  ('dependabot_alert', 'fixed', 'iso27001', 'A.8.8', 'positive', 'Vulnerability remediated'),
  ('dependabot_alert', 'dismissed', 'iso27001', 'A.8.8', 'informational', 'Dismissed by a user — risk-acceptance justification subject to review'),
  ('dependabot_alert', 'auto_dismissed', 'iso27001', 'A.8.8', 'positive', 'Auto-dismissed by GitHub (e.g. dependency removed)'),

  -- Code scanning findings.
  ('code_scanning_alert', 'open', 'soc2', 'CC7.1', 'negative', 'Unremediated static-analysis finding'),
  ('code_scanning_alert', 'fixed', 'soc2', 'CC7.1', 'positive', 'Finding remediated'),
  ('code_scanning_alert', 'dismissed', 'soc2', 'CC7.1', 'informational', 'Dismissed by a user — risk-acceptance justification subject to review'),
  ('code_scanning_alert', 'open', 'iso27001', 'A.8.28', 'negative', 'Unremediated static-analysis finding'),
  ('code_scanning_alert', 'fixed', 'iso27001', 'A.8.28', 'positive', 'Finding remediated'),
  ('code_scanning_alert', 'dismissed', 'iso27001', 'A.8.28', 'informational', 'Dismissed by a user — risk-acceptance justification subject to review'),

  -- Secret scanning findings ("resolved" may be wont_fix — a human decision,
  -- not a verified remediation).
  ('secret_scanning_alert', 'open', 'soc2', 'CC6.6', 'negative', 'Live credential exposure'),
  ('secret_scanning_alert', 'resolved', 'soc2', 'CC6.6', 'informational', 'Resolution recorded — reason (revoked vs. won''t-fix) subject to review'),
  ('secret_scanning_alert', 'open', 'soc2', 'CC6.1', 'negative', 'Exposed credential undermines logical access controls'),
  ('secret_scanning_alert', 'resolved', 'soc2', 'CC6.1', 'informational', 'Resolution recorded — reason (revoked vs. won''t-fix) subject to review'),
  ('secret_scanning_alert', 'open', 'iso27001', 'A.5.17', 'negative', 'Exposed authentication information'),
  ('secret_scanning_alert', 'resolved', 'iso27001', 'A.5.17', 'informational', 'Resolution recorded — reason (revoked vs. won''t-fix) subject to review'),

  -- Repository collaborators (the `member` webhook is repo-scoped).
  ('member_access', 'added', 'soc2', 'CC6.2', 'informational', 'Repository collaborator added — access grant logged for review'),
  ('member_access', 'removed', 'soc2', 'CC6.3', 'informational', 'Repository collaborator removed — deprovisioning recorded; timeliness subject to review'),
  ('member_access', 'edited', 'soc2', 'CC6.3', 'informational', 'Repository collaborator permission changed — logged for review'),
  ('member_access', 'added', 'iso27001', 'A.5.18', 'informational', 'Repository collaborator added — access-rights change, audit trail'),
  ('member_access', 'removed', 'iso27001', 'A.5.18', 'informational', 'Repository collaborator removed — access-rights change, audit trail'),
  ('member_access', 'edited', 'iso27001', 'A.5.18', 'informational', 'Repository collaborator permission changed — access-rights change, audit trail'),

  -- Organization membership changes (`organization` webhook).
  ('org_membership', 'member_added', 'soc2', 'CC6.2', 'informational', 'Organization member added — access grant logged for review'),
  ('org_membership', 'member_removed', 'soc2', 'CC6.3', 'informational', 'Organization member removed — deprovisioning recorded; timeliness subject to review'),
  ('org_membership', 'member_invited', 'soc2', 'CC6.2', 'informational', 'Organization invitation issued — logged for review'),
  ('org_membership', 'member_added', 'iso27001', 'A.5.18', 'informational', 'Organization member added — access-rights change, audit trail'),
  ('org_membership', 'member_removed', 'iso27001', 'A.5.18', 'informational', 'Organization member removed — access-rights change, audit trail'),
  ('org_membership', 'member_invited', 'iso27001', 'A.5.18', 'informational', 'Organization invitation issued — access-rights change, audit trail'),

  -- Repository made public: worth surfacing beyond the generic inventory trail.
  ('repository', 'publicized', 'soc2', 'CC6.1', 'informational', 'Repository made public — visibility change affecting asset confidentiality, flagged for review');
