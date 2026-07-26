-- Migration 0007: close the asymmetric-coverage gaps from the framework-mapping
-- review. Three signals were mapped in only one framework although the
-- equivalent control clearly exists in the other. See docs/framework-mapping.md.
--
-- 1. Dependabot -> ISO A.8.8 (Management of technical vulnerabilities). A.8.8 is
--    one control covering the whole vulnerability lifecycle (identify -> evaluate
--    -> remediate), so — unlike the SOC 2 split across CC7.1/CC7.2 — every status
--    maps to this single control.
-- 2. Code scanning -> SOC 2 CC7.1 (detection & monitoring), mirroring how
--    Dependabot's tooling-active fact already maps to CC7.1. Only the tooling-
--    active (NULL) row is added; finding-level rows are deliberately NOT routed
--    to CC7.2 here, pending the CC7.1-vs-CC7.2 decision noted in the doc.
-- 3. Secret scanning -> ISO A.5.17 (Authentication information). A leaked
--    credential is exposed authentication information; mirrors the SOC 2
--    CC6.6/CC6.1 rows into ISO.
INSERT INTO control_mappings (resource, status, framework, control_id, posture, rationale) VALUES
  -- Dependabot: ISO technical-vulnerability management (full lifecycle, one control)
  ('dependabot_alert', NULL, 'iso27001', 'A.8.8', 'positive', 'Technical vulnerability management — detection tooling is active'),
  ('dependabot_alert', 'open', 'iso27001', 'A.8.8', 'negative', 'Unremediated known technical vulnerability'),
  ('dependabot_alert', 'fixed', 'iso27001', 'A.8.8', 'positive', 'Vulnerability remediated'),
  ('dependabot_alert', 'dismissed', 'iso27001', 'A.8.8', 'positive', 'Vulnerability remediated (risk accepted)'),
  ('dependabot_alert', 'auto_dismissed', 'iso27001', 'A.8.8', 'positive', 'Vulnerability remediated (e.g. dependency removed)'),

  -- Code scanning: SOC 2 detection tooling active (findings intentionally unmapped here)
  ('code_scanning_alert', NULL, 'soc2', 'CC7.1', 'positive', 'Detection tooling is active — SAST runs in the development pipeline'),

  -- Secret scanning: ISO authentication-information protection
  ('secret_scanning_alert', NULL, 'iso27001', 'A.5.17', 'positive', 'Authentication information protection — leaked-credential detection is active'),
  ('secret_scanning_alert', 'open', 'iso27001', 'A.5.17', 'negative', 'Exposed authentication information'),
  ('secret_scanning_alert', 'resolved', 'iso27001', 'A.5.17', 'positive', 'Authentication information exposure remediated');
