-- Secret scanning now maps to BOTH CC6.6 and CC6.1. A leaked credential is
-- simultaneously an external-access vector (CC6.6 — protection against threats
-- outside the system boundary, already mapped in 0002) and a compromise of the
-- logical-access controls themselves (CC6.1 — logical access security over
-- protected assets), since the credential is itself a logical-access key.
-- Auditors differ on which is the primary home; attesting both lets the export
-- satisfy whichever the control narrative uses. Each secret-scanning snapshot
-- therefore emits the CC6.1 rows below in addition to its CC6.6 rows.
INSERT INTO control_mappings (resource, status, framework, control_id, posture, rationale) VALUES
  ('secret_scanning_alert', NULL, 'soc2', 'CC6.1', 'positive', 'Logical-access credential protection — leaked-credential detection is active'),
  ('secret_scanning_alert', 'open', 'soc2', 'CC6.1', 'negative', 'Exposed credential undermines logical access controls'),
  ('secret_scanning_alert', 'resolved', 'soc2', 'CC6.1', 'positive', 'Logical access control restored — exposure remediated');
