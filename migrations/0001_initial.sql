CREATE TABLE installations (
  installation_id INTEGER PRIMARY KEY,
  org_login TEXT NOT NULL,
  installed_at TEXT NOT NULL,
  suspended_at TEXT
);

CREATE TABLE snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  installation_id INTEGER NOT NULL,
  repo TEXT,                    -- null for org-level facts
  control_id TEXT,               -- e.g. 'SOC2-CC6.1' — nullable until mapping table is built
  resource TEXT NOT NULL,        -- e.g. 'branch_protection', 'secret_scanning_alert', 'member_access'
  status TEXT NOT NULL,          -- e.g. 'enabled', 'disabled', 'open', 'resolved'
  raw_payload TEXT,              -- original JSON, for audit trail / re-mapping later
  captured_at TEXT NOT NULL,
  FOREIGN KEY (installation_id) REFERENCES installations(installation_id)
);

CREATE INDEX idx_snapshots_installation ON snapshots(installation_id, captured_at);
CREATE INDEX idx_snapshots_control ON snapshots(control_id);
