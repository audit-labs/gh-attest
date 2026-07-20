CREATE TABLE exports (
  id TEXT PRIMARY KEY,           -- uuid
  installation_id INTEGER NOT NULL,
  framework TEXT NOT NULL,        -- 'soc2' | 'iso27001' | 'all'
  format TEXT NOT NULL,           -- 'csv' | 'pdf'
  status TEXT NOT NULL,           -- 'queued' | 'processing' | 'done' | 'error'
  r2_key TEXT,                    -- null until rendered
  error TEXT,                     -- populated on failure
  created_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY (installation_id) REFERENCES installations(installation_id)
);

CREATE INDEX idx_exports_installation ON exports(installation_id, created_at);
