-- Repos an installation has opted out of: they are skipped by the poller and
-- filtered out of the evidence query, so an excluded repo neither costs
-- subrequests nor reports a gap. Snapshots already collected for the repo are
-- left in place — an exclusion is a reporting decision, not a deletion, and
-- removing the exclusion restores the history.
CREATE TABLE repo_exclusions (
  installation_id INTEGER NOT NULL,
  repo TEXT NOT NULL,             -- full name, e.g. 'acme/api'
  excluded_at TEXT NOT NULL,
  PRIMARY KEY (installation_id, repo),
  FOREIGN KEY (installation_id) REFERENCES installations(installation_id)
);
