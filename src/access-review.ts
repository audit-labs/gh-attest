// Resources written by the access poller. Each poll writes the full current
// set with one shared captured_at, so a captured_at value identifies a
// coherent point-in-time snapshot to diff against.
const ACCESS_RESOURCES = ["org_member", "team_member"] as const;

export interface AccessDiffEntry {
  resource: string;
  subject: string;
  change: "added" | "removed" | "changed";
  from: string | null;
  to: string | null;
}

export interface AccessDiff {
  currentAt: string | null;
  priorAt: string | null;
  currentCount: number;
  entries: AccessDiffEntry[];
}

interface AccessRow {
  resource: string;
  subject: string;
  status: string;
}

async function fetchSet(db: D1Database, installationId: number, capturedAt: string): Promise<AccessRow[]> {
  const { results } = await db
    .prepare(
      `SELECT resource, subject, status FROM snapshots
       WHERE installation_id = ?1 AND captured_at = ?2
         AND resource IN ('org_member', 'team_member')
         AND subject IS NOT NULL`,
    )
    .bind(installationId, capturedAt)
    .all<AccessRow>();
  return results;
}

// Compare the most recent access snapshot against the most recent one taken
// at or before `since`. Returns an empty diff (with timestamps) when there is
// no baseline to compare against yet.
export async function buildAccessDiff(
  db: D1Database,
  installationId: number,
  since: string,
): Promise<AccessDiff> {
  const resourceList = ACCESS_RESOURCES.map((r) => `'${r}'`).join(", ");

  const latest = await db
    .prepare(
      `SELECT MAX(captured_at) AS t FROM snapshots
       WHERE installation_id = ?1 AND resource IN (${resourceList})`,
    )
    .bind(installationId)
    .first<{ t: string | null }>();

  const currentAt = latest?.t ?? null;
  if (!currentAt) return { currentAt: null, priorAt: null, currentCount: 0, entries: [] };

  // The baseline is the newest snapshot at or before `since` that is also
  // strictly older than the current one. Without the second condition a
  // same-day comparison would select the current snapshot as its own
  // baseline and report no changes at all.
  const prior = await db
    .prepare(
      `SELECT MAX(captured_at) AS t FROM snapshots
       WHERE installation_id = ?1 AND resource IN (${resourceList})
         AND captured_at <= ?2 AND captured_at < ?3`,
    )
    .bind(installationId, since, currentAt)
    .first<{ t: string | null }>();
  const priorAt = prior?.t ?? null;

  const current = await fetchSet(db, installationId, currentAt);

  // With no baseline there is nothing to diff. Returning the whole current
  // set as "added" would read as though everyone had just been granted
  // access, which is exactly the wrong thing to tell an auditor.
  if (!priorAt) return { currentAt, priorAt: null, currentCount: current.length, entries: [] };

  const priorRows = await fetchSet(db, installationId, priorAt);

  const key = (r: AccessRow) => `${r.resource}|${r.subject}`;
  const currentMap = new Map(current.map((r) => [key(r), r]));
  const priorMap = new Map(priorRows.map((r) => [key(r), r]));

  const entries: AccessDiffEntry[] = [];

  for (const [k, row] of currentMap) {
    const before = priorMap.get(k);
    if (!before) {
      entries.push({ resource: row.resource, subject: row.subject, change: "added", from: null, to: row.status });
    } else if (before.status !== row.status) {
      entries.push({
        resource: row.resource,
        subject: row.subject,
        change: "changed",
        from: before.status,
        to: row.status,
      });
    }
  }

  for (const [k, row] of priorMap) {
    if (!currentMap.has(k)) {
      entries.push({ resource: row.resource, subject: row.subject, change: "removed", from: row.status, to: null });
    }
  }

  entries.sort(
    (a, b) => a.change.localeCompare(b.change) || a.resource.localeCompare(b.resource) || a.subject.localeCompare(b.subject),
  );

  return { currentAt, priorAt, currentCount: current.length, entries };
}
