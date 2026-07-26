// Sync check: assert that the control-framework mappings in migrations/ exactly
// match the reference table in docs/framework-mapping.md. The migrations are the
// source of truth the engine reads; the doc is the human-readable copy an auditor
// relies on. If they drift, the doc is lying — so this fails CI.
//
// It works by actually applying every migration to an in-memory SQLite database
// (so migration 0003's delete-and-reinsert is handled exactly as production D1
// would), reading back control_mappings, and diffing against the rows parsed out
// of the doc's "Complete mapping reference" table.
//
// Run: npm run test:mappings   (no dependencies — uses Node's built-in sqlite)

import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDir = join(repoRoot, "migrations");
const docPath = join(repoRoot, "docs", "framework-mapping.md");

// A "·" in the doc's Status column means the mapping's status is NULL (matches
// any status); normalize both sides to this sentinel so they compare equal.
const NULL_STATUS = "·";
const key = (resource, status, framework, control, posture) =>
  `${resource}|${status ?? NULL_STATUS}|${framework}|${control}|${posture}`;

// --- 1. Source of truth: apply migrations, read control_mappings. ---
function rowsFromMigrations() {
  const db = new DatabaseSync(":memory:");
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const file of files) {
    db.exec(readFileSync(join(migrationsDir, file), "utf8"));
  }
  const rows = db
    .prepare("SELECT resource, status, framework, control_id, posture FROM control_mappings")
    .all();
  db.close();
  return new Set(rows.map((r) => key(r.resource, r.status, r.framework, r.control_id, r.posture)));
}

// --- 2. Human-readable copy: parse the doc's reference table. ---
// Matches only rows of the reference table, which are shaped:
//   | `resource` | status | SOC 2 | CC8.1 | positive | rationale |
// The framework name in cell 3 and the bare posture word in cell 5 are what
// distinguish these from the per-section tables (framework-first, prose posture)
// and the glossary (bolded control in cell 1), so those are not matched.
const FRAMEWORK_LABELS = { "SOC 2": "soc2", "ISO 27001": "iso27001" };
const ROW_RE =
  /^\|\s*`([^`]+)`\s*\|\s*(.+?)\s*\|\s*(SOC 2|ISO 27001)\s*\|\s*([\w.]+)\s*\|\s*(positive|negative|informational)\s*\|/;

function rowsFromDoc() {
  const set = new Set();
  for (const line of readFileSync(docPath, "utf8").split("\n")) {
    const m = ROW_RE.exec(line);
    if (!m) continue;
    const [, resource, statusCell, frameworkLabel, control, posture] = m;
    const status = statusCell.replace(/`/g, "").trim(); // already "·" for NULL
    set.add(key(resource, status, FRAMEWORK_LABELS[frameworkLabel], control, posture));
  }
  return set;
}

// --- 3. Diff. ---
const db = rowsFromMigrations();
const doc = rowsFromDoc();

const onlyInDb = [...db].filter((k) => !doc.has(k)).sort();
const onlyInDoc = [...doc].filter((k) => !db.has(k)).sort();

if (onlyInDb.length === 0 && onlyInDoc.length === 0) {
  console.log(`✓ mappings in sync: ${db.size} rows match between migrations/ and docs/framework-mapping.md`);
  process.exit(0);
}

console.error("✗ control-mapping drift between migrations/ and docs/framework-mapping.md\n");
console.error("  columns: resource | status | framework | control | posture\n");
if (onlyInDb.length) {
  console.error(`  In migrations but MISSING from the doc (${onlyInDb.length}):`);
  for (const k of onlyInDb) console.error(`    + ${k}`);
}
if (onlyInDoc.length) {
  console.error(`  In the doc but MISSING from migrations (${onlyInDoc.length}):`);
  for (const k of onlyInDoc) console.error(`    - ${k}`);
}
console.error("\n  Fix: update whichever is wrong so migrations/ and the doc's reference table agree.");
process.exit(1);
