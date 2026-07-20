import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";

export type Framework = "soc2" | "iso27001" | "all";
export type ExportFormat = "csv" | "pdf";

export interface EvidenceRow {
  repo: string | null;
  // Org-scoped facts (access review) identify a person or team here rather
  // than a repository.
  subject: string | null;
  resource: string;
  status: string;
  framework: string;
  control_id: string;
  posture: string;
  rationale: string;
  captured_at: string;
}

// Current posture = the latest snapshot per (repo, resource) for this
// installation, joined to the control mapping table. snapshots is
// append-only, so "latest row wins" gives point-in-time current state.
// Rows whose resource/status pair has no mapping (e.g. "unavailable", or
// raw push/installation events) simply don't appear — no evidence either way.
export async function buildEvidenceRows(
  db: D1Database,
  installationId: number,
  framework: Framework,
): Promise<EvidenceRow[]> {
  const { results } = await db
    .prepare(
      `WITH access_latest AS (
         SELECT MAX(captured_at) AS t FROM snapshots
         WHERE installation_id = ?1 AND resource IN ('org_member', 'team_member')
       ),
       latest AS (
         SELECT repo, subject, resource, status, captured_at,
                ROW_NUMBER() OVER (
                  PARTITION BY repo, subject, resource
                  ORDER BY captured_at DESC, id DESC
                ) AS rn
         FROM snapshots
         WHERE installation_id = ?1
       )
       SELECT l.repo, l.subject, l.resource, l.status, cm.framework, cm.control_id,
              cm.posture, cm.rationale, l.captured_at
       FROM latest l
       JOIN control_mappings cm
         ON cm.resource = l.resource
        AND (cm.status IS NULL OR cm.status = l.status)
       WHERE l.rn = 1
         AND (?2 = 'all' OR cm.framework = ?2)
         -- Access facts are a full set per poll: a member who lost access has
         -- no newer row, so "latest row per subject" would keep attesting
         -- their access forever. Only the most recent poll batch counts.
         AND (
           l.resource NOT IN ('org_member', 'team_member')
           OR l.captured_at = (SELECT t FROM access_latest)
         )
       ORDER BY cm.framework, cm.control_id, l.repo`,
    )
    .bind(installationId, framework)
    .all<EvidenceRow>();

  return results;
}

const CSV_COLUMNS: Array<keyof EvidenceRow> = [
  "framework",
  "control_id",
  "posture",
  "repo",
  "subject",
  "resource",
  "status",
  "rationale",
  "captured_at",
];

export function renderCsv(rows: EvidenceRow[]): string {
  const lines = [CSV_COLUMNS.map(csvEscape).join(",")];
  for (const row of rows) {
    lines.push(CSV_COLUMNS.map((col) => csvEscape(row[col] ?? "")).join(","));
  }
  // CRLF line endings — RFC 4180, and what spreadsheet apps expect.
  return lines.join("\r\n") + "\r\n";
}

function csvEscape(value: string | number): string {
  const str = String(value);
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export interface ExportMeta {
  framework: Framework;
  installationId: number;
  generatedAt: string;
}

interface Column {
  header: string;
  key: keyof EvidenceRow;
  width: number;
}

const PDF_COLUMNS: Column[] = [
  { header: "Control", key: "control_id", width: 60 },
  { header: "Posture", key: "posture", width: 75 },
  { header: "Repo / Subject", key: "repo", width: 175 },
  { header: "Resource", key: "resource", width: 110 },
  { header: "Status", key: "status", width: 82 },
];

const PAGE = { width: 612, height: 792, margin: 50 };
const ROW_HEIGHT = 15;
const FONT_SIZE = 8;

const POSTURE_COLOR: Record<string, ReturnType<typeof rgb>> = {
  positive: rgb(0.1, 0.5, 0.2),
  negative: rgb(0.7, 0.15, 0.15),
  informational: rgb(0.4, 0.4, 0.4),
};

export async function renderPdf(rows: EvidenceRow[], meta: ExportMeta): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);

  const frameworkLabel = meta.framework === "all" ? "SOC 2 + ISO 27001" : meta.framework.toUpperCase();
  let page = doc.addPage([PAGE.width, PAGE.height]);
  let y = PAGE.height - PAGE.margin;

  // Title block.
  page.drawText("Compliance Evidence", { x: PAGE.margin, y, size: 18, font: bold });
  y -= 22;
  page.drawText(
    `${frameworkLabel}  ·  Installation ${meta.installationId}  ·  Generated ${meta.generatedAt}  ·  ${rows.length} findings`,
    { x: PAGE.margin, y, size: 9, font, color: rgb(0.35, 0.35, 0.35) },
  );
  y -= 24;

  y = drawHeader(page, bold, y);

  for (const row of rows) {
    if (y < PAGE.margin + ROW_HEIGHT) {
      page = doc.addPage([PAGE.width, PAGE.height]);
      y = PAGE.height - PAGE.margin;
      y = drawHeader(page, bold, y);
    }
    let x = PAGE.margin;
    for (const col of PDF_COLUMNS) {
      // The repo column doubles as the scope column: org-level access facts
      // carry a subject (member/team) instead of a repository.
      const raw = col.key === "repo" ? String(row.repo ?? row.subject ?? "") : String(row[col.key] ?? "");
      const text = truncate(raw, font, FONT_SIZE, col.width - 4);
      const color = col.key === "posture" ? POSTURE_COLOR[row.posture] ?? rgb(0, 0, 0) : rgb(0.1, 0.1, 0.1);
      page.drawText(text, { x, y, size: FONT_SIZE, font, color });
      x += col.width;
    }
    y -= ROW_HEIGHT;
  }

  return doc.save();
}

function drawHeader(page: PDFPage, bold: PDFFont, y: number): number {
  let x = PAGE.margin;
  for (const col of PDF_COLUMNS) {
    page.drawText(col.header, { x, y, size: FONT_SIZE, font: bold });
    x += col.width;
  }
  const lineY = y - 4;
  page.drawLine({
    start: { x: PAGE.margin, y: lineY },
    end: { x: PAGE.width - PAGE.margin, y: lineY },
    thickness: 0.5,
    color: rgb(0.6, 0.6, 0.6),
  });
  return y - ROW_HEIGHT;
}

function truncate(text: string, font: PDFFont, size: number, maxWidth: number): string {
  if (font.widthOfTextAtSize(text, size) <= maxWidth) return text;
  let truncated = text;
  while (truncated.length > 1 && font.widthOfTextAtSize(truncated + "…", size) > maxWidth) {
    truncated = truncated.slice(0, -1);
  }
  return truncated + "…";
}
